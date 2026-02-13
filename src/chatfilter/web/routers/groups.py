"""FastAPI router for chat group operations.

This module handles CRUD operations for chat groups, including
file uploads, Google Sheets imports, and direct URL imports.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from typing import Annotated

import httpx
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from chatfilter.exporter import export_to_csv
from chatfilter.importer.google_sheets import fetch_google_sheet
from chatfilter.importer.parser import ChatListEntry, parse_chat_list
from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType
from chatfilter.models.group import ChatTypeEnum, GroupSettings, GroupStatus
from chatfilter.security.url_validator import URLValidationError, validate_url
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase

logger = logging.getLogger(__name__)

router = APIRouter()

# Maximum file size for group uploads (10MB as per security requirements)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
# Chunk size for reading uploaded files
READ_CHUNK_SIZE = 8192  # 8 KB chunks

# Allowed file extensions
ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".xls", ".txt"}

# MIME type mappings for validation
ALLOWED_MIME_TYPES = {
    ".csv": {"text/csv", "text/plain", "application/csv"},
    ".xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip",  # XLSX is a ZIP archive
    },
    ".xls": {
        "application/vnd.ms-excel",
        "application/octet-stream",  # Legacy binary format
    },
    ".txt": {"text/plain"},
}


def _detect_mime_type(content: bytes) -> str:
    """Detect MIME type from file content using magic bytes.

    Args:
        content: File content bytes

    Returns:
        Detected MIME type string
    """
    if not content:
        return "application/octet-stream"

    # Check for XLSX (ZIP archive with specific structure)
    if content[:2] == b"PK":
        # XLSX files are ZIP archives starting with PK
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    # Check for XLS (old binary format)
    if content[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "application/vnd.ms-excel"

    # Check if it's text (CSV or TXT)
    try:
        # Try to decode as UTF-8
        content[:1024].decode("utf-8")
        # Check if it looks like CSV (contains common delimiters)
        sample = content[:2048].decode("utf-8", errors="ignore")
        if any(delimiter in sample for delimiter in [",", ";", "\t"]):
            return "text/csv"
        return "text/plain"
    except (UnicodeDecodeError, AttributeError):
        pass

    return "application/octet-stream"


def _validate_file_type(file_ext: str, content: bytes) -> None:
    """Validate that file content matches the declared extension.

    Args:
        file_ext: File extension (e.g., '.csv', '.xlsx')
        content: File content bytes

    Raises:
        ValueError: If MIME type doesn't match extension
    """
    detected_mime = _detect_mime_type(content)
    allowed_mimes = ALLOWED_MIME_TYPES.get(file_ext, set())

    if detected_mime not in allowed_mimes:
        raise ValueError(
            f"File content type ({detected_mime}) does not match "
            f"extension ({file_ext}). Expected one of: {', '.join(allowed_mimes)}"
        )


async def read_upload_with_size_limit(
    upload_file: UploadFile, max_size: int, file_type: str = "file"
) -> bytes:
    """Read uploaded file with size limit enforcement.

    Reads file in chunks to prevent loading large files into memory.
    Raises ValueError if file exceeds size limit.

    Args:
        upload_file: FastAPI UploadFile object
        max_size: Maximum allowed file size in bytes
        file_type: Description of file type for error messages

    Returns:
        File content as bytes

    Raises:
        ValueError: If file exceeds size limit
    """
    content = bytearray()
    bytes_read = 0

    while True:
        chunk = await upload_file.read(READ_CHUNK_SIZE)
        if not chunk:
            break

        bytes_read += len(chunk)
        if bytes_read > max_size:
            raise ValueError(
                f"{file_type.capitalize()} size exceeds maximum allowed "
                f"size of {max_size / 1024 / 1024:.1f} MB"
            )

        content.extend(chunk)

    return bytes(content)


async def fetch_file_from_url(url: str, max_size: int, timeout: float = 30.0) -> bytes:
    """Fetch file from direct URL with security validation.

    Args:
        url: Direct file URL
        max_size: Maximum allowed file size in bytes
        timeout: Request timeout in seconds

    Returns:
        File content as bytes

    Raises:
        ValueError: If URL validation fails or file exceeds size limit
    """
    # Validate URL for security (SSRF prevention)
    try:
        validate_url(url)
    except URLValidationError as e:
        raise ValueError(f"URL validation failed: {e}") from e

    async with (
        httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client,
        client.stream("GET", url) as response,
    ):
        response.raise_for_status()

        # Stream response with size limit
        chunks = []
        total_size = 0

        async for chunk in response.iter_bytes():
            total_size += len(chunk)
            if total_size > max_size:
                raise ValueError(
                    f"File size exceeds maximum allowed size of {max_size / 1024 / 1024:.1f} MB"
                )
            chunks.append(chunk)

        return b"".join(chunks)


def _get_group_service() -> GroupService:
    """Get or create GroupService instance.

    Returns:
        GroupService instance
    """
    from chatfilter.config import get_settings

    settings = get_settings()
    db_path = settings.data_dir / "groups.db"
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    db = GroupDatabase(db_path)
    return GroupService(db)


@router.post("/api/groups", response_class=HTMLResponse)
async def create_group(
    request: Request,
    name: Annotated[str, Form()],
    source_type: Annotated[str, Form()],  # 'file_upload' | 'google_sheets' | 'file_url'
    file_upload: Annotated[UploadFile | None, File()] = None,
    google_sheets_url: Annotated[str | None, Form()] = None,
    file_url: Annotated[str | None, Form()] = None,
) -> HTMLResponse:
    """Create a new chat group.

    Accepts three input methods:
    1. File upload (CSV/XLSX/TXT)
    2. Google Sheets URL
    3. Direct file URL

    Args:
        request: FastAPI request object
        name: Group name
        source_type: Type of source ('file_upload', 'google_sheets', 'file_url')
        file_upload: Uploaded file (for file_upload type)
        google_sheets_url: Google Sheets URL (for google_sheets type)
        file_url: Direct file URL (for file_url type)

    Returns:
        HTML partial with new group card or error message
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    # Validate group name
    if not name or not name.strip():
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": "Group name is required"},
        )

    try:
        # Get chat entries based on source type
        chat_entries: list[ChatListEntry]

        if source_type == "file_upload":
            if not file_upload:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "File upload is required"},
                )

            # Validate file extension
            filename = file_upload.filename or "unknown"
            file_ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

            if file_ext not in ALLOWED_EXTENSIONS:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={
                        "error": f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
                    },
                )

            # Read file with size limit
            try:
                file_content = await read_upload_with_size_limit(
                    file_upload, MAX_FILE_SIZE, "file"
                )
            except ValueError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": str(e)},
                )

            # Validate MIME type matches extension
            try:
                _validate_file_type(file_ext, file_content)
            except ValueError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": str(e)},
                )

            # Parse chat list from file
            try:
                chat_entries = parse_chat_list(file_content, filename)
            except Exception as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to parse file: {str(e)}"},
                )

        elif source_type == "google_sheets":
            if not google_sheets_url:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "Google Sheets URL is required"},
                )

            # Fetch and parse Google Sheets (returns ChatListEntry objects directly)
            try:
                chat_entries = await fetch_google_sheet(google_sheets_url)
            except Exception as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to fetch Google Sheets: {str(e)}"},
                )

        elif source_type == "file_url":
            if not file_url:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "File URL is required"},
                )

            # Fetch file from URL with validation
            try:
                file_content = await fetch_file_from_url(file_url, max_size=MAX_FILE_SIZE)
                # Extract filename from URL or use default
                filename = file_url.rsplit("/", 1)[-1] if "/" in file_url else "file.txt"
            except ValueError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": str(e)},
                )
            except HTTPException as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to fetch file: {e.detail}"},
                )

            # Parse chat list from fetched file
            try:
                chat_entries = parse_chat_list(file_content, filename)
            except Exception as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to parse file: {str(e)}"},
                )

        else:
            return templates.TemplateResponse(
                request=request,
                name="partials/error_message.html",
                context={"error": f"Invalid source type: {source_type}"},
            )

        if not chat_entries:
            return templates.TemplateResponse(
                request=request,
                name="partials/error_message.html",
                context={"error": "No valid chat references found in file"},
            )

        # Create group via GroupService
        service = _get_group_service()
        chat_refs = [entry.value for entry in chat_entries]
        group = service.create_group(name.strip(), chat_refs)

        # Get group stats for card rendering
        stats = service.get_group_stats(group.id)

        # Render group card partial
        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context={"group": group, "stats": stats},
        )

    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to create group: {str(e)}"},
        )


@router.get("/api/groups", response_class=HTMLResponse)
async def list_groups(request: Request) -> HTMLResponse:
    """List all chat groups.

    Returns HTML partial with list of group cards for HTMX swap.

    Args:
        request: FastAPI request object

    Returns:
        HTML partial with groups list
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service()
        groups = service.list_groups()

        # Get stats for each group
        groups_with_stats = []
        for group in groups:
            stats = service.get_group_stats(group.id)
            groups_with_stats.append({"group": group, "stats": stats})

        return templates.TemplateResponse(
            request=request,
            name="partials/groups_list.html",
            context={"groups": groups_with_stats},
        )

    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to load groups: {str(e)}"},
        )


@router.get("/api/groups/{group_id}", response_class=HTMLResponse)
async def get_group(request: Request, group_id: str) -> HTMLResponse:
    """Get group details.

    Args:
        request: FastAPI request object
        group_id: Group identifier

    Returns:
        HTML partial with group card
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service()
        group = service.get_group(group_id)

        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        stats = service.get_group_stats(group_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context={"group": group, "stats": stats},
        )

    except HTTPException:
        raise
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to load group: {str(e)}"},
        )


@router.patch("/api/groups/{group_id}", response_class=HTMLResponse)
async def update_group(
    request: Request,
    group_id: str,
    name: Annotated[str, Form()],
) -> HTMLResponse:
    """Update a chat group.

    Currently supports updating group name only.

    Args:
        request: FastAPI request object
        group_id: Group identifier
        name: New group name

    Returns:
        HTML partial with updated group card
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    # Validate name
    if not name or not name.strip():
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": "Group name is required"},
        )

    try:
        service = _get_group_service()
        updated_group = service.update_group_name(group_id, name)

        if not updated_group:
            raise HTTPException(status_code=404, detail="Group not found")

        stats = service.get_group_stats(group_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context={"group": updated_group, "stats": stats},
        )

    except HTTPException:
        raise
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to update group: {str(e)}"},
        )


@router.delete("/api/groups/{group_id}", response_class=HTMLResponse)
async def delete_group(group_id: str) -> HTMLResponse:
    """Delete a chat group.

    Args:
        group_id: Group identifier

    Returns:
        Empty response for OOB swap
    """
    try:
        service = _get_group_service()
        service.delete_group(group_id)

        # Return empty response - HTMX will handle DOM removal via OOB swap
        return HTMLResponse(content="", status_code=200)

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete group: {str(e)}"
        ) from e


async def _generate_group_sse_events(
    group_id: str,
    request: Request,
) -> AsyncGenerator[str, None]:
    """Generate SSE events for group analysis progress.

    Currently a placeholder until GroupAnalysisEngine is implemented.
    Returns immediate completion with current group stats.

    Args:
        group_id: Group identifier
        request: FastAPI request for disconnect detection

    Yields:
        SSE formatted event strings
    """
    service = _get_group_service()

    # Verify group exists
    group = service.get_group(group_id)
    if not group:
        yield f"event: error\ndata: {json.dumps({'error': 'Group not found'})}\n\n"
        return

    # Get current stats
    stats = service.get_group_stats(group_id)

    # Send initial event with current state
    init_data = {
        "group_id": group_id,
        "total": stats.total,
        "analyzed": stats.analyzed,
        "failed": stats.failed,
        "pending": stats.pending,
    }
    yield f"event: init\ndata: {json.dumps(init_data)}\n\n"

    # TODO: When GroupAnalysisEngine is implemented, subscribe to real progress events here
    # For now, just send completion event immediately
    await asyncio.sleep(0.1)  # Small delay to prevent client-side race conditions

    complete_data = {
        "group_id": group_id,
        "total": stats.total,
        "analyzed": stats.analyzed,
        "message": "No active analysis",
    }
    yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"


@router.get("/api/groups/{group_id}/progress")
async def get_group_progress(
    group_id: str,
    request: Request,
) -> StreamingResponse:
    """SSE endpoint for streaming group analysis progress.

    Currently returns immediate completion. Will stream real-time progress
    when GroupAnalysisEngine is implemented.

    Args:
        group_id: Group identifier
        request: FastAPI request

    Returns:
        StreamingResponse with SSE events

    Raises:
        HTTPException: If group not found
    """
    # Verify group exists
    service = _get_group_service()
    group = service.get_group(group_id)

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    return StreamingResponse(
        _generate_group_sse_events(group_id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.get("/api/groups/{group_id}/export")
async def export_group_results(group_id: str) -> Response:
    """Export group analysis results as CSV.

    Downloads all analyzed chats for the group with their metrics.

    Args:
        group_id: Group identifier

    Returns:
        CSV file with analysis results

    Raises:
        HTTPException: If group not found or no results available
    """
    # Verify group exists
    service = _get_group_service()
    group = service.get_group(group_id)

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Load results from database
    results_data = service._db.load_results(group_id)

    if not results_data:
        raise HTTPException(
            status_code=404,
            detail="No analysis results available for this group",
        )

    # Convert database results to AnalysisResult objects
    analysis_results: list[AnalysisResult] = []

    for result in results_data:
        metrics_dict = result["metrics_data"]

        # Extract chat info from metrics_data
        # The metrics_data structure varies, but typically includes chat metadata
        chat_ref = result["chat_ref"]

        # Try to determine chat type from group_chats table
        with service._db._connection() as conn:
            cursor = conn.execute(
                "SELECT chat_type FROM group_chats WHERE group_id = ? AND chat_ref = ?",
                (group_id, chat_ref),
            )
            row = cursor.fetchone()

        if row:
            chat_type_str = row["chat_type"]
            # Map ChatTypeEnum to ChatType
            type_mapping = {
                ChatTypeEnum.GROUP.value: ChatType.GROUP,
                ChatTypeEnum.FORUM.value: ChatType.FORUM,
                ChatTypeEnum.CHANNEL_COMMENTS.value: ChatType.CHANNEL_WITH_COMMENTS,
                ChatTypeEnum.CHANNEL_NO_COMMENTS.value: ChatType.CHANNEL_NO_COMMENTS,
                ChatTypeEnum.DEAD.value: ChatType.CHANNEL_NO_COMMENTS,  # Fallback
                ChatTypeEnum.PENDING.value: ChatType.GROUP,  # Fallback
            }
            chat_type = type_mapping.get(chat_type_str, ChatType.GROUP)
        else:
            chat_type = ChatType.GROUP  # Fallback

        # Create AnalysisResult
        # Note: metrics_data might not have all fields, use sensible defaults
        analysis_result = AnalysisResult(
            chat=Chat(
                id=metrics_dict.get("chat_id", 0),
                title=metrics_dict.get("chat_title", chat_ref),
                chat_type=chat_type,
                username=metrics_dict.get("chat_username"),
            ),
            metrics=ChatMetrics(
                message_count=metrics_dict.get("message_count", 0),
                unique_authors=metrics_dict.get("unique_authors", 0),
                history_hours=metrics_dict.get("history_hours", 0.0),
                first_message_at=metrics_dict.get("first_message_at"),
                last_message_at=metrics_dict.get("last_message_at"),
            ),
            analyzed_at=result["analyzed_at"],
        )

        analysis_results.append(analysis_result)

    # Generate CSV using existing exporter
    csv_content = export_to_csv(analysis_results, include_bom=True)

    # Generate filename
    from datetime import UTC, datetime

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"{group.name.replace(' ', '_')}_{timestamp}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.put("/api/groups/{group_id}/settings", response_class=HTMLResponse)
async def update_group_settings(
    request: Request,
    group_id: str,
    message_limit: Annotated[int, Form()],
    leave_after: Annotated[bool, Form()] = False,
) -> HTMLResponse:
    """Update group analysis settings.

    Args:
        request: FastAPI request object
        group_id: Group identifier
        message_limit: Maximum messages to analyze per chat (10-10000)
        leave_after: Whether to leave chat after analysis

    Returns:
        HTML partial with updated group card or error message

    Raises:
        HTTPException: If group not found or validation fails
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Create and validate settings
        settings = GroupSettings(
            message_limit=message_limit,
            leave_after_analysis=leave_after,
        )

        # Update via service
        service = _get_group_service()
        service.update_settings(group_id, settings)

        # Get updated group for rendering
        group = service.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        stats = service.get_group_stats(group_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context={"group": group, "stats": stats},
        )

    except ValueError as e:
        # Validation error from GroupSettings or service
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": str(e)},
        )
    except HTTPException:
        raise
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to update settings: {str(e)}"},
        )


@router.post("/api/groups/{group_id}/start", response_class=HTMLResponse)
async def start_group_analysis(
    request: Request,
    group_id: str,
) -> HTMLResponse:
    """Start group analysis.

    Updates group status to IN_PROGRESS. Actual analysis engine integration
    will be added when GroupAnalysisEngine is implemented (ChatFilter-1dx8h).

    Args:
        request: FastAPI request object
        group_id: Group identifier

    Returns:
        HTML partial with updated group card or error message

    Raises:
        HTTPException: If group not found
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service()

        # Update status to IN_PROGRESS
        updated_group = service.update_status(group_id, GroupStatus.IN_PROGRESS)

        if not updated_group:
            raise HTTPException(status_code=404, detail="Group not found")

        # TODO: When GroupAnalysisEngine is ready, call engine.start(group_id) here

        stats = service.get_group_stats(group_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context={"group": updated_group, "stats": stats},
        )

    except HTTPException:
        raise
    except ValueError as e:
        # Status transition validation error
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": str(e)},
        )
    except Exception as e:
        logger.exception("Failed to start analysis for group %s", group_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to start analysis: {str(e)}"},
        )


@router.post("/api/groups/{group_id}/stop", response_class=HTMLResponse)
async def stop_group_analysis(
    request: Request,
    group_id: str,
) -> HTMLResponse:
    """Stop group analysis.

    Updates group status to PAUSED. Actual analysis engine integration
    will be added when GroupAnalysisEngine is implemented (ChatFilter-1dx8h).

    Args:
        request: FastAPI request object
        group_id: Group identifier

    Returns:
        HTML partial with updated group card or error message

    Raises:
        HTTPException: If group not found
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service()

        # Update status to PAUSED
        updated_group = service.update_status(group_id, GroupStatus.PAUSED)

        if not updated_group:
            raise HTTPException(status_code=404, detail="Group not found")

        # TODO: When GroupAnalysisEngine is ready, call engine.stop(group_id) here

        stats = service.get_group_stats(group_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context={"group": updated_group, "stats": stats},
        )

    except HTTPException:
        raise
    except ValueError as e:
        # Status transition validation error
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": str(e)},
        )
    except Exception as e:
        logger.exception("Failed to stop analysis for group %s", group_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to stop analysis: {str(e)}"},
        )

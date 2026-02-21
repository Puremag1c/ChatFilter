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
from urllib.parse import quote

import httpx
from fastapi import APIRouter, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, Response, StreamingResponse

from chatfilter.analyzer.group_engine import (
    GroupAnalysisEngine,
    NoConnectedAccountsError,
)
from chatfilter.analyzer.progress import ProgressTracker
from chatfilter.exporter.csv import export_group_results_to_csv
from chatfilter.importer.google_sheets import fetch_google_sheet
from chatfilter.importer.parser import ChatListEntry, parse_chat_list
from chatfilter.models.group import AnalysisMode, GroupSettings, GroupStatus
from chatfilter.security.url_validator import URLValidationError, validate_url
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase

router = APIRouter()
logger = logging.getLogger(__name__)


def _convert_results_for_exporter(results: list[dict]) -> list[dict]:
    """Convert flat results structure to exporter-compatible format.

    Converts service.get_results() flat structure to old nested structure
    expected by to_csv_rows_dynamic.

    Args:
        results: List of flat result dicts from service.get_results()

    Returns:
        List of dicts with metrics_data nested structure
    """
    converted = []
    for result in results:
        # Extract all fields into metrics_data dict
        metrics_data = {
            "title": result.get("title", ""),
            "chat_type": result.get("chat_type"),
            "subscribers": result.get("subscribers"),
            "messages_per_hour": result.get("messages_per_hour"),
            "unique_authors_per_hour": result.get("unique_authors_per_hour"),
            "moderation": result.get("moderation"),
            "captcha": result.get("captcha"),
            "status": result.get("status"),
        }
        converted.append({
            "chat_ref": result["chat_ref"],
            "metrics_data": metrics_data,
        })
    return converted


def parse_optional_int(value: str | None) -> int | None:
    """Convert query param to int, treating empty string as None.

    Args:
        value: Query parameter value (can be empty string from HTMX forms)

    Returns:
        Parsed integer or None if empty/None
    """
    if value is None or value == "":
        return None
    return int(value)


def parse_optional_float(value: str | None) -> float | None:
    """Convert query param to float, treating empty string as None.

    Args:
        value: Query parameter value (can be empty string from HTMX forms)

    Returns:
        Parsed float or None if empty/None
    """
    if value is None or value == "":
        return None
    return float(value)


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


def _get_group_service(request: Request | None = None) -> GroupService:
    """Get or create GroupService instance.

    Args:
        request: Optional FastAPI request for engine initialization

    Returns:
        GroupService instance
    """
    from chatfilter.config import get_settings

    settings = get_settings()
    db_path = settings.data_dir / "groups.db"
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    db = GroupDatabase(db_path)

    # If request provided, wire up engine
    engine = None
    if request is not None:
        engine = _get_group_engine(request)

    return GroupService(db, engine=engine)


# Singletons
_group_engine: GroupAnalysisEngine | None = None
_progress_tracker: ProgressTracker | None = None


def _get_group_engine(request: Request) -> GroupAnalysisEngine:
    """Get or create GroupAnalysisEngine instance (singleton).

    Args:
        request: FastAPI request to access app state

    Returns:
        GroupAnalysisEngine instance

    Raises:
        RuntimeError: If required app state components are not initialized
    """
    global _group_engine

    if _group_engine is not None:
        return _group_engine

    # Get dependencies from app state
    session_manager = request.app.state.app_state.session_manager
    if session_manager is None:
        raise RuntimeError("SessionManager not initialized in app state")

    # Get GroupDatabase from service
    service = _get_group_service()
    db = service._db

    # Create and cache engine
    _group_engine = GroupAnalysisEngine(
        db=db,
        session_manager=session_manager,
    )

    return _group_engine


def _get_progress_tracker() -> ProgressTracker:
    """Get or create ProgressTracker instance (singleton).

    Returns:
        ProgressTracker instance
    """
    global _progress_tracker

    if _progress_tracker is not None:
        return _progress_tracker

    # Get GroupDatabase from service
    service = _get_group_service()
    db = service._db

    # Create and cache tracker
    _progress_tracker = ProgressTracker(db)

    return _progress_tracker


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

        # Return empty response with HX-Trigger header to refresh the container
        return HTMLResponse(content="", status_code=200, headers={'HX-Trigger': 'refreshGroups'})

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

    Subscribes to ProgressTracker events and streams them as SSE.
    Sends heartbeat pings every 15s to detect stale connections.

    Args:
        group_id: Group identifier
        request: FastAPI request for disconnect detection

    Yields:
        SSE formatted event strings
    """
    service = _get_group_service()
    tracker = _get_progress_tracker()

    # Verify group exists
    group = service.get_group(group_id)
    if not group:
        yield f"event: error\ndata: {json.dumps({'error': 'Group not found'})}\n\n"
        return

    # Get analysis start time
    started_at = service._db.get_analysis_started_at(group_id)

    # Get global processed/total counts from DB
    processed, total = service._db.count_processed_chats(group_id)

    # Send initial event with current state
    init_data = {
        "group_id": group_id,
        "started_at": started_at.isoformat() if started_at else None,
        "processed": processed,
        "total": total,
        "status": group.status.value,
    }
    yield f"event: init\ndata: {json.dumps(init_data)}\n\n"

    # Check if group is already in terminal state (race condition fix)
    # If analysis completed/failed/paused BEFORE we subscribed, send completion immediately
    if group.status in (GroupStatus.COMPLETED, GroupStatus.FAILED, GroupStatus.PAUSED):
        # Send final complete event with current counts
        complete_data = {
            "group_id": group_id,
            "processed": processed,
            "total": total,
            "message": "Analysis complete",
        }
        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"
        return  # Don't subscribe or wait for events

    # Track max processed count for monotonic guarantee
    max_processed = processed

    # Subscribe to progress tracker events
    progress_queue = tracker.subscribe(group_id)

    # Heartbeat tracking (using non-blocking event loop time)
    loop = asyncio.get_event_loop()
    last_heartbeat = loop.time()
    HEARTBEAT_INTERVAL = 15.0  # seconds

    try:
        # Stream progress events until completion
        while True:
            # Check for client disconnect
            if await request.is_disconnected():
                break

            # Send heartbeat ping every 15s
            now = loop.time()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                yield f"event: ping\ndata: {json.dumps({'timestamp': now})}\n\n"
                last_heartbeat = now

            try:
                # Wait for next event with timeout to allow heartbeat checks
                event = await asyncio.wait_for(progress_queue.get(), timeout=1.0)

                if event is None:
                    # Analysis completed - get final counts from DB
                    final_processed, final_total = service._db.count_processed_chats(group_id)
                    # Enforce monotonic guarantee: max with last sent value
                    max_processed = max(max_processed, final_processed)
                    complete_data = {
                        "group_id": group_id,
                        "processed": max_processed,
                        "total": final_total,
                        "message": "Analysis complete",
                    }
                    yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"
                    break

                # Send progress event
                # Note: event.current and event.total are now global DB-based counts
                # from publish_from_db() in ProgressTracker
                # Enforce monotonic guarantee: never decrease
                max_processed = max(max_processed, event.current)
                progress_data = {
                    "group_id": event.group_id,
                    "status": event.status,
                    "processed": max_processed,
                    "total": event.total,
                    "chat_title": event.chat_title,
                    "message": event.message,
                }
                # Include status breakdown for live badge updates
                if event.breakdown:
                    progress_data["breakdown"] = event.breakdown
                yield f"event: progress\ndata: {json.dumps(progress_data)}\n\n"

                # Send error event if present
                if event.error:
                    error_data = {
                        "group_id": event.group_id,
                        "error": event.error,
                    }
                    yield f"event: error\ndata: {json.dumps(error_data)}\n\n"

            except asyncio.TimeoutError:
                # Timeout waiting for event - continue to check disconnect and heartbeat
                continue

    finally:
        # Cleanup: queue will be cleaned up by tracker
        pass


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


def _apply_export_filters(
    results_data: list[dict],
    *,
    chat_types: str | None = None,
    subscribers_min: int | None = None,
    subscribers_max: int | None = None,
    activity_min: float | None = None,
    activity_max: float | None = None,
    authors_min: float | None = None,
    authors_max: float | None = None,
    moderation: str = "all",
    captcha: str = "all",
) -> list[dict]:
    """Apply export filters to results data.

    Accepts results from service.get_results() which has flat structure.
    """
    allowed_chat_types = None
    if chat_types:
        allowed_chat_types = set(t.strip() for t in chat_types.split(",") if t.strip())

    filtered = []

    for result in results_data:
        # New model: flat structure from service.get_results()
        if allowed_chat_types:
            if result.get("chat_type") not in allowed_chat_types:
                continue

        if subscribers_min is not None or subscribers_max is not None:
            subscribers = result.get("subscribers")
            # When min=0, include chats with NULL subscribers (treat as "no lower bound")
            # Only exclude NULL if min > 0 or max is set (requires actual value for comparison)
            if subscribers is None:
                if (subscribers_min is not None and subscribers_min > 0) or subscribers_max is not None:
                    continue
            else:
                if subscribers_min is not None and subscribers < subscribers_min:
                    continue
                if subscribers_max is not None and subscribers > subscribers_max:
                    continue

        if activity_min is not None or activity_max is not None:
            activity = result.get("messages_per_hour")
            if activity is None:
                continue
            if activity_min is not None and activity < activity_min:
                continue
            if activity_max is not None and activity > activity_max:
                continue

        if authors_min is not None or authors_max is not None:
            authors = result.get("unique_authors_per_hour")
            if authors is None:
                continue
            if authors_min is not None and authors < authors_min:
                continue
            if authors_max is not None and authors > authors_max:
                continue

        if moderation != "all":
            mod_value = result.get("moderation")
            if moderation == "yes" and mod_value is not True:
                continue
            if moderation == "no" and mod_value is not False:
                continue

        if captcha != "all":
            captcha_value = result.get("captcha")
            if captcha == "yes" and captcha_value is not True:
                continue
            if captcha == "no" and captcha_value is not False:
                continue

        filtered.append(result)

    return filtered


@router.get("/api/groups/{group_id}/export/preview", response_class=HTMLResponse)
async def preview_export_count(
    group_id: str,
    chat_types: list[str] | None = Query(None),
    subscribers_min: str | None = None,
    subscribers_max: str | None = None,
    activity_min: str | None = None,
    activity_max: str | None = None,
    authors_min: str | None = None,
    authors_max: str | None = None,
    moderation: str = "all",
    captcha: str = "all",
) -> HTMLResponse:
    """Preview export count with filters applied.

    Returns HTML fragment showing how many chats match the current filters.
    Used by HTMX to update preview count in export modal.

    Args:
        group_id: Group identifier
        chat_types: Comma-separated list of chat types to include
        subscribers_min: Minimum subscribers count (string from query param, empty = None)
        subscribers_max: Maximum subscribers count (string from query param, empty = None)
        activity_min: Minimum messages per hour (string from query param, empty = None)
        activity_max: Maximum messages per hour (string from query param, empty = None)
        authors_min: Minimum unique authors per hour (string from query param, empty = None)
        authors_max: Maximum unique authors per hour (string from query param, empty = None)
        moderation: Filter by moderation (all/yes/no)
        captcha: Filter by captcha (all/yes/no)

    Returns:
        HTML fragment with count: '<span>Подходит: X из Y чатов</span>'

    Raises:
        HTTPException: If group not found
    """
    # Parse query params: empty string → None
    parsed_subscribers_min = parse_optional_int(subscribers_min)
    parsed_subscribers_max = parse_optional_int(subscribers_max)
    parsed_activity_min = parse_optional_float(activity_min)
    parsed_activity_max = parse_optional_float(activity_max)
    parsed_authors_min = parse_optional_float(authors_min)
    parsed_authors_max = parse_optional_float(authors_max)

    # Verify group exists
    service = _get_group_service()
    group = service.get_group(group_id)

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Load results from service (reads from group_chats columns)
    results_data = service.get_results(group_id)
    total_count = len(results_data)

    # Convert chat_types list to comma-separated string
    chat_types_str = ",".join(chat_types) if chat_types else None

    # Apply filters
    filtered_results = _apply_export_filters(
        results_data,
        chat_types=chat_types_str,
        subscribers_min=parsed_subscribers_min,
        subscribers_max=parsed_subscribers_max,
        activity_min=parsed_activity_min,
        activity_max=parsed_activity_max,
        authors_min=parsed_authors_min,
        authors_max=parsed_authors_max,
        moderation=moderation,
        captcha=captcha,
    )

    matching_count = len(filtered_results)

    # Return HTML fragment for HTMX swap with data attribute
    return HTMLResponse(
        content=f'<span data-count="{matching_count}">Подходит: {matching_count} из {total_count} чатов</span>',
        status_code=200,
    )


@router.get("/api/groups/{group_id}/export")
async def export_group_results(
    group_id: str,
    chat_types: list[str] | None = Query(None),
    subscribers_min: str | None = None,
    subscribers_max: str | None = None,
    activity_min: str | None = None,
    activity_max: str | None = None,
    authors_min: str | None = None,
    authors_max: str | None = None,
    moderation: str = "all",
    captcha: str = "all",
) -> Response:
    """Export group analysis results as CSV with dynamic columns and filtering.

    Columns are determined by the group's settings - only selected
    metrics are included in the CSV output.

    Args:
        group_id: Group identifier
        chat_types: Comma-separated list of chat types to include
        subscribers_min: Minimum subscribers count (string from query param, empty = None)
        subscribers_max: Maximum subscribers count (string from query param, empty = None)
        activity_min: Minimum messages per hour (string from query param, empty = None)
        activity_max: Maximum messages per hour (string from query param, empty = None)
        authors_min: Minimum unique authors per hour (string from query param, empty = None)
        authors_max: Maximum unique authors per hour (string from query param, empty = None)
        moderation: Filter by moderation (all/yes/no)
        captcha: Filter by captcha (all/yes/no)

    Returns:
        CSV file with filtered analysis results

    Raises:
        HTTPException: If group not found or no results available
    """
    # Parse query params: empty string → None
    parsed_subscribers_min = parse_optional_int(subscribers_min)
    parsed_subscribers_max = parse_optional_int(subscribers_max)
    parsed_activity_min = parse_optional_float(activity_min)
    parsed_activity_max = parse_optional_float(activity_max)
    parsed_authors_min = parse_optional_float(authors_min)
    parsed_authors_max = parse_optional_float(authors_max)

    # Verify group exists and load settings
    service = _get_group_service()
    group = service.get_group(group_id)

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Load results from service (reads from group_chats columns)
    results_data = service.get_results(group_id)

    # Convert chat_types list to comma-separated string
    chat_types_str = ",".join(chat_types) if chat_types else None

    # Apply filters
    filtered_results = _apply_export_filters(
        results_data,
        chat_types=chat_types_str,
        subscribers_min=parsed_subscribers_min,
        subscribers_max=parsed_subscribers_max,
        activity_min=parsed_activity_min,
        activity_max=parsed_activity_max,
        authors_min=parsed_authors_min,
        authors_max=parsed_authors_max,
        moderation=moderation,
        captcha=captcha,
    )

    # Always return CSV with headers, even if no results yet
    # This prevents browser from saving JSON error as a file
    # Convert flat results to exporter-compatible format (nested metrics_data)
    exporter_format = _convert_results_for_exporter(filtered_results or [])
    csv_content = export_group_results_to_csv(
        exporter_format,
        settings=group.settings,
        include_bom=True,
    )

    # Generate filename from group name
    import re
    import unicodedata
    from datetime import datetime

    # Sanitize group name for filename (security: prevent path traversal + header injection)
    sanitized_name = group.name if group.name else ""
    # Normalize unicode characters
    sanitized_name = unicodedata.normalize("NFKD", sanitized_name)
    # Strip path separators and parent dir sequences
    sanitized_name = sanitized_name.replace("/", "").replace("\\", "").replace("..", "")
    # Remove control characters (prevent HTTP Response Splitting)
    sanitized_name = re.sub(r"[\x00-\x1f\x7f]", "", sanitized_name)
    # Remove dangerous chars but PRESERVE non-ASCII (Cyrillic, etc.)
    sanitized_name = re.sub(r'[^\w\s-]', '', sanitized_name)
    # Replace spaces with underscores
    sanitized_name = sanitized_name.replace(" ", "_")
    # Limit length (filesystem limits)
    sanitized_name = sanitized_name[:255]

    # Fallback if empty after sanitization
    if not sanitized_name:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_name = f"sanitized_export_{timestamp}"

    # Create ASCII fallback for old browsers (transliterate or timestamp)
    ascii_fallback = sanitized_name.encode('ascii', 'ignore').decode('ascii')
    if not ascii_fallback:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ascii_fallback = f"export_{timestamp}"

    # RFC 5987 encoding: filename for old browsers, filename* for modern ones
    filename_ascii = f"{ascii_fallback}.csv"
    filename_utf8 = f"{sanitized_name}.csv"
    filename_encoded = quote(filename_utf8.encode('utf-8'))

    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename_ascii}"; filename*=UTF-8\'\'{filename_encoded}',
        },
    )



@router.put("/api/groups/{group_id}/settings", response_class=HTMLResponse)
async def update_group_settings(
    request: Request,
    group_id: str,
    detect_chat_type: Annotated[bool, Form()] = False,
    detect_subscribers: Annotated[bool, Form()] = False,
    detect_activity: Annotated[bool, Form()] = False,
    detect_unique_authors: Annotated[bool, Form()] = False,
    detect_moderation: Annotated[bool, Form()] = False,
    detect_captcha: Annotated[bool, Form()] = False,
    time_window: Annotated[int, Form()] = 24,
) -> HTMLResponse:
    """Update group analysis settings.

    Args:
        request: FastAPI request object
        group_id: Group identifier
        detect_chat_type: Whether to detect chat type (default: False)
        detect_subscribers: Whether to detect subscribers (default: False)
        detect_activity: Whether to detect activity (default: False)
        detect_unique_authors: Whether to detect unique authors (default: False)
        detect_moderation: Whether to detect moderation (default: False)
        detect_captcha: Whether to detect captcha (default: False)
        time_window: Time window in hours for activity analysis (default: 24)

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
            detect_chat_type=detect_chat_type,
            detect_subscribers=detect_subscribers,
            detect_activity=detect_activity,
            detect_unique_authors=detect_unique_authors,
            detect_moderation=detect_moderation,
            detect_captcha=detect_captcha,
            time_window=time_window,
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

    Triggers GroupAnalysisEngine to join chats, resolve types, and analyze them.
    Requires at least one connected Telegram account.

    Args:
        request: FastAPI request object
        group_id: Group identifier

    Returns:
        HTML partial with updated group card or error message

    Raises:
        HTTPException: If group not found or no accounts connected
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service(request)
        session_mgr = request.app.state.app_state.session_manager

        # Verify group exists
        group = service.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Validate connected accounts BEFORE starting
        connected_accounts = [
            sid for sid in session_mgr.list_sessions()
            if await session_mgr.is_healthy(sid)
        ]

        if not connected_accounts:
            # Return error toast via HX-Trigger
            trigger_data = json.dumps({
                "refreshGroups": None,
                "showToast": {
                    "message": "No connected Telegram accounts. Please connect at least one account.",
                    "type": "error"
                }
            })
            return HTMLResponse(
                content='',
                status_code=200,
                headers={'HX-Trigger': trigger_data}
            )

        # Start analysis via service (creates task internally, handles status)
        await service.start_analysis(group_id)

        # Return 204 No Content with HX-Trigger header to refresh the container
        return HTMLResponse(content='', status_code=204, headers={'HX-Trigger': 'refreshGroups'})

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start analysis: {e}",
        )




@router.post("/api/groups/{group_id}/reanalyze", response_class=HTMLResponse)
async def reanalyze_group(
    request: Request,
    group_id: str,
    mode: str = Query(..., pattern="^(increment|overwrite)$"),
) -> HTMLResponse:
    """Re-analyze a completed group with specified mode.

    Only available for completed groups.

    Modes:
    - increment: Fill missing metrics only (skips chats with existing data)
    - overwrite: Clear all results and re-analyze from scratch

    Args:
        request: FastAPI request object
        group_id: Group identifier
        mode: Re-analysis mode ('increment' or 'overwrite')

    Returns:
        HTML partial with updated group card or error message

    Raises:
        HTTPException: If group not found or status != COMPLETED (409 Conflict)
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service(request)
        session_mgr = request.app.state.app_state.session_manager

        # Verify group exists and check status
        group = service.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Validate status == COMPLETED (prevents concurrent analysis and incomplete groups)
        if group.status != GroupStatus.COMPLETED:
            error_msg = (
                "Analysis already running" if group.status == GroupStatus.IN_PROGRESS
                else "Re-analysis is only available for completed groups"
            )
            return templates.TemplateResponse(
                request=request,
                name="partials/error_message.html",
                context={"error": error_msg},
                status_code=409,
            )

        # Convert mode string to AnalysisMode enum
        analysis_mode = AnalysisMode.INCREMENT if mode == "increment" else AnalysisMode.OVERWRITE

        # Validate connected accounts BEFORE starting
        connected_accounts = [
            sid for sid in session_mgr.list_sessions()
            if await session_mgr.is_healthy(sid)
        ]

        if not connected_accounts:
            # Return error toast via HX-Trigger
            trigger_data = json.dumps({
                "refreshGroups": None,
                "showToast": {
                    "message": "No connected Telegram accounts. Please connect at least one account.",
                    "type": "error"
                }
            })
            return HTMLResponse(
                content='',
                status_code=200,
                headers={'HX-Trigger': trigger_data}
            )

        # Reanalyze via service (handles mode, task creation, status)
        await service.reanalyze(group_id, mode=analysis_mode)

        # Return 204 No Content with HX-Trigger header to refresh the container
        return HTMLResponse(content='', status_code=204, headers={'HX-Trigger': 'refreshGroups'})

    except HTTPException:
        raise
    except Exception as e:
        mode_description = "incremental" if mode == "increment" else "overwrite"
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start {mode_description} analysis: {e}",
        )




@router.post("/api/groups/{group_id}/stop", response_class=HTMLResponse)
async def stop_group_analysis(
    request: Request,
    group_id: str,
) -> HTMLResponse:
    """Stop group analysis.

    Cancels all active tasks for the group and updates status to PAUSED.

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
        service = _get_group_service(request)

        # Stop analysis via service (cancels task, updates status)
        service.stop_analysis(group_id)

        # Return 204 No Content with HX-Trigger header to refresh the container
        return HTMLResponse(content='', status_code=204, headers={'HX-Trigger': 'refreshGroups'})

    except HTTPException:
        raise
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to stop analysis: {str(e)}"},
        )


@router.post("/api/groups/{group_id}/resume", response_class=HTMLResponse)
async def resume_group_analysis(
    request: Request,
    group_id: str,
) -> HTMLResponse:
    """Resume paused group analysis.

    Continues analysis for pending and failed chats only (skips done chats).

    Args:
        request: FastAPI request object
        group_id: Group identifier

    Returns:
        HTML partial with updated group card or error message

    Raises:
        HTTPException:
            - 404 if group not found
            - 400 if group not paused or no chats to analyze
            - 409 if concurrent resume request (atomic update failed)
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service(request)
        session_mgr = request.app.state.app_state.session_manager

        # Verify group exists
        group = service.get_group(group_id)
        if not group:
            trigger_data = json.dumps({
                "refreshGroups": None,
                "showToast": {
                    "message": "Group not found",
                    "type": "error"
                }
            })
            return HTMLResponse(
                content='',
                status_code=404,
                headers={'HX-Trigger': trigger_data}
            )

        # Validate status == PAUSED or handle concurrent resume
        if group.status == GroupStatus.IN_PROGRESS:
            # Concurrent resume attempt — return 409 (idempotent retry)
            trigger_data = json.dumps({
                "refreshGroups": None,
                "showToast": {
                    "message": "Another operation in progress",
                    "type": "error"
                }
            })
            return HTMLResponse(
                content='',
                status_code=409,
                headers={'HX-Trigger': trigger_data}
            )
        elif group.status != GroupStatus.PAUSED:
            # Invalid state (completed, failed, pending) — return 400
            trigger_data = json.dumps({
                "refreshGroups": None,
                "showToast": {
                    "message": "Can only resume paused groups",
                    "type": "error"
                }
            })
            return HTMLResponse(
                content='',
                status_code=400,
                headers={'HX-Trigger': trigger_data}
            )

        # Check if there are chats to analyze (pending + failed)
        stats = service.get_group_stats(group_id)
        pending_count = stats.status_pending
        failed_count = stats.failed

        if pending_count + failed_count == 0:
            # No chats to analyze — return error
            trigger_data = json.dumps({
                "refreshGroups": None,
                "showToast": {
                    "message": "No chats to analyze",
                    "type": "error"
                }
            })
            return HTMLResponse(
                content='',
                status_code=400,
                headers={'HX-Trigger': trigger_data}
            )

        # Validate connected accounts BEFORE starting
        connected_accounts = [
            sid for sid in session_mgr.list_sessions()
            if await session_mgr.is_healthy(sid)
        ]

        if not connected_accounts:
            # Return error toast via HX-Trigger
            trigger_data = json.dumps({
                "refreshGroups": None,
                "showToast": {
                    "message": "No connected Telegram accounts. Please connect at least one account.",
                    "type": "error"
                }
            })
            return HTMLResponse(
                content='',
                status_code=200,
                headers={'HX-Trigger': trigger_data}
            )

        # Resume analysis via service (handles status, task)
        await service.start_analysis(group_id)

        # Return 204 No Content with HX-Trigger header to refresh the container
        return HTMLResponse(content='', status_code=204, headers={'HX-Trigger': 'refreshGroups'})

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to resume analysis: {e}",
        )


@router.get("/api/groups/modal/create", response_class=HTMLResponse)
async def get_create_group_modal(request: Request) -> HTMLResponse:
    """Get create group modal HTML.

    Args:
        request: FastAPI request object

    Returns:
        HTML modal for creating a group
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    return templates.TemplateResponse(
        request=request,
        name="partials/modals/create_group_modal.html",
        context={},
    )


@router.get("/api/groups/modal/settings/{group_id}", response_class=HTMLResponse)
async def get_settings_modal(request: Request, group_id: str) -> HTMLResponse:
    """Get group settings modal HTML.

    Args:
        request: FastAPI request object
        group_id: Group identifier

    Returns:
        HTML modal for editing group settings

    Raises:
        HTTPException: If group not found
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service()
        group = service.get_group(group_id)

        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        return templates.TemplateResponse(
            request=request,
            name="partials/modals/settings_modal.html",
            context={"group": group},
        )

    except HTTPException:
        raise
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to load settings: {str(e)}"},
        )


@router.get("/api/groups/modal/reanalyze-confirm/{group_id}", response_class=HTMLResponse)
async def get_reanalyze_confirm_modal(request: Request, group_id: str) -> HTMLResponse:
    """Get re-analysis confirmation modal HTML.

    Args:
        request: FastAPI request object
        group_id: Group identifier

    Returns:
        HTML modal for confirming destructive re-analysis (overwrite mode)

    Raises:
        HTTPException: If group not found
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service()
        group = service.get_group(group_id)

        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        return templates.TemplateResponse(
            request=request,
            name="partials/modals/reanalyze_confirm_modal.html",
            context={"group": group},
        )

    except HTTPException:
        raise
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to load confirmation modal: {str(e)}"},
        )


@router.get("/api/groups/{group_id}/export/modal", response_class=HTMLResponse)
async def get_export_modal(request: Request, group_id: str) -> HTMLResponse:
    """Get export filter modal HTML.

    Args:
        request: FastAPI request object
        group_id: Group identifier

    Returns:
        HTML modal for filtering export results

    Raises:
        HTTPException: If group not found
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service()
        group = service.get_group(group_id)

        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Load results to determine available chat types
        results_data = service.get_results(group_id)

        # Extract unique chat types from results
        available_chat_types = set()
        for result in results_data:
            chat_type = result.get("chat_type")
            if chat_type:
                available_chat_types.add(chat_type)

        # Convert to sorted list for consistent ordering
        available_chat_types = sorted(available_chat_types)

        return templates.TemplateResponse(
            request=request,
            name="partials/export_modal.html",
            context={
                "group": group,
                "available_chat_types": available_chat_types,
            },
        )

    except HTTPException:
        raise
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to load export modal: {str(e)}"},
        )

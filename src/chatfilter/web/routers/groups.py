"""Groups CRUD router for managing chat groups."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Path, Request, UploadFile
from fastapi.responses import HTMLResponse

from chatfilter.importer import (
    GoogleSheetsError,
    ParseError,
    fetch_google_sheet,
    is_google_sheets_url,
    parse_chat_list,
)
from chatfilter.security.url_validator import URLValidationError, validate_url

logger = logging.getLogger(__name__)

router = APIRouter(tags=["groups"])

# Maximum file size for group uploads (10 MB)
MAX_FILE_SIZE = 10 * 1024 * 1024

# Allowed file extensions
ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".xls", ".txt"}

# Read chunk size for streaming uploads
READ_CHUNK_SIZE = 64 * 1024


async def _read_upload_with_size_limit(
    upload_file: UploadFile, max_size: int
) -> bytes:
    """Read uploaded file with size limit enforcement.

    Args:
        upload_file: FastAPI UploadFile object.
        max_size: Maximum allowed file size in bytes.

    Returns:
        File content as bytes.

    Raises:
        ValueError: If file size exceeds max_size.
    """
    chunks: list[bytes] = []
    total_size = 0

    while True:
        chunk = await upload_file.read(READ_CHUNK_SIZE)
        if not chunk:
            break

        total_size += len(chunk)
        if total_size > max_size:
            raise ValueError(
                f"File too large (max {max_size // 1024 // 1024} MB)"
            )

        chunks.append(chunk)

    return b"".join(chunks)


def _get_file_extension(filename: str) -> str:
    """Extract lowercase file extension from filename."""
    import os

    _, ext = os.path.splitext(filename.lower())
    return ext


@router.post("/api/groups", response_class=HTMLResponse)
async def create_group(
    request: Request,
    group_name: Annotated[str, Form()],
    source_type: Annotated[str, Form()] = "file",
    google_sheets_url: Annotated[str, Form()] = "",
    file_url: Annotated[str, Form()] = "",
    chatlist_file: Annotated[UploadFile | None, File()] = None,
) -> HTMLResponse:
    """Create a new chat group.

    Accepts chat references from file upload, Google Sheets URL, or direct file URL.
    Returns HTML partial of the new group card for HTMX.
    """
    from chatfilter.web.app import get_templates
    from chatfilter.web.dependencies import get_group_service

    templates = get_templates()
    service = get_group_service()

    # Validate group name
    group_name = group_name.strip()
    if not group_name:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": "Group name is required"},
            status_code=422,
        )

    try:
        entries = []

        if source_type == "google_sheets":
            # Google Sheets URL
            url = google_sheets_url.strip()
            if not url:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "Google Sheets URL is required"},
                    status_code=422,
                )

            if not is_google_sheets_url(url):
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "Invalid Google Sheets URL"},
                    status_code=422,
                )

            entries = await fetch_google_sheet(url)

        elif source_type == "file_url":
            # Direct file URL
            url = file_url.strip()
            if not url:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "File URL is required"},
                    status_code=422,
                )

            # Validate URL against allowlist
            try:
                validate_url(url)
            except URLValidationError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"URL not allowed: {e}"},
                    status_code=422,
                )

            # Fetch the file
            import httpx

            try:
                async with httpx.AsyncClient(
                    timeout=30.0, follow_redirects=True
                ) as client:
                    async with client.stream("GET", url) as response:
                        response.raise_for_status()

                        accumulated = 0
                        chunks: list[bytes] = []
                        async for chunk in response.aiter_bytes():
                            accumulated += len(chunk)
                            if accumulated > MAX_FILE_SIZE:
                                return templates.TemplateResponse(
                                    request=request,
                                    name="partials/error_message.html",
                                    context={
                                        "error": f"File too large (max {MAX_FILE_SIZE // 1024 // 1024} MB)"
                                    },
                                    status_code=422,
                                )
                            chunks.append(chunk)

                        content = b"".join(chunks)

            except httpx.HTTPStatusError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to fetch file: HTTP {e.response.status_code}"},
                    status_code=422,
                )
            except httpx.RequestError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to fetch file: {e}"},
                    status_code=422,
                )

            # Guess filename from URL for format detection
            from urllib.parse import urlparse

            path = urlparse(url).path
            filename = path.rsplit("/", 1)[-1] if "/" in path else "unknown.csv"
            entries = parse_chat_list(content, filename)

        else:
            # File upload (default)
            if chatlist_file is None or not chatlist_file.filename:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "File is required"},
                    status_code=422,
                )

            filename = chatlist_file.filename
            ext = _get_file_extension(filename)
            if ext not in ALLOWED_EXTENSIONS:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={
                        "error": f"Unsupported file type: {ext}. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
                    },
                    status_code=422,
                )

            try:
                content = await _read_upload_with_size_limit(
                    chatlist_file, MAX_FILE_SIZE
                )
            except ValueError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": str(e)},
                    status_code=422,
                )

            if not content:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "File is empty"},
                    status_code=422,
                )

            entries = parse_chat_list(content, filename)

        if not entries:
            return templates.TemplateResponse(
                request=request,
                name="partials/error_message.html",
                context={"error": "No valid chat entries found"},
                status_code=422,
            )

        # Deduplicate
        seen: set[str] = set()
        unique_refs: list[str] = []
        for entry in entries:
            if entry.normalized not in seen:
                seen.add(entry.normalized)
                unique_refs.append(entry.value)

        # Create group via service
        group = service.create_group(name=group_name, chat_refs=unique_refs)

        logger.info(
            f"Created group '{group.name}' with {group.chat_count} chats (id={group.id})"
        )

        # Return the new group card for HTMX append
        stats = service.get_group_stats(group.id)
        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context={"group": group, "stats": stats},
        )

    except GoogleSheetsError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": str(e)},
            status_code=422,
        )
    except ParseError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Parse error: {e}"},
            status_code=422,
        )
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": str(e)},
            status_code=422,
        )
    except Exception:
        logger.exception("Unexpected error creating group")
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": "An unexpected error occurred. Please try again."},
            status_code=500,
        )


@router.get("/api/groups", response_class=HTMLResponse)
async def list_groups(request: Request) -> HTMLResponse:
    """List all groups. Returns HTML partial for HTMX."""
    from chatfilter.web.app import get_templates
    from chatfilter.web.dependencies import get_group_service

    templates = get_templates()
    service = get_group_service()

    groups = service.list_groups()

    # Build stats for each group
    groups_with_stats = []
    for group in groups:
        stats = service.get_group_stats(group.id)
        groups_with_stats.append({"group": group, "stats": stats})

    return templates.TemplateResponse(
        request=request,
        name="partials/groups_list.html",
        context={"groups_with_stats": groups_with_stats},
    )


@router.get("/api/groups/{group_id}", response_class=HTMLResponse)
async def get_group(
    request: Request,
    group_id: Annotated[str, Path()],
) -> HTMLResponse:
    """Get group details. Returns HTML partial for HTMX."""
    from chatfilter.web.app import get_templates
    from chatfilter.web.dependencies import get_group_service

    templates = get_templates()
    service = get_group_service()

    group = service.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    stats = service.get_group_stats(group_id)
    return templates.TemplateResponse(
        request=request,
        name="partials/group_card.html",
        context={"group": group, "stats": stats},
    )


@router.put("/api/groups/{group_id}", response_class=HTMLResponse)
async def update_group(
    request: Request,
    group_id: Annotated[str, Path()],
    group_name: Annotated[str, Form()],
) -> HTMLResponse:
    """Update group name. Returns updated group card for HTMX swap."""
    from chatfilter.web.app import get_templates
    from chatfilter.web.dependencies import get_group_service

    templates = get_templates()
    service = get_group_service()

    group = service.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    group_name = group_name.strip()
    if not group_name:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": "Group name cannot be empty"},
            status_code=422,
        )

    # Update group name in database
    from datetime import UTC, datetime

    service._db.save_group(
        group_id=group_id,
        name=group_name,
        settings=group.settings.model_dump(),
        status=group.status.value,
        created_at=group.created_at,
        updated_at=datetime.now(UTC),
    )

    # Reload updated group
    updated_group = service.get_group(group_id)
    stats = service.get_group_stats(group_id)

    return templates.TemplateResponse(
        request=request,
        name="partials/group_card.html",
        context={"group": updated_group, "stats": stats},
    )


@router.delete("/api/groups/{group_id}", response_class=HTMLResponse)
async def delete_group(
    group_id: Annotated[str, Path()],
) -> HTMLResponse:
    """Delete a group. Returns empty response for HTMX removal."""
    from chatfilter.web.dependencies import get_group_service

    service = get_group_service()

    group = service.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    service.delete_group(group_id)
    logger.info(f"Deleted group '{group.name}' (id={group_id})")

    return HTMLResponse(content="", status_code=200)

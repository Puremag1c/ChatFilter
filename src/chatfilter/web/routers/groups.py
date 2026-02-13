"""FastAPI router for chat group operations.

This module handles CRUD operations for chat groups, including
file uploads, Google Sheets imports, and direct URL imports.
"""

from __future__ import annotations

import io
from typing import Annotated

import httpx
from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse

from chatfilter.importer.google_sheets import fetch_google_sheet
from chatfilter.importer.parser import ChatListEntry, parse_chat_list
from chatfilter.security.url_validator import URLValidationError, validate_url
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase

router = APIRouter()

# Maximum file size for group uploads (10MB as per security requirements)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
# Chunk size for reading uploaded files
READ_CHUNK_SIZE = 8192  # 8 KB chunks

# Allowed file extensions
ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".xls", ".txt"}


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

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        async with client.stream("GET", url) as response:
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
        )

"""Chat list upload router for importing chats from files and Google Sheets."""

from __future__ import annotations

import logging
import time
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, File, Form, Path, Request, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from chatfilter.i18n import _
from chatfilter.importer import (
    ChatListEntry,
    GoogleSheetsError,
    ParseError,
    fetch_google_sheet,
    is_google_sheets_url,
    parse_chat_list,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["chatlist"])

# Maximum file size for uploads
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

# TTL for imported lists (1 hour)
LIST_TTL_SECONDS = 3600

# Maximum number of stored lists (LRU eviction)
MAX_STORED_LISTS = 100

# In-memory storage for imported chat lists with timestamps
# Structure: {list_id: (timestamp, entries)}
_imported_lists: dict[str, tuple[float, list[ChatListEntry]]] = {}


def deduplicate_entries(entries: list[ChatListEntry]) -> list[ChatListEntry]:
    """Remove duplicate entries while preserving order.

    Deduplication is based on the normalized chat reference (username/ID).

    Args:
        entries: List of chat entries, potentially with duplicates.

    Returns:
        List of unique entries in original order.
    """
    seen: set[str] = set()
    unique: list[ChatListEntry] = []
    for entry in entries:
        if entry.normalized not in seen:
            seen.add(entry.normalized)
            unique.append(entry)
    return unique


class ImportResult(BaseModel):
    """Result of a chat list import."""

    success: bool
    list_id: str | None = None
    entry_count: int = 0
    error: str | None = None
    entries: list[ChatListEntry] = []


def _cleanup_expired_lists() -> int:
    """Remove expired lists (TTL) and enforce max size (LRU).

    Returns:
        Number of lists removed.
    """
    now = time.time()
    removed = 0

    # Remove expired entries (TTL)
    expired_ids = [
        list_id
        for list_id, (timestamp, _) in _imported_lists.items()
        if now - timestamp > LIST_TTL_SECONDS
    ]
    for list_id in expired_ids:
        del _imported_lists[list_id]
        removed += 1

    # Enforce max size (LRU - remove oldest)
    if len(_imported_lists) > MAX_STORED_LISTS:
        # Sort by timestamp (oldest first)
        sorted_ids = sorted(_imported_lists.keys(), key=lambda x: _imported_lists[x][0])
        # Remove oldest until we're under the limit
        while len(_imported_lists) > MAX_STORED_LISTS:
            oldest_id = sorted_ids.pop(0)
            del _imported_lists[oldest_id]
            removed += 1

    if removed > 0:
        logger.debug(f"Cleaned up {removed} expired/excess chat lists")

    return removed


def store_chat_list(entries: list[ChatListEntry]) -> str:
    """Store a chat list and return its ID.

    Args:
        entries: List of chat entries to store.

    Returns:
        Unique list ID.
    """
    # Cleanup before adding new entry
    _cleanup_expired_lists()

    list_id = str(uuid4())
    _imported_lists[list_id] = (time.time(), entries)
    return list_id


def get_chat_list(list_id: str) -> list[ChatListEntry] | None:
    """Retrieve a stored chat list by ID.

    Args:
        list_id: The list ID.

    Returns:
        List of entries or None if not found/expired.
    """
    entry = _imported_lists.get(list_id)
    if entry is None:
        return None

    timestamp, entries = entry
    # Check if expired
    if time.time() - timestamp > LIST_TTL_SECONDS:
        del _imported_lists[list_id]
        return None

    return entries


def clear_chat_list(list_id: str) -> bool:
    """Remove a stored chat list.

    Args:
        list_id: The list ID.

    Returns:
        True if removed, False if not found.
    """
    if list_id in _imported_lists:
        del _imported_lists[list_id]
        return True
    return False


@router.post("/api/chatlist/upload", response_class=HTMLResponse)
async def upload_chat_list(
    request: Request,
    chatlist_file: Annotated[UploadFile, File()],
) -> HTMLResponse:
    """Upload and parse a chat list file (txt/csv/xlsx).

    Returns HTML partial for HTMX to display result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Read file content
        content = await chatlist_file.read()

        if len(content) > MAX_FILE_SIZE:
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": _("File too large (max {size} MB)").format(
                        size=MAX_FILE_SIZE // 1024 // 1024
                    ),
                },
            )

        if not content:
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": _("File is empty"),
                },
            )

        # Get filename for format detection
        filename = chatlist_file.filename or "unknown.txt"

        # Parse the file
        try:
            entries = parse_chat_list(content, filename)
        except ParseError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": _("Parse error: {error}").format(error=e),
                },
            )

        if not entries:
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": _("No valid chat entries found in file"),
                },
            )

        # Remove duplicates while preserving order
        unique_entries = deduplicate_entries(entries)

        # Store the list
        list_id = store_chat_list(unique_entries)

        logger.info(
            f"Imported {len(unique_entries)} chats from file '{filename}' (list_id={list_id})"
        )

        return templates.TemplateResponse(
            request=request,
            name="partials/chatlist_result.html",
            context={
                "success": True,
                "list_id": list_id,
                "entry_count": len(unique_entries),
                "entries": unique_entries,
                "source": filename,
            },
        )

    except Exception:
        logger.exception("Unexpected error during file upload")
        return templates.TemplateResponse(
            request=request,
            name="partials/chatlist_result.html",
            context={
                "success": False,
                "error": _(
                    "An unexpected error occurred while processing the file. Please try again."
                ),
            },
        )


@router.post("/api/chatlist/fetch_sheet", response_class=HTMLResponse)
async def fetch_google_sheet_endpoint(
    request: Request,
    sheet_url: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Fetch and parse a Google Sheet.

    Returns HTML partial for HTMX to display result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Validate URL
        sheet_url = sheet_url.strip()
        if not sheet_url:
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": _("Please enter a Google Sheets URL"),
                },
            )

        if not is_google_sheets_url(sheet_url):
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": _("Invalid Google Sheets URL"),
                },
            )

        # Fetch and parse
        try:
            entries = await fetch_google_sheet(sheet_url)
        except GoogleSheetsError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": str(e),
                },
            )

        if not entries:
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": _("No valid chat entries found in spreadsheet"),
                },
            )

        # Remove duplicates
        unique_entries = deduplicate_entries(entries)

        # Store the list
        list_id = store_chat_list(unique_entries)

        logger.info(f"Imported {len(unique_entries)} chats from Google Sheet (list_id={list_id})")

        return templates.TemplateResponse(
            request=request,
            name="partials/chatlist_result.html",
            context={
                "success": True,
                "list_id": list_id,
                "entry_count": len(unique_entries),
                "entries": unique_entries,
                "source": "Google Sheets",
            },
        )

    except Exception:
        logger.exception("Unexpected error during Google Sheets fetch")
        return templates.TemplateResponse(
            request=request,
            name="partials/chatlist_result.html",
            context={
                "success": False,
                "error": _(
                    "An unexpected error occurred while fetching the Google Sheet. Please try again."
                ),
            },
        )


@router.get("/api/chatlist/{list_id}", response_class=HTMLResponse)
async def get_chat_list_entries(
    request: Request,
    list_id: Annotated[
        str, Path(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    ],
) -> HTMLResponse:
    """Get entries for a stored chat list.

    Returns HTML partial with the list of entries.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    entries = get_chat_list(list_id)
    if entries is None:
        return templates.TemplateResponse(
            request=request,
            name="partials/chatlist_entries.html",
            context={
                "error": _("List not found or expired"),
            },
        )

    return templates.TemplateResponse(
        request=request,
        name="partials/chatlist_entries.html",
        context={
            "list_id": list_id,
            "entries": entries,
        },
    )


@router.delete("/api/chatlist/{list_id}", response_class=HTMLResponse)
async def delete_chat_list(
    list_id: Annotated[
        str, Path(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    ],
) -> HTMLResponse:
    """Delete a stored chat list.

    Returns empty response for HTMX.

    Raises:
        HTTPException: 404 if list not found
    """
    from fastapi import HTTPException

    if not clear_chat_list(list_id):
        raise HTTPException(status_code=404, detail=f"Chat list {list_id} not found")
    return HTMLResponse(content="", status_code=200)

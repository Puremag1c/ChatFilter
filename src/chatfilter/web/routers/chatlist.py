"""Chat list upload router for importing chats from files and Google Sheets."""

from __future__ import annotations

import logging
from typing import Annotated
from uuid import uuid4

from fastapi import APIRouter, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

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

# In-memory storage for imported chat lists (session-scoped)
# In production, you might want to use Redis or similar
_imported_lists: dict[str, list[ChatListEntry]] = {}


class ImportResult(BaseModel):
    """Result of a chat list import."""

    success: bool
    list_id: str | None = None
    entry_count: int = 0
    error: str | None = None
    entries: list[ChatListEntry] = []


def store_chat_list(entries: list[ChatListEntry]) -> str:
    """Store a chat list and return its ID.

    Args:
        entries: List of chat entries to store.

    Returns:
        Unique list ID.
    """
    list_id = str(uuid4())[:8]
    _imported_lists[list_id] = entries
    return list_id


def get_chat_list(list_id: str) -> list[ChatListEntry] | None:
    """Retrieve a stored chat list by ID.

    Args:
        list_id: The list ID.

    Returns:
        List of entries or None if not found.
    """
    return _imported_lists.get(list_id)


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
                    "error": f"File too large (max {MAX_FILE_SIZE // 1024 // 1024} MB)",
                },
            )

        if not content:
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": "File is empty",
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
                    "error": f"Parse error: {e}",
                },
            )

        if not entries:
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": "No valid chat entries found in file",
                },
            )

        # Remove duplicates while preserving order
        seen = set()
        unique_entries = []
        for entry in entries:
            if entry.normalized not in seen:
                seen.add(entry.normalized)
                unique_entries.append(entry)

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
                "error": "An unexpected error occurred while processing the file. Please try again.",
            },
        )


@router.post("/api/chatlist/fetch-sheet", response_class=HTMLResponse)
async def fetch_google_sheet_endpoint(
    request: Request,
    sheet_url: Annotated[str, Form()],
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
                    "error": "Please enter a Google Sheets URL",
                },
            )

        if not is_google_sheets_url(sheet_url):
            return templates.TemplateResponse(
                request=request,
                name="partials/chatlist_result.html",
                context={
                    "success": False,
                    "error": "Invalid Google Sheets URL",
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
                    "error": "No valid chat entries found in spreadsheet",
                },
            )

        # Remove duplicates
        seen = set()
        unique_entries = []
        for entry in entries:
            if entry.normalized not in seen:
                seen.add(entry.normalized)
                unique_entries.append(entry)

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
                "error": "An unexpected error occurred while fetching the Google Sheet. Please try again.",
            },
        )


@router.get("/api/chatlist/{list_id}", response_class=HTMLResponse)
async def get_chat_list_entries(
    request: Request,
    list_id: str,
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
                "error": "List not found or expired",
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
async def delete_chat_list(list_id: str) -> HTMLResponse:
    """Delete a stored chat list.

    Returns empty response for HTMX.
    """
    clear_chat_list(list_id)
    return HTMLResponse(content="", status_code=200)

"""Groups router for chat group CRUD operations."""

from __future__ import annotations

import io
import logging
from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse

from chatfilter.importer.google_sheets import fetch_google_sheet
from chatfilter.importer.parser import ParseError, parse_chat_list
from chatfilter.service.group_service import GroupService
from chatfilter.web.dependencies import get_group_service

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/api/groups", response_class=HTMLResponse)
async def create_group(
    request: Request,
    group_name: Annotated[str, Form()],
    source_type: Annotated[str, Form()],
    file: Annotated[UploadFile | None, File()] = None,
    google_sheets_url: Annotated[str | None, Form()] = None,
    file_url: Annotated[str | None, Form()] = None,
) -> HTMLResponse:
    """Create a new chat group from file upload, Google Sheets, or direct URL.

    Args:
        group_name: Name of the group.
        source_type: One of: 'upload', 'google_sheets', 'url'.
        file: Uploaded file (if source_type == 'upload').
        google_sheets_url: Google Sheets URL (if source_type == 'google_sheets').
        file_url: Direct file URL (if source_type == 'url').

    Returns:
        HTML partial with created group card or error message.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()
    group_service = get_group_service()

    try:
        # Validate group name
        if not group_name or not group_name.strip():
            return templates.TemplateResponse(
                request=request,
                name="partials/create_group_result.html",
                context={"success": False, "error": "Group name cannot be empty"},
            )

        # Get file content based on source type
        file_content: bytes
        filename: str

        if source_type == "upload":
            if not file:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/create_group_result.html",
                    context={"success": False, "error": "No file uploaded"},
                )
            file_content = await file.read()
            filename = file.filename or "file.txt"

        elif source_type == "google_sheets":
            if not google_sheets_url:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/create_group_result.html",
                    context={"success": False, "error": "Google Sheets URL is required"},
                )
            try:
                # fetch_google_sheet returns list[ChatListEntry] directly
                parsed_entries = await fetch_google_sheet(google_sheets_url)
                # Skip parse_chat_list for Google Sheets - already parsed
                file_content = None
                filename = None
            except Exception as e:
                logger.error(f"Failed to fetch Google Sheets: {e}")
                return templates.TemplateResponse(
                    request=request,
                    name="partials/create_group_result.html",
                    context={"success": False, "error": f"Failed to fetch Google Sheets: {e}"},
                )

        elif source_type == "url":
            if not file_url:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/create_group_result.html",
                    context={"success": False, "error": "File URL is required"},
                )
            try:
                # Fetch file from URL (using existing validated fetch logic)
                import httpx

                async with httpx.AsyncClient() as client:
                    response = await client.get(file_url, follow_redirects=True)
                    response.raise_for_status()
                    file_content = response.content
                # Extract filename from URL or use default
                filename = file_url.split("/")[-1] or "file.txt"
            except Exception as e:
                logger.error(f"Failed to fetch file from URL: {e}")
                return templates.TemplateResponse(
                    request=request,
                    name="partials/create_group_result.html",
                    context={"success": False, "error": f"Failed to fetch file: {e}"},
                )

        else:
            return templates.TemplateResponse(
                request=request,
                name="partials/create_group_result.html",
                context={
                    "success": False,
                    "error": f"Invalid source_type: {source_type}. Must be 'upload', 'google_sheets', or 'url'.",
                },
            )

        # Parse file content (skip for Google Sheets - already parsed)
        if file_content is not None:
            try:
                parsed_entries = parse_chat_list(file_content, filename)
            except ParseError as e:
                logger.error(f"Failed to parse chat list: {e}")
                return templates.TemplateResponse(
                    request=request,
                    name="partials/create_group_result.html",
                    context={"success": False, "error": f"Failed to parse file: {e}"},
                )

        if not parsed_entries:
            return templates.TemplateResponse(
                request=request,
                name="partials/create_group_result.html",
                context={"success": False, "error": "No valid chat references found in file"},
            )

        # Extract chat refs from parsed entries
        chat_refs = [entry.value for entry in parsed_entries]

        # Create group via GroupService
        try:
            group = group_service.create_group(group_name.strip(), chat_refs)
        except ValueError as e:
            logger.error(f"Failed to create group: {e}")
            return templates.TemplateResponse(
                request=request,
                name="partials/create_group_result.html",
                context={"success": False, "error": str(e)},
            )

        # Return success with group card
        return templates.TemplateResponse(
            request=request,
            name="partials/create_group_result.html",
            context={"success": True, "group": group},
        )

    except Exception as e:
        logger.exception("Unexpected error creating group")
        return templates.TemplateResponse(
            request=request,
            name="partials/create_group_result.html",
            context={"success": False, "error": f"Unexpected error: {e}"},
        )


@router.get("/api/groups", response_class=HTMLResponse)
async def list_groups(request: Request) -> HTMLResponse:
    """List all chat groups.

    Returns:
        HTML partial with groups list.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()
    group_service = get_group_service()

    groups = group_service.list_groups()

    return templates.TemplateResponse(
        request=request,
        name="partials/groups_list.html",
        context={"groups": groups},
    )


@router.get("/api/groups/{group_id}", response_class=HTMLResponse)
async def get_group(request: Request, group_id: str) -> HTMLResponse:
    """Get group details.

    Args:
        group_id: Group identifier.

    Returns:
        HTML partial with group details.

    Raises:
        HTTPException: If group not found.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()
    group_service = get_group_service()

    group = group_service.get_group(group_id)
    if not group:
        raise HTTPException(status_code=404, detail=f"Group not found: {group_id}")

    # Get group stats
    stats = group_service.get_group_stats(group_id)

    return templates.TemplateResponse(
        request=request,
        name="partials/group_detail.html",
        context={"group": group, "stats": stats},
    )


@router.delete("/api/groups/{group_id}", response_class=HTMLResponse)
async def delete_group(request: Request, group_id: str) -> HTMLResponse:
    """Delete a chat group.

    Args:
        group_id: Group identifier.

    Returns:
        Empty response for HTMX (removes element from DOM).
    """
    group_service = get_group_service()

    try:
        group_service.delete_group(group_id)
        # Return empty response - HTMX will remove the element from DOM
        return HTMLResponse(content="", status_code=200)
    except Exception as e:
        logger.error(f"Failed to delete group {group_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete group: {e}")

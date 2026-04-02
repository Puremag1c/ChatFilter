"""CRUD operations for groups router.

This module handles create, read, update, delete operations for groups,
plus group settings management.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse

from chatfilter.importer.google_sheets import fetch_google_sheet
from chatfilter.importer.parser import ChatListEntry, parse_chat_list
from chatfilter.models.catalog import AnalysisModeEnum
from chatfilter.web.dependencies import WebSession
from chatfilter.web.template_helpers import get_template_context

from .helpers import (
    ALLOWED_EXTENSIONS,
    MAX_FILE_SIZE,
    _get_group_service,
    _validate_file_type,
    fetch_file_from_url,
    read_upload_with_size_limit,
)

router = APIRouter()


@router.post("/api/groups", response_class=HTMLResponse)
async def create_group(
    request: Request,
    web_session: WebSession,
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
            status_code=422,
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
                    status_code=422,
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
                    status_code=422,
                )

            # Read file with size limit
            try:
                file_content = await read_upload_with_size_limit(file_upload, MAX_FILE_SIZE, "file")
            except ValueError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": str(e)},
                    status_code=422,
                )

            # Validate MIME type matches extension
            try:
                _validate_file_type(file_ext, file_content)
            except ValueError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": str(e)},
                    status_code=422,
                )

            # Parse chat list from file
            try:
                chat_entries = parse_chat_list(file_content, filename)
            except Exception as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to parse file: {str(e)}"},
                    status_code=422,
                )

        elif source_type == "google_sheets":
            if not google_sheets_url:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "Google Sheets URL is required"},
                    status_code=422,
                )

            # Fetch and parse Google Sheets (returns ChatListEntry objects directly)
            try:
                chat_entries = await fetch_google_sheet(google_sheets_url)
            except Exception as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to fetch Google Sheets: {str(e)}"},
                    status_code=422,
                )

        elif source_type == "file_url":
            if not file_url:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": "File URL is required"},
                    status_code=422,
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
                    status_code=422,
                )
            except HTTPException as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to fetch file: {e.detail}"},
                    status_code=422,
                )

            # Parse chat list from fetched file
            try:
                chat_entries = parse_chat_list(file_content, filename)
            except Exception as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/error_message.html",
                    context={"error": f"Failed to parse file: {str(e)}"},
                    status_code=422,
                )

        else:
            return templates.TemplateResponse(
                request=request,
                name="partials/error_message.html",
                context={"error": f"Invalid source type: {source_type}"},
                status_code=422,
            )

        if not chat_entries:
            return templates.TemplateResponse(
                request=request,
                name="partials/error_message.html",
                context={"error": "No valid chat references found in file"},
                status_code=422,
            )

        # Create group via GroupService
        service = _get_group_service()
        chat_refs = [entry.value for entry in chat_entries]
        user_id: str = web_session.get("user_id", "")
        group = service.create_group(name.strip(), chat_refs, user_id=user_id)

        # Get group stats for card rendering
        stats = service.get_group_stats(group.id)

        # Render group card partial
        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context=get_template_context(request, group=group, stats=stats),
        )

    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to create group: {str(e)}"},
            status_code=422,
        )


@router.get("/api/groups", response_class=HTMLResponse)
async def list_groups(request: Request, web_session: WebSession) -> HTMLResponse:
    """List all chat groups.

    Returns HTML partial with list of group cards for HTMX swap.

    Args:
        request: FastAPI request object
        web_session: User's web session

    Returns:
        HTML partial with groups list
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service()
        user_id: str = web_session.get("user_id", "")
        groups = service.list_groups(user_id=user_id)

        # Get stats for each group
        groups_with_stats = []
        for group in groups:
            stats = service.get_group_stats(group.id)
            groups_with_stats.append({"group": group, "stats": stats})

        return templates.TemplateResponse(
            request=request,
            name="partials/groups_list.html",
            context=get_template_context(request, groups=groups_with_stats),
        )

    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to load groups: {str(e)}"},
        )


@router.get("/api/groups/{group_id}", response_class=HTMLResponse)
async def get_group(request: Request, web_session: WebSession, group_id: str) -> HTMLResponse:
    """Get group details.

    Args:
        request: FastAPI request object
        web_session: User's web session
        group_id: Group identifier

    Returns:
        HTML partial with group card
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service()
        user_id: str = web_session.get("user_id", "")
        group = service.get_group(group_id, user_id=user_id)

        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        stats = service.get_group_stats(group_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context=get_template_context(request, group=group, stats=stats),
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
    web_session: WebSession,
    group_id: str,
    name: Annotated[str, Form()],
) -> HTMLResponse:
    """Update a chat group.

    Currently supports updating group name only.

    Args:
        request: FastAPI request object
        web_session: User's web session
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
        user_id: str = web_session.get("user_id", "")
        updated_group = service.update_group_name(group_id, name, user_id=user_id)

        if not updated_group:
            raise HTTPException(status_code=404, detail="Group not found")

        stats = service.get_group_stats(group_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context=get_template_context(request, group=updated_group, stats=stats),
        )

    except PermissionError as e:
        raise HTTPException(status_code=403, detail="Access denied") from e
    except HTTPException:
        raise
    except Exception as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/error_message.html",
            context={"error": f"Failed to update group: {str(e)}"},
        )


@router.delete("/api/groups/{group_id}", response_class=HTMLResponse)
async def delete_group(web_session: WebSession, group_id: str) -> HTMLResponse:
    """Delete a chat group.

    Args:
        web_session: User's web session
        group_id: Group identifier

    Returns:
        Empty response for OOB swap
    """
    import json

    try:
        service = _get_group_service()
        user_id: str = web_session.get("user_id", "")
        service.delete_group(group_id, user_id=user_id)

        # Return empty response with HX-Trigger header to refresh the container and show toast
        trigger = json.dumps(
            {"refreshGroups": {}, "showToast": {"type": "success", "message": "Группа удалена"}}
        )
        return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": trigger})

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete group: {str(e)}") from e


@router.put("/api/groups/{group_id}/settings", response_class=HTMLResponse)
async def update_group_settings(
    request: Request,
    web_session: WebSession,
    group_id: str,
    analysis_mode: Annotated[str, Form()] = "quick",
) -> HTMLResponse:
    """Update group analysis settings.

    Args:
        request: FastAPI request object
        group_id: Group identifier
        analysis_mode: Analysis mode ('quick' or 'deep', default: 'quick')

    Returns:
        HTML partial with updated group card or error message

    Raises:
        HTTPException: If group not found or validation fails
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Validate and convert analysis_mode to GroupSettings
        try:
            mode = AnalysisModeEnum(analysis_mode)
        except ValueError:
            return templates.TemplateResponse(
                request=request,
                name="partials/error_message.html",
                context={
                    "error": f"Invalid analysis_mode: {analysis_mode}. Must be 'quick' or 'deep'"
                },
                status_code=422,
            )
        settings = mode.to_group_settings()

        # Update via service
        service = _get_group_service()
        user_id: str = web_session.get("user_id", "")
        service.update_settings(group_id, settings, user_id=user_id)

        # Get updated group for rendering
        group = service.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        stats = service.get_group_stats(group_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context=get_template_context(request, group=group, stats=stats),
        )

    except PermissionError as e:
        raise HTTPException(status_code=403, detail="Access denied") from e
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

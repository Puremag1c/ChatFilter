"""Modal endpoints for groups router.

This module handles rendering HTML modals for various group operations.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from .helpers import _get_group_service

router = APIRouter()


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

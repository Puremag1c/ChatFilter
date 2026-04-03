"""Modal endpoints for groups router.

This module handles rendering HTML modals for various group operations.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse

from chatfilter.web.dependencies import WebSession

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
async def get_settings_modal(
    request: Request, web_session: WebSession, group_id: str
) -> HTMLResponse:
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
        user_id: str = web_session.get("user_id", "")
        group = service.get_group(group_id, user_id=user_id)

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
async def get_reanalyze_confirm_modal(
    request: Request, web_session: WebSession, group_id: str
) -> HTMLResponse:
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
        user_id: str = web_session.get("user_id", "")
        group = service.get_group(group_id, user_id=user_id)

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


@router.get("/api/groups/modal/collect", response_class=HTMLResponse)
async def get_collect_modal(request: Request) -> HTMLResponse:
    """Get collect chats modal HTML with platform list.

    Args:
        request: FastAPI request object

    Returns:
        HTML modal for collecting chats via search
    """
    from chatfilter.scraper import registry
    from chatfilter.web.app import get_templates

    templates = get_templates()

    service = _get_group_service()
    db = service._db

    # Build platform info list: all platforms with availability flag
    all_settings = {s["id"]: s for s in db.get_all_platform_settings()}
    cost_icons = {"cheap": "💚", "medium": "🟡", "expensive": "🔴"}
    platforms_info = []
    for platform in registry.get_all():
        settings = all_settings.get(platform.id)
        disabled_reason = None
        if settings is not None:
            enabled = bool(settings.get("enabled", True))
            has_key = bool(settings.get("api_key")) if platform.needs_api_key else True
            if not enabled:
                disabled_reason = "Platform disabled"
            elif not has_key:
                disabled_reason = "API key required"
        else:
            enabled = True
            has_key = not platform.needs_api_key
            if not has_key:
                disabled_reason = "API key required"
        available = enabled and has_key
        platforms_info.append(
            {
                "id": platform.id,
                "name": platform.name,
                "cost_tier": platform.cost_tier,
                "cost_icon": cost_icons.get(platform.cost_tier, "🟡"),
                "needs_api_key": platform.needs_api_key,
                "available": available,
                "disabled_reason": disabled_reason,
            }
        )

    return templates.TemplateResponse(
        request=request,
        name="partials/modals/collect_modal.html",
        context={"platforms": platforms_info},
    )


@router.get("/api/groups/{group_id}/export/modal", response_class=HTMLResponse)
async def get_export_modal(
    request: Request, web_session: WebSession, group_id: str
) -> HTMLResponse:
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
        user_id: str = web_session.get("user_id", "")
        group = service.get_group(group_id, user_id=user_id)

        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Load results to determine available chat types
        results_data = service.get_results(group_id)

        # Extract unique chat types from results
        available_chat_types_set: set[str] = set()
        for result in results_data:
            chat_type = result.get("chat_type")
            if chat_type:
                available_chat_types_set.add(chat_type)

        # Convert to sorted list for consistent ordering
        available_chat_types = sorted(available_chat_types_set)

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

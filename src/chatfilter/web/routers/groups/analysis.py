"""Analysis control endpoints for groups router.

This module handles starting, stopping, resuming, and reanalyzing groups.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from chatfilter.models.group import AnalysisMode, GroupStatus
from chatfilter.telegram.session.models import SessionState
from chatfilter.web.dependencies import WebSession
from chatfilter.web.template_helpers import get_template_context

from .helpers import _get_group_service

router = APIRouter()


@router.post("/api/groups/{group_id}/start", response_class=HTMLResponse)
async def start_group_analysis(
    request: Request,
    web_session: WebSession,
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

    get_templates()

    try:
        service = _get_group_service(request)
        session_mgr = request.app.state.app_state.session_manager
        user_id: str = web_session.get("user_id", "")

        # Verify group exists and belongs to this user
        group = service.get_group(group_id, user_id=user_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Guard against duplicate analysis (e.g. double-click)
        if group.status == GroupStatus.IN_PROGRESS:
            return HTMLResponse(
                content="",
                status_code=409,
                headers={
                    "HX-Trigger": json.dumps(
                        {"showToast": {"message": "Analysis already running", "type": "warning"}}
                    )
                },
            )

        # Validate connected accounts BEFORE starting (instant in-memory check)
        connected_accounts = [
            sid
            for sid in session_mgr.list_sessions()
            if (info := session_mgr.get_info(sid)) and info.state == SessionState.CONNECTED
        ]

        if not connected_accounts:
            # Return error toast via HX-Trigger
            trigger_data = json.dumps(
                {
                    "refreshGroups": None,
                    "showToast": {
                        "message": "No connected Telegram accounts. Please connect at least one account.",
                        "type": "error",
                    },
                }
            )
            return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": trigger_data})

        service.start_analysis(group_id)

        # Return 204 No Content with HX-Trigger header to refresh the container
        return HTMLResponse(content="", status_code=204, headers={"HX-Trigger": "refreshGroups"})

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start analysis: {e}",
        ) from e


@router.post("/api/groups/{group_id}/reanalyze", response_class=HTMLResponse)
async def reanalyze_group(
    request: Request,
    web_session: WebSession,
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
        user_id: str = web_session.get("user_id", "")

        # Verify group exists and belongs to this user
        group = service.get_group(group_id, user_id=user_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Validate status == COMPLETED (prevents concurrent analysis and incomplete groups)
        if group.status != GroupStatus.COMPLETED:
            error_msg = (
                "Analysis already running"
                if group.status == GroupStatus.IN_PROGRESS
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

        # Validate connected accounts BEFORE starting (instant in-memory check)
        connected_accounts = [
            sid
            for sid in session_mgr.list_sessions()
            if (info := session_mgr.get_info(sid)) and info.state == SessionState.CONNECTED
        ]

        if not connected_accounts:
            # Return error toast via HX-Trigger
            trigger_data = json.dumps(
                {
                    "refreshGroups": None,
                    "showToast": {
                        "message": "No connected Telegram accounts. Please connect at least one account.",
                        "type": "error",
                    },
                }
            )
            return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": trigger_data})

        service.reanalyze(group_id, mode=analysis_mode)

        # Return 204 No Content with HX-Trigger header to refresh the container
        return HTMLResponse(content="", status_code=204, headers={"HX-Trigger": "refreshGroups"})

    except HTTPException:
        raise
    except Exception as e:
        mode_description = "incremental" if mode == "increment" else "overwrite"
        raise HTTPException(
            status_code=500,
            detail=f"Failed to start {mode_description} analysis: {e}",
        ) from e


@router.post("/api/groups/{group_id}/stop", response_class=HTMLResponse)
async def stop_group_analysis(
    request: Request,
    web_session: WebSession,
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
        user_id: str = web_session.get("user_id", "")

        # Verify group exists and belongs to this user
        group = service.get_group(group_id, user_id=user_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        # Stop analysis via service (cancels task, updates status)
        service.stop_analysis(group_id)

        # Return 204 No Content with HX-Trigger header to refresh the container
        return HTMLResponse(content="", status_code=204, headers={"HX-Trigger": "refreshGroups"})

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
    web_session: WebSession,
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
        user_id: str = web_session.get("user_id", "")

        # Verify group exists and belongs to this user
        group = service.get_group(group_id, user_id=user_id)
        if not group:
            trigger_data = json.dumps(
                {
                    "refreshGroups": None,
                    "showToast": {"message": "Group not found", "type": "error"},
                }
            )
            return HTMLResponse(content="", status_code=404, headers={"HX-Trigger": trigger_data})

        # Validate status == PAUSED or handle concurrent resume
        if group.status == GroupStatus.IN_PROGRESS:
            # Concurrent resume attempt — return 409 (idempotent retry)
            trigger_data = json.dumps(
                {
                    "refreshGroups": None,
                    "showToast": {"message": "Another operation in progress", "type": "error"},
                }
            )
            return HTMLResponse(content="", status_code=409, headers={"HX-Trigger": trigger_data})
        elif group.status != GroupStatus.PAUSED:
            # Invalid state (completed, failed, pending) — return 400
            trigger_data = json.dumps(
                {
                    "refreshGroups": None,
                    "showToast": {"message": "Can only resume paused groups", "type": "error"},
                }
            )
            return HTMLResponse(content="", status_code=400, headers={"HX-Trigger": trigger_data})

        # Check if there are chats to analyze (pending + failed)
        stats = service.get_group_stats(group_id)
        pending_count = stats.status_pending
        failed_count = stats.failed

        if pending_count + failed_count == 0:
            # No chats to analyze — return error
            trigger_data = json.dumps(
                {
                    "refreshGroups": None,
                    "showToast": {"message": "No chats to analyze", "type": "error"},
                }
            )
            return HTMLResponse(content="", status_code=400, headers={"HX-Trigger": trigger_data})

        # Validate connected accounts BEFORE starting (instant in-memory check)
        connected_accounts = [
            sid
            for sid in session_mgr.list_sessions()
            if (info := session_mgr.get_info(sid)) and info.state == SessionState.CONNECTED
        ]

        if not connected_accounts:
            # Return error toast via HX-Trigger
            trigger_data = json.dumps(
                {
                    "refreshGroups": None,
                    "showToast": {
                        "message": "No connected Telegram accounts. Please connect at least one account.",
                        "type": "error",
                    },
                }
            )
            return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": trigger_data})

        service.start_analysis(group_id)

        # Return updated card with in_progress state so SSE connection starts immediately
        updated_group = service.get_group(group_id)
        updated_stats = service.get_group_stats(group_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/group_card.html",
            context=get_template_context(request, group=updated_group, stats=updated_stats),
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to resume analysis: {e}",
        ) from e

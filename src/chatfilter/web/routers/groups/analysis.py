"""Analysis control endpoints: start, stop, resume, reanalyze."""

from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from chatfilter.models.group import AnalysisMode, GroupStatus

from .helpers import _get_group_service

router = APIRouter()


@router.post("/api/groups/{group_id}/start", response_class=HTMLResponse)
async def start_group_analysis(
    request: Request,
    group_id: str,
) -> HTMLResponse:
    """Start group analysis."""
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service(request)
        session_mgr = request.app.state.app_state.session_manager

        group = service.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

        connected_accounts = [
            sid for sid in session_mgr.list_sessions()
            if await session_mgr.is_healthy(sid)
        ]

        if not connected_accounts:
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

        await service.start_analysis(group_id)

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
    mode: str = Query(..., regex="^(increment|overwrite)$"),
) -> HTMLResponse:
    """Re-analyze a completed group with specified mode."""
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service(request)
        session_mgr = request.app.state.app_state.session_manager

        group = service.get_group(group_id)
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")

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

        analysis_mode = AnalysisMode.INCREMENT if mode == "increment" else AnalysisMode.OVERWRITE

        connected_accounts = [
            sid for sid in session_mgr.list_sessions()
            if await session_mgr.is_healthy(sid)
        ]

        if not connected_accounts:
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

        await service.reanalyze(group_id, mode=analysis_mode)

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
    """Stop group analysis."""
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service(request)

        service.stop_analysis(group_id)

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
    """Resume paused group analysis."""
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        service = _get_group_service(request)
        session_mgr = request.app.state.app_state.session_manager

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

        if group.status == GroupStatus.IN_PROGRESS:
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

        stats = service.get_group_stats(group_id)
        pending_count = stats.status_pending
        failed_count = stats.failed

        if pending_count + failed_count == 0:
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

        connected_accounts = [
            sid for sid in session_mgr.list_sessions()
            if await session_mgr.is_healthy(sid)
        ]

        if not connected_accounts:
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

        await service.start_analysis(group_id)

        return HTMLResponse(content='', status_code=204, headers={'HX-Trigger': 'refreshGroups'})

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to resume analysis: {e}",
        )

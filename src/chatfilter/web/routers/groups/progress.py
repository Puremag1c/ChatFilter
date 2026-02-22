"""SSE progress streaming endpoints for group analysis."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse

from chatfilter.models.group import GroupStatus

from .helpers import _get_group_service, _get_progress_tracker

router = APIRouter()


async def _generate_group_sse_events(
    group_id: str,
    request: Request,
) -> AsyncGenerator[str, None]:
    """Generate SSE events for group analysis progress."""
    service = _get_group_service()
    tracker = _get_progress_tracker()

    group = service.get_group(group_id)
    if not group:
        yield f"event: error\ndata: {json.dumps({'error': 'Group not found'})}\n\n"
        return

    started_at = service._db.get_analysis_started_at(group_id)
    processed, total = service._db.count_processed_chats(group_id)

    init_data = {
        "group_id": group_id,
        "started_at": started_at.isoformat() if started_at else None,
        "processed": processed,
        "total": total,
        "status": group.status.value,
    }
    yield f"event: init\ndata: {json.dumps(init_data)}\n\n"

    if group.status in (GroupStatus.COMPLETED, GroupStatus.FAILED, GroupStatus.PAUSED):
        complete_data = {
            "group_id": group_id,
            "processed": processed,
            "total": total,
            "message": "Analysis complete",
        }
        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"
        return

    max_processed = processed
    progress_queue = tracker.subscribe(group_id)

    loop = asyncio.get_event_loop()
    last_heartbeat = loop.time()
    HEARTBEAT_INTERVAL = 15.0

    try:
        while True:
            if await request.is_disconnected():
                break

            now = loop.time()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                yield f"event: ping\ndata: {json.dumps({'timestamp': now})}\n\n"
                last_heartbeat = now

            try:
                event = await asyncio.wait_for(progress_queue.get(), timeout=1.0)

                if event is None:
                    final_processed, final_total = service._db.count_processed_chats(group_id)
                    max_processed = max(max_processed, final_processed)
                    complete_data = {
                        "group_id": group_id,
                        "processed": max_processed,
                        "total": final_total,
                        "message": "Analysis complete",
                    }
                    yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"
                    break

                max_processed = max(max_processed, event.current)
                progress_data = {
                    "group_id": event.group_id,
                    "status": event.status,
                    "processed": max_processed,
                    "total": event.total,
                    "chat_title": event.chat_title,
                    "message": event.message,
                }
                if event.breakdown:
                    progress_data["breakdown"] = event.breakdown
                yield f"event: progress\ndata: {json.dumps(progress_data)}\n\n"

                if event.error:
                    error_data = {
                        "group_id": event.group_id,
                        "error": event.error,
                    }
                    yield f"event: error\ndata: {json.dumps(error_data)}\n\n"

            except asyncio.TimeoutError:
                continue

    finally:
        pass


@router.get("/api/groups/{group_id}/progress")
async def get_group_progress(
    group_id: str,
    request: Request,
) -> StreamingResponse:
    """SSE endpoint for streaming group analysis progress."""
    service = _get_group_service()
    group = service.get_group(group_id)

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    return StreamingResponse(
        _generate_group_sse_events(group_id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

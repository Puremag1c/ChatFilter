"""Progress tracking (SSE) for groups router.

This module handles Server-Sent Events for real-time analysis progress.
"""

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
    """Generate SSE events for group analysis progress.

    Subscribes to ProgressTracker events and streams them as SSE.
    Sends heartbeat pings every 15s to detect stale connections.

    Args:
        group_id: Group identifier
        request: FastAPI request for disconnect detection

    Yields:
        SSE formatted event strings
    """
    service = _get_group_service()
    tracker = _get_progress_tracker()

    # Verify group exists
    group = service.get_group(group_id)
    if not group:
        yield f"event: error\ndata: {json.dumps({'error': 'Group not found'})}\n\n"
        return

    # Get analysis start time
    started_at = service._db.get_analysis_started_at(group_id)

    # Get global processed/total counts from DB
    processed, total = service._db.count_processed_chats(group_id)

    # Send initial event with current state
    init_data = {
        "group_id": group_id,
        "started_at": started_at.isoformat() if started_at else None,
        "processed": processed,
        "total": total,
        "status": group.status.value,
    }
    yield f"event: init\ndata: {json.dumps(init_data)}\n\n"

    # Check if group is already in terminal state (race condition fix)
    # If analysis completed/failed/paused BEFORE we subscribed, send completion immediately
    if group.status in (GroupStatus.COMPLETED, GroupStatus.FAILED, GroupStatus.PAUSED):
        # Send final complete event with current counts
        complete_data = {
            "group_id": group_id,
            "processed": processed,
            "total": total,
            "message": "Analysis complete",
        }
        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"
        return  # Don't subscribe or wait for events

    # Track max processed count for monotonic guarantee
    max_processed = processed

    # Subscribe to progress tracker events
    progress_queue = tracker.subscribe(group_id)

    # Heartbeat tracking (using non-blocking event loop time)
    loop = asyncio.get_event_loop()
    last_heartbeat = loop.time()
    HEARTBEAT_INTERVAL = 15.0  # seconds

    try:
        # Stream progress events until completion
        while True:
            # Check for client disconnect
            if await request.is_disconnected():
                break

            # Send heartbeat ping every 15s
            now = loop.time()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                yield f"event: ping\ndata: {json.dumps({'timestamp': now})}\n\n"
                last_heartbeat = now

            try:
                # Wait for next event with timeout to allow heartbeat checks
                event = await asyncio.wait_for(progress_queue.get(), timeout=1.0)

                if event is None:
                    # Analysis completed - get final counts from DB
                    final_processed, final_total = service._db.count_processed_chats(group_id)
                    # Enforce monotonic guarantee: max with last sent value
                    max_processed = max(max_processed, final_processed)
                    complete_data = {
                        "group_id": group_id,
                        "processed": max_processed,
                        "total": final_total,
                        "message": "Analysis complete",
                    }
                    yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"
                    break

                # Send progress event
                # Note: event.current and event.total are now global DB-based counts
                # from publish_from_db() in ProgressTracker
                # Enforce monotonic guarantee: never decrease
                max_processed = max(max_processed, event.current)
                progress_data = {
                    "group_id": event.group_id,
                    "status": event.status,
                    "processed": max_processed,
                    "total": event.total,
                    "chat_title": event.chat_title,
                    "message": event.message,
                }
                # Include status breakdown for live badge updates
                if event.breakdown:
                    progress_data["breakdown"] = event.breakdown
                # Include FloodWait expiry timestamp if present
                if event.flood_wait_until:
                    progress_data["flood_wait_until"] = event.flood_wait_until.isoformat()
                yield f"event: progress\ndata: {json.dumps(progress_data)}\n\n"

                # Send error event if present
                if event.error:
                    error_data = {
                        "group_id": event.group_id,
                        "error": event.error,
                    }
                    yield f"event: error\ndata: {json.dumps(error_data)}\n\n"

            except asyncio.TimeoutError:
                # Timeout waiting for event - continue to check disconnect and heartbeat
                continue

    finally:
        # Cleanup: queue will be cleaned up by tracker
        pass


@router.get("/api/groups/{group_id}/progress")
async def get_group_progress(
    group_id: str,
    request: Request,
) -> StreamingResponse:
    """SSE endpoint for streaming group analysis progress.

    Currently returns immediate completion. Will stream real-time progress
    when GroupAnalysisEngine is implemented.

    Args:
        group_id: Group identifier
        request: FastAPI request

    Returns:
        StreamingResponse with SSE events

    Raises:
        HTTPException: If group not found
    """
    # Verify group exists
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
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )

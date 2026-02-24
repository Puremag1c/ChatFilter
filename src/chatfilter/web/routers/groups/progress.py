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


async def _generate_unified_sse_events(
    request: Request,
) -> AsyncGenerator[str, None]:
    """Generate multiplexed SSE events for ALL active group analyses.

    Subscribes to ProgressTracker for all in_progress groups and streams
    their events as SSE. Each event includes group_id for client routing.
    Sends heartbeat pings every 15s to detect stale connections.

    Args:
        request: FastAPI request for disconnect detection

    Yields:
        SSE formatted event strings with group_id in data
    """
    service = _get_group_service()
    tracker = _get_progress_tracker()

    # Find all groups with status=in_progress
    all_groups = service.get_all_groups()
    active_groups = [g for g in all_groups if g.status == GroupStatus.IN_PROGRESS]

    # Track subscriptions for cleanup
    subscriptions: dict[str, asyncio.Queue] = {}

    # Subscribe to each active group and send init events
    for group in active_groups:
        group_id = group.group_id

        # Get current state from DB
        started_at = service._db.get_analysis_started_at(group_id)
        processed, total = service._db.count_processed_chats(group_id)

        # Send init event
        init_data = {
            "group_id": group_id,
            "started_at": started_at.isoformat() if started_at else None,
            "processed": processed,
            "total": total,
            "status": group.status.value,
        }
        yield f"event: init\ndata: {json.dumps(init_data)}\n\n"

        # Subscribe to progress tracker
        subscriptions[group_id] = tracker.subscribe(group_id)

    # Merge all subscription queues into single async stream
    # We'll use asyncio.create_task to monitor all queues concurrently

    # Heartbeat tracking
    loop = asyncio.get_event_loop()
    last_heartbeat = loop.time()
    HEARTBEAT_INTERVAL = 15.0  # seconds

    try:
        # Create tasks to wait on all queues
        pending_tasks = {}
        for group_id, queue in subscriptions.items():
            task = asyncio.create_task(queue.get())
            pending_tasks[task] = group_id

        while pending_tasks or subscriptions:
            # Check for client disconnect
            if await request.is_disconnected():
                break

            # Send heartbeat ping every 15s
            now = loop.time()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL:
                yield f"event: ping\ndata: {json.dumps({'timestamp': now})}\n\n"
                last_heartbeat = now

            # Wait for any queue to have data (with timeout for heartbeat)
            if pending_tasks:
                done, pending = await asyncio.wait(
                    pending_tasks.keys(),
                    timeout=1.0,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                # Process completed tasks
                for task in done:
                    group_id = pending_tasks.pop(task)
                    event = task.result()

                    if event is None:
                        # Completion sentinel - send complete event and unsubscribe
                        final_processed, final_total = service._db.count_processed_chats(group_id)
                        complete_data = {
                            "group_id": group_id,
                            "processed": final_processed,
                            "total": final_total,
                            "message": "Analysis complete",
                        }
                        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"

                        # Remove subscription
                        subscriptions.pop(group_id, None)
                    else:
                        # Progress event - send and create new task for next event
                        progress_data = {
                            "group_id": event.group_id,
                            "status": event.status,
                            "processed": event.current,
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

                        # Create new task for next event from this group
                        if group_id in subscriptions:
                            new_task = asyncio.create_task(subscriptions[group_id].get())
                            pending_tasks[new_task] = group_id
            else:
                # No pending tasks, just sleep for heartbeat
                await asyncio.sleep(1.0)

    finally:
        # Cleanup: cancel pending tasks
        for task in pending_tasks.keys():
            task.cancel()


@router.get("/api/groups/events")
async def get_unified_group_events(
    request: Request,
) -> StreamingResponse:
    """Unified SSE endpoint for streaming progress from ALL active groups.

    Multiplexes progress events from all in_progress groups into a single stream.
    Each event includes group_id so client can dispatch to the correct card.

    Returns:
        StreamingResponse with multiplexed SSE events

    Event types:
        - init: Initial state for each active group (sent on connect)
        - progress: Progress update (includes group_id, processed, total, chat_title)
        - complete: Group analysis finished (includes group_id)
        - ping: Heartbeat (every 15s)
        - error: Error message (includes group_id)
    """
    return StreamingResponse(
        _generate_unified_sse_events(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


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

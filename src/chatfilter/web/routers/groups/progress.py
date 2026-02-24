"""Progress tracking (SSE) for groups router.

This module handles Server-Sent Events for real-time analysis progress.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from chatfilter.models.group import GroupStatus

from .helpers import _get_group_service, _get_progress_tracker

router = APIRouter()
logger = logging.getLogger(__name__)


def _sanitize_chat_title(title: str | None) -> str:
    """Sanitize chat title to prevent leaking sensitive data via SSE.

    - Strip control characters
    - Limit length to 100 chars
    - Return empty string if None

    Args:
        title: Raw chat title from Telegram

    Returns:
        Sanitized chat title safe for SSE transmission
    """
    if not title:
        return ""

    # Strip control characters (ASCII 0-31 and 127)
    sanitized = re.sub(r"[\x00-\x1f\x7f]", "", title)

    # Limit length
    max_length = 100
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "..."

    return sanitized


def _sanitize_error_message(error: str | None) -> str:
    """Sanitize error message to prevent leaking sensitive data via SSE.

    Returns generic error message for client. Full error should be logged server-side.

    Args:
        error: Raw error message (may contain stack traces, file paths, etc.)

    Returns:
        Generic error message safe for SSE transmission
    """
    if not error:
        return "An error occurred during analysis"

    # Never send raw exception messages, stack traces, or DB errors
    # Always return generic message
    return "Analysis error. Please try again or contact support."


async def _generate_unified_sse_events(
    request: Request,
) -> AsyncGenerator[str, None]:
    """Generate multiplexed SSE events for ALL active group analyses.

    Subscribes to ProgressTracker for all in_progress groups and streams
    their events as SSE. Each event includes group_id for client routing.
    Sends heartbeat pings every 15s to detect stale connections.

    All errors are sanitized before sending to prevent data leakage.
    Full errors are logged server-side.

    Args:
        request: FastAPI request for disconnect detection

    Yields:
        SSE formatted event strings with group_id in data
    """
    try:
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
                                "chat_title": _sanitize_chat_title(event.chat_title),
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
                                # Log full error server-side
                                logger.error(
                                    f"SSE progress error for group {event.group_id}: {event.error}",
                                    extra={"group_id": event.group_id, "raw_error": event.error},
                                )
                                # Send sanitized error to client
                                error_data = {
                                    "group_id": event.group_id,
                                    "error": _sanitize_error_message(event.error),
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

    except Exception as e:
        # Log full exception server-side
        logger.exception("Unhandled exception in unified SSE stream")
        # Send generic error to client (no stack trace, no internal details)
        yield f"event: error\ndata: {json.dumps({'error': 'Stream error. Please refresh.'})}\n\n"


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


# Old per-group SSE endpoint removed
# Use /api/groups/events unified endpoint instead

"""Server-Sent Events (SSE) endpoint for real-time session status updates."""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from fastapi import Request
from fastapi.responses import StreamingResponse

from chatfilter.web.events import get_event_bus
from chatfilter.web.template_helpers import get_template_context
from .helpers import list_stored_sessions

if TYPE_CHECKING:
    from fastapi import APIRouter

logger = logging.getLogger(__name__)


async def session_events(request: Request):
    """SSE endpoint for real-time session status updates.

    This endpoint provides Server-Sent Events (SSE) for session status changes.
    Clients can connect to receive real-time updates when session statuses change.

    Returns:
        StreamingResponse: SSE stream with session status events
    """
    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import get_auth_state_manager
    from chatfilter.web.dependencies import get_session_manager

    templates = get_templates()
    session_manager = get_session_manager()
    auth_manager = get_auth_state_manager()

    # Queue for this client's events
    event_queue: asyncio.Queue[tuple[str, str] | None] = asyncio.Queue()

    async def event_generator():
        """Generate SSE events from the queue."""
        try:
            # Send initial connection message
            yield 'data: {"type": "connected"}\n\n'

            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    logger.debug("SSE client disconnected")
                    break

                try:
                    # Wait for events with timeout to check disconnect status
                    event = await asyncio.wait_for(event_queue.get(), timeout=30.0)

                    if event is None:  # Shutdown signal
                        break

                    session_id, new_status = event

                    # Get full session data for this session
                    all_sessions = list_stored_sessions(session_manager, auth_manager)
                    session_data = next(
                        (s for s in all_sessions if s.session_id == session_id),
                        None
                    )

                    if session_data:
                        # Render session row HTML with hx-swap-oob
                        html = templates.get_template("partials/session_row.html").render(
                            get_template_context(request, session=session_data)
                        )
                        # Add hx-swap-oob="true" to both rows (main row + config row)
                        # The template renders two <tr> elements that need OOB swaps
                        html_with_oob = html.replace(
                            f'<tr id="session-{session_id}"',
                            f'<tr id="session-{session_id}" hx-swap-oob="true"'
                        ).replace(
                            f'<tr class="config-row" id="session-config-row-{session_id}"',
                            f'<tr class="config-row" id="session-config-row-{session_id}" hx-swap-oob="true"'
                        )
                        # Minify: remove newlines for SSE single-line data format
                        html_compact = html_with_oob.replace('\n', ' ').replace('  ', ' ')
                        yield f"event: message\ndata: {html_compact}\n\n"

                except TimeoutError:
                    # Send keepalive comment to prevent timeout
                    yield ": keepalive\n\n"

        except asyncio.CancelledError:
            logger.debug("SSE event generator cancelled")
        finally:
            # Unsubscribe from event bus
            get_event_bus().unsubscribe(event_handler)
            logger.debug("SSE client unsubscribed from event bus")

    async def event_handler(session_id: str, new_status: str, data: dict | None = None):
        """Handler for event bus messages."""
        try:
            await event_queue.put((session_id, new_status))
        except Exception:
            logger.exception("Error putting event in queue")

    # Subscribe to event bus
    get_event_bus().subscribe(event_handler)
    logger.debug("SSE client subscribed to event bus")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


def register_sse_routes(router: APIRouter) -> None:
    """Register SSE routes to the router."""
    router.get("/api/sessions/events")(session_events)

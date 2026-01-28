"""Analysis router for starting analysis and streaming progress via SSE.

ARCHITECTURE: Async Request/Task Separation
============================================

This module implements a fire-and-forget async architecture to prevent HTTP
request timeouts when running long-duration background tasks.

Key Principles:
--------------

1. REQUEST ONLY STARTS TASK
   - HTTP POST /api/analysis/start validates inputs and creates a background task
   - Returns immediately with task ID (< 1 second)
   - NO blocking operations (no Telegram API calls during HTTP request)
   - Prevents HTTP request timeout regardless of task duration

2. PROGRESS THROUGH SSE
   - GET /api/analysis/{task_id}/progress streams real-time progress
   - Server-Sent Events (SSE) with heartbeat every 15 seconds
   - Client disconnect detection and backpressure handling
   - Task continues running even if client disconnects

3. SEPARATE RESULT ENDPOINTS
   - GET /api/analysis/{task_id}/results retrieves completed analysis
   - GET /api/analysis/{task_id}/status polls task status (fallback)
   - Results persisted to SQLite for retrieval after server restart

4. BACKGROUND TASK EXECUTION
   - FastAPI BackgroundTasks + persistent TaskQueue with SQLite
   - Chat info pre-cached at task start (not during HTTP request)
   - Multiple timeout layers: task-level (1h), per-chat (5m), stall detection (10m)
   - Graceful handling of Telegram connection failures

This architecture allows analysis tasks to run for hours without any HTTP
timeout issues, while providing real-time progress updates to clients.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from chatfilter.analyzer.task_queue import (
    BatchProgressCallback,
    QueueFullError,
    TaskStatus,
    get_task_queue,
)
from chatfilter.i18n import _
from chatfilter.models import AnalysisResult

if TYPE_CHECKING:
    from chatfilter.models import Chat
from chatfilter.web.dependencies import get_chat_analysis_service
from chatfilter.web.routers.chats import get_session_paths
from chatfilter.web.session import get_session, set_session_cookie

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


class RealAnalysisExecutor:
    """Real implementation of analysis executor using service layer."""

    def __init__(self) -> None:
        """Initialize executor with service layer."""
        self._service = get_chat_analysis_service()

    async def get_chat_info(
        self,
        session_id: str,
        chat_id: int,
    ) -> Chat | None:
        """Get chat info - delegates to service layer."""
        return await self._service.get_chat_info(session_id, chat_id)

    async def pre_cache_chats(
        self,
        session_id: str,
    ) -> None:
        """Pre-cache all chat info for better progress display.

        This is called at the start of background task execution to fetch
        and cache chat metadata from Telegram. This prevents the HTTP request
        from blocking on Telegram connection.

        Args:
            session_id: Session identifier

        Raises:
            Exception: Connection or fetch errors (non-fatal)
        """
        await self._service.get_chats(session_id)

    async def analyze_chat(
        self,
        session_id: str,
        chat_id: int,
        message_limit: int = 1000,
        batch_size: int = 1000,
        use_streaming: bool | None = None,
        memory_limit_mb: float = 1024.0,
        enable_memory_monitoring: bool = False,
        batch_progress_callback: BatchProgressCallback | None = None,
    ) -> AnalysisResult:
        """Analyze a single chat.

        Args:
            session_id: Session identifier
            chat_id: Chat ID to analyze
            message_limit: Maximum messages to fetch (default 1000)
            batch_size: Batch size for streaming mode
            use_streaming: Force streaming mode (None = auto-detect)
            memory_limit_mb: Memory threshold in MB
            enable_memory_monitoring: Enable memory monitoring
            batch_progress_callback: Optional callback for batch progress updates
        """
        return await self._service.analyze_chat(
            session_id,
            chat_id,
            message_limit,
            batch_size,
            use_streaming,
            memory_limit_mb,
            enable_memory_monitoring,
            batch_progress_callback,
        )


class StartAnalysisResponse(BaseModel):
    """Response from starting analysis."""

    task_id: str
    status: str
    total_chats: int


class TaskStatusResponse(BaseModel):
    """Response from task status endpoint."""

    task_id: str
    status: str
    current: int
    total: int
    results_count: int
    error: str | None = None


class CancelResponse(BaseModel):
    """Response from cancel task endpoint."""

    status: str
    message: str
    partial_results: int


class ForceCancelResponse(BaseModel):
    """Response from force-cancel task endpoint."""

    status: str
    message: str
    reason: str
    partial_results: int


class OrphanedTaskResponse(BaseModel):
    """Response from check-orphaned endpoint."""

    task_id: str | None = None
    status: str | None = None
    results_count: int | None = None
    error: str | None = None
    total_chats: int | None = None


class DismissResponse(BaseModel):
    """Response from dismiss-notification endpoint."""

    status: str


@router.post("/start", response_class=HTMLResponse)
async def start_analysis(
    request: Request,
    background_tasks: BackgroundTasks,
    session_id: Annotated[str, Form()] = "",
    chat_ids: Annotated[list[int] | None, Form()] = None,
    message_limit: Annotated[int, Form()] = 1000,
) -> HTMLResponse:
    """Start analysis of selected chats.

    Creates a background task and returns HTML partial with progress UI.

    Args:
        request: FastAPI request
        background_tasks: Background tasks manager
        session_id: Session identifier
        chat_ids: List of chat IDs to analyze
        message_limit: Maximum messages to fetch per chat (10-10000)

    Returns:
        HTML partial with SSE progress container
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    # Handle None or empty chat_ids
    if chat_ids is None:
        chat_ids = []

    if not session_id:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_progress.html",
            context={
                "error": _("No session selected"),
                "error_action": _("Select a Telegram session from the dropdown above"),
                "error_action_type": "check_input",
            },
        )

    if not chat_ids:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_progress.html",
            context={
                "error": _("No chats selected for analysis"),
                "error_action": _(
                    "Select at least one chat from the list above by checking the boxes"
                ),
                "error_action_type": "check_input",
            },
        )

    # Validate message_limit
    if message_limit < 10 or message_limit > 10000:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_progress.html",
            context={
                "error": _("Message limit must be between 10 and 10000"),
                "error_action": _(
                    "Adjust the 'Messages per chat' setting to a value between 10 and 10000"
                ),
                "error_action_type": "check_input",
            },
        )

    # Validate session exists (quick local check only)
    try:
        get_session_paths(session_id)
    except HTTPException as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_progress.html",
            context={
                "error": e.detail,
                "error_action": _("Upload a valid session file from the Sessions page"),
                "error_action_type": "reauth",
            },
        )

    # Validate chat_ids to prevent stale state (ChatFilter-9526)
    # If chats were deleted/removed from Telegram after selection,
    # we filter them out before starting analysis
    service = get_chat_analysis_service()
    try:
        # Use timeout to prevent blocking if Telegram connection is slow
        # If validation times out, we proceed with original list (background task will handle errors)
        valid_ids, invalid_ids = await asyncio.wait_for(
            service.validate_chat_ids(session_id, chat_ids),
            timeout=5.0,
        )

        if invalid_ids:
            logger.warning(
                f"Detected {len(invalid_ids)} stale chat IDs for session '{session_id}': {invalid_ids}"
            )

        # If ALL selected chats are invalid, return error
        if not valid_ids:
            invalid_list = ", ".join(str(cid) for cid in invalid_ids[:5])
            if len(invalid_ids) > 5:
                invalid_list += f", ... ({len(invalid_ids) - 5} more)"

            return templates.TemplateResponse(
                request=request,
                name="partials/analysis_progress.html",
                context={
                    "error": _("All selected chats are no longer accessible"),
                    "error_action": _(
                        "The selected chats (IDs: {invalid_list}) may have been deleted "
                        "or removed from Telegram. Please refresh the chat list and select valid chats."
                    ).format(invalid_list=invalid_list),
                    "error_action_type": "check_input",
                },
            )

        # If some chats are invalid, filter them out and continue with valid ones
        if invalid_ids:
            chat_ids = valid_ids
            logger.info(
                f"Filtered {len(invalid_ids)} invalid chat IDs, "
                f"proceeding with {len(valid_ids)} valid chats"
            )

    except TimeoutError:
        # Validation timed out - proceed with original list
        # Background task will handle any errors when fetching messages
        logger.warning(
            f"Chat ID validation timed out for session '{session_id}', "
            f"proceeding with {len(chat_ids)} chat IDs"
        )
    except Exception as e:
        # Validation failed - log error and proceed with original list
        logger.error(
            f"Chat ID validation failed for session '{session_id}': {e}, "
            f"proceeding with {len(chat_ids)} chat IDs"
        )

    # Check for existing active task with same parameters (deduplication)
    queue = get_task_queue()
    existing_task = queue.find_active_task(session_id, chat_ids, message_limit)

    is_duplicate = False
    if existing_task:
        # Return existing task instead of creating duplicate
        logger.info(
            f"Reusing existing task {existing_task.task_id} for {len(chat_ids)} chats "
            f"(status: {existing_task.status})"
        )
        task = existing_task
        is_duplicate = True
    else:
        # Create new analysis task
        try:
            task = queue.create_task(session_id, chat_ids, message_limit)
        except QueueFullError as e:
            # Queue is full - return error with helpful message
            return templates.TemplateResponse(
                request=request,
                name="partials/analysis_progress.html",
                context={
                    "error": _("Analysis queue is at capacity ({limit} concurrent tasks).").format(
                        limit=e.limit
                    ),
                    "error_action": _(
                        "Wait for currently running analyses to complete, or cancel an existing analysis"
                    ),
                    "error_action_type": "wait",
                },
            )

        # Start background analysis
        executor = RealAnalysisExecutor()
        background_tasks.add_task(queue.run_task, task.task_id, executor)

        logger.info(f"Started analysis task {task.task_id} for {len(chat_ids)} chats")

    # Store task_id in session for orphaned result detection
    session = get_session(request)
    session.set("current_task_id", str(task.task_id))

    response = templates.TemplateResponse(
        request=request,
        name="partials/analysis_progress.html",
        context={
            "task_id": str(task.task_id),
            "total_chats": len(chat_ids),
            "is_duplicate": is_duplicate,
        },
    )
    set_session_cookie(response, session)
    return response


async def _generate_sse_events(
    task_id: UUID,
    request: Request,
) -> AsyncGenerator[str, None]:
    """Generate SSE events for task progress.

    Args:
        task_id: Task UUID
        request: FastAPI request for disconnect detection

    Yields:
        SSE formatted event strings
    """
    queue = get_task_queue()

    try:
        progress_queue = await queue.subscribe(task_id)
    except KeyError:
        yield f"event: error\ndata: {json.dumps({'error': 'Task not found'})}\n\n"
        return

    # Send initial event
    task = queue.get_task(task_id)
    if task:
        init_data = {
            "current": len(task.results),
            "total": len(task.chat_ids),
            "status": task.status.value,
            "sequence": task.event_sequence,
        }
        yield f"event: init\ndata: {json.dumps(init_data)}\n\n"

        # If task is already in final state, send completion event and close
        if task.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.TIMEOUT,
        ):
            if task.status == TaskStatus.COMPLETED:
                complete_data = {
                    "results_count": len(task.results),
                    "sequence": task.event_sequence,
                }
                yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"
            elif task.status == TaskStatus.CANCELLED:
                cancel_data = {
                    "results_count": len(task.results),
                    "message": _("Analysis cancelled"),
                    "sequence": task.event_sequence,
                }
                yield f"event: cancelled\ndata: {json.dumps(cancel_data)}\n\n"
            elif task.status == TaskStatus.TIMEOUT:
                timeout_data = {
                    "results_count": len(task.results),
                    "error": task.error or _("Task timed out"),
                    "sequence": task.event_sequence,
                }
                yield f"event: timeout\ndata: {json.dumps(timeout_data)}\n\n"
            elif task.status == TaskStatus.FAILED:
                error_data = {
                    "error": task.error or _("Unknown error"),
                    "sequence": task.event_sequence,
                }
                yield f"event: error\ndata: {json.dumps(error_data)}\n\n"
            # Clean up and return early
            await queue.unsubscribe(task_id, progress_queue)
            return

    # Heartbeat interval for keepalive
    heartbeat_interval = 15  # seconds

    try:
        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                logger.debug(f"Client disconnected from SSE stream for task {task_id}")
                break

            try:
                # Wait for event with timeout for heartbeat
                event = await asyncio.wait_for(
                    progress_queue.get(),
                    timeout=heartbeat_interval,
                )

                if event is None:
                    # Task completed, send final event
                    task = queue.get_task(task_id)
                    if task and task.status == TaskStatus.COMPLETED:
                        complete_data = {
                            "results_count": len(task.results),
                            "sequence": task.event_sequence,
                        }
                        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"
                    elif task and task.status == TaskStatus.CANCELLED:
                        cancel_data = {
                            "results_count": len(task.results),
                            "message": _("Analysis cancelled"),
                            "sequence": task.event_sequence,
                        }
                        yield f"event: cancelled\ndata: {json.dumps(cancel_data)}\n\n"
                    elif task and task.status == TaskStatus.TIMEOUT:
                        timeout_data = {
                            "results_count": len(task.results),
                            "error": task.error or _("Task timed out"),
                            "sequence": task.event_sequence,
                        }
                        yield f"event: timeout\ndata: {json.dumps(timeout_data)}\n\n"
                    elif task and task.status == TaskStatus.FAILED:
                        error_data = {
                            "error": task.error or _("Unknown error"),
                            "sequence": task.event_sequence,
                        }
                        yield f"event: error\ndata: {json.dumps(error_data)}\n\n"
                    break

                # Send progress event
                event_data = {
                    "current": event.current,
                    "total": event.total,
                    "status": event.status.value,
                    "sequence": event.sequence,
                    "chat_title": event.chat_title,
                    "message": event.message,
                }
                if event.error:
                    event_data["error"] = event.error

                yield f"event: progress\ndata: {json.dumps(event_data)}\n\n"

            except TimeoutError:
                # Send heartbeat to keep connection alive
                yield ": heartbeat\n\n"

    finally:
        await queue.unsubscribe(task_id, progress_queue)


@router.get("/{task_id}/progress")
async def get_progress_stream(
    task_id: str,
    request: Request,
) -> StreamingResponse:
    """SSE endpoint for streaming analysis progress.

    Args:
        task_id: Task UUID string
        request: FastAPI request

    Returns:
        StreamingResponse with SSE events

    Raises:
        HTTPException: If task_id is invalid
    """
    try:
        uuid_task_id = UUID(task_id)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid task ID format",
        ) from err

    queue = get_task_queue()
    task = queue.get_task(uuid_task_id)

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )

    return StreamingResponse(
        _generate_sse_events(uuid_task_id, request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.get("/{task_id}/results", response_class=HTMLResponse)
async def get_results(
    task_id: str,
    request: Request,
) -> HTMLResponse:
    """Get analysis results as HTML partial.

    Args:
        task_id: Task UUID string
        request: FastAPI request

    Returns:
        HTML partial with results table
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    # Clear orphaned task notification when viewing results
    session = get_session(request)
    current_task_id = session.get("current_task_id")
    if current_task_id == task_id:
        session.delete("current_task_id")

    try:
        uuid_task_id = UUID(task_id)
    except ValueError:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_results.html",
            context={"error": _("Invalid task ID format")},
        )

    queue = get_task_queue()
    task = queue.get_task(uuid_task_id)

    if task is None:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_results.html",
            context={"error": _("Task not found")},
        )

    if task.status == TaskStatus.IN_PROGRESS:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_results.html",
            context={"error": _("Analysis still in progress")},
        )

    if task.status == TaskStatus.PENDING:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_results.html",
            context={"error": _("Analysis not started")},
        )

    if task.status == TaskStatus.FAILED:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_results.html",
            context={"error": task.error or _("Analysis failed")},
        )

    if task.status == TaskStatus.TIMEOUT:
        return templates.TemplateResponse(
            request=request,
            name="partials/analysis_results.html",
            context={
                "task_id": task_id,
                "results": task.results,
                "session_id": task.session_id,
                "is_partial": True,
                "error": task.error or _("Analysis timed out"),
            },
        )

    # For COMPLETED or CANCELLED, show results (partial results for cancelled)
    response = templates.TemplateResponse(
        request=request,
        name="partials/analysis_results.html",
        context={
            "task_id": task_id,
            "results": task.results,
            "session_id": task.session_id,
            "is_partial": task.status == TaskStatus.CANCELLED,
        },
    )
    set_session_cookie(response, session)
    return response


@router.get("/{task_id}/status", response_model=TaskStatusResponse)
async def get_status(task_id: str) -> TaskStatusResponse:
    """Get current task status (for polling fallback).

    Args:
        task_id: Task UUID string

    Returns:
        Task status JSON

    Raises:
        HTTPException: If task not found
    """
    try:
        uuid_task_id = UUID(task_id)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid task ID format",
        ) from err

    queue = get_task_queue()
    task = queue.get_task(uuid_task_id)

    if task is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task not found",
        )

    return TaskStatusResponse(
        task_id=str(task.task_id),
        status=task.status.value,
        current=task.current_chat_index,
        total=len(task.chat_ids),
        results_count=len(task.results),
        error=task.error,
    )


@router.post("/{task_id}/cancel", response_model=CancelResponse)
async def cancel_analysis(task_id: str) -> CancelResponse:
    """Cancel a running analysis task gracefully.

    Waits for current chat to finish before stopping.

    Args:
        task_id: Task UUID string

    Returns:
        Status message with partial results count

    Raises:
        HTTPException: If task not found or cannot be cancelled
    """
    try:
        uuid_task_id = UUID(task_id)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid task ID format",
        ) from err

    queue = get_task_queue()

    if queue.cancel_task(uuid_task_id):
        task = queue.get_task(uuid_task_id)
        logger.info(f"Analysis task {task_id} cancelled by user")
        return CancelResponse(
            status="cancelled",
            message=_("Analysis cancelled successfully"),
            partial_results=len(task.results) if task else 0,
        )
    else:
        task = queue.get_task(uuid_task_id)
        if task is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel task with status: {task.status.value}",
            )


@router.post("/{task_id}/force_cancel", response_model=ForceCancelResponse)
async def force_cancel_analysis(
    task_id: str, reason: str = "User-requested forced cancellation"
) -> ForceCancelResponse:
    """Forcefully cancel a running analysis task immediately.

    This is more aggressive than regular cancel - it immediately cancels
    the asyncio task without waiting for the current operation to complete.
    Use this for hung/deadlocked tasks that aren't responding to graceful
    cancellation.

    Args:
        task_id: Task UUID string
        reason: Optional reason for forced cancellation

    Returns:
        Status message with cancellation details

    Raises:
        HTTPException: If task not found or cannot be cancelled
    """
    try:
        uuid_task_id = UUID(task_id)
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid task ID format",
        ) from err

    queue = get_task_queue()

    if await queue.force_cancel_task(uuid_task_id, reason=reason):
        task = queue.get_task(uuid_task_id)
        logger.warning(f"Analysis task {task_id} force-cancelled by user: {reason}")
        return ForceCancelResponse(
            status="force_cancelled",
            message=_("Task force-cancelled successfully"),
            reason=reason,
            partial_results=len(task.results) if task else 0,
        )
    else:
        task = queue.get_task(uuid_task_id)
        if task is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Task not found",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot force-cancel task with status: {task.status.value}",
            )


@router.get("/check_orphaned", response_model=OrphanedTaskResponse)
async def check_orphaned_task(request: Request) -> OrphanedTaskResponse:
    """Check if there's a completed task in session that user hasn't seen.

    This endpoint is called on page load to detect if analysis completed
    while the user was away (browser closed, network disconnected, etc.).

    Returns:
        Task info if completed task exists and hasn't been acknowledged,
        or empty response if no orphaned task
    """
    session = get_session(request)
    task_id_str = session.get("current_task_id")

    if not task_id_str:
        return OrphanedTaskResponse()

    # Check if user has already been notified about this completion
    notified_tasks = session.get("notified_task_ids", set())
    if task_id_str in notified_tasks:
        return OrphanedTaskResponse()

    try:
        task_id = UUID(task_id_str)
    except ValueError:
        # Invalid task ID in session, clear it
        session.delete("current_task_id")
        return OrphanedTaskResponse()

    queue = get_task_queue()
    task = queue.get_task(task_id)

    if task is None:
        # Task no longer exists, clear from session
        session.delete("current_task_id")
        return OrphanedTaskResponse()

    # Check if task is in a terminal state
    terminal_states = [
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.TIMEOUT,
    ]

    if task.status in terminal_states:
        # Mark as notified so we don't show the notification again
        if isinstance(notified_tasks, set):
            notified_tasks.add(task_id_str)
        else:
            notified_tasks = {task_id_str}
        session.set("notified_task_ids", notified_tasks)

        return OrphanedTaskResponse(
            task_id=str(task.task_id),
            status=task.status.value,
            results_count=len(task.results),
            error=task.error,
            total_chats=len(task.chat_ids),
        )

    # Task is still pending or in progress
    return OrphanedTaskResponse()


@router.post("/{task_id}/dismiss_notification", response_model=DismissResponse)
async def dismiss_orphaned_notification(task_id: str, request: Request) -> DismissResponse:
    """Dismiss the orphaned task notification.

    Called when user explicitly dismisses the notification or views results.

    Args:
        task_id: Task UUID string
        request: FastAPI request

    Returns:
        Status message
    """
    session = get_session(request)

    # Clear current_task_id if it matches
    current_task_id = session.get("current_task_id")
    if current_task_id == task_id:
        session.delete("current_task_id")

    return DismissResponse(status="dismissed")

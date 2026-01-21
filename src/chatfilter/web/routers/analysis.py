"""Analysis router for starting analysis and streaming progress via SSE."""

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
from chatfilter.models import AnalysisResult

if TYPE_CHECKING:
    from chatfilter.models import Chat
from chatfilter.service.chat_analysis import SessionNotFoundError
from chatfilter.web.routers.chats import get_chat_service, get_session_paths

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


class RealAnalysisExecutor:
    """Real implementation of analysis executor using service layer."""

    def __init__(self) -> None:
        """Initialize executor with service layer."""
        self._service = get_chat_service()

    async def get_chat_info(
        self,
        session_id: str,
        chat_id: int,
    ) -> Chat | None:
        """Get chat info - delegates to service layer."""
        return await self._service.get_chat_info(session_id, chat_id)

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


@router.post("/start", response_class=HTMLResponse)
async def start_analysis(
    request: Request,
    background_tasks: BackgroundTasks,
    session_id: Annotated[str, Form()],
    chat_ids: Annotated[list[int], Form()],
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

    if not session_id:
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {
                "request": request,
                "error": "No session selected",
                "error_action": "Select a Telegram session from the dropdown above",
                "error_action_type": "check_input",
            },
        )

    if not chat_ids:
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {
                "request": request,
                "error": "No chats selected for analysis",
                "error_action": "Select at least one chat from the list above by checking the boxes",
                "error_action_type": "check_input",
            },
        )

    # Validate message_limit
    if message_limit < 10 or message_limit > 10000:
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {
                "request": request,
                "error": "Message limit must be between 10 and 10000",
                "error_action": "Adjust the 'Messages per chat' setting to a value between 10 and 10000",
                "error_action_type": "check_input",
            },
        )

    # Validate session exists
    try:
        get_session_paths(session_id)
    except HTTPException as e:
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {
                "request": request,
                "error": e.detail,
                "error_action": "Upload a valid session file from the Sessions page",
                "error_action_type": "reauth",
            },
        )

    # Fetch chat info for the cache (needed for progress display)
    service = get_chat_service()
    try:
        # This will cache chat info in the service
        await service.get_chats(session_id)
    except SessionNotFoundError as e:
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {
                "request": request,
                "error": str(e),
                "error_action": "Upload a valid session file from the Sessions page",
                "error_action_type": "reauth",
            },
        )
    except Exception as e:
        logger.exception(f"Failed to fetch chat info: {e}")
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {
                "request": request,
                "error": f"Failed to connect to Telegram: {e}",
                "error_action": "Check your internet connection and verify your session is valid",
                "error_action_type": "retry",
            },
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
                "partials/analysis_progress.html",
                {
                    "request": request,
                    "error": f"Analysis queue is at capacity ({e.limit} concurrent tasks).",
                    "error_action": "Wait for currently running analyses to complete, or cancel an existing analysis",
                    "error_action_type": "wait",
                },
            )

        # Start background analysis
        executor = RealAnalysisExecutor()
        background_tasks.add_task(queue.run_task, task.task_id, executor)

        logger.info(f"Started analysis task {task.task_id} for {len(chat_ids)} chats")

    return templates.TemplateResponse(
        "partials/analysis_progress.html",
        {
            "request": request,
            "task_id": str(task.task_id),
            "total_chats": len(chat_ids),
            "is_duplicate": is_duplicate,
        },
    )


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
        init_data = {"total": len(task.chat_ids), "status": task.status.value}
        yield f"event: init\ndata: {json.dumps(init_data)}\n\n"

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
                        complete_data = {"results_count": len(task.results)}
                        yield f"event: complete\ndata: {json.dumps(complete_data)}\n\n"
                    elif task and task.status == TaskStatus.CANCELLED:
                        cancel_data = {
                            "results_count": len(task.results),
                            "message": "Analysis cancelled",
                        }
                        yield f"event: cancelled\ndata: {json.dumps(cancel_data)}\n\n"
                    elif task and task.status == TaskStatus.TIMEOUT:
                        timeout_data = {
                            "results_count": len(task.results),
                            "error": task.error or "Task timed out",
                        }
                        yield f"event: timeout\ndata: {json.dumps(timeout_data)}\n\n"
                    elif task and task.status == TaskStatus.FAILED:
                        error_data = {"error": task.error or "Unknown error"}
                        yield f"event: error\ndata: {json.dumps(error_data)}\n\n"
                    break

                # Send progress event
                event_data = {
                    "current": event.current,
                    "total": event.total,
                    "status": event.status.value,
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

    try:
        uuid_task_id = UUID(task_id)
    except ValueError:
        return templates.TemplateResponse(
            "partials/analysis_results.html",
            {"request": request, "error": "Invalid task ID format"},
        )

    queue = get_task_queue()
    task = queue.get_task(uuid_task_id)

    if task is None:
        return templates.TemplateResponse(
            "partials/analysis_results.html",
            {"request": request, "error": "Task not found"},
        )

    if task.status == TaskStatus.IN_PROGRESS:
        return templates.TemplateResponse(
            "partials/analysis_results.html",
            {"request": request, "error": "Analysis still in progress"},
        )

    if task.status == TaskStatus.PENDING:
        return templates.TemplateResponse(
            "partials/analysis_results.html",
            {"request": request, "error": "Analysis not started"},
        )

    if task.status == TaskStatus.FAILED:
        return templates.TemplateResponse(
            "partials/analysis_results.html",
            {"request": request, "error": task.error or "Analysis failed"},
        )

    if task.status == TaskStatus.TIMEOUT:
        return templates.TemplateResponse(
            "partials/analysis_results.html",
            {
                "request": request,
                "task_id": task_id,
                "results": task.results,
                "session_id": task.session_id,
                "is_partial": True,
                "error": task.error or "Analysis timed out",
            },
        )

    # For COMPLETED or CANCELLED, show results (partial results for cancelled)
    return templates.TemplateResponse(
        "partials/analysis_results.html",
        {
            "request": request,
            "task_id": task_id,
            "results": task.results,
            "session_id": task.session_id,
            "is_partial": task.status == TaskStatus.CANCELLED,
        },
    )


@router.get("/{task_id}/status")
async def get_status(task_id: str) -> dict[str, str | int | None]:
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

    return {
        "task_id": str(task.task_id),
        "status": task.status.value,
        "current": task.current_chat_index,
        "total": len(task.chat_ids),
        "results_count": len(task.results),
        "error": task.error,
    }


@router.post("/{task_id}/cancel")
async def cancel_analysis(task_id: str) -> dict[str, str | int]:
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
        return {
            "status": "cancelled",
            "message": "Analysis cancelled successfully",
            "partial_results": len(task.results) if task else 0,
        }
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


@router.post("/{task_id}/force-cancel")
async def force_cancel_analysis(
    task_id: str, reason: str = "User-requested forced cancellation"
) -> dict[str, str | int]:
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
        return {
            "status": "force_cancelled",
            "message": "Task force-cancelled successfully",
            "reason": reason,
            "partial_results": len(task.results) if task else 0,
        }
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

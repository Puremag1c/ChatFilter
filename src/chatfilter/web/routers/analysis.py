"""Analysis router for starting analysis and streaming progress via SSE."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from chatfilter.analyzer import compute_metrics
from chatfilter.analyzer.task_queue import (
    AnalysisExecutor,
    ProgressEvent,
    TaskStatus,
    get_task_queue,
)
from chatfilter.models import AnalysisResult, Chat
from chatfilter.telegram.client import TelegramClientLoader, get_messages
from chatfilter.telegram.session_manager import SessionManager
from chatfilter.web.routers.chats import DATA_DIR, get_session_manager, get_session_paths

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analysis", tags=["analysis"])


# Chat cache to avoid repeated lookups
_chat_cache: dict[str, dict[int, Chat]] = {}


class RealAnalysisExecutor:
    """Real implementation of analysis executor using Telegram client."""

    def __init__(self, session_manager: SessionManager) -> None:
        self._session_manager = session_manager
        self._loaders: dict[str, TelegramClientLoader] = {}

    def _ensure_loader(self, session_id: str) -> None:
        """Ensure loader is registered for session."""
        if session_id not in self._loaders:
            session_path, config_path = get_session_paths(session_id)
            loader = TelegramClientLoader(session_path, config_path)
            loader.validate()
            self._session_manager.register(session_id, loader)
            self._loaders[session_id] = loader

    async def get_chat_info(
        self,
        session_id: str,
        chat_id: int,
    ) -> Chat | None:
        """Get chat info from cache or Telegram."""
        # Check cache first
        if session_id in _chat_cache and chat_id in _chat_cache[session_id]:
            return _chat_cache[session_id][chat_id]
        return None

    async def analyze_chat(
        self,
        session_id: str,
        chat_id: int,
    ) -> AnalysisResult:
        """Analyze a single chat."""
        self._ensure_loader(session_id)

        async with self._session_manager.session(session_id) as client:
            # Fetch messages
            messages = await get_messages(client, chat_id, limit=1000)

            # Compute metrics
            metrics = compute_metrics(messages)

            # Get chat info from cache
            chat = await self.get_chat_info(session_id, chat_id)
            if chat is None:
                # Create minimal chat info
                from chatfilter.models import ChatType

                chat = Chat(
                    id=chat_id,
                    title=f"Chat {chat_id}",
                    chat_type=ChatType.GROUP,
                )

            return AnalysisResult(
                chat=chat,
                metrics=metrics,
                analyzed_at=datetime.now(UTC),
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
) -> HTMLResponse:
    """Start analysis of selected chats.

    Creates a background task and returns HTML partial with progress UI.

    Args:
        request: FastAPI request
        background_tasks: Background tasks manager
        session_id: Session identifier
        chat_ids: List of chat IDs to analyze

    Returns:
        HTML partial with SSE progress container
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    if not session_id:
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {"request": request, "error": "No session selected"},
        )

    if not chat_ids:
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {"request": request, "error": "No chats selected for analysis"},
        )

    # Validate session exists
    try:
        get_session_paths(session_id)
    except HTTPException as e:
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {"request": request, "error": e.detail},
        )

    # Fetch chat info for the cache (needed for progress display)
    try:
        session_path, config_path = get_session_paths(session_id)
        loader = TelegramClientLoader(session_path, config_path)
        loader.validate()

        manager = get_session_manager()
        manager.register(session_id, loader)

        async with manager.session(session_id) as client:
            from chatfilter.telegram.client import get_dialogs

            chats = await get_dialogs(client)

            # Cache chat info
            if session_id not in _chat_cache:
                _chat_cache[session_id] = {}
            for chat in chats:
                _chat_cache[session_id][chat.id] = chat

    except Exception as e:
        logger.exception(f"Failed to fetch chat info: {e}")
        return templates.TemplateResponse(
            "partials/analysis_progress.html",
            {"request": request, "error": f"Failed to connect to Telegram: {e}"},
        )

    # Create analysis task
    queue = get_task_queue()
    task = queue.create_task(session_id, chat_ids)

    # Start background analysis
    executor = RealAnalysisExecutor(get_session_manager())
    background_tasks.add_task(queue.run_task, task.task_id, executor)

    logger.info(f"Started analysis task {task.task_id} for {len(chat_ids)} chats")

    return templates.TemplateResponse(
        "partials/analysis_progress.html",
        {
            "request": request,
            "task_id": str(task.task_id),
            "total_chats": len(chat_ids),
        },
    )


async def _generate_sse_events(
    task_id: UUID,
    request: Request,
) -> asyncio.AsyncGenerator[str, None]:
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
        yield f"event: init\ndata: {json.dumps({'total': len(task.chat_ids), 'status': task.status.value})}\n\n"

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
                        yield f"event: complete\ndata: {json.dumps({'results_count': len(task.results)})}\n\n"
                    elif task and task.status == TaskStatus.FAILED:
                        yield f"event: error\ndata: {json.dumps({'error': task.error or 'Unknown error'})}\n\n"
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

            except asyncio.TimeoutError:
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
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid task ID format",
        )

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

    if task.status == TaskStatus.FAILED:
        return templates.TemplateResponse(
            "partials/analysis_results.html",
            {"request": request, "error": task.error or "Analysis failed"},
        )

    return templates.TemplateResponse(
        "partials/analysis_results.html",
        {
            "request": request,
            "task_id": task_id,
            "results": task.results,
            "session_id": task.session_id,
        },
    )


@router.get("/{task_id}/status")
async def get_status(task_id: str) -> dict:
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
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid task ID format",
        )

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

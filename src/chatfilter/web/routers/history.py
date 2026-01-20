"""History endpoints for accessing past analysis results."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

from chatfilter.analyzer.task_queue import AnalysisTask, TaskStatus
from chatfilter.models import AnalysisResult
from chatfilter.storage.database import TaskDatabase
from chatfilter.web.dependencies import get_database

router = APIRouter(prefix="/api/history", tags=["history"])


class TaskSummary(BaseModel):
    """Summary of a task for history listing."""

    task_id: UUID
    session_id: str
    chat_count: int
    result_count: int
    message_limit: int
    status: TaskStatus
    created_at: str
    completed_at: str | None
    error: str | None


class HistoryListResponse(BaseModel):
    """Response for history list endpoint."""

    tasks: list[TaskSummary]
    total: int
    page: int
    page_size: int
    has_more: bool


class TaskDetailResponse(BaseModel):
    """Response for task detail endpoint."""

    task_id: UUID
    session_id: str
    chat_ids: list[int]
    message_limit: int
    status: TaskStatus
    created_at: str
    started_at: str | None
    completed_at: str | None
    error: str | None
    results: list[AnalysisResult]


class HistoryStats(BaseModel):
    """Statistics about analysis history."""

    total_tasks: int
    completed_tasks: int
    failed_tasks: int
    cancelled_tasks: int
    timeout_tasks: int


@router.get("/")
async def list_history(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 20,
    status: Annotated[TaskStatus | None, Query()] = None,
) -> HistoryListResponse:
    """List historical analysis tasks with pagination.

    Args:
        page: Page number (1-indexed)
        page_size: Number of tasks per page (max 100)
        status: Optional status filter (completed, failed, cancelled, timeout)

    Returns:
        Paginated list of task summaries
    """
    db = get_database()

    # Determine status filter
    status_filter = [status] if status else None

    # Calculate offset
    offset = (page - 1) * page_size

    # Load tasks with pagination
    tasks = db.load_completed_tasks(
        limit=page_size,
        offset=offset,
        status_filter=status_filter,
    )

    # Get total count for pagination
    total = db.count_completed_tasks(status_filter=status_filter)

    # Convert to summaries
    summaries = [
        TaskSummary(
            task_id=task.task_id,
            session_id=task.session_id,
            chat_count=len(task.chat_ids),
            result_count=len(task.results),
            message_limit=task.message_limit,
            status=task.status,
            created_at=task.created_at.isoformat(),
            completed_at=task.completed_at.isoformat() if task.completed_at else None,
            error=task.error,
        )
        for task in tasks
    ]

    return HistoryListResponse(
        tasks=summaries,
        total=total,
        page=page,
        page_size=page_size,
        has_more=(offset + len(tasks)) < total,
    )


@router.get("/stats")
async def get_history_stats() -> HistoryStats:
    """Get statistics about analysis history.

    Returns:
        Statistics including total tasks and breakdown by status
    """
    db = get_database()

    return HistoryStats(
        total_tasks=db.count_completed_tasks(),
        completed_tasks=db.count_completed_tasks(status_filter=[TaskStatus.COMPLETED]),
        failed_tasks=db.count_completed_tasks(status_filter=[TaskStatus.FAILED]),
        cancelled_tasks=db.count_completed_tasks(status_filter=[TaskStatus.CANCELLED]),
        timeout_tasks=db.count_completed_tasks(status_filter=[TaskStatus.TIMEOUT]),
    )


@router.get("/{task_id}")
async def get_task_history(
    task_id: Annotated[UUID, Path()],
) -> TaskDetailResponse:
    """Get detailed information about a historical task.

    Args:
        task_id: UUID of the task to retrieve

    Returns:
        Task details including all analysis results

    Raises:
        HTTPException: 404 if task not found
    """
    db = get_database()
    task = db.load_task(task_id)

    if task is None:
        raise HTTPException(status_code=404, detail=f"Task {task_id} not found")

    return TaskDetailResponse(
        task_id=task.task_id,
        session_id=task.session_id,
        chat_ids=task.chat_ids,
        message_limit=task.message_limit,
        status=task.status,
        created_at=task.created_at.isoformat(),
        started_at=task.started_at.isoformat() if task.started_at else None,
        completed_at=task.completed_at.isoformat() if task.completed_at else None,
        error=task.error,
        results=task.results,
    )

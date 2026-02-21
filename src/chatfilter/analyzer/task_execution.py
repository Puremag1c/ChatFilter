"""Task execution logic for the analysis queue.

Handles:
- Running analysis tasks with timeout protection
- Per-chat analysis with progress reporting
- Checkpoint resume for interrupted tasks
- Stalled task monitoring
- Recovery of incomplete tasks on startup
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

from chatfilter.analyzer.task_models import (
    AnalysisTask,
    ProgressEvent,
    TaskStatus,
)
from chatfilter.telegram.client import ChatAccessDeniedError

if TYPE_CHECKING:
    from chatfilter.analyzer.task_models import AnalysisExecutor

logger = logging.getLogger(__name__)

try:
    from chatfilter.utils.memory import log_memory_usage
except ImportError:
    log_memory_usage = None  # type: ignore[assignment]


def load_incomplete_tasks(queue: object) -> None:
    """Load incomplete tasks from database on startup.

    For tasks left in IN_PROGRESS status (from crashes):
    - If age > stale_task_threshold_hours: mark as FAILED
    - Otherwise: reset to PENDING for retry

    Args:
        queue: TaskQueue instance
    """
    db = queue._db  # type: ignore[union-attr]
    if not db:
        return

    try:
        incomplete_tasks = db.load_incomplete_tasks()
        recovered_count = 0
        stale_count = 0
        stale_threshold = queue._stale_task_threshold_hours  # type: ignore[union-attr]

        for task in incomplete_tasks:
            queue._tasks[task.task_id] = task  # type: ignore[union-attr]
            queue._subscribers[task.task_id] = []  # type: ignore[union-attr]

            if task.status == TaskStatus.IN_PROGRESS:
                task_timestamp = task.started_at if task.started_at else task.created_at
                if task_timestamp.tzinfo is None:
                    task_timestamp = task_timestamp.replace(tzinfo=UTC)
                task_age_hours = (datetime.now(UTC) - task_timestamp).total_seconds() / 3600

                if task_age_hours > stale_threshold:
                    task.status = TaskStatus.FAILED
                    task.error = (
                        f"Task abandoned after application crash "
                        f"(stale for {task_age_hours:.1f} hours, threshold: {stale_threshold}h)"
                    )
                    task.completed_at = datetime.now(UTC)
                    db.save_task(task)
                    stale_count += 1
                    logger.warning(
                        f"Marked stale task {task.task_id} as FAILED (age: {task_age_hours:.1f}h)"
                    )
                else:
                    task.status = TaskStatus.PENDING
                    db.save_task(task)
                    recovered_count += 1
                    partial_results = len(task.results)
                    logger.info(
                        f"Recovered task {task.task_id} for retry (age: {task_age_hours:.1f}h, "
                        f"{partial_results} results preserved)"
                    )
            else:
                recovered_count += 1

        if incomplete_tasks:
            logger.info(
                f"Task recovery complete: {recovered_count} recovered, {stale_count} marked stale"
            )
    except Exception as e:
        logger.exception(f"Failed to load incomplete tasks from database: {e}")


async def run_task_with_timeout(
    task_id: UUID,
    executor: AnalysisExecutor,
    queue: object,
) -> None:
    """Execute an analysis task with timeout and cancellation protection.

    Wraps run_task_impl with task-level timeout and cancellation handling.

    Args:
        task_id: Task UUID to run
        executor: Analysis executor implementation
        queue: TaskQueue instance
    """
    queue._ensure_monitor_started()  # type: ignore[union-attr]

    current_task = asyncio.current_task()
    if current_task:
        queue._running_tasks[task_id] = current_task  # type: ignore[union-attr]

    try:
        task_timeout = queue._task_timeout_seconds  # type: ignore[union-attr]
        if task_timeout > 0:
            await asyncio.wait_for(
                run_task_impl(task_id, executor, queue),
                timeout=task_timeout,
            )
        else:
            await run_task_impl(task_id, executor, queue)
    except TimeoutError:
        task = queue._tasks.get(task_id)  # type: ignore[union-attr]
        if task:
            task_timeout = queue._task_timeout_seconds  # type: ignore[union-attr]
            task.status = TaskStatus.TIMEOUT
            task.error = f"Task exceeded maximum execution time ({task_timeout}s)"
            task.completed_at = datetime.now(UTC)

            if queue._db:  # type: ignore[union-attr]
                queue._db.save_task(task)  # type: ignore[union-attr]

            task.event_sequence += 1
            await queue._publish_event(  # type: ignore[union-attr]
                ProgressEvent(
                    task_id=task_id,
                    status=TaskStatus.TIMEOUT,
                    current=task.current_chat_index,
                    total=len(task.chat_ids),
                    sequence=task.event_sequence,
                    error=task.error,
                )
            )

            logger.error(f"Task {task_id} timed out after {task_timeout}s")
            await queue._signal_completion(task_id)  # type: ignore[union-attr]
    except asyncio.CancelledError:
        task = queue._tasks.get(task_id)  # type: ignore[union-attr]
        if task and task.status != TaskStatus.CANCELLED:
            task.status = TaskStatus.CANCELLED
            task.error = task.error or "Task was force-cancelled"
            task.completed_at = datetime.now(UTC)

            if queue._db:  # type: ignore[union-attr]
                queue._db.save_task(task)  # type: ignore[union-attr]

            task.event_sequence += 1
            await queue._publish_event(  # type: ignore[union-attr]
                ProgressEvent(
                    task_id=task_id,
                    status=TaskStatus.CANCELLED,
                    current=task.current_chat_index,
                    total=len(task.chat_ids),
                    sequence=task.event_sequence,
                    message="Task was force-cancelled",
                )
            )

            logger.info(f"Task {task_id} was force-cancelled")
            await queue._signal_completion(task_id)  # type: ignore[union-attr]
        raise  # Re-raise to properly handle cancellation
    finally:
        queue._running_tasks.pop(task_id, None)  # type: ignore[union-attr]


async def run_task_impl(
    task_id: UUID,
    executor: AnalysisExecutor,
    queue: object,
) -> None:
    """Execute an analysis task: iterate chats, publish progress, store results.

    Args:
        task_id: Task UUID to run
        executor: Analysis executor implementation
        queue: TaskQueue instance (used for publishing events and accessing state)
    """
    # Access queue internals via the TaskQueue instance
    task: AnalysisTask | None = queue._tasks.get(task_id)  # type: ignore[union-attr]
    if task is None:
        raise KeyError(f"Task {task_id} not found")

    task.status = TaskStatus.IN_PROGRESS
    task.started_at = datetime.now(UTC)
    task.last_progress_at = datetime.now(UTC)  # Initialize progress tracking

    # Persist status change
    if queue._db:  # type: ignore[union-attr]
        queue._db.save_task(task)  # type: ignore[union-attr]

    # Log memory at task start
    if queue._enable_memory_monitoring and log_memory_usage is not None:  # type: ignore[union-attr]
        log_memory_usage(f"Task {task_id} start")

    # Pre-cache chat info for better progress display
    try:
        await executor.pre_cache_chats(task.session_id)
    except Exception as e:
        # Non-fatal: we can still proceed with minimal chat info
        logger.warning(f"Failed to pre-cache chat info for task {task_id}: {e}")

    # Checkpoint resume: skip already-analyzed chats
    resume_index = len(task.results)
    if resume_index > 0:
        logger.info(
            f"Resuming task {task_id} from checkpoint: "
            f"{resume_index}/{len(task.chat_ids)} chats already analyzed"
        )
        task.event_sequence += 1
        await queue._publish_event(  # type: ignore[union-attr]
            ProgressEvent(
                task_id=task_id,
                status=TaskStatus.IN_PROGRESS,
                current=resume_index,
                total=len(task.chat_ids),
                sequence=task.event_sequence,
                message=f"Resuming from checkpoint ({resume_index} chats already analyzed)...",
            )
        )

    try:
        for i in range(resume_index, len(task.chat_ids)):
            chat_id = task.chat_ids[i]
            # Check if task was cancelled
            if task.status == TaskStatus.CANCELLED:
                logger.info(f"Task {task_id} was cancelled, stopping execution")
                partial_count = len(task.results)
                task.event_sequence += 1
                await queue._publish_event(  # type: ignore[union-attr]
                    ProgressEvent(
                        task_id=task_id,
                        status=TaskStatus.CANCELLED,
                        current=i,
                        total=len(task.chat_ids),
                        sequence=task.event_sequence,
                        message=f"Analysis cancelled. {partial_count} chats analyzed before cancellation.",
                    )
                )
                break

            task.current_chat_index = i

            # Get chat info for progress display
            chat_info = await executor.get_chat_info(task.session_id, chat_id)
            chat_title = chat_info.title if chat_info else f"Chat {chat_id}"

            # Publish progress event
            task.event_sequence += 1
            await queue._publish_event(  # type: ignore[union-attr]
                ProgressEvent(
                    task_id=task_id,
                    status=TaskStatus.IN_PROGRESS,
                    current=i,
                    total=len(task.chat_ids),
                    sequence=task.event_sequence,
                    chat_title=chat_title,
                    message=f"Analyzing {chat_title}...",
                )
            )

            # Create batch progress callback
            async def batch_progress_callback(
                messages_processed: int,
                batch_number: int,
                total_batches: int | None = None,
                *,
                current_index: int = i,
                current_chat_title: str = chat_title,
            ) -> None:
                """Report batch progress to subscribers."""
                task.event_sequence += 1
                await queue._publish_event(  # type: ignore[union-attr]
                    ProgressEvent(
                        task_id=task_id,
                        status=TaskStatus.IN_PROGRESS,
                        current=current_index,
                        total=len(task.chat_ids),
                        sequence=task.event_sequence,
                        chat_title=current_chat_title,
                        message=f"Processing batch {batch_number}...",
                        messages_processed=messages_processed,
                        batch_number=batch_number,
                        total_batches=total_batches,
                    )
                )
                # Update last progress timestamp for stall detection
                task.last_progress_at = datetime.now(UTC)

            # Analyze chat with per-chat timeout
            try:
                per_chat_timeout = queue._per_chat_timeout_seconds  # type: ignore[union-attr]
                if per_chat_timeout > 0:
                    result = await asyncio.wait_for(
                        executor.analyze_chat(
                            session_id=task.session_id,
                            chat_id=chat_id,
                            message_limit=task.message_limit,
                            batch_progress_callback=batch_progress_callback,
                        ),
                        timeout=per_chat_timeout,
                    )
                else:
                    result = await executor.analyze_chat(
                        session_id=task.session_id,
                        chat_id=chat_id,
                        message_limit=task.message_limit,
                        batch_progress_callback=batch_progress_callback,
                    )
                task.results.append(result)

                # Persist result and update task state
                if queue._db:  # type: ignore[union-attr]
                    queue._db.save_task_result(task_id, result)  # type: ignore[union-attr]
                    queue._db.save_task(task)  # type: ignore[union-attr]

                # Check memory after each chat
                if queue._memory_monitor:  # type: ignore[union-attr]
                    queue._memory_monitor.check()  # type: ignore[union-attr]

            except TimeoutError:
                per_chat_timeout = queue._per_chat_timeout_seconds  # type: ignore[union-attr]
                logger.warning(
                    f"Chat {chat_id} ({chat_title}) analysis timed out "
                    f"after {per_chat_timeout}s. Skipping and continuing."
                )
                # Continue with other chats - don't fail entire task
            except ChatAccessDeniedError as e:
                # Chat is inaccessible (kicked, banned, left, or private/deleted)
                logger.info(f"Skipping inaccessible chat {chat_id} ({chat_title}): {e}")
                # Continue with other chats - this is expected behavior
            except Exception as e:
                # Unexpected error - log as warning
                logger.warning(f"Failed to analyze chat {chat_id} ({chat_title}): {e}")
                # Continue with other chats

        # Only mark as completed if not cancelled
        if task.status != TaskStatus.CANCELLED:
            task.status = TaskStatus.COMPLETED
            task.completed_at = datetime.now(UTC)

            # Persist completion
            if queue._db:  # type: ignore[union-attr]
                queue._db.save_task(task)  # type: ignore[union-attr]

            task.event_sequence += 1
            await queue._publish_event(  # type: ignore[union-attr]
                ProgressEvent(
                    task_id=task_id,
                    status=TaskStatus.COMPLETED,
                    current=len(task.chat_ids),
                    total=len(task.chat_ids),
                    sequence=task.event_sequence,
                    message=f"Analysis complete. {len(task.results)} chats analyzed.",
                )
            )

            logger.info(f"Task {task_id} completed with {len(task.results)} results")

            # Log memory at task completion
            if queue._enable_memory_monitoring and log_memory_usage is not None:  # type: ignore[union-attr]
                log_memory_usage(f"Task {task_id} completed")
        else:
            # Task was cancelled
            logger.info(f"Task {task_id} cancelled with {len(task.results)} partial results")

    except Exception as e:
        # Only mark as failed if not cancelled
        if task.status != TaskStatus.CANCELLED:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = datetime.now(UTC)

            # Persist failure
            if queue._db:  # type: ignore[union-attr]
                queue._db.save_task(task)  # type: ignore[union-attr]

            task.event_sequence += 1
            await queue._publish_event(  # type: ignore[union-attr]
                ProgressEvent(
                    task_id=task_id,
                    status=TaskStatus.FAILED,
                    current=task.current_chat_index,
                    total=len(task.chat_ids),
                    sequence=task.event_sequence,
                    error=str(e),
                )
            )

            logger.exception(f"Task {task_id} failed: {e}")

    finally:
        await queue._signal_completion(task_id)  # type: ignore[union-attr]
        # Automatic cleanup: check if we should clear old completed tasks
        await queue._auto_cleanup_if_needed()  # type: ignore[union-attr]


async def monitor_stalled_tasks(queue: object) -> None:
    """Background task to monitor for stalled/hung tasks.

    Checks periodically for tasks that haven't made progress within
    the configured stall timeout period.

    Args:
        queue: TaskQueue instance
    """
    stall_check_interval = queue._stall_check_interval_seconds  # type: ignore[union-attr]
    stall_timeout = queue._progress_stall_timeout_seconds  # type: ignore[union-attr]

    while True:
        try:
            await asyncio.sleep(stall_check_interval)

            now = datetime.now(UTC)
            for task_id, task in list(queue._tasks.items()):  # type: ignore[union-attr]
                if task.status != TaskStatus.IN_PROGRESS:
                    continue

                # Check if task has stalled (no progress for too long)
                if task.last_progress_at:
                    time_since_progress = (now - task.last_progress_at).total_seconds()
                    if time_since_progress > stall_timeout:
                        logger.warning(
                            f"Task {task_id} detected as stalled "
                            f"({time_since_progress:.0f}s since last progress). "
                            f"Forcing cancellation."
                        )
                        await queue.force_cancel_task(  # type: ignore[union-attr]
                            task_id,
                            reason=f"Task stalled: no progress for {time_since_progress:.0f}s",
                        )

        except asyncio.CancelledError:
            logger.info("Task stall monitor shutting down")
            break
        except Exception as e:
            logger.exception(f"Error in stall monitor: {e}")
            # Continue monitoring despite errors

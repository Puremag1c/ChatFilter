"""SSE event publishing and subscriber management for the task queue.

Handles:
- Subscribing/unsubscribing to task progress events
- Publishing events to subscribers with backpressure handling
- Detecting and disconnecting slow/hung clients
- Cleaning up orphaned subscribers
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import UTC, datetime
from uuid import UUID

from chatfilter.analyzer.task_models import (
    ProgressEvent,
    SubscriberHealth,
    TaskStatus,
)

logger = logging.getLogger(__name__)


async def subscribe(
    subscribers: dict[UUID, list[SubscriberHealth]],
    lock: asyncio.Lock,
    task_id: UUID,
    tasks: dict[UUID, object],
) -> asyncio.Queue[ProgressEvent | None]:
    """Subscribe to progress events for a task.

    Args:
        subscribers: Subscriber registry
        lock: Shared asyncio lock
        task_id: Task UUID to subscribe to
        tasks: Task registry (for existence check)

    Returns:
        asyncio.Queue that receives ProgressEvent objects.
        None is sent when task completes/fails to signal end.

    Raises:
        KeyError: If task not found
    """
    if task_id not in tasks:
        raise KeyError(f"Task {task_id} not found")

    queue: asyncio.Queue[ProgressEvent | None] = asyncio.Queue(maxsize=100)
    health = SubscriberHealth(queue=queue)

    async with lock:
        subscribers[task_id].append(health)

    logger.debug(f"New subscriber for task {task_id}")
    return queue


async def unsubscribe(
    subscribers: dict[UUID, list[SubscriberHealth]],
    lock: asyncio.Lock,
    task_id: UUID,
    queue: asyncio.Queue[ProgressEvent | None],
) -> None:
    """Unsubscribe from progress events.

    Args:
        subscribers: Subscriber registry
        lock: Shared asyncio lock
        task_id: Task UUID
        queue: Queue to unsubscribe
    """
    async with lock:
        if task_id in subscribers:
            # Find and remove subscriber health by queue reference
            for health in subscribers[task_id][:]:  # Copy list to iterate safely
                if health.queue is queue:
                    subscribers[task_id].remove(health)
                    logger.debug(f"Unsubscribed from task {task_id}")
                    break


async def publish_event(
    event: ProgressEvent,
    subscribers: dict[UUID, list[SubscriberHealth]],
    lock: asyncio.Lock,
    tasks: dict[UUID, object],
    max_consecutive_full_queue: int,
    subscriber_disconnect_threshold: int,
) -> None:
    """Publish a progress event to all subscribers.

    Args:
        event: Event to publish
        subscribers: Subscriber registry
        lock: Shared asyncio lock
        tasks: Task registry (for updating last_progress_at)
        max_consecutive_full_queue: Disconnect after N consecutive full queues
        subscriber_disconnect_threshold: Disconnect after N total dropped events
    """
    # Update last progress time for deadlock detection
    task = tasks.get(event.task_id)
    if task and event.status == TaskStatus.IN_PROGRESS:
        task.last_progress_at = datetime.now(UTC)  # type: ignore[union-attr]

    async with lock:
        subs = subscribers.get(event.task_id, [])
        subscribers_to_remove: list[SubscriberHealth] = []

        for health in subs:
            # Skip already disconnected subscribers
            if health.is_disconnected:
                continue

            try:
                # Non-blocking put with backpressure handling
                health.queue.put_nowait(event)
                # Queue accepted event - reset consecutive counter
                health.consecutive_full_count = 0

            except asyncio.QueueFull:
                # Queue is full - track this for backpressure
                health.consecutive_full_count += 1
                health.total_events_dropped += 1
                health.last_full_time = datetime.now(UTC)

                # Check if client should be forcibly disconnected
                should_disconnect = False
                disconnect_reason = ""

                if (
                    max_consecutive_full_queue > 0
                    and health.consecutive_full_count >= max_consecutive_full_queue
                ):
                    should_disconnect = True
                    disconnect_reason = (
                        f"consecutive full queue ({health.consecutive_full_count} times)"
                    )

                elif (
                    subscriber_disconnect_threshold > 0
                    and health.total_events_dropped >= subscriber_disconnect_threshold
                ):
                    should_disconnect = True
                    disconnect_reason = f"total dropped events ({health.total_events_dropped})"

                if should_disconnect:
                    health.is_disconnected = True
                    subscribers_to_remove.append(health)
                    logger.warning(
                        f"Forcibly disconnecting slow SSE client for task {event.task_id}: "
                        f"{disconnect_reason}. This prevents memory leaks from clients that "
                        f"read events slower than they're generated."
                    )
                    # Send a final None to signal disconnection
                    # Clear space in queue if needed to ensure None is delivered
                    try:
                        health.queue.put_nowait(None)
                    except asyncio.QueueFull:
                        # Queue is full, clear oldest event and add None
                        with contextlib.suppress(asyncio.QueueEmpty):
                            health.queue.get_nowait()
                        # Try again to send None
                        with contextlib.suppress(asyncio.QueueFull):
                            health.queue.put_nowait(None)
                else:
                    # Drop oldest event to prevent memory issues
                    try:
                        health.queue.get_nowait()
                        health.queue.put_nowait(event)
                    except asyncio.QueueEmpty:
                        # Queue was emptied concurrently, try to add event again
                        with contextlib.suppress(asyncio.QueueFull):
                            health.queue.put_nowait(event)

        # Remove disconnected subscribers
        for health in subscribers_to_remove:
            with contextlib.suppress(ValueError):
                subs.remove(health)


async def signal_completion(
    task_id: UUID,
    subscribers: dict[UUID, list[SubscriberHealth]],
    lock: asyncio.Lock,
) -> None:
    """Signal task completion to all subscribers.

    Args:
        task_id: Completed task ID
        subscribers: Subscriber registry
        lock: Shared asyncio lock
    """
    async with lock:
        subs = subscribers.get(task_id, [])
        for health in subs:
            with contextlib.suppress(asyncio.QueueFull):
                health.queue.put_nowait(None)


async def cleanup_orphaned_subscribers(
    subscribers: dict[UUID, list[SubscriberHealth]],
    lock: asyncio.Lock,
    tasks: dict[UUID, object],
) -> int:
    """Clean up subscriber queues for completed/failed/cancelled/timeout tasks.

    Orphaned subscribers can occur when clients disconnect abruptly
    without properly unsubscribing. This method removes subscriber
    lists for tasks that are no longer active.

    Args:
        subscribers: Subscriber registry
        lock: Shared asyncio lock
        tasks: Task registry

    Returns:
        Number of subscriber lists cleaned up
    """
    async with lock:
        cleaned_count = 0
        for task_id in list(subscribers.keys()):
            task = tasks.get(task_id)
            # Clean subscribers for completed/failed/cancelled/timeout tasks
            if task and task.status in (  # type: ignore[union-attr]
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
                TaskStatus.TIMEOUT,
            ):
                subscriber_count = len(subscribers[task_id])
                if subscriber_count > 0:
                    logger.info(
                        f"Cleaning {subscriber_count} orphaned subscribers "
                        f"for task {task_id} (status: {task.status})"  # type: ignore[union-attr]
                    )
                    subscribers[task_id].clear()
                    cleaned_count += 1
            # Also clean subscribers for non-existent tasks
            elif task is None:
                subscriber_count = len(subscribers[task_id])
                if subscriber_count > 0:
                    logger.warning(
                        f"Cleaning {subscriber_count} orphaned subscribers "
                        f"for non-existent task {task_id}"
                    )
                    del subscribers[task_id]
                    cleaned_count += 1
        return cleaned_count

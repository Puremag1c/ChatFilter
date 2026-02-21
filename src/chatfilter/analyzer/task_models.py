"""Data models, enums, protocols, and exceptions for the task queue.

Contains all type definitions used across the task queue system:
- TaskStatus enum for task lifecycle states
- ProgressEvent for SSE streaming updates
- AnalysisTask for task state tracking
- SubscriberHealth for backpressure monitoring
- Protocol definitions for dependency injection
- QueueFullError exception
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from chatfilter.models import AnalysisResult, Chat


class QueueFullError(Exception):
    """Raised when task queue has reached maximum concurrent tasks."""

    def __init__(self, current: int, limit: int):
        """Initialize error.

        Args:
            current: Current number of active tasks
            limit: Maximum allowed concurrent tasks
        """
        self.current = current
        self.limit = limit
        super().__init__(
            f"Task queue is full: {current}/{limit} concurrent tasks. "
            f"Please wait for some tasks to complete before starting new ones."
        )


class TaskStatus(str, Enum):
    """Status of an analysis task."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"  # Task exceeded time limit


@dataclass
class ProgressEvent:
    """Progress update event for SSE streaming."""

    task_id: UUID
    status: TaskStatus
    current: int  # Current chat index (0-based)
    total: int  # Total number of chats
    sequence: int  # Monotonically increasing event sequence number for ordering
    chat_title: str | None = None  # Currently processing chat
    message: str | None = None  # Optional status message
    error: str | None = None  # Error message if failed
    # Batch-level progress (for large chats with streaming)
    messages_processed: int | None = None  # Total messages processed so far
    batch_number: int | None = None  # Current batch number
    total_batches: int | None = None  # Estimated total batches (if known)


@dataclass
class SubscriberHealth:
    """Track health metrics for a subscriber to detect slow/hung clients."""

    queue: asyncio.Queue[ProgressEvent | None]
    consecutive_full_count: int = 0  # Consecutive times queue was full
    total_events_dropped: int = 0  # Total events dropped for this subscriber
    last_full_time: datetime | None = None  # Last time queue was full
    is_disconnected: bool = False  # True if forcibly disconnected


@dataclass
class AnalysisTask:
    """Represents an analysis task in the queue."""

    task_id: UUID
    session_id: str
    chat_ids: list[int]
    message_limit: int = 1000
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    started_at: datetime | None = None
    completed_at: datetime | None = None
    results: list[AnalysisResult] = field(default_factory=list)
    error: str | None = None
    current_chat_index: int = 0
    last_progress_at: datetime | None = None  # Track last progress for deadlock detection
    event_sequence: int = 0  # Monotonically increasing sequence for SSE event ordering


class BatchProgressCallback(Protocol):
    """Callback protocol for batch progress updates."""

    async def __call__(
        self,
        messages_processed: int,
        batch_number: int,
        total_batches: int | None = None,
    ) -> None:
        """Report batch progress.

        Args:
            messages_processed: Total messages processed so far
            batch_number: Current batch number
            total_batches: Estimated total batches (if known)
        """
        ...


class AnalysisExecutor(Protocol):
    """Protocol for analysis executor (allows test injection)."""

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
        """Analyze a single chat and return results.

        Args:
            session_id: Session identifier
            chat_id: Chat ID to analyze
            message_limit: Maximum messages to fetch
            batch_size: Batch size for streaming mode
            use_streaming: Force streaming mode (None = auto-detect)
            memory_limit_mb: Memory threshold in MB
            enable_memory_monitoring: Enable memory monitoring
            batch_progress_callback: Optional callback for batch progress updates
        """
        ...

    async def get_chat_info(
        self,
        session_id: str,
        chat_id: int,
    ) -> Chat | None:
        """Get chat info for a chat ID."""
        ...

    async def pre_cache_chats(
        self,
        session_id: str,
    ) -> None:
        """Pre-cache all chat info for better progress display.

        This method is called at the start of background task execution
        to fetch and cache chat metadata. This prevents the HTTP request
        from blocking on Telegram connection.

        Args:
            session_id: Session identifier

        Raises:
            Exception: Connection or fetch errors (non-fatal, can continue with minimal info)
        """
        ...

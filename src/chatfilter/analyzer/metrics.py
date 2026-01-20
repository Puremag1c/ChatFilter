"""Metrics computation from message data."""

from __future__ import annotations

import logging
from datetime import datetime

from chatfilter.models.analysis import ChatMetrics
from chatfilter.models.message import Message

logger = logging.getLogger(__name__)


def compute_metrics(messages: list[Message]) -> ChatMetrics:
    """Compute chat metrics from a list of messages.

    Analyzes the provided messages to calculate:
    - message_count: Total number of messages
    - unique_authors: Number of distinct author IDs
    - history_hours: Time span from first to last message in hours
    - first_message_at: Timestamp of the earliest message
    - last_message_at: Timestamp of the latest message

    Note on anonymous authors:
        In Telegram channels and groups with anonymous admins, sender_id can be None.
        Anonymous messages use chat_id as their author_id, meaning all anonymous
        messages in a chat are counted as ONE author. This is a deliberate design
        decision to ensure consistent unique_authors counts without skipping messages.

    Args:
        messages: List of Message models to analyze. Messages should be
            sorted by timestamp but the function handles unsorted input.

    Returns:
        ChatMetrics with computed values. Returns ChatMetrics.empty()
        if messages list is empty.

    Example:
        ```python
        from chatfilter.analyzer import compute_metrics
        from chatfilter.models import Message

        messages = [msg1, msg2, msg3]
        metrics = compute_metrics(messages)
        print(f"Unique authors: {metrics.unique_authors}")
        print(f"History span: {metrics.history_hours:.1f} hours")
        ```
    """
    if not messages:
        return ChatMetrics.empty()

    # Count unique authors
    author_ids = {msg.author_id for msg in messages}
    unique_authors = len(author_ids)

    # Find timestamp range
    timestamps = [msg.timestamp for msg in messages]
    first_message_at = min(timestamps)
    last_message_at = max(timestamps)

    # Calculate history span in hours
    time_delta = last_message_at - first_message_at
    history_hours = time_delta.total_seconds() / 3600.0

    return ChatMetrics(
        message_count=len(messages),
        unique_authors=unique_authors,
        history_hours=history_hours,
        first_message_at=first_message_at,
        last_message_at=last_message_at,
    )


class StreamingMetricsAggregator:
    """Incremental metrics computation for large message streams.

    Computes chat metrics on-the-fly without loading all messages into memory.
    Suitable for chats with millions of messages where memory is constrained.

    Example:
        ```python
        aggregator = StreamingMetricsAggregator()

        # Process messages in batches
        async for batch in get_message_batches(chat_id, batch_size=1000):
            aggregator.add_batch(batch)

        # Get final metrics
        metrics = aggregator.get_metrics()
        print(f"Processed {metrics.message_count} messages")
        print(f"Unique authors: {metrics.unique_authors}")
        ```
    """

    def __init__(self) -> None:
        """Initialize empty aggregator."""
        self._message_count = 0
        self._author_ids: set[int] = set()
        self._first_message_at: datetime | None = None
        self._last_message_at: datetime | None = None

    def add_batch(self, messages: list[Message]) -> None:
        """Add a batch of messages to the aggregation.

        Updates metrics incrementally without storing messages in memory.

        Args:
            messages: Batch of messages to process
        """
        if not messages:
            return

        # Update message count
        self._message_count += len(messages)

        # Update unique authors (set handles deduplication)
        for msg in messages:
            self._author_ids.add(msg.author_id)

        # Update timestamp range
        batch_timestamps = [msg.timestamp for msg in messages]
        batch_first = min(batch_timestamps)
        batch_last = max(batch_timestamps)

        if self._first_message_at is None or batch_first < self._first_message_at:
            self._first_message_at = batch_first

        if self._last_message_at is None or batch_last > self._last_message_at:
            self._last_message_at = batch_last

        logger.debug(
            f"Aggregated batch: +{len(messages)} messages, "
            f"total={self._message_count}, unique_authors={len(self._author_ids)}"
        )

    def add_message(self, message: Message) -> None:
        """Add a single message to the aggregation.

        Convenience method for single-message processing.

        Args:
            message: Message to process
        """
        self.add_batch([message])

    def get_metrics(self) -> ChatMetrics:
        """Get the computed metrics.

        Returns:
            ChatMetrics with all aggregated values. Returns ChatMetrics.empty()
            if no messages have been processed.
        """
        if self._message_count == 0:
            return ChatMetrics.empty()

        # Calculate history span
        assert self._first_message_at is not None
        assert self._last_message_at is not None

        time_delta = self._last_message_at - self._first_message_at
        history_hours = time_delta.total_seconds() / 3600.0

        return ChatMetrics(
            message_count=self._message_count,
            unique_authors=len(self._author_ids),
            history_hours=history_hours,
            first_message_at=self._first_message_at,
            last_message_at=self._last_message_at,
        )

    def reset(self) -> None:
        """Reset all aggregation state."""
        self._message_count = 0
        self._author_ids.clear()
        self._first_message_at = None
        self._last_message_at = None

    @property
    def message_count(self) -> int:
        """Get current message count."""
        return self._message_count

    @property
    def unique_authors(self) -> int:
        """Get current unique author count."""
        return len(self._author_ids)

    @property
    def author_set_size_bytes(self) -> int:
        """Estimate memory usage of author ID set.

        Returns:
            Approximate memory usage in bytes
        """
        # Each int in Python is ~28 bytes + set overhead
        # Conservative estimate: 32 bytes per ID + 200 bytes base overhead
        return len(self._author_ids) * 32 + 200

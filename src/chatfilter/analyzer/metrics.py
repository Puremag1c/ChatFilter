"""Metrics computation from message data."""

from __future__ import annotations

from chatfilter.models.analysis import ChatMetrics
from chatfilter.models.message import Message


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

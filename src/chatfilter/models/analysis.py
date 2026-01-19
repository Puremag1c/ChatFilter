"""Analysis result models."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, computed_field, field_validator

from .chat import Chat


class ChatMetrics(BaseModel):
    """Computed metrics for a chat.

    Attributes:
        message_count: Total number of messages analyzed.
        unique_authors: Number of unique message authors.
        history_hours: Length of message history in hours.
        first_message_at: Timestamp of the oldest message.
        last_message_at: Timestamp of the newest message.
        messages_per_hour: Computed message rate (messages / hours).

    Example:
        >>> from datetime import datetime, timezone
        >>> metrics = ChatMetrics(
        ...     message_count=100,
        ...     unique_authors=10,
        ...     history_hours=24.5,
        ...     first_message_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        ...     last_message_at=datetime(2024, 1, 2, tzinfo=timezone.utc),
        ... )
        >>> metrics.unique_authors
        10
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    message_count: int
    unique_authors: int
    history_hours: float
    first_message_at: datetime | None
    last_message_at: datetime | None

    @field_validator("message_count", "unique_authors")
    @classmethod
    def counts_must_be_non_negative(cls, v: int) -> int:
        """Validate that counts are non-negative."""
        if v < 0:
            raise ValueError("count cannot be negative")
        return v

    @field_validator("history_hours")
    @classmethod
    def history_hours_must_be_non_negative(cls, v: float) -> float:
        """Validate that history hours is non-negative."""
        if v < 0:
            raise ValueError("history_hours cannot be negative")
        return v

    @computed_field  # type: ignore[prop-decorator]
    @property
    def messages_per_hour(self) -> float:
        """Calculate message rate (messages per hour).

        Returns 0.0 for edge cases:
        - No messages (message_count == 0)
        - Single message or all messages at same time (history_hours == 0)

        For chats with history, returns message_count / history_hours.
        """
        if self.message_count == 0 or self.history_hours == 0:
            return 0.0
        return self.message_count / self.history_hours

    @classmethod
    def empty(cls) -> ChatMetrics:
        """Create empty metrics for chats with no messages."""
        return cls(
            message_count=0,
            unique_authors=0,
            history_hours=0.0,
            first_message_at=None,
            last_message_at=None,
        )

    @classmethod
    def fake(
        cls,
        message_count: int | None = None,
        unique_authors: int | None = None,
        history_hours: float | None = None,
        first_message_at: datetime | None = None,
        last_message_at: datetime | None = None,
    ) -> ChatMetrics:
        """Create fake ChatMetrics for testing.

        Args:
            message_count: Number of messages (default: random 10-1000).
            unique_authors: Number of authors (default: random 1-50).
            history_hours: History length (default: random 1-168).
            first_message_at: First message time (default: calculated).
            last_message_at: Last message time (default: 1 hour ago).

        Returns:
            ChatMetrics instance with test data.
        """
        _last = last_message_at or (datetime.now(UTC) - timedelta(hours=1))
        _hours = history_hours if history_hours is not None else random.uniform(1.0, 168.0)
        _first = first_message_at or (_last - timedelta(hours=_hours))

        return cls(
            message_count=message_count if message_count is not None else random.randint(10, 1000),
            unique_authors=unique_authors if unique_authors is not None else random.randint(1, 50),
            history_hours=_hours,
            first_message_at=_first,
            last_message_at=_last,
        )


class AnalysisResult(BaseModel):
    """Complete analysis result for a chat.

    Combines chat information with computed metrics.

    Attributes:
        chat: The analyzed chat.
        metrics: Computed metrics from message analysis.
        analyzed_at: When the analysis was performed.

    Example:
        >>> from datetime import datetime, timezone
        >>> from chatfilter.models import Chat, ChatType
        >>> chat = Chat(id=1, title="Test", chat_type=ChatType.GROUP)
        >>> result = AnalysisResult(
        ...     chat=chat,
        ...     metrics=ChatMetrics.empty(),
        ...     analyzed_at=datetime.now(timezone.utc),
        ... )
        >>> result.chat.title
        'Test'
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    chat: Chat
    metrics: ChatMetrics
    analyzed_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_active(self) -> bool:
        """Check if chat has recent activity (within last 7 days)."""
        if self.metrics.last_message_at is None:
            return False
        now = datetime.now(UTC)
        return (now - self.metrics.last_message_at) < timedelta(days=7)

    @classmethod
    def fake(
        cls,
        chat: Chat | None = None,
        metrics: ChatMetrics | None = None,
        analyzed_at: datetime | None = None,
    ) -> AnalysisResult:
        """Create fake AnalysisResult for testing.

        Args:
            chat: Chat instance (default: fake chat).
            metrics: Metrics instance (default: fake metrics).
            analyzed_at: Analysis timestamp (default: now).

        Returns:
            AnalysisResult instance with test data.
        """
        return cls(
            chat=chat if chat is not None else Chat.fake(),
            metrics=metrics if metrics is not None else ChatMetrics.fake(),
            analyzed_at=analyzed_at if analyzed_at is not None else datetime.now(UTC),
        )

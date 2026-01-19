"""Message domain model."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from pydantic import BaseModel, ConfigDict, field_validator


class Message(BaseModel):
    """Telegram message representation.

    Attributes:
        id: Unique message identifier within the chat.
        chat_id: ID of the chat this message belongs to.
        author_id: ID of the message author (sender).
        timestamp: When the message was sent (must be in the past).
        text: Message text content (may be empty for media messages).

    Example:
        >>> from datetime import datetime, timezone
        >>> msg = Message(
        ...     id=1,
        ...     chat_id=123,
        ...     author_id=456,
        ...     timestamp=datetime(2024, 1, 1, tzinfo=timezone.utc),
        ...     text="Hello"
        ... )
        >>> msg.author_id
        456
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    id: int
    chat_id: int
    author_id: int
    timestamp: datetime
    text: str = ""

    @field_validator("chat_id")
    @classmethod
    def chat_id_must_be_positive(cls, v: int) -> int:
        """Validate that chat ID is positive."""
        if v <= 0:
            raise ValueError("chat_id must be positive")
        return v

    @field_validator("author_id")
    @classmethod
    def author_id_must_be_positive(cls, v: int) -> int:
        """Validate that author ID is positive."""
        if v <= 0:
            raise ValueError("author_id must be positive")
        return v

    @field_validator("timestamp")
    @classmethod
    def timestamp_must_be_in_past(cls, v: datetime) -> datetime:
        """Validate that timestamp is not in the future.

        Allows a small tolerance (1 minute) for clock skew.
        """
        now = datetime.now(UTC)
        tolerance = timedelta(minutes=1)
        if v > now + tolerance:
            raise ValueError("timestamp cannot be in the future")
        # Ensure timezone-aware
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return v

    @classmethod
    def fake(
        cls,
        id: int | None = None,
        chat_id: int | None = None,
        author_id: int | None = None,
        timestamp: datetime | None = None,
        text: str | None = None,
    ) -> Message:
        """Create a fake Message for testing.

        Args:
            id: Message ID (default: random int).
            chat_id: Chat ID (default: random positive int).
            author_id: Author ID (default: random positive int).
            timestamp: Message timestamp (default: 1 hour ago).
            text: Message text (default: "Test message").

        Returns:
            Message instance with test data.

        Example:
            >>> msg = Message.fake(text="Hello")
            >>> msg.text
            'Hello'
        """
        default_timestamp = datetime.now(UTC) - timedelta(hours=1)
        return cls(
            id=id if id is not None else random.randint(1, 1_000_000),
            chat_id=chat_id if chat_id is not None else random.randint(1, 1_000_000),
            author_id=author_id if author_id is not None else random.randint(1, 1_000_000),
            timestamp=timestamp if timestamp is not None else default_timestamp,
            text=text if text is not None else "Test message",
        )

"""Chat domain model."""

from __future__ import annotations

import random
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator


class ChatType(str, Enum):
    """Type of Telegram chat."""

    PRIVATE = "private"
    GROUP = "group"
    SUPERGROUP = "supergroup"
    CHANNEL = "channel"
    FORUM = "forum"


class Chat(BaseModel):
    """Telegram chat representation.

    Attributes:
        id: Unique chat identifier (positive integer).
        title: Chat title or name.
        chat_type: Type of chat (private, group, channel, etc.).
        username: Optional public username (@username).
        member_count: Number of members (if available).
        is_archived: Whether the chat is archived (in folder 1).

    Example:
        >>> chat = Chat(id=123, title="Test Chat", chat_type=ChatType.GROUP)
        >>> chat.id
        123
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    id: int
    title: str
    chat_type: ChatType
    username: str | None = None
    member_count: int | None = None
    is_archived: bool = False

    @field_validator("id")
    @classmethod
    def id_must_be_positive(cls, v: int) -> int:
        """Validate that chat ID is positive."""
        if v <= 0:
            raise ValueError("chat id must be positive")
        return v

    @field_validator("member_count")
    @classmethod
    def member_count_must_be_non_negative(cls, v: int | None) -> int | None:
        """Validate that member count is non-negative if provided."""
        if v is not None and v < 0:
            raise ValueError("member_count cannot be negative")
        return v

    @classmethod
    def fake(
        cls,
        id: int | None = None,
        title: str | None = None,
        chat_type: ChatType | None = None,
        username: str | None = None,
        member_count: int | None = None,
        is_archived: bool = False,
    ) -> Chat:
        """Create a fake Chat for testing.

        Args:
            id: Chat ID (default: random positive int).
            title: Chat title (default: "Test Chat").
            chat_type: Chat type (default: GROUP).
            username: Optional username.
            member_count: Optional member count.
            is_archived: Whether the chat is archived (default: False).

        Returns:
            Chat instance with test data.

        Example:
            >>> chat = Chat.fake()
            >>> chat.title
            'Test Chat'
        """
        return cls(
            id=id if id is not None else random.randint(1, 1_000_000),
            title=title if title is not None else "Test Chat",
            chat_type=chat_type if chat_type is not None else ChatType.GROUP,
            username=username,
            member_count=member_count,
            is_archived=is_archived,
        )

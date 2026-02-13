"""Group chat models for batch analysis."""

from __future__ import annotations

import random
from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator


class GroupStatus(str, Enum):
    """Status of a chat group."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PAUSED = "paused"
    COMPLETED = "completed"


class ChatTypeEnum(str, Enum):
    """Type classification for group chat."""

    PENDING = "pending"
    GROUP = "group"
    FORUM = "forum"
    CHANNEL_COMMENTS = "channel_comments"
    CHANNEL_NO_COMMENTS = "channel_no_comments"
    DEAD = "dead"


class GroupChatStatus(str, Enum):
    """Processing status for individual chat in group."""

    PENDING = "pending"
    JOINING = "joining"
    ANALYZING = "analyzing"
    DONE = "done"
    FAILED = "failed"


class GroupSettings(BaseModel):
    """Settings for group analysis.

    Attributes:
        message_limit: Maximum messages to analyze per chat (10-10000).
        leave_after_analysis: Whether to leave chat after analysis.

    Example:
        >>> settings = GroupSettings(message_limit=100)
        >>> settings.message_limit
        100
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    message_limit: int = 100
    leave_after_analysis: bool = False

    @field_validator("message_limit")
    @classmethod
    def message_limit_in_range(cls, v: int) -> int:
        """Validate that message_limit is in valid range."""
        if v < 10 or v > 10000:
            raise ValueError("message_limit must be between 10 and 10000")
        return v

    @classmethod
    def fake(
        cls,
        message_limit: int | None = None,
        leave_after_analysis: bool = False,
    ) -> GroupSettings:
        """Create fake GroupSettings for testing.

        Args:
            message_limit: Message limit (default: 100).
            leave_after_analysis: Whether to leave after analysis (default: False).

        Returns:
            GroupSettings instance with test data.
        """
        return cls(
            message_limit=message_limit if message_limit is not None else 100,
            leave_after_analysis=leave_after_analysis,
        )


class ChatGroup(BaseModel):
    """Chat group for batch analysis.

    Attributes:
        id: Unique group identifier.
        name: Group name.
        settings: Analysis settings.
        status: Current processing status.
        chat_count: Number of chats in group.
        created_at: When the group was created.
        updated_at: When the group was last updated.

    Example:
        >>> from datetime import datetime, timezone
        >>> group = ChatGroup(
        ...     id="grp-123",
        ...     name="Test Group",
        ...     settings=GroupSettings(),
        ...     status=GroupStatus.PENDING,
        ...     chat_count=5,
        ...     created_at=datetime.now(timezone.utc),
        ...     updated_at=datetime.now(timezone.utc),
        ... )
        >>> group.name
        'Test Group'
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    id: str
    name: str
    settings: GroupSettings
    status: GroupStatus
    chat_count: int
    created_at: datetime
    updated_at: datetime

    @field_validator("chat_count")
    @classmethod
    def chat_count_must_be_non_negative(cls, v: int) -> int:
        """Validate that chat_count is non-negative."""
        if v < 0:
            raise ValueError("chat_count cannot be negative")
        return v

    @classmethod
    def fake(
        cls,
        id: str | None = None,
        name: str | None = None,
        settings: GroupSettings | None = None,
        status: GroupStatus | None = None,
        chat_count: int | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> ChatGroup:
        """Create fake ChatGroup for testing.

        Args:
            id: Group ID (default: random ID).
            name: Group name (default: "Test Group").
            settings: Group settings (default: fake settings).
            status: Group status (default: PENDING).
            chat_count: Number of chats (default: random 1-10).
            created_at: Creation timestamp (default: now).
            updated_at: Update timestamp (default: now).

        Returns:
            ChatGroup instance with test data.
        """
        now = datetime.now(UTC)
        return cls(
            id=id if id is not None else f"grp-{random.randint(100000, 999999)}",
            name=name if name is not None else "Test Group",
            settings=settings if settings is not None else GroupSettings.fake(),
            status=status if status is not None else GroupStatus.PENDING,
            chat_count=chat_count if chat_count is not None else random.randint(1, 10),
            created_at=created_at if created_at is not None else now,
            updated_at=updated_at if updated_at is not None else now,
        )


class GroupChat(BaseModel):
    """Individual chat in a group.

    Attributes:
        id: Unique chat entry identifier.
        group_id: Parent group ID.
        chat_ref: Chat reference (link or username).
        chat_type: Type classification.
        status: Processing status.
        assigned_account: Account assigned to process this chat.
        error: Error message if failed.

    Example:
        >>> chat = GroupChat(
        ...     id="gc-123",
        ...     group_id="grp-123",
        ...     chat_ref="https://t.me/testchat",
        ...     chat_type=ChatTypeEnum.PENDING,
        ...     status=GroupChatStatus.PENDING,
        ...     assigned_account=None,
        ...     error=None,
        ... )
        >>> chat.status
        <GroupChatStatus.PENDING: 'pending'>
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    id: str
    group_id: str
    chat_ref: str
    chat_type: ChatTypeEnum
    status: GroupChatStatus
    assigned_account: str | None
    error: str | None

    @classmethod
    def fake(
        cls,
        id: str | None = None,
        group_id: str | None = None,
        chat_ref: str | None = None,
        chat_type: ChatTypeEnum | None = None,
        status: GroupChatStatus | None = None,
        assigned_account: str | None = None,
        error: str | None = None,
    ) -> GroupChat:
        """Create fake GroupChat for testing.

        Args:
            id: Chat entry ID (default: random ID).
            group_id: Parent group ID (default: random ID).
            chat_ref: Chat reference (default: test link).
            chat_type: Chat type (default: PENDING).
            status: Processing status (default: PENDING).
            assigned_account: Assigned account (default: None).
            error: Error message (default: None).

        Returns:
            GroupChat instance with test data.
        """
        return cls(
            id=id if id is not None else f"gc-{random.randint(100000, 999999)}",
            group_id=group_id if group_id is not None else f"grp-{random.randint(100000, 999999)}",
            chat_ref=chat_ref if chat_ref is not None else "https://t.me/testchat",
            chat_type=chat_type if chat_type is not None else ChatTypeEnum.PENDING,
            status=status if status is not None else GroupChatStatus.PENDING,
            assigned_account=assigned_account,
            error=error,
        )


class GroupStats(BaseModel):
    """Statistics for group processing.

    Attributes:
        total: Total number of chats.
        pending: Chats not yet processed.
        dead: Dead/inaccessible chats.
        groups: Regular group chats.
        forums: Forum chats.
        channels_with_comments: Channels with comments enabled.
        channels_no_comments: Channels without comments.
        analyzed: Successfully analyzed chats.
        failed: Failed chat processing.

    Example:
        >>> stats = GroupStats(
        ...     total=10,
        ...     pending=5,
        ...     dead=1,
        ...     groups=2,
        ...     forums=1,
        ...     channels_with_comments=1,
        ...     channels_no_comments=0,
        ...     analyzed=3,
        ...     failed=1,
        ... )
        >>> stats.total
        10
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    total: int
    pending: int
    dead: int
    groups: int
    forums: int
    channels_with_comments: int
    channels_no_comments: int
    analyzed: int
    failed: int

    @field_validator("total", "pending", "dead", "groups", "forums",
                     "channels_with_comments", "channels_no_comments",
                     "analyzed", "failed")
    @classmethod
    def counts_must_be_non_negative(cls, v: int) -> int:
        """Validate that all counts are non-negative."""
        if v < 0:
            raise ValueError("count cannot be negative")
        return v

    @classmethod
    def empty(cls) -> GroupStats:
        """Create empty stats."""
        return cls(
            total=0,
            pending=0,
            dead=0,
            groups=0,
            forums=0,
            channels_with_comments=0,
            channels_no_comments=0,
            analyzed=0,
            failed=0,
        )

    @classmethod
    def fake(
        cls,
        total: int | None = None,
        pending: int | None = None,
        dead: int | None = None,
        groups: int | None = None,
        forums: int | None = None,
        channels_with_comments: int | None = None,
        channels_no_comments: int | None = None,
        analyzed: int | None = None,
        failed: int | None = None,
    ) -> GroupStats:
        """Create fake GroupStats for testing.

        Args:
            total: Total count (default: 10).
            pending: Pending count (default: 3).
            dead: Dead count (default: 1).
            groups: Group count (default: 2).
            forums: Forum count (default: 1).
            channels_with_comments: Channels with comments (default: 1).
            channels_no_comments: Channels without comments (default: 2).
            analyzed: Analyzed count (default: 4).
            failed: Failed count (default: 1).

        Returns:
            GroupStats instance with test data.
        """
        return cls(
            total=total if total is not None else 10,
            pending=pending if pending is not None else 3,
            dead=dead if dead is not None else 1,
            groups=groups if groups is not None else 2,
            forums=forums if forums is not None else 1,
            channels_with_comments=channels_with_comments if channels_with_comments is not None else 1,
            channels_no_comments=channels_no_comments if channels_no_comments is not None else 2,
            analyzed=analyzed if analyzed is not None else 4,
            failed=failed if failed is not None else 1,
        )

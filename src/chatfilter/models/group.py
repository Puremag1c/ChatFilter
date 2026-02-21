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
    FAILED = "failed"


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


class AnalysisMode(str, Enum):
    """Re-analysis mode for group analysis."""

    FRESH = "fresh"  # Default: clear results + full analysis
    INCREMENT = "increment"  # Skip clear, only fetch missing metrics
    OVERWRITE = "overwrite"  # Clear results + reset all chats + full analysis


class GroupSettings(BaseModel):
    """Settings for group analysis.

    Attributes:
        detect_chat_type: Whether to detect chat type (group/channel/forum).
        detect_subscribers: Whether to detect subscriber count.
        detect_activity: Whether to detect message activity metrics.
        detect_unique_authors: Whether to detect unique author count.
        detect_moderation: Whether to detect moderation settings.
        detect_captcha: Whether to detect captcha presence.
        time_window: Time window in hours for activity analysis (1/6/24/48).

    Example:
        >>> settings = GroupSettings()
        >>> settings.detect_chat_type
        True
        >>> settings.time_window
        24
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    detect_chat_type: bool = True
    detect_subscribers: bool = True
    detect_activity: bool = True
    detect_unique_authors: bool = True
    detect_moderation: bool = True
    detect_captcha: bool = True
    time_window: int = 24

    @field_validator("time_window")
    @classmethod
    def time_window_must_be_valid(cls, v: int) -> int:
        """Validate that time_window is one of allowed values."""
        if v not in (1, 6, 24, 48):
            raise ValueError("time_window must be one of: 1, 6, 24, 48")
        return v

    def needs_join(self) -> bool:
        """Check if analysis requires joining the chat.

        Returns:
            True if any metric requires joining the chat.
        """
        return self.detect_activity or self.detect_unique_authors or self.detect_captcha

    @classmethod
    def from_dict(cls, data: dict) -> GroupSettings:
        """Create GroupSettings from dict, handling legacy format.

        Migrates old settings format (message_limit, leave_after_analysis) to new format.
        Old fields are ignored, defaults are used for new fields.

        Args:
            data: Settings dictionary (may contain old or new format).

        Returns:
            GroupSettings instance with migrated data.

        Example:
            >>> # New format works as-is
            >>> settings = GroupSettings.from_dict({"detect_chat_type": False})
            >>> settings.detect_chat_type
            False
            >>> # Old format gets default values
            >>> old_settings = GroupSettings.from_dict({"message_limit": 100})
            >>> old_settings.detect_chat_type
            True
        """
        # Define known new field names
        new_fields = {
            "detect_chat_type",
            "detect_subscribers",
            "detect_activity",
            "detect_unique_authors",
            "detect_moderation",
            "detect_captcha",
            "time_window",
        }

        # Filter data to only include known new fields
        filtered_data = {k: v for k, v in data.items() if k in new_fields}

        # Create GroupSettings with filtered data (missing fields use defaults)
        return cls(**filtered_data)

    @classmethod
    def fake(
        cls,
        detect_chat_type: bool = True,
        detect_subscribers: bool = True,
        detect_activity: bool = True,
        detect_unique_authors: bool = True,
        detect_moderation: bool = True,
        detect_captcha: bool = True,
        time_window: int = 24,
    ) -> GroupSettings:
        """Create fake GroupSettings for testing.

        Args:
            detect_chat_type: Whether to detect chat type (default: True).
            detect_subscribers: Whether to detect subscribers (default: True).
            detect_activity: Whether to detect activity (default: True).
            detect_unique_authors: Whether to detect unique authors (default: True).
            detect_moderation: Whether to detect moderation (default: True).
            detect_captcha: Whether to detect captcha (default: True).
            time_window: Time window in hours (default: 24).

        Returns:
            GroupSettings instance with test data.
        """
        return cls(
            detect_chat_type=detect_chat_type,
            detect_subscribers=detect_subscribers,
            detect_activity=detect_activity,
            detect_unique_authors=detect_unique_authors,
            detect_moderation=detect_moderation,
            detect_captcha=detect_captcha,
            time_window=time_window,
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
        pending: Chats with type PENDING (not yet classified).
        dead: Dead/inaccessible chats.
        groups: Regular group chats.
        forums: Forum chats.
        channels_with_comments: Channels with comments enabled.
        channels_no_comments: Channels without comments.
        analyzed: Successfully analyzed chats (status DONE).
        failed: Failed chat processing (status FAILED).
        skipped_moderation: Chats skipped due to join approval required.
        status_pending: Chats with status PENDING (not started).
        status_joining: Chats with status JOINING (join in progress).
        status_analyzing: Chats with status ANALYZING (analysis in progress).

    Note:
        - `pending` refers to ChatTypeEnum.PENDING (type classification)
        - `status_pending` refers to GroupChatStatus.PENDING (processing status)
        These are different concepts.

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
        ...     status_pending=5,
        ...     status_joining=0,
        ...     status_analyzing=1,
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
    skipped_moderation: int = 0
    status_pending: int = 0
    status_joining: int = 0
    status_analyzing: int = 0

    @field_validator("total", "pending", "dead", "groups", "forums",
                     "channels_with_comments", "channels_no_comments",
                     "analyzed", "failed", "skipped_moderation",
                     "status_pending", "status_joining", "status_analyzing")
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
            skipped_moderation=0,
            status_pending=0,
            status_joining=0,
            status_analyzing=0,
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
        skipped_moderation: int | None = None,
        status_pending: int | None = None,
        status_joining: int | None = None,
        status_analyzing: int | None = None,
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
            skipped_moderation: Skipped moderation count (default: 0).
            status_pending: Status pending count (default: 0).
            status_joining: Status joining count (default: 0).
            status_analyzing: Status analyzing count (default: 0).

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
            skipped_moderation=skipped_moderation if skipped_moderation is not None else 0,
            status_pending=status_pending if status_pending is not None else 0,
            status_joining=status_joining if status_joining is not None else 0,
            status_analyzing=status_analyzing if status_analyzing is not None else 0,
        )

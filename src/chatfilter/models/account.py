"""Account information model for Telegram subscription tracking."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, computed_field, field_validator

# Telegram subscription limits
STANDARD_CHAT_LIMIT = 500
PREMIUM_CHAT_LIMIT = 1000

# Warning thresholds (percentage of limit)
WARNING_THRESHOLD = 0.90  # 90% - warn user
CRITICAL_THRESHOLD = 0.98  # 98% - critical warning


class AccountInfo(BaseModel):
    """Telegram account information with subscription limits tracking.

    Attributes:
        user_id: User's Telegram ID.
        username: User's username (without @).
        first_name: User's first name.
        last_name: User's last name (optional).
        is_premium: Whether user has Telegram Premium subscription.
        chat_count: Current number of chats/channels subscribed to.

    Example:
        >>> info = AccountInfo(
        ...     user_id=123456,
        ...     username="testuser",
        ...     first_name="Test",
        ...     is_premium=False,
        ...     chat_count=450
        ... )
        >>> info.chat_limit
        500
        >>> info.remaining_slots
        50
        >>> info.is_near_limit
        True
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    user_id: int
    username: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    is_premium: bool = False
    chat_count: int = 0

    @field_validator("user_id")
    @classmethod
    def user_id_must_be_positive(cls, v: int) -> int:
        """Validate that user ID is positive."""
        if v <= 0:
            raise ValueError("user_id must be positive")
        return v

    @field_validator("chat_count")
    @classmethod
    def chat_count_must_be_non_negative(cls, v: int) -> int:
        """Validate that chat count is non-negative."""
        if v < 0:
            raise ValueError("chat_count cannot be negative")
        return v

    @computed_field  # type: ignore[prop-decorator]
    @property
    def chat_limit(self) -> int:
        """Get the chat subscription limit based on Premium status.

        Returns:
            500 for standard accounts, 1000 for Premium accounts.
        """
        return PREMIUM_CHAT_LIMIT if self.is_premium else STANDARD_CHAT_LIMIT

    @computed_field  # type: ignore[prop-decorator]
    @property
    def remaining_slots(self) -> int:
        """Get the number of remaining chat slots.

        Returns:
            Number of chats that can still be joined.
        """
        return max(0, self.chat_limit - self.chat_count)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_at_limit(self) -> bool:
        """Check if account is at the subscription limit.

        Returns:
            True if no more chats can be joined.
        """
        return self.chat_count >= self.chat_limit

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_near_limit(self) -> bool:
        """Check if account is approaching the subscription limit.

        Returns:
            True if at or above 90% of limit (warning threshold).
        """
        return self.chat_count >= int(self.chat_limit * WARNING_THRESHOLD)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_critical(self) -> bool:
        """Check if account is at critical subscription level.

        Returns:
            True if at or above 98% of limit (critical threshold).
        """
        return self.chat_count >= int(self.chat_limit * CRITICAL_THRESHOLD)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def usage_percent(self) -> float:
        """Get subscription usage as a percentage.

        Returns:
            Usage percentage (0-100+, can exceed 100 if over limit).
        """
        return (self.chat_count / self.chat_limit) * 100

    @computed_field  # type: ignore[prop-decorator]
    @property
    def display_name(self) -> str:
        """Get a display name for the account.

        Returns:
            Username with @ if available, otherwise first name, otherwise user ID.
        """
        if self.username:
            return f"@{self.username}"
        if self.first_name:
            return self.first_name
        return str(self.user_id)

    def can_join_chats(self, count: int = 1) -> bool:
        """Check if the account can join a specific number of chats.

        Args:
            count: Number of chats to join (default: 1).

        Returns:
            True if there are enough remaining slots.
        """
        return self.remaining_slots >= count

    @classmethod
    def fake(
        cls,
        user_id: int | None = None,
        username: str | None = None,
        first_name: str | None = None,
        last_name: str | None = None,
        is_premium: bool = False,
        chat_count: int = 100,
    ) -> AccountInfo:
        """Create a fake AccountInfo for testing.

        Args:
            user_id: User ID (default: random positive int).
            username: Username.
            first_name: First name.
            last_name: Last name.
            is_premium: Premium status.
            chat_count: Current chat count.

        Returns:
            AccountInfo instance with test data.
        """
        import random

        return cls(
            user_id=user_id if user_id is not None else random.randint(1, 1_000_000),
            username=username,
            first_name=first_name or "Test",
            last_name=last_name,
            is_premium=is_premium,
            chat_count=chat_count,
        )

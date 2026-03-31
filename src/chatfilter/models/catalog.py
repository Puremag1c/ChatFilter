"""Catalog models for chat discovery and subscription tracking."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from .group import ChatTypeEnum, GroupSettings


class AnalysisModeEnum(StrEnum):
    """Analysis mode for catalog chats.

    quick: detect_chat_type + detect_subscribers + detect_moderation (no join needed)
    deep: all of quick + detect_activity + detect_unique_authors + detect_captcha
    """

    QUICK = "quick"
    DEEP = "deep"

    def to_group_settings(self) -> GroupSettings:
        """Convert analysis mode to GroupSettings for backward compatibility with worker.

        Returns:
            GroupSettings configured for this analysis mode.
        """
        if self == AnalysisModeEnum.QUICK:
            return GroupSettings(
                detect_chat_type=True,
                detect_subscribers=True,
                detect_moderation=True,
                detect_activity=False,
                detect_unique_authors=False,
                detect_captcha=False,
                time_window=24,
            )
        # DEEP: all features enabled
        return GroupSettings(
            detect_chat_type=True,
            detect_subscribers=True,
            detect_moderation=True,
            detect_activity=True,
            detect_unique_authors=True,
            detect_captcha=True,
            time_window=24,
        )


class CatalogChat(BaseModel):
    """A Telegram chat stored in the public catalog.

    Attributes:
        id: Internal catalog identifier (chat_ref string).
        telegram_id: Telegram chat ID.
        title: Display title of the chat.
        chat_type: Classified chat type.
        subscribers: Subscriber/member count.
        moderation: Whether the chat has moderation enabled.
        messages_per_hour: Average messages per hour (EMA).
        unique_authors_per_hour: Average unique authors per hour (EMA).
        captcha: Whether the chat has captcha enabled.
        partial_data: True if analysis was partial (e.g. quick mode).
        last_check: Timestamp of last analysis.
        analysis_mode: Mode used for last analysis.
        created_at: When the chat was first added to catalog.
    """

    model_config = ConfigDict(
        strict=False,
        frozen=False,
    )

    id: str
    telegram_id: int
    title: str
    chat_type: ChatTypeEnum = ChatTypeEnum.PENDING
    subscribers: int = 0
    moderation: bool = False
    messages_per_hour: float = 0.0
    unique_authors_per_hour: float = 0.0
    captcha: bool = False
    partial_data: bool = False
    last_check: datetime | None = None
    analysis_mode: AnalysisModeEnum = AnalysisModeEnum.QUICK
    created_at: datetime | None = None

    def is_fresh(self, freshness_days: int) -> bool:
        """Check if the catalog data is still fresh.

        Args:
            freshness_days: Number of days within which data is considered fresh.

        Returns:
            True if last_check is within freshness_days from now.
        """
        if self.last_check is None:
            return False
        cutoff = datetime.now(UTC) - timedelta(days=freshness_days)
        last = self.last_check
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        return last >= cutoff


class AccountSubscription(BaseModel):
    """Subscription linking an account to a catalog chat.

    Attributes:
        account_id: Internal account identifier.
        catalog_chat_id: Internal catalog chat identifier (chat_ref).
        telegram_chat_id: Telegram chat ID for the actual subscription.
        joined_at: When the subscription was created.
    """

    model_config = ConfigDict(
        strict=False,
        frozen=False,
    )

    account_id: int
    catalog_chat_id: str
    telegram_chat_id: int
    joined_at: datetime | None = None

"""Monitoring models for incremental/continuous chat analysis."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, computed_field


class ChatMonitorState(BaseModel):
    """Persistent state for a monitored chat.

    Tracks the last sync point and accumulated metrics to enable
    incremental updates without re-fetching all messages.

    Attributes:
        session_id: Telegram session identifier.
        chat_id: Telegram chat ID.
        last_message_id: ID of the most recent message seen.
        last_message_at: Timestamp of the most recent message.
        last_sync_at: When the last sync was performed.
        is_enabled: Whether continuous monitoring is enabled.
        message_count: Total messages seen across all syncs.
        unique_author_ids: Set of unique author IDs (stored as list for JSON).
        first_message_at: Timestamp of the first message ever seen.
        created_at: When monitoring was first enabled.
    """

    model_config = ConfigDict(
        strict=True,
        frozen=False,  # Mutable to allow incremental updates
        extra="forbid",
    )

    session_id: str
    chat_id: int
    last_message_id: int | None = None
    last_message_at: datetime | None = None
    last_sync_at: datetime | None = None
    is_enabled: bool = True
    message_count: int = 0
    unique_author_ids: list[int] = Field(default_factory=list)
    first_message_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @computed_field  # type: ignore[prop-decorator]
    @property
    def unique_authors(self) -> int:
        """Number of unique message authors."""
        return len(self.unique_author_ids)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def history_hours(self) -> float:
        """Time span from first to last message in hours."""
        if self.first_message_at is None or self.last_message_at is None:
            return 0.0
        delta = self.last_message_at - self.first_message_at
        return delta.total_seconds() / 3600.0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def messages_per_hour(self) -> float:
        """Average message rate across entire history."""
        if self.message_count == 0 or self.history_hours == 0:
            return 0.0
        return self.message_count / self.history_hours


class SyncSnapshot(BaseModel):
    """Snapshot of metrics at a point in time for trend tracking.

    Each sync creates a snapshot to track growth over time.

    Attributes:
        chat_id: Telegram chat ID.
        sync_at: When this snapshot was taken.
        message_count: Total messages at this point.
        unique_authors: Unique authors at this point.
        new_messages: Messages added in this sync.
        new_authors: New authors discovered in this sync.
        sync_duration_seconds: How long the sync took.
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    chat_id: int
    sync_at: datetime
    message_count: int
    unique_authors: int
    new_messages: int = 0
    new_authors: int = 0
    sync_duration_seconds: float | None = None


class MonitoringSummary(BaseModel):
    """Summary of monitoring state for a chat.

    Used for API responses to display monitoring status.
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    session_id: str
    chat_id: int
    chat_title: str | None = None
    is_enabled: bool
    last_sync_at: datetime | None
    message_count: int
    unique_authors: int
    messages_per_hour: float
    history_hours: float
    sync_count: int = 0


class GrowthMetrics(BaseModel):
    """Growth metrics over a time period.

    Computed from sync snapshots to show trends.

    Attributes:
        chat_id: Telegram chat ID.
        period_start: Start of the analysis period.
        period_end: End of the analysis period.
        period_hours: Duration of the period in hours.
        total_new_messages: Messages added during period.
        total_new_authors: New authors during period.
        messages_per_hour: Message rate during period.
        author_growth_rate: New authors per hour.
        snapshots: Individual sync snapshots in the period.
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
    )

    chat_id: int
    period_start: datetime
    period_end: datetime
    period_hours: float
    total_new_messages: int
    total_new_authors: int
    messages_per_hour: float
    author_growth_rate: float
    snapshots: list[SyncSnapshot] = Field(default_factory=list)

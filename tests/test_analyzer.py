"""Tests for chat analyzer module."""

from datetime import UTC, datetime, timedelta

import pytest

from chatfilter.analyzer import compute_metrics
from chatfilter.models import ChatMetrics, Message


class TestComputeMetrics:
    """Tests for compute_metrics function."""

    def test_empty_messages(self) -> None:
        """Test that empty message list returns empty metrics."""
        result = compute_metrics([])

        assert result.message_count == 0
        assert result.unique_authors == 0
        assert result.history_hours == 0.0
        assert result.first_message_at is None
        assert result.last_message_at is None

    def test_single_message(self) -> None:
        """Test metrics for a single message."""
        timestamp = datetime.now(UTC) - timedelta(hours=1)
        msg = Message.fake(author_id=123, timestamp=timestamp)

        result = compute_metrics([msg])

        assert result.message_count == 1
        assert result.unique_authors == 1
        assert result.history_hours == 0.0  # No time span with single message
        assert result.first_message_at == timestamp
        assert result.last_message_at == timestamp

    def test_multiple_messages_same_author(self) -> None:
        """Test that same author is counted once."""
        now = datetime.now(UTC)
        messages = [
            Message.fake(id=1, author_id=100, timestamp=now - timedelta(hours=2)),
            Message.fake(id=2, author_id=100, timestamp=now - timedelta(hours=1)),
            Message.fake(id=3, author_id=100, timestamp=now),
        ]

        result = compute_metrics(messages)

        assert result.message_count == 3
        assert result.unique_authors == 1  # Same author

    def test_multiple_unique_authors(self) -> None:
        """Test counting of unique authors."""
        now = datetime.now(UTC)
        messages = [
            Message.fake(id=1, author_id=100, timestamp=now - timedelta(hours=3)),
            Message.fake(id=2, author_id=200, timestamp=now - timedelta(hours=2)),
            Message.fake(id=3, author_id=300, timestamp=now - timedelta(hours=1)),
            Message.fake(id=4, author_id=100, timestamp=now),  # Duplicate author
        ]

        result = compute_metrics(messages)

        assert result.message_count == 4
        assert result.unique_authors == 3  # 100, 200, 300

    def test_history_hours_calculation(self) -> None:
        """Test that history hours is calculated correctly."""
        now = datetime.now(UTC)
        first = now - timedelta(hours=24)
        last = now

        messages = [
            Message.fake(id=1, timestamp=first),
            Message.fake(id=2, timestamp=now - timedelta(hours=12)),
            Message.fake(id=3, timestamp=last),
        ]

        result = compute_metrics(messages)

        assert result.history_hours == pytest.approx(24.0, rel=0.01)
        assert result.first_message_at == first
        assert result.last_message_at == last

    def test_unsorted_messages(self) -> None:
        """Test that unsorted messages are handled correctly."""
        now = datetime.now(UTC)
        oldest = now - timedelta(hours=10)
        middle = now - timedelta(hours=5)
        newest = now

        # Messages in random order
        messages = [
            Message.fake(id=2, timestamp=middle),
            Message.fake(id=3, timestamp=newest),
            Message.fake(id=1, timestamp=oldest),
        ]

        result = compute_metrics(messages)

        assert result.first_message_at == oldest
        assert result.last_message_at == newest
        assert result.history_hours == pytest.approx(10.0, rel=0.01)

    def test_fractional_hours(self) -> None:
        """Test that fractional hours are calculated correctly."""
        now = datetime.now(UTC)
        # 90 minutes = 1.5 hours
        first = now - timedelta(minutes=90)

        messages = [
            Message.fake(id=1, timestamp=first),
            Message.fake(id=2, timestamp=now),
        ]

        result = compute_metrics(messages)

        assert result.history_hours == pytest.approx(1.5, rel=0.01)

    def test_preserves_timezone_info(self) -> None:
        """Test that timestamp timezone info is preserved."""
        timestamp = datetime(2024, 6, 15, 12, 0, 0, tzinfo=UTC)
        msg = Message.fake(timestamp=timestamp)

        result = compute_metrics([msg])

        assert result.first_message_at is not None
        assert result.first_message_at.tzinfo is not None
        assert result.last_message_at is not None
        assert result.last_message_at.tzinfo is not None


class TestMessagesPerHour:
    """Tests for messages_per_hour computed property."""

    def test_empty_metrics_returns_zero(self) -> None:
        """Test that empty metrics returns 0 messages per hour."""
        metrics = ChatMetrics.empty()

        assert metrics.messages_per_hour == 0.0

    def test_single_message_returns_zero(self) -> None:
        """Test that single message (history_hours=0) returns 0."""
        now = datetime.now(UTC)
        metrics = ChatMetrics(
            message_count=1,
            unique_authors=1,
            history_hours=0.0,
            first_message_at=now,
            last_message_at=now,
        )

        assert metrics.messages_per_hour == 0.0

    def test_normal_calculation(self) -> None:
        """Test normal messages per hour calculation."""
        now = datetime.now(UTC)
        # 100 messages over 10 hours = 10 messages/hour
        metrics = ChatMetrics(
            message_count=100,
            unique_authors=5,
            history_hours=10.0,
            first_message_at=now - timedelta(hours=10),
            last_message_at=now,
        )

        assert metrics.messages_per_hour == pytest.approx(10.0, rel=0.01)

    def test_fractional_rate(self) -> None:
        """Test fractional messages per hour."""
        now = datetime.now(UTC)
        # 30 messages over 24 hours = 1.25 messages/hour
        metrics = ChatMetrics(
            message_count=30,
            unique_authors=3,
            history_hours=24.0,
            first_message_at=now - timedelta(hours=24),
            last_message_at=now,
        )

        assert metrics.messages_per_hour == pytest.approx(1.25, rel=0.01)

    def test_high_activity(self) -> None:
        """Test high activity chat."""
        now = datetime.now(UTC)
        # 1000 messages over 2 hours = 500 messages/hour
        metrics = ChatMetrics(
            message_count=1000,
            unique_authors=50,
            history_hours=2.0,
            first_message_at=now - timedelta(hours=2),
            last_message_at=now,
        )

        assert metrics.messages_per_hour == pytest.approx(500.0, rel=0.01)

    def test_via_compute_metrics(self) -> None:
        """Test that compute_metrics result has correct messages_per_hour."""
        now = datetime.now(UTC)
        # 6 messages over 2 hours = 3 messages/hour
        messages = [
            Message.fake(id=i, timestamp=now - timedelta(hours=2 - i * 0.4))
            for i in range(6)
        ]

        result = compute_metrics(messages)

        # 6 messages, ~2 hours span
        expected_rate = result.message_count / result.history_hours
        assert result.messages_per_hour == pytest.approx(expected_rate, rel=0.01)

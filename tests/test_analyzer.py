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


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_messages_with_identical_timestamps(self) -> None:
        """Test that messages with identical timestamps are handled correctly."""
        now = datetime.now(UTC)
        # All messages at the exact same timestamp
        messages = [
            Message.fake(id=i, author_id=100 + i, timestamp=now)
            for i in range(5)
        ]

        result = compute_metrics(messages)

        assert result.message_count == 5
        assert result.unique_authors == 5
        assert result.history_hours == 0.0  # No time span
        assert result.first_message_at == now
        assert result.last_message_at == now
        assert result.messages_per_hour == 0.0

    def test_large_message_count(self) -> None:
        """Test with very large number of messages."""
        now = datetime.now(UTC)
        # Create 10,000 messages over 100 hours
        messages = [
            Message.fake(
                id=i,
                author_id=(i % 500) + 1,  # 500 unique authors
                timestamp=now - timedelta(hours=100 - i * 0.01),
            )
            for i in range(10000)
        ]

        result = compute_metrics(messages)

        assert result.message_count == 10000
        assert result.unique_authors == 500
        assert result.history_hours == pytest.approx(100.0, rel=0.01)
        assert result.messages_per_hour == pytest.approx(100.0, rel=0.01)

    def test_microsecond_precision(self) -> None:
        """Test that microsecond precision is handled correctly."""
        base = datetime(2024, 6, 15, 12, 0, 0, 0, tzinfo=UTC)
        # Messages 500 microseconds apart
        messages = [
            Message.fake(id=1, timestamp=base),
            Message.fake(id=2, timestamp=base.replace(microsecond=500)),
        ]

        result = compute_metrics(messages)

        # 500 microseconds = 0.0005 seconds = 0.0005/3600 hours
        expected_hours = 0.0005 / 3600.0
        assert result.history_hours == pytest.approx(expected_hours, rel=0.01)
        assert result.first_message_at == base
        assert result.last_message_at == base.replace(microsecond=500)

    def test_very_long_time_span(self) -> None:
        """Test with messages spanning multiple years."""
        old = datetime(2020, 1, 1, 0, 0, 0, tzinfo=UTC)
        recent = datetime(2024, 1, 1, 0, 0, 0, tzinfo=UTC)

        messages = [
            Message.fake(id=1, timestamp=old),
            Message.fake(id=2, timestamp=recent),
        ]

        result = compute_metrics(messages)

        # 4 years = ~35,064 hours (4 * 365.25 * 24)
        expected_hours = (recent - old).total_seconds() / 3600.0
        assert result.history_hours == pytest.approx(expected_hours, rel=0.001)
        assert result.first_message_at == old
        assert result.last_message_at == recent

    def test_all_messages_same_author_different_times(self) -> None:
        """Test multiple messages from single author over time."""
        now = datetime.now(UTC)
        # 100 messages from one author over 24 hours
        # First message at -24h, last at now
        messages = [
            Message.fake(
                id=i,
                author_id=42,
                timestamp=now - timedelta(hours=24) + timedelta(hours=i * 24.0 / 99),
            )
            for i in range(100)
        ]

        result = compute_metrics(messages)

        assert result.message_count == 100
        assert result.unique_authors == 1
        assert result.history_hours == pytest.approx(24.0, rel=0.01)
        assert result.messages_per_hour == pytest.approx(100.0 / 24.0, rel=0.01)

    def test_extreme_author_diversity(self) -> None:
        """Test when every message is from a unique author."""
        now = datetime.now(UTC)
        # 50 messages, each from a different author, spanning 50 minutes
        # First message at -50min, last at now
        messages = [
            Message.fake(
                id=i,
                author_id=1000 + i,
                timestamp=now - timedelta(minutes=50) + timedelta(minutes=i * 50.0 / 49),
            )
            for i in range(50)
        ]

        result = compute_metrics(messages)

        assert result.message_count == 50
        assert result.unique_authors == 50  # All unique
        assert result.history_hours == pytest.approx(50.0 / 60.0, rel=0.01)

    def test_two_authors_alternating(self) -> None:
        """Test with exactly two authors sending alternating messages."""
        now = datetime.now(UTC)
        # 10 messages spanning 10 hours
        # First message at -10h, last at now
        messages = [
            Message.fake(
                id=i,
                author_id=100 if i % 2 == 0 else 200,
                timestamp=now - timedelta(hours=10) + timedelta(hours=i * 10.0 / 9),
            )
            for i in range(10)
        ]

        result = compute_metrics(messages)

        assert result.message_count == 10
        assert result.unique_authors == 2
        assert result.history_hours == pytest.approx(10.0, rel=0.01)

    def test_messages_in_reverse_chronological_order(self) -> None:
        """Test messages sorted newest to oldest."""
        now = datetime.now(UTC)
        # Messages in reverse order (newest first)
        messages = [
            Message.fake(id=1, timestamp=now),
            Message.fake(id=2, timestamp=now - timedelta(hours=5)),
            Message.fake(id=3, timestamp=now - timedelta(hours=10)),
        ]

        result = compute_metrics(messages)

        assert result.first_message_at == now - timedelta(hours=10)
        assert result.last_message_at == now
        assert result.history_hours == pytest.approx(10.0, rel=0.01)

    def test_single_author_with_zero_time_span(self) -> None:
        """Test multiple messages from one author at exact same time."""
        now = datetime.now(UTC)
        messages = [
            Message.fake(id=i, author_id=42, timestamp=now)
            for i in range(10)
        ]

        result = compute_metrics(messages)

        assert result.message_count == 10
        assert result.unique_authors == 1
        assert result.history_hours == 0.0
        assert result.messages_per_hour == 0.0

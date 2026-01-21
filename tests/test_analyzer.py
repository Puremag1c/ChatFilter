"""Tests for chat analyzer module."""

from datetime import UTC, datetime, timedelta

import pytest

from chatfilter.analyzer import compute_metrics
from chatfilter.analyzer.metrics import StreamingMetricsAggregator
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

    def test_anonymous_authors_counted_as_chat(self) -> None:
        """Test that anonymous authors (sender=None) are counted as the chat itself.

        In Telegram channels and groups with anonymous admins, sender_id can be None.
        The current implementation assigns chat_id as the author_id for these messages,
        meaning all anonymous messages in a chat are counted as ONE author (the chat).

        This is a deliberate design decision:
        - Pros: Simple, consistent, prevents zero unique_authors in anonymous-only chats
        - Cons: May undercount if multiple people post anonymously

        Alternative approaches considered:
        - Skip anonymous messages: Would lose message count data
        - Count each as unique: Would overcount if same person posts multiple times
        """
        now = datetime.now(UTC)
        chat_id = 999

        # Simulate channel where all messages use chat_id as author_id (anonymous)
        messages = [
            Message.fake(
                id=1, chat_id=chat_id, author_id=chat_id, timestamp=now - timedelta(hours=3)
            ),
            Message.fake(
                id=2, chat_id=chat_id, author_id=chat_id, timestamp=now - timedelta(hours=2)
            ),
            Message.fake(
                id=3, chat_id=chat_id, author_id=chat_id, timestamp=now - timedelta(hours=1)
            ),
        ]

        result = compute_metrics(messages)

        assert result.message_count == 3
        assert result.unique_authors == 1  # All anonymous messages counted as one author

    def test_mixed_anonymous_and_regular_authors(self) -> None:
        """Test unique author counting with mix of anonymous and regular authors."""
        now = datetime.now(UTC)
        chat_id = 999

        messages = [
            # Anonymous messages (use chat_id as author)
            Message.fake(
                id=1, chat_id=chat_id, author_id=chat_id, timestamp=now - timedelta(hours=5)
            ),
            Message.fake(
                id=2, chat_id=chat_id, author_id=chat_id, timestamp=now - timedelta(hours=4)
            ),
            # Regular users
            Message.fake(id=3, chat_id=chat_id, author_id=100, timestamp=now - timedelta(hours=3)),
            Message.fake(id=4, chat_id=chat_id, author_id=200, timestamp=now - timedelta(hours=2)),
            Message.fake(
                id=5, chat_id=chat_id, author_id=100, timestamp=now - timedelta(hours=1)
            ),  # Duplicate
        ]

        result = compute_metrics(messages)

        assert result.message_count == 5
        assert result.unique_authors == 3  # chat_id (anonymous), 100, 200

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
            Message.fake(id=i, timestamp=now - timedelta(hours=2 - i * 0.4)) for i in range(6)
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
        messages = [Message.fake(id=i, author_id=100 + i, timestamp=now) for i in range(5)]

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
        messages = [Message.fake(id=i, author_id=42, timestamp=now) for i in range(10)]

        result = compute_metrics(messages)

        assert result.message_count == 10
        assert result.unique_authors == 1
        assert result.history_hours == 0.0
        assert result.messages_per_hour == 0.0


class TestMessageGapDetection:
    """Tests for deleted message gap detection."""

    def test_no_gaps_sequential_ids(self) -> None:
        """Test that sequential message IDs result in no gaps detected."""
        now = datetime.now(UTC)
        messages = [
            Message.fake(id=1, timestamp=now - timedelta(hours=2)),
            Message.fake(id=2, timestamp=now - timedelta(hours=1)),
            Message.fake(id=3, timestamp=now),
        ]

        result = compute_metrics(messages)

        assert result.has_message_gaps is False

    def test_gaps_detected_with_missing_ids(self) -> None:
        """Test that gaps in message IDs are detected (deleted messages)."""
        now = datetime.now(UTC)
        # Messages with IDs 1, 5, 10 - missing 2,3,4,6,7,8,9
        messages = [
            Message.fake(id=1, timestamp=now - timedelta(hours=2)),
            Message.fake(id=5, timestamp=now - timedelta(hours=1)),
            Message.fake(id=10, timestamp=now),
        ]

        result = compute_metrics(messages)

        assert result.has_message_gaps is True
        # ID range is 10-1+1 = 10, but we only have 3 messages
        assert result.message_count == 3

    def test_single_message_has_no_gaps(self) -> None:
        """Test that a single message cannot have gaps."""
        now = datetime.now(UTC)
        messages = [Message.fake(id=42, timestamp=now)]

        result = compute_metrics(messages)

        assert result.has_message_gaps is False

    def test_empty_messages_has_no_gaps(self) -> None:
        """Test that empty message list has no gaps."""
        result = compute_metrics([])

        assert result.has_message_gaps is False

    def test_gaps_affect_history_hours_note(self) -> None:
        """Test that gaps are noted even when history_hours seems accurate.

        This is important because if the first or last message was deleted,
        the history_hours calculation would be based on remaining messages
        and would underestimate the true span.
        """
        now = datetime.now(UTC)
        # IDs 100, 101, 105 - suggests messages before 100 and between 101-105 were deleted
        messages = [
            Message.fake(id=100, timestamp=now - timedelta(hours=2)),
            Message.fake(id=101, timestamp=now - timedelta(hours=1)),
            Message.fake(id=105, timestamp=now),
        ]

        result = compute_metrics(messages)

        assert result.has_message_gaps is True
        # history_hours is calculated from timestamps we have
        assert result.history_hours == pytest.approx(2.0, rel=0.01)
        # But the gap flag warns users that the true history might be longer


class TestStreamingMetricsAggregator:
    """Tests for StreamingMetricsAggregator class."""

    def test_empty_aggregator_returns_empty_metrics(self) -> None:
        """Test that empty aggregator returns empty metrics."""
        aggregator = StreamingMetricsAggregator()
        result = aggregator.get_metrics()

        assert result.message_count == 0
        assert result.unique_authors == 0
        assert result.history_hours == 0.0
        assert result.first_message_at is None
        assert result.last_message_at is None

    def test_add_single_batch(self) -> None:
        """Test adding a single batch of messages."""
        aggregator = StreamingMetricsAggregator()
        now = datetime.now(UTC)
        batch = [
            Message.fake(id=1, author_id=100, timestamp=now - timedelta(hours=2)),
            Message.fake(id=2, author_id=200, timestamp=now - timedelta(hours=1)),
            Message.fake(id=3, author_id=100, timestamp=now),
        ]

        aggregator.add_batch(batch)
        result = aggregator.get_metrics()

        assert result.message_count == 3
        assert result.unique_authors == 2  # 100 and 200
        assert result.history_hours == pytest.approx(2.0, rel=0.01)

    def test_add_multiple_batches(self) -> None:
        """Test adding multiple batches incrementally."""
        aggregator = StreamingMetricsAggregator()
        now = datetime.now(UTC)

        # First batch
        batch1 = [
            Message.fake(id=1, author_id=100, timestamp=now - timedelta(hours=5)),
            Message.fake(id=2, author_id=200, timestamp=now - timedelta(hours=4)),
        ]
        aggregator.add_batch(batch1)

        # Second batch
        batch2 = [
            Message.fake(id=3, author_id=300, timestamp=now - timedelta(hours=3)),
            Message.fake(
                id=4, author_id=100, timestamp=now - timedelta(hours=2)
            ),  # Duplicate author
        ]
        aggregator.add_batch(batch2)

        # Third batch
        batch3 = [
            Message.fake(id=5, author_id=400, timestamp=now - timedelta(hours=1)),
            Message.fake(id=6, author_id=200, timestamp=now),  # Duplicate author
        ]
        aggregator.add_batch(batch3)

        result = aggregator.get_metrics()

        assert result.message_count == 6
        assert result.unique_authors == 4  # 100, 200, 300, 400
        assert result.history_hours == pytest.approx(5.0, rel=0.01)
        assert result.first_message_at == now - timedelta(hours=5)
        assert result.last_message_at == now

    def test_add_single_message(self) -> None:
        """Test adding messages one at a time."""
        aggregator = StreamingMetricsAggregator()
        now = datetime.now(UTC)

        aggregator.add_message(
            Message.fake(id=1, author_id=100, timestamp=now - timedelta(hours=1))
        )
        aggregator.add_message(Message.fake(id=2, author_id=200, timestamp=now))

        result = aggregator.get_metrics()

        assert result.message_count == 2
        assert result.unique_authors == 2
        assert result.history_hours == pytest.approx(1.0, rel=0.01)

    def test_empty_batch_ignored(self) -> None:
        """Test that empty batches don't affect metrics."""
        aggregator = StreamingMetricsAggregator()
        now = datetime.now(UTC)

        batch1 = [Message.fake(id=1, timestamp=now - timedelta(hours=1))]
        aggregator.add_batch(batch1)

        # Add empty batch
        aggregator.add_batch([])

        batch2 = [Message.fake(id=2, timestamp=now)]
        aggregator.add_batch(batch2)

        result = aggregator.get_metrics()

        assert result.message_count == 2
        assert result.history_hours == pytest.approx(1.0, rel=0.01)

    def test_batches_with_out_of_order_timestamps(self) -> None:
        """Test that batches with out-of-order timestamps are handled correctly."""
        aggregator = StreamingMetricsAggregator()
        now = datetime.now(UTC)

        # First batch with newer messages
        batch1 = [
            Message.fake(id=1, timestamp=now - timedelta(hours=2)),
            Message.fake(id=2, timestamp=now),
        ]
        aggregator.add_batch(batch1)

        # Second batch with older messages (out of order)
        batch2 = [
            Message.fake(id=3, timestamp=now - timedelta(hours=10)),
            Message.fake(id=4, timestamp=now - timedelta(hours=5)),
        ]
        aggregator.add_batch(batch2)

        result = aggregator.get_metrics()

        # Should correctly identify the oldest and newest timestamps
        assert result.first_message_at == now - timedelta(hours=10)
        assert result.last_message_at == now
        assert result.history_hours == pytest.approx(10.0, rel=0.01)

    def test_reset_clears_state(self) -> None:
        """Test that reset clears all aggregated state."""
        aggregator = StreamingMetricsAggregator()
        now = datetime.now(UTC)

        # Add some messages
        batch = [
            Message.fake(id=1, author_id=100, timestamp=now - timedelta(hours=1)),
            Message.fake(id=2, author_id=200, timestamp=now),
        ]
        aggregator.add_batch(batch)

        # Verify state is set
        assert aggregator.message_count == 2
        assert aggregator.unique_authors == 2

        # Reset
        aggregator.reset()

        # Verify state is cleared
        assert aggregator.message_count == 0
        assert aggregator.unique_authors == 0
        result = aggregator.get_metrics()
        assert result.message_count == 0

    def test_large_number_of_batches(self) -> None:
        """Test processing many batches (simulating large chat)."""
        aggregator = StreamingMetricsAggregator()
        now = datetime.now(UTC)

        # Simulate 100 batches of 100 messages each = 10,000 messages
        for batch_num in range(100):
            batch = [
                Message.fake(
                    id=batch_num * 100 + i,
                    author_id=(batch_num * 100 + i) % 50 + 1,  # 50 unique authors (1-50)
                    timestamp=now - timedelta(hours=100 - batch_num),
                )
                for i in range(100)
            ]
            aggregator.add_batch(batch)

        result = aggregator.get_metrics()

        assert result.message_count == 10_000
        assert result.unique_authors == 50
        assert result.history_hours == pytest.approx(100.0, rel=0.01)

    def test_matches_compute_metrics_result(self) -> None:
        """Test that streaming aggregator produces same result as compute_metrics."""
        now = datetime.now(UTC)

        # Create test messages
        messages = [
            Message.fake(
                id=i, author_id=(i % 10) + 1, timestamp=now - timedelta(hours=20 - i * 0.5)
            )
            for i in range(40)
        ]

        # Compute with standard function
        standard_result = compute_metrics(messages)

        # Compute with streaming aggregator (split into 4 batches)
        aggregator = StreamingMetricsAggregator()
        for i in range(4):
            batch = messages[i * 10 : (i + 1) * 10]
            aggregator.add_batch(batch)

        streaming_result = aggregator.get_metrics()

        # Results should match
        assert streaming_result.message_count == standard_result.message_count
        assert streaming_result.unique_authors == standard_result.unique_authors
        assert streaming_result.history_hours == pytest.approx(
            standard_result.history_hours, rel=0.001
        )
        assert streaming_result.first_message_at == standard_result.first_message_at
        assert streaming_result.last_message_at == standard_result.last_message_at

    def test_author_set_size_bytes_estimation(self) -> None:
        """Test memory estimation for author ID set."""
        aggregator = StreamingMetricsAggregator()
        now = datetime.now(UTC)

        # Add messages with 100 unique authors
        batch = [Message.fake(id=i, author_id=i + 1, timestamp=now) for i in range(100)]
        aggregator.add_batch(batch)

        # Estimate should be roughly 100 * 32 + 200 = ~3400 bytes
        estimate = aggregator.author_set_size_bytes
        assert estimate > 3000  # At least 3KB
        assert estimate < 5000  # Less than 5KB (conservative upper bound)

    def test_progressive_properties(self) -> None:
        """Test that properties update as batches are added."""
        aggregator = StreamingMetricsAggregator()
        now = datetime.now(UTC)

        # Initially empty
        assert aggregator.message_count == 0
        assert aggregator.unique_authors == 0

        # Add first batch
        batch1 = [Message.fake(id=1, author_id=100, timestamp=now)]
        aggregator.add_batch(batch1)
        assert aggregator.message_count == 1
        assert aggregator.unique_authors == 1

        # Add second batch
        batch2 = [
            Message.fake(
                id=2, author_id=100, timestamp=now - timedelta(minutes=30)
            ),  # Duplicate author
            Message.fake(id=3, author_id=200, timestamp=now),  # New author
        ]
        aggregator.add_batch(batch2)
        assert aggregator.message_count == 3
        assert aggregator.unique_authors == 2

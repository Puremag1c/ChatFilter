"""Tests for analysis result model validation.

Tests validation logic that prevents corrupted data (NaN, negative values,
impossible dates) from being displayed in UI or exported to CSV.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType


class TestChatMetricsValidation:
    """Test ChatMetrics validation rules."""

    def test_valid_metrics(self):
        """Test that valid metrics are accepted."""
        metrics = ChatMetrics(
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            has_message_gaps=False,
        )
        assert metrics.message_count == 100
        assert metrics.unique_authors == 10
        assert metrics.history_hours == 24.5

    def test_negative_message_count(self):
        """Test that negative message_count is rejected."""
        with pytest.raises(ValidationError, match="count cannot be negative"):
            ChatMetrics(
                message_count=-1,
                unique_authors=10,
                history_hours=24.5,
                first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
                last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            )

    def test_negative_unique_authors(self):
        """Test that negative unique_authors is rejected."""
        with pytest.raises(ValidationError, match="count cannot be negative"):
            ChatMetrics(
                message_count=100,
                unique_authors=-1,
                history_hours=24.5,
                first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
                last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            )

    def test_negative_history_hours(self):
        """Test that negative history_hours is rejected."""
        with pytest.raises(ValidationError, match="history_hours cannot be negative"):
            ChatMetrics(
                message_count=100,
                unique_authors=10,
                history_hours=-1.0,
                first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
                last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            )

    def test_nan_history_hours(self):
        """Test that NaN history_hours is rejected."""
        with pytest.raises(ValidationError, match="history_hours cannot be NaN"):
            ChatMetrics(
                message_count=100,
                unique_authors=10,
                history_hours=float("nan"),
                first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
                last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            )

    def test_inf_history_hours(self):
        """Test that infinite history_hours is rejected."""
        with pytest.raises(ValidationError, match="history_hours cannot be infinite"):
            ChatMetrics(
                message_count=100,
                unique_authors=10,
                history_hours=float("inf"),
                first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
                last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            )

    def test_unique_authors_exceeds_message_count(self):
        """Test that unique_authors > message_count is rejected."""
        with pytest.raises(
            ValidationError,
            match="unique_authors.*cannot exceed.*message_count",
        ):
            ChatMetrics(
                message_count=10,
                unique_authors=20,
                history_hours=24.5,
                first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
                last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            )

    def test_messages_without_authors(self):
        """Test that message_count > 0 requires unique_authors > 0."""
        with pytest.raises(
            ValidationError,
            match="message_count > 0 requires at least one unique_author",
        ):
            ChatMetrics(
                message_count=100,
                unique_authors=0,
                history_hours=24.5,
                first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
                last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            )

    def test_inverted_date_range(self):
        """Test that first_message_at > last_message_at is rejected."""
        with pytest.raises(
            ValidationError,
            match="first_message_at cannot be after last_message_at",
        ):
            ChatMetrics(
                message_count=100,
                unique_authors=10,
                history_hours=24.5,
                first_message_at=datetime(2024, 1, 2, tzinfo=UTC),
                last_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            )

    def test_future_first_message(self):
        """Test that first_message_at in the future is rejected."""
        future = datetime.now(UTC) + timedelta(days=1)
        with pytest.raises(
            ValidationError,
            match="first_message_at cannot be in the future",
        ):
            ChatMetrics(
                message_count=100,
                unique_authors=10,
                history_hours=24.5,
                first_message_at=future,
                last_message_at=future + timedelta(hours=1),
            )

    def test_future_last_message(self):
        """Test that last_message_at in the future is rejected."""
        future = datetime.now(UTC) + timedelta(days=1)
        with pytest.raises(
            ValidationError,
            match="last_message_at cannot be in the future",
        ):
            ChatMetrics(
                message_count=100,
                unique_authors=10,
                history_hours=24.5,
                first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
                last_message_at=future,
            )

    def test_empty_chat_valid(self):
        """Test that empty chat metrics (0 messages, 0 authors) are valid."""
        metrics = ChatMetrics(
            message_count=0,
            unique_authors=0,
            history_hours=0.0,
            first_message_at=None,
            last_message_at=None,
        )
        assert metrics.message_count == 0
        assert metrics.unique_authors == 0

    def test_messages_per_hour_computed_correctly(self):
        """Test that messages_per_hour is computed correctly."""
        metrics = ChatMetrics(
            message_count=100,
            unique_authors=10,
            history_hours=10.0,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
        )
        assert metrics.messages_per_hour == 10.0

    def test_messages_per_hour_zero_for_empty(self):
        """Test that messages_per_hour is 0 for empty chats."""
        metrics = ChatMetrics.empty()
        assert metrics.messages_per_hour == 0.0

    def test_messages_per_hour_zero_for_zero_history(self):
        """Test that messages_per_hour is 0 when history_hours is 0."""
        metrics = ChatMetrics(
            message_count=10,
            unique_authors=5,
            history_hours=0.0,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=datetime(2024, 1, 1, tzinfo=UTC),
        )
        assert metrics.messages_per_hour == 0.0


class TestAnalysisResultValidation:
    """Test AnalysisResult validation rules."""

    def test_valid_result(self):
        """Test that valid analysis result is accepted."""
        chat = Chat(id=1, title="Test", chat_type=ChatType.GROUP)
        metrics = ChatMetrics(
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
        )
        result = AnalysisResult(
            chat=chat,
            metrics=metrics,
            analyzed_at=datetime(2024, 1, 2, 1, 0, tzinfo=UTC),
        )
        assert result.chat.title == "Test"
        assert result.metrics.message_count == 100

    def test_analyzed_at_in_future(self):
        """Test that analyzed_at significantly in the future is rejected."""
        chat = Chat(id=1, title="Test", chat_type=ChatType.GROUP)
        metrics = ChatMetrics.empty()
        future = datetime.now(UTC) + timedelta(hours=1)

        with pytest.raises(
            ValidationError,
            match="analyzed_at cannot be in the future",
        ):
            AnalysisResult(
                chat=chat,
                metrics=metrics,
                analyzed_at=future,
            )

    def test_analyzed_at_before_last_message(self):
        """Test that analyzed_at before last_message_at is rejected."""
        chat = Chat(id=1, title="Test", chat_type=ChatType.GROUP)
        last_msg = datetime(2024, 1, 2, tzinfo=UTC)
        metrics = ChatMetrics(
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=last_msg,
        )

        # analyzed_at 1 hour before last message (should fail)
        with pytest.raises(
            ValidationError,
            match="analyzed_at cannot be before last_message_at",
        ):
            AnalysisResult(
                chat=chat,
                metrics=metrics,
                analyzed_at=last_msg - timedelta(hours=1),
            )

    def test_analyzed_at_near_last_message_with_tolerance(self):
        """Test that analyzed_at within tolerance of last_message_at is accepted."""
        chat = Chat(id=1, title="Test", chat_type=ChatType.GROUP)
        last_msg = datetime(2024, 1, 2, 12, 0, tzinfo=UTC)
        metrics = ChatMetrics(
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=last_msg,
        )

        # analyzed_at 2 minutes before last message (within 5 min tolerance - should pass)
        result = AnalysisResult(
            chat=chat,
            metrics=metrics,
            analyzed_at=last_msg - timedelta(minutes=2),
        )
        assert result.metrics.message_count == 100

    def test_is_active_recent_messages(self):
        """Test that is_active is True for recent messages."""
        chat = Chat(id=1, title="Test", chat_type=ChatType.GROUP)
        recent = datetime.now(UTC) - timedelta(days=3)
        metrics = ChatMetrics(
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=recent,
        )
        result = AnalysisResult(
            chat=chat,
            metrics=metrics,
            analyzed_at=datetime.now(UTC),
        )
        assert result.is_active is True

    def test_is_active_old_messages(self):
        """Test that is_active is False for old messages."""
        chat = Chat(id=1, title="Test", chat_type=ChatType.GROUP)
        old = datetime.now(UTC) - timedelta(days=30)
        metrics = ChatMetrics(
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=old,
        )
        result = AnalysisResult(
            chat=chat,
            metrics=metrics,
            analyzed_at=datetime.now(UTC),
        )
        assert result.is_active is False

    def test_is_active_no_messages(self):
        """Test that is_active is False when no messages."""
        chat = Chat(id=1, title="Test", chat_type=ChatType.GROUP)
        metrics = ChatMetrics.empty()
        result = AnalysisResult(
            chat=chat,
            metrics=metrics,
            analyzed_at=datetime.now(UTC),
        )
        assert result.is_active is False


class TestValidationEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_single_message_chat(self):
        """Test that a chat with a single message is valid."""
        metrics = ChatMetrics(
            message_count=1,
            unique_authors=1,
            history_hours=0.0,  # Single message has no history
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=datetime(2024, 1, 1, tzinfo=UTC),
        )
        assert metrics.message_count == 1
        assert metrics.messages_per_hour == 0.0

    def test_very_large_message_count(self):
        """Test that very large message counts are accepted."""
        metrics = ChatMetrics(
            message_count=1_000_000,
            unique_authors=10_000,
            history_hours=8760.0,  # 1 year
            first_message_at=datetime(2023, 1, 1, tzinfo=UTC),
            last_message_at=datetime(2024, 1, 1, tzinfo=UTC),
        )
        assert metrics.message_count == 1_000_000
        assert metrics.messages_per_hour == pytest.approx(114.155, rel=0.01)

    def test_very_small_history_hours(self):
        """Test that very small but positive history_hours is accepted."""
        metrics = ChatMetrics(
            message_count=10,
            unique_authors=5,
            history_hours=0.001,  # About 3.6 seconds
            first_message_at=datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC),
            last_message_at=datetime(2024, 1, 1, 12, 0, 3, tzinfo=UTC),
        )
        assert metrics.history_hours == 0.001
        assert metrics.messages_per_hour == 10_000

    def test_equal_first_and_last_message_times(self):
        """Test that equal first and last message times is valid."""
        same_time = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
        metrics = ChatMetrics(
            message_count=5,
            unique_authors=3,
            history_hours=0.0,
            first_message_at=same_time,
            last_message_at=same_time,
        )
        assert metrics.first_message_at == metrics.last_message_at
        assert metrics.messages_per_hour == 0.0

"""Tests for export endpoint validation.

Tests validation logic in AnalysisResultInput to ensure corrupted data
is rejected before CSV export.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from chatfilter.models import ChatType
from chatfilter.web.routers.export import AnalysisResultInput


class TestAnalysisResultInputValidation:
    """Test AnalysisResultInput validation rules."""

    def test_valid_input(self):
        """Test that valid input is accepted."""
        input_data = AnalysisResultInput(
            chat_id=123,
            chat_title="Test Chat",
            chat_type=ChatType.GROUP,
            chat_username="testchat",
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            analyzed_at=datetime(2024, 1, 2, 1, 0, tzinfo=UTC),
        )
        assert input_data.chat_id == 123
        assert input_data.message_count == 100

    def test_negative_chat_id(self):
        """Test that negative or zero chat_id is rejected."""
        with pytest.raises(ValidationError, match="greater than 0"):
            AnalysisResultInput(
                chat_id=0,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=10,
                history_hours=24.5,
            )

        with pytest.raises(ValidationError, match="greater than 0"):
            AnalysisResultInput(
                chat_id=-123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=10,
                history_hours=24.5,
            )

    def test_negative_message_count(self):
        """Test that negative message_count is rejected."""
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=-1,
                unique_authors=10,
                history_hours=24.5,
            )

    def test_negative_unique_authors(self):
        """Test that negative unique_authors is rejected."""
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=-1,
                history_hours=24.5,
            )

    def test_negative_history_hours(self):
        """Test that negative history_hours is rejected."""
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=10,
                history_hours=-1.0,
            )

    def test_nan_history_hours(self):
        """Test that NaN history_hours is rejected."""
        # NaN is caught by Pydantic's ge=0 constraint before custom validator
        with pytest.raises(ValidationError, match="greater than or equal to 0"):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=10,
                history_hours=float("nan"),
            )

    def test_inf_history_hours(self):
        """Test that infinite history_hours is rejected."""
        with pytest.raises(ValidationError, match="history_hours cannot be infinite"):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=10,
                history_hours=float("inf"),
            )

    def test_unique_authors_exceeds_message_count(self):
        """Test that unique_authors > message_count is rejected."""
        with pytest.raises(
            ValidationError,
            match="unique_authors.*cannot exceed.*message_count",
        ):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=10,
                unique_authors=20,
                history_hours=24.5,
            )

    def test_messages_without_authors(self):
        """Test that message_count > 0 requires unique_authors > 0."""
        with pytest.raises(
            ValidationError,
            match="message_count > 0 requires at least one unique_author",
        ):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=0,
                history_hours=24.5,
            )

    def test_inverted_date_range(self):
        """Test that first_message_at > last_message_at is rejected."""
        with pytest.raises(
            ValidationError,
            match="first_message_at cannot be after last_message_at",
        ):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
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
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
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
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=10,
                history_hours=24.5,
                first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
                last_message_at=future,
            )

    def test_future_analyzed_at(self):
        """Test that analyzed_at significantly in the future is rejected."""
        future = datetime.now(UTC) + timedelta(hours=1)
        with pytest.raises(
            ValidationError,
            match="analyzed_at cannot be in the future",
        ):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=10,
                history_hours=24.5,
                analyzed_at=future,
            )

    def test_analyzed_at_before_last_message(self):
        """Test that analyzed_at before last_message_at is rejected."""
        last_msg = datetime(2024, 1, 2, tzinfo=UTC)

        with pytest.raises(
            ValidationError,
            match="analyzed_at cannot be before last_message_at",
        ):
            AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=ChatType.GROUP,
                message_count=100,
                unique_authors=10,
                history_hours=24.5,
                last_message_at=last_msg,
                analyzed_at=last_msg - timedelta(hours=1),
            )

    def test_to_analysis_result_conversion(self):
        """Test that valid input converts to AnalysisResult correctly."""
        input_data = AnalysisResultInput(
            chat_id=123,
            chat_title="Test Chat",
            chat_type=ChatType.GROUP,
            chat_username="testchat",
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
            first_message_at=datetime(2024, 1, 1, tzinfo=UTC),
            last_message_at=datetime(2024, 1, 2, tzinfo=UTC),
            analyzed_at=datetime(2024, 1, 2, 1, 0, tzinfo=UTC),
        )

        result = input_data.to_analysis_result()

        assert result.chat.id == 123
        assert result.chat.title == "Test Chat"
        assert result.chat.chat_type == ChatType.GROUP
        assert result.chat.username == "testchat"
        assert result.metrics.message_count == 100
        assert result.metrics.unique_authors == 10
        assert result.metrics.history_hours == 24.5
        assert result.analyzed_at == datetime(2024, 1, 2, 1, 0, tzinfo=UTC)

    def test_empty_chat_valid(self):
        """Test that empty chat data (0 messages, 0 authors) is valid."""
        input_data = AnalysisResultInput(
            chat_id=123,
            chat_title="Empty Chat",
            chat_type=ChatType.GROUP,
            message_count=0,
            unique_authors=0,
            history_hours=0.0,
        )
        assert input_data.message_count == 0
        assert input_data.unique_authors == 0

    def test_missing_optional_fields(self):
        """Test that optional fields can be omitted."""
        input_data = AnalysisResultInput(
            chat_id=123,
            chat_title="Test",
            chat_type=ChatType.PRIVATE,
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
        )
        assert input_data.chat_username is None
        assert input_data.first_message_at is None
        assert input_data.last_message_at is None
        assert input_data.analyzed_at is None

    def test_all_chat_types_valid(self):
        """Test that all chat types are accepted."""
        for chat_type in ChatType:
            input_data = AnalysisResultInput(
                chat_id=123,
                chat_title="Test",
                chat_type=chat_type,
                message_count=100,
                unique_authors=10,
                history_hours=24.5,
            )
            assert input_data.chat_type == chat_type


class TestExportValidationEdgeCases:
    """Test edge cases specific to export validation."""

    def test_very_long_chat_title(self):
        """Test that very long chat titles are accepted."""
        long_title = "A" * 1000
        input_data = AnalysisResultInput(
            chat_id=123,
            chat_title=long_title,
            chat_type=ChatType.GROUP,
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
        )
        assert len(input_data.chat_title) == 1000

    def test_unicode_chat_title(self):
        """Test that unicode chat titles are accepted."""
        input_data = AnalysisResultInput(
            chat_id=123,
            chat_title="Test 🎉 Тест ✨",
            chat_type=ChatType.GROUP,
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
        )
        assert "🎉" in input_data.chat_title
        assert "Тест" in input_data.chat_title

    def test_zero_values_valid_for_empty_chat(self):
        """Test that all zero values are valid for empty chats."""
        input_data = AnalysisResultInput(
            chat_id=1,
            chat_title="Empty",
            chat_type=ChatType.GROUP,
            message_count=0,
            unique_authors=0,
            history_hours=0.0,
            first_message_at=None,
            last_message_at=None,
        )
        result = input_data.to_analysis_result()
        assert result.metrics.message_count == 0
        assert result.metrics.messages_per_hour == 0.0

    def test_boundary_positive_chat_id(self):
        """Test that chat_id = 1 (minimum valid) is accepted."""
        input_data = AnalysisResultInput(
            chat_id=1,
            chat_title="Test",
            chat_type=ChatType.PRIVATE,
            message_count=10,
            unique_authors=2,
            history_hours=1.0,
        )
        assert input_data.chat_id == 1

    def test_very_large_chat_id(self):
        """Test that very large chat IDs are accepted."""
        large_id = 9_999_999_999_999
        input_data = AnalysisResultInput(
            chat_id=large_id,
            chat_title="Test",
            chat_type=ChatType.SUPERGROUP,
            message_count=100,
            unique_authors=10,
            history_hours=24.5,
        )
        assert input_data.chat_id == large_id

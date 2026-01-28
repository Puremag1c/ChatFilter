"""Tests for Message domain model.

Tests cover:
- Message: creation, validation, fake factory
- Field validators: chat_id, author_id, timestamp
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from chatfilter.models.message import Message


class TestMessageCreation:
    """Tests for Message creation."""

    def test_valid_message(self) -> None:
        """Should create valid message."""
        now = datetime.now(UTC) - timedelta(hours=1)
        msg = Message(
            id=1,
            chat_id=123,
            author_id=456,
            timestamp=now,
            text="Hello",
        )

        assert msg.id == 1
        assert msg.chat_id == 123
        assert msg.author_id == 456
        assert msg.timestamp == now
        assert msg.text == "Hello"

    def test_default_text(self) -> None:
        """Text should default to empty string."""
        msg = Message(
            id=1,
            chat_id=123,
            author_id=456,
            timestamp=datetime.now(UTC) - timedelta(hours=1),
        )

        assert msg.text == ""

    def test_frozen_model(self) -> None:
        """Message should be immutable (frozen)."""
        msg = Message(
            id=1,
            chat_id=123,
            author_id=456,
            timestamp=datetime.now(UTC) - timedelta(hours=1),
            text="Hello",
        )

        with pytest.raises((ValidationError, AttributeError)):
            msg.text = "Changed"  # type: ignore


class TestChatIdValidation:
    """Tests for chat_id validation."""

    def test_positive_chat_id(self) -> None:
        """Should accept positive chat_id."""
        msg = Message(
            id=1,
            chat_id=1,
            author_id=1,
            timestamp=datetime.now(UTC) - timedelta(hours=1),
        )

        assert msg.chat_id == 1

    def test_zero_chat_id_rejected(self) -> None:
        """Should reject zero chat_id."""
        with pytest.raises(ValidationError) as exc_info:
            Message(
                id=1,
                chat_id=0,
                author_id=1,
                timestamp=datetime.now(UTC) - timedelta(hours=1),
            )

        assert "chat_id must be positive" in str(exc_info.value)

    def test_negative_chat_id_rejected(self) -> None:
        """Should reject negative chat_id."""
        with pytest.raises(ValidationError) as exc_info:
            Message(
                id=1,
                chat_id=-1,
                author_id=1,
                timestamp=datetime.now(UTC) - timedelta(hours=1),
            )

        assert "chat_id must be positive" in str(exc_info.value)


class TestAuthorIdValidation:
    """Tests for author_id validation."""

    def test_positive_author_id(self) -> None:
        """Should accept positive author_id."""
        msg = Message(
            id=1,
            chat_id=1,
            author_id=123,
            timestamp=datetime.now(UTC) - timedelta(hours=1),
        )

        assert msg.author_id == 123

    def test_zero_author_id_rejected(self) -> None:
        """Should reject zero author_id."""
        with pytest.raises(ValidationError) as exc_info:
            Message(
                id=1,
                chat_id=1,
                author_id=0,
                timestamp=datetime.now(UTC) - timedelta(hours=1),
            )

        assert "author_id must be positive" in str(exc_info.value)

    def test_negative_author_id_rejected(self) -> None:
        """Should reject negative author_id."""
        with pytest.raises(ValidationError) as exc_info:
            Message(
                id=1,
                chat_id=1,
                author_id=-1,
                timestamp=datetime.now(UTC) - timedelta(hours=1),
            )

        assert "author_id must be positive" in str(exc_info.value)


class TestTimestampValidation:
    """Tests for timestamp validation."""

    def test_past_timestamp(self) -> None:
        """Should accept timestamp in the past."""
        past = datetime.now(UTC) - timedelta(days=1)
        msg = Message(
            id=1,
            chat_id=1,
            author_id=1,
            timestamp=past,
        )

        assert msg.timestamp == past

    def test_future_timestamp_rejected(self) -> None:
        """Should reject timestamp in the future."""
        future = datetime.now(UTC) + timedelta(hours=1)
        with pytest.raises(ValidationError) as exc_info:
            Message(
                id=1,
                chat_id=1,
                author_id=1,
                timestamp=future,
            )

        assert "cannot be in the future" in str(exc_info.value)

    def test_near_future_allowed(self) -> None:
        """Should allow small future offset (clock skew tolerance)."""
        # Within 1 minute tolerance
        near_future = datetime.now(UTC) + timedelta(seconds=30)
        msg = Message(
            id=1,
            chat_id=1,
            author_id=1,
            timestamp=near_future,
        )

        assert msg.timestamp == near_future

    def test_naive_timestamp_rejected(self) -> None:
        """Should reject naive (no timezone) timestamp.

        Note: The comparison with aware datetime raises TypeError before
        the explicit tzinfo check can run, but Pydantic wraps this in
        ValidationError.
        """
        naive = datetime.now()  # No timezone
        with pytest.raises((ValidationError, TypeError)):
            Message(
                id=1,
                chat_id=1,
                author_id=1,
                timestamp=naive,
            )


class TestMessageFake:
    """Tests for Message.fake factory method."""

    def test_creates_valid_message(self) -> None:
        """Should create valid message with defaults."""
        msg = Message.fake()

        assert isinstance(msg, Message)
        assert msg.id > 0
        assert msg.chat_id > 0
        assert msg.author_id > 0
        assert msg.text == "Test message"

    def test_custom_values(self) -> None:
        """Should use provided values."""
        msg = Message.fake(
            id=42,
            chat_id=100,
            author_id=200,
            text="Custom text",
        )

        assert msg.id == 42
        assert msg.chat_id == 100
        assert msg.author_id == 200
        assert msg.text == "Custom text"

    def test_custom_timestamp(self) -> None:
        """Should accept custom timestamp."""
        custom_time = datetime.now(UTC) - timedelta(days=7)
        msg = Message.fake(timestamp=custom_time)

        assert msg.timestamp == custom_time

    def test_different_each_call(self) -> None:
        """Each call should generate different IDs (random)."""
        msg1 = Message.fake()
        msg2 = Message.fake()

        # Very unlikely to be the same
        assert msg1.id != msg2.id or msg1.chat_id != msg2.chat_id

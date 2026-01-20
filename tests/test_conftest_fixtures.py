"""Tests for the shared test fixtures in conftest.py.

This test file verifies that the new Telegram mock fixtures work correctly
and can be used by other tests.
"""

from datetime import UTC, datetime

import pytest

from chatfilter.models.chat import Chat, ChatType
from chatfilter.models.message import Message


class TestFakeChatFactory:
    """Tests for fake_chat_factory fixture."""

    def test_creates_default_chat(self, fake_chat_factory):
        """Test creating a default chat."""
        chat = fake_chat_factory()

        assert isinstance(chat, Chat)
        assert chat.id > 0
        assert chat.title == "Test Chat"
        assert chat.chat_type == ChatType.GROUP

    def test_creates_custom_chat(self, fake_chat_factory):
        """Test creating a custom chat."""
        chat = fake_chat_factory(
            id=123,
            title="Custom Chat",
            chat_type=ChatType.CHANNEL,
            username="custom",
            member_count=100,
        )

        assert chat.id == 123
        assert chat.title == "Custom Chat"
        assert chat.chat_type == ChatType.CHANNEL
        assert chat.username == "custom"
        assert chat.member_count == 100

    def test_deterministic_with_seed_offset(self, fake_chat_factory):
        """Test that same seed_offset produces same IDs."""
        chat1 = fake_chat_factory(seed_offset=5)
        chat2 = fake_chat_factory(seed_offset=5)

        assert chat1.id == chat2.id

    def test_different_seed_offsets_produce_different_ids(self, fake_chat_factory):
        """Test that different seed_offsets produce different IDs."""
        chat1 = fake_chat_factory(seed_offset=1)
        chat2 = fake_chat_factory(seed_offset=2)

        assert chat1.id != chat2.id


class TestFakeMessageFactory:
    """Tests for fake_message_factory fixture."""

    def test_creates_default_message(self, fake_message_factory):
        """Test creating a default message."""
        msg = fake_message_factory()

        assert isinstance(msg, Message)
        assert msg.id > 0
        assert msg.chat_id > 0
        assert msg.author_id > 0
        assert msg.text == "Test message"
        assert msg.timestamp.tzinfo is not None

    def test_creates_custom_message(self, fake_message_factory):
        """Test creating a custom message."""
        now = datetime.now(UTC)
        msg = fake_message_factory(
            id=456,
            chat_id=789,
            author_id=101,
            timestamp=now,
            text="Custom text",
        )

        assert msg.id == 456
        assert msg.chat_id == 789
        assert msg.author_id == 101
        assert msg.timestamp == now
        assert msg.text == "Custom text"

    def test_deterministic_with_seed_offset(self, fake_message_factory):
        """Test that same seed_offset produces same IDs."""
        msg1 = fake_message_factory(seed_offset=10)
        msg2 = fake_message_factory(seed_offset=10)

        assert msg1.id == msg2.id
        assert msg1.chat_id == msg2.chat_id
        assert msg1.author_id == msg2.author_id


class TestMockDialogFactory:
    """Tests for mock_dialog_factory fixture."""

    def test_creates_user_dialog(self, mock_dialog_factory):
        """Test creating a user dialog."""
        dialog = mock_dialog_factory(1, "user", "John Doe", username="john")

        assert dialog.id == 1
        assert dialog.name == "John Doe"
        assert dialog.entity.username == "john"

    def test_creates_channel_dialog(self, mock_dialog_factory):
        """Test creating a channel dialog."""
        dialog = mock_dialog_factory(
            2, "channel", "News Channel", username="news", participants_count=1000
        )

        assert dialog.id == 2
        assert dialog.title == "News Channel"
        assert dialog.entity.username == "news"
        assert dialog.entity.participants_count == 1000

    def test_creates_megagroup_dialog(self, mock_dialog_factory):
        """Test creating a megagroup dialog."""
        dialog = mock_dialog_factory(3, "channel", "Big Group", megagroup=True)

        assert dialog.entity.megagroup is True
        assert dialog.entity.forum is False

    def test_creates_forum_dialog(self, mock_dialog_factory):
        """Test creating a forum dialog."""
        dialog = mock_dialog_factory(
            4, "channel", "Forum", megagroup=True, forum=True
        )

        assert dialog.entity.megagroup is True
        assert dialog.entity.forum is True


class TestMockMessageFactory:
    """Tests for mock_message_factory fixture."""

    def test_creates_basic_message(self, mock_message_factory):
        """Test creating a basic message."""
        msg = mock_message_factory(1, "Hello world")

        assert msg.id == 1
        assert msg.message == "Hello world"
        assert msg.sender_id == 123
        assert msg.media is None

    def test_creates_message_with_media(self, mock_message_factory):
        """Test creating a message with media."""
        msg = mock_message_factory(2, "Check this out", has_media=True)

        assert msg.id == 2
        assert msg.media is not None

    def test_creates_channel_post(self, mock_message_factory):
        """Test creating a channel post (no sender)."""
        msg = mock_message_factory(3, "Channel announcement", sender_id=None)

        assert msg.id == 3
        assert msg.sender_id is None


@pytest.mark.asyncio
async def test_mock_telegram_client(mock_telegram_client):
    """Test that mock_telegram_client fixture works."""
    # Test that async methods are configured
    await mock_telegram_client.connect()
    await mock_telegram_client.disconnect()

    # Test that iter methods return empty iterators
    dialogs = []
    async for dialog in mock_telegram_client.iter_dialogs():
        dialogs.append(dialog)
    assert len(dialogs) == 0

    messages = []
    async for msg in mock_telegram_client.iter_messages(123):
        messages.append(msg)
    assert len(messages) == 0


class TestEdgeCaseChats:
    """Tests for edge_case_chats fixture."""

    def test_has_expected_edge_cases(self, edge_case_chats):
        """Test that all expected edge cases are present."""
        expected_cases = [
            "empty",
            "unicode",
            "long_title",
            "deleted_account",
            "no_username",
            "zero_members",
            "forum",
        ]

        for case in expected_cases:
            assert case in edge_case_chats

    def test_empty_chat(self, edge_case_chats):
        """Test empty chat edge case."""
        chat = edge_case_chats["empty"]
        assert chat.title == ""
        assert chat.chat_type == ChatType.PRIVATE

    def test_unicode_chat(self, edge_case_chats):
        """Test unicode chat edge case."""
        chat = edge_case_chats["unicode"]
        assert "🎉" in chat.title
        assert "Тестовая" in chat.title
        assert "中文" in chat.title

    def test_forum_chat(self, edge_case_chats):
        """Test forum chat edge case."""
        chat = edge_case_chats["forum"]
        assert chat.chat_type == ChatType.FORUM


class TestEdgeCaseMessages:
    """Tests for edge_case_messages fixture."""

    def test_has_expected_edge_cases(self, edge_case_messages):
        """Test that all expected edge cases are present."""
        expected_cases = [
            "empty",
            "unicode",
            "long_text",
            "emoji_only",
            "deleted_author",
            "old_message",
            "recent_message",
            "newlines",
            "special_chars",
        ]

        for case in expected_cases:
            assert case in edge_case_messages

    def test_empty_message(self, edge_case_messages):
        """Test empty message edge case."""
        msg = edge_case_messages["empty"]
        assert msg.text == ""

    def test_unicode_message(self, edge_case_messages):
        """Test unicode message edge case."""
        msg = edge_case_messages["unicode"]
        assert "👋" in msg.text
        assert "Привет" in msg.text
        assert "你好" in msg.text

    def test_emoji_only_message(self, edge_case_messages):
        """Test emoji-only message edge case."""
        msg = edge_case_messages["emoji_only"]
        assert msg.text == "🎉🚀💻🔥✨"

    def test_newlines_message(self, edge_case_messages):
        """Test message with newlines."""
        msg = edge_case_messages["newlines"]
        assert "\n" in msg.text
        assert "Line 1" in msg.text

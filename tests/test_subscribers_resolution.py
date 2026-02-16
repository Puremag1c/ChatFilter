"""Tests for subscribers resolution via GetFullChannelRequest.

Verifies that _resolve_by_username and _resolve_by_invite correctly
call GetFullChannelRequest when participants_count is None on the
initial entity, and that the resolved subscribers value flows through
to the CSV export.

Bug: https://github.com/.../issues/ChatFilter-o91yq
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, MagicMock, call

import pytest
from telethon import errors
from telethon.tl.functions.channels import GetFullChannelRequest
from telethon.tl.types import Channel, ChatInviteAlready, ChatInvitePeek

from chatfilter.analyzer.group_engine import GroupAnalysisEngine, _ResolvedChat
from chatfilter.exporter.csv import to_csv_rows_dynamic
from chatfilter.models.group import ChatTypeEnum, GroupSettings
from chatfilter.storage.group_database import GroupDatabase

if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def group_db(tmp_path: Path) -> GroupDatabase:
    """Create a temporary GroupDatabase for testing."""
    db_path = tmp_path / "test_groups.db"
    return GroupDatabase(db_path=str(db_path))


@pytest.fixture
def mock_session_manager() -> MagicMock:
    """Create a mock SessionManager."""
    mgr = MagicMock()
    mgr.list_sessions.return_value = ["account1"]
    mgr.is_healthy = AsyncMock(return_value=True)
    mock_client = AsyncMock()
    mock_context = AsyncMock()
    mock_context.__aenter__.return_value = mock_client
    mock_context.__aexit__.return_value = None
    mgr.session.return_value = mock_context
    return mgr


@pytest.fixture
def engine(
    group_db: GroupDatabase, mock_session_manager: MagicMock
) -> GroupAnalysisEngine:
    """Create a GroupAnalysisEngine instance for testing."""
    return GroupAnalysisEngine(db=group_db, session_manager=mock_session_manager)


def _make_channel(
    *,
    channel_id: int = 123456,
    title: str = "Test Channel",
    megagroup: bool = True,
    participants_count: int | None = None,
    join_request: bool = False,
) -> MagicMock:
    """Create a mock Channel entity."""
    ch = MagicMock(spec=Channel)
    ch.id = channel_id
    ch.title = title
    ch.megagroup = megagroup
    ch.forum = False
    ch.broadcast = not megagroup
    ch.join_request = join_request
    ch.participants_count = participants_count
    return ch


def _make_full_channel_result(participants_count: int) -> MagicMock:
    """Create a mock result for GetFullChannelRequest (messages.ChatFull)."""
    result = MagicMock()
    result.full_chat = MagicMock()
    result.full_chat.participants_count = participants_count
    return result


class TestResolveByUsernameSubscribers:
    """Tests for _resolve_by_username returning numeric subscribers."""

    @pytest.mark.asyncio
    async def test_get_entity_has_participants_count(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """When get_entity returns participants_count, use it directly."""
        mock_client = AsyncMock()
        channel = _make_channel(participants_count=5000)
        mock_client.get_entity = AsyncMock(return_value=channel)

        chat = {"id": 1, "chat_ref": "@testchannel"}
        resolved = await engine._resolve_by_username(
            mock_client, chat, "testchannel", "account1"
        )

        assert resolved.subscribers == 5000
        assert resolved.status == "done"
        # GetFullChannelRequest should NOT be called
        mock_client.assert_not_awaited()  # no __call__ on client

    @pytest.mark.asyncio
    async def test_get_entity_no_participants_calls_full_channel(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """When get_entity returns participants_count=None, call GetFullChannelRequest."""
        mock_client = AsyncMock()
        channel = _make_channel(participants_count=None)
        mock_client.get_entity = AsyncMock(return_value=channel)

        full_result = _make_full_channel_result(participants_count=12345)
        mock_client.__call__ = AsyncMock(return_value=full_result)
        # Telethon uses client(request) syntax → calls __call__
        mock_client.return_value = full_result

        chat = {"id": 1, "chat_ref": "@testchannel"}
        resolved = await engine._resolve_by_username(
            mock_client, chat, "testchannel", "account1"
        )

        assert resolved.subscribers == 12345
        assert resolved.status == "done"
        assert resolved.chat_type == ChatTypeEnum.GROUP.value

    @pytest.mark.asyncio
    async def test_full_channel_request_fails_gracefully(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """When GetFullChannelRequest fails, subscribers remains None."""
        mock_client = AsyncMock()
        channel = _make_channel(participants_count=None)
        mock_client.get_entity = AsyncMock(return_value=channel)
        mock_client.return_value = None
        mock_client.side_effect = Exception("API error")

        chat = {"id": 1, "chat_ref": "@testchannel"}
        resolved = await engine._resolve_by_username(
            mock_client, chat, "testchannel", "account1"
        )

        # Should still resolve but with None subscribers
        assert resolved.subscribers is None
        assert resolved.status == "done"

    @pytest.mark.asyncio
    async def test_full_channel_flood_wait_propagates(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """FloodWaitError from GetFullChannelRequest is re-raised."""
        mock_client = AsyncMock()
        channel = _make_channel(participants_count=None)
        mock_client.get_entity = AsyncMock(return_value=channel)

        flood_error = errors.FloodWaitError(request=None, capture=0)
        flood_error.seconds = 30
        mock_client.return_value = None
        mock_client.side_effect = flood_error

        chat = {"id": 1, "chat_ref": "@testchannel"}
        with pytest.raises(errors.FloodWaitError):
            await engine._resolve_by_username(
                mock_client, chat, "testchannel", "account1"
            )

    @pytest.mark.asyncio
    async def test_get_entity_zero_participants_no_full_channel_call(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """When get_entity returns participants_count=0, keep it (don't call GetFullChannel)."""
        mock_client = AsyncMock()
        channel = _make_channel(participants_count=0)
        mock_client.get_entity = AsyncMock(return_value=channel)

        chat = {"id": 1, "chat_ref": "@emptychannel"}
        resolved = await engine._resolve_by_username(
            mock_client, chat, "emptychannel", "account1"
        )

        assert resolved.subscribers == 0
        assert resolved.status == "done"


class TestResolveByInviteSubscribers:
    """Tests for _resolve_by_invite with ChatInviteAlready and ChatInvitePeek."""

    @pytest.mark.asyncio
    async def test_invite_already_channel_no_participants_calls_full(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """ChatInviteAlready with Channel that has no participants_count."""
        mock_client = AsyncMock()
        channel = _make_channel(participants_count=None)

        invite_already = MagicMock(spec=ChatInviteAlready)
        invite_already.chat = channel

        full_result = _make_full_channel_result(participants_count=9999)
        # First call returns invite_already (CheckChatInviteRequest),
        # second call returns full_result (GetFullChannelRequest)
        mock_client.side_effect = [invite_already, full_result]

        chat = {"id": 2, "chat_ref": "https://t.me/+abc123"}
        resolved = await engine._resolve_by_invite(
            mock_client, chat, "abc123", "account1"
        )

        assert resolved.subscribers == 9999
        assert resolved.status == "done"

    @pytest.mark.asyncio
    async def test_invite_peek_channel_no_participants_calls_full(
        self, engine: GroupAnalysisEngine
    ) -> None:
        """ChatInvitePeek with Channel that has no participants_count."""
        mock_client = AsyncMock()
        channel = _make_channel(participants_count=None)

        invite_peek = MagicMock(spec=ChatInvitePeek)
        invite_peek.chat = channel

        full_result = _make_full_channel_result(participants_count=7777)
        mock_client.side_effect = [invite_peek, full_result]

        chat = {"id": 3, "chat_ref": "https://t.me/+xyz789"}
        resolved = await engine._resolve_by_invite(
            mock_client, chat, "xyz789", "account1"
        )

        assert resolved.subscribers == 7777
        assert resolved.status == "done"


class TestSubscribersEndToEnd:
    """End-to-end test: resolve → save → DB → CSV export with subscribers."""

    def test_subscribers_flow_to_csv(
        self, engine: GroupAnalysisEngine, group_db: GroupDatabase
    ) -> None:
        """Verify subscribers value flows from _ResolvedChat through to CSV output."""
        group_id = "test-group-1"
        settings = GroupSettings()  # all defaults = True

        # Create a group in DB
        group_db.save_group(
            group_id=group_id,
            name="Subscriber Test Group",
            settings=settings.model_dump(),
            status="in_progress",
        )

        # Simulate Phase 1 resolved chat with subscribers
        resolved = _ResolvedChat(
            db_chat_id=1,
            chat_ref="@testchannel",
            chat_type=ChatTypeEnum.GROUP.value,
            title="Test Channel",
            subscribers=12345,
            moderation=False,
            numeric_id=123456,
            status="done",
        )

        chat = {
            "id": 1,
            "chat_ref": "@testchannel",
            "chat_type": ChatTypeEnum.PENDING.value,
        }

        # Save Phase 1 result
        engine._save_phase1_result(
            group_id, chat, resolved, "account1", settings,
        )

        # Load results from DB
        results = group_db.load_results(group_id)
        assert len(results) == 1
        assert results[0]["metrics_data"]["subscribers"] == 12345

        # Generate CSV rows
        rows = list(to_csv_rows_dynamic(results, settings))
        headers = rows[0]
        data_row = rows[1]

        # Verify subscribers column and value
        assert "subscribers" in headers
        subs_idx = headers.index("subscribers")
        assert data_row[subs_idx] == "12345"

    def test_none_subscribers_shows_empty_in_csv(
        self, engine: GroupAnalysisEngine, group_db: GroupDatabase
    ) -> None:
        """Verify None subscribers renders as empty string in CSV."""
        group_id = "test-group-2"
        settings = GroupSettings()

        group_db.save_group(
            group_id=group_id,
            name="None Subscribers Group",
            settings=settings.model_dump(),
            status="in_progress",
        )

        resolved = _ResolvedChat(
            db_chat_id=2,
            chat_ref="@private_channel",
            chat_type=ChatTypeEnum.GROUP.value,
            title="Private Channel",
            subscribers=None,  # Could not retrieve
            moderation=False,
            numeric_id=789,
            status="done",
        )

        chat = {
            "id": 2,
            "chat_ref": "@private_channel",
            "chat_type": ChatTypeEnum.PENDING.value,
        }

        engine._save_phase1_result(
            group_id, chat, resolved, "account1", settings,
        )

        results = group_db.load_results(group_id)
        assert results[0]["metrics_data"]["subscribers"] is None

        rows = list(to_csv_rows_dynamic(results, settings))
        headers = rows[0]
        data_row = rows[1]

        subs_idx = headers.index("subscribers")
        assert data_row[subs_idx] == ""  # None → empty string

    def test_subscribers_not_saved_when_detect_disabled(
        self, engine: GroupAnalysisEngine, group_db: GroupDatabase
    ) -> None:
        """When detect_subscribers=False, subscribers key not in metrics_data."""
        group_id = "test-group-3"
        settings = GroupSettings(detect_subscribers=False)

        group_db.save_group(
            group_id=group_id,
            name="No Subscribers Group",
            settings=settings.model_dump(),
            status="in_progress",
        )

        resolved = _ResolvedChat(
            db_chat_id=3,
            chat_ref="@nocountchat",
            chat_type=ChatTypeEnum.GROUP.value,
            title="No Count Chat",
            subscribers=5000,
            moderation=False,
            numeric_id=456,
            status="done",
        )

        chat = {
            "id": 3,
            "chat_ref": "@nocountchat",
            "chat_type": ChatTypeEnum.PENDING.value,
        }

        engine._save_phase1_result(
            group_id, chat, resolved, "account1", settings,
        )

        results = group_db.load_results(group_id)
        assert "subscribers" not in results[0]["metrics_data"]

        # CSV should NOT have subscribers column
        rows = list(to_csv_rows_dynamic(results, settings))
        headers = rows[0]
        assert "subscribers" not in headers

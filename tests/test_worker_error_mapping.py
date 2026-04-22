"""Phase 0 — Telegram error → (status, chat_type) mapping tests.

Business rules:
    - Telegram responded → GroupChatStatus.DONE, chat_type reflects reality.
    - Network/unknown crash → worker re-raises, retry.py handles rotation.
    - Our own parse error (invalid chat_ref) → status=ERROR, chat_type=PENDING
      (retriable by explicit user action, not billable).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from telethon import errors
from telethon.tl.types import Channel, ChatInvite, ChatInviteAlready

from chatfilter.analyzer.worker import ChatResult, process_chat
from chatfilter.models.group import ChatTypeEnum, GroupChatStatus, GroupSettings


# ------------------------------------------------------------------
# helpers
# ------------------------------------------------------------------


def _quick_settings() -> GroupSettings:
    """Settings that do NOT require join — stop after resolve."""
    return GroupSettings(
        detect_activity=False,
        detect_unique_authors=False,
        detect_moderation=False,
        detect_captcha=False,
    )


def _chat(chat_ref: str = "@test") -> dict[str, Any]:
    return {"chat_ref": chat_ref, "id": 1, "group_id": "g1"}


def _mock_channel(
    *,
    broadcast: bool = False,
    megagroup: bool = True,
    forum: bool = False,
    linked_chat_id: int | None = None,
    restricted: bool = False,
    restriction_reason: list | None = None,
    participants_count: int = 100,
    title: str = "Test",
    id_: int = 1001,
) -> MagicMock:
    """Build a MagicMock for telethon Channel entity."""
    ch = MagicMock(spec=Channel)
    ch.broadcast = broadcast
    ch.megagroup = megagroup
    ch.forum = forum
    ch.restricted = restricted
    ch.restriction_reason = restriction_reason or []
    ch.participants_count = participants_count
    ch.title = title
    ch.id = id_
    ch.join_request = False
    ch.linked_chat_id = linked_chat_id
    return ch


def _client_with_resolve_exception(exc: BaseException) -> AsyncMock:
    client = AsyncMock()
    client.get_entity = AsyncMock(side_effect=exc)
    return client


def _client_with_channel(ch: MagicMock, linked_chat_id: int | None = None) -> AsyncMock:
    """Client that resolves to given Channel and also answers GetFullChannel."""
    client = AsyncMock()
    client.get_entity = AsyncMock(return_value=ch)
    full_chat = MagicMock()
    full_chat.participants_count = ch.participants_count
    full_chat.linked_chat_id = linked_chat_id
    full_channel = MagicMock()
    full_channel.full_chat = full_chat
    client.return_value = full_channel  # for await client(GetFullChannelRequest(...))
    return client


# ------------------------------------------------------------------
# NEGATIVE results (Telegram answered "dead/banned/private/restricted")
# ------------------------------------------------------------------


class TestResolveFailuresBecomeDone:
    """Telegram tells us *what* the chat is — we mark DONE and classify."""

    @pytest.mark.asyncio
    async def test_username_not_occupied_is_dead(self) -> None:
        client = _client_with_resolve_exception(errors.UsernameNotOccupiedError(request=None))
        r = await process_chat(_chat("@ghost"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.DEAD.value

    @pytest.mark.asyncio
    async def test_username_invalid_is_dead(self) -> None:
        client = _client_with_resolve_exception(errors.UsernameInvalidError(request=None))
        r = await process_chat(_chat("@x"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.DEAD.value

    @pytest.mark.asyncio
    async def test_channel_private_is_private(self) -> None:
        client = _client_with_resolve_exception(errors.ChannelPrivateError(request=None))
        r = await process_chat(_chat("@p"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.PRIVATE.value

    @pytest.mark.asyncio
    async def test_channel_banned_is_banned(self) -> None:
        client = _client_with_resolve_exception(errors.ChannelBannedError(request=None))
        r = await process_chat(_chat("@b"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.BANNED.value

    @pytest.mark.asyncio
    async def test_chat_forbidden_is_banned(self) -> None:
        client = _client_with_resolve_exception(errors.ChatForbiddenError(request=None))
        r = await process_chat(_chat("@f"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.BANNED.value

    @pytest.mark.asyncio
    async def test_chat_restricted_is_restricted(self) -> None:
        client = _client_with_resolve_exception(errors.ChatRestrictedError(request=None))
        r = await process_chat(_chat("@r"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.RESTRICTED.value


class TestChannelRestrictedFlag:
    """Channel.restricted=True with platform=all → RESTRICTED even though no exception."""

    @pytest.mark.asyncio
    async def test_restricted_platform_all_is_restricted(self) -> None:
        reason = MagicMock()
        reason.platform = "all"
        reason.reason = "porno"
        reason.text = "This channel is restricted"
        ch = _mock_channel(
            broadcast=True, megagroup=False, restricted=True, restriction_reason=[reason]
        )
        client = _client_with_channel(ch)
        r = await process_chat(_chat("@porn"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.RESTRICTED.value

    @pytest.mark.asyncio
    async def test_restricted_platform_ios_only_not_restricted(self) -> None:
        """restriction for a non-'all' platform is ignored — channel is still live."""
        reason = MagicMock()
        reason.platform = "ios"
        reason.reason = "copyright"
        reason.text = "Restricted on iOS"
        ch = _mock_channel(
            broadcast=True, megagroup=False, restricted=True, restriction_reason=[reason]
        )
        client = _client_with_channel(ch)
        r = await process_chat(_chat("@c"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type != ChatTypeEnum.RESTRICTED.value
        # should be classified normally (broadcast + no linked_chat → CHANNEL_NO_COMMENTS)
        assert r.chat_type == ChatTypeEnum.CHANNEL_NO_COMMENTS.value


# ------------------------------------------------------------------
# POSITIVE results (normal chat types)
# ------------------------------------------------------------------


class TestNormalChannelClassification:
    """Live Channel classified correctly by flags."""

    @pytest.mark.asyncio
    async def test_broadcast_with_linked_is_channel_with_comments(self) -> None:
        ch = _mock_channel(broadcast=True, megagroup=False, linked_chat_id=2002)
        client = _client_with_channel(ch, linked_chat_id=2002)
        r = await process_chat(_chat("@news"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.CHANNEL_COMMENTS.value

    @pytest.mark.asyncio
    async def test_broadcast_without_linked_is_channel_no_comments(self) -> None:
        ch = _mock_channel(broadcast=True, megagroup=False, linked_chat_id=None)
        client = _client_with_channel(ch, linked_chat_id=None)
        r = await process_chat(_chat("@broadcast"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.CHANNEL_NO_COMMENTS.value

    @pytest.mark.asyncio
    async def test_megagroup_non_forum_is_group(self) -> None:
        ch = _mock_channel(broadcast=False, megagroup=True, forum=False)
        client = _client_with_channel(ch)
        r = await process_chat(_chat("@grp"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.GROUP.value

    @pytest.mark.asyncio
    async def test_megagroup_forum_is_forum(self) -> None:
        ch = _mock_channel(broadcast=False, megagroup=True, forum=True)
        client = _client_with_channel(ch)
        r = await process_chat(_chat("@forum"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.FORUM.value


# ------------------------------------------------------------------
# ROTATION triggers — worker must re-raise, not classify.
# ------------------------------------------------------------------


class TestRotationTriggers:
    """Per retry.py: some errors cause account rotation; worker re-raises."""

    @pytest.mark.asyncio
    async def test_floodwait_reraises(self) -> None:
        client = _client_with_resolve_exception(errors.FloodWaitError(request=None, capture=5))
        with pytest.raises(errors.FloodWaitError):
            await process_chat(_chat("@c"), client, "acc1", _quick_settings())

    @pytest.mark.asyncio
    async def test_user_banned_in_channel_reraises(self) -> None:
        """Our account got banned in THIS chat — try another account, not mark chat as BANNED.

        (Telegram banning the chat itself returns ChannelBanned/ChannelForbidden —
        those are handled in TestResolveFailuresBecomeDone.)
        """
        client = _client_with_resolve_exception(errors.UserBannedInChannelError(request=None))
        with pytest.raises(errors.UserBannedInChannelError):
            await process_chat(_chat("@c"), client, "acc1", _quick_settings())


class TestCrashReraises:
    """Network/unknown crashes must re-raise so retry.py can rotate."""

    @pytest.mark.asyncio
    async def test_network_error_reraises(self) -> None:
        """OSError (= network / connection) must propagate — do NOT classify as DEAD."""
        client = _client_with_resolve_exception(OSError("Connection refused"))
        with pytest.raises(OSError):
            await process_chat(_chat("@c"), client, "acc1", _quick_settings())

    @pytest.mark.asyncio
    async def test_asyncio_timeout_reraises(self) -> None:
        client = _client_with_resolve_exception(TimeoutError("resolve timed out"))
        with pytest.raises(TimeoutError):
            await process_chat(_chat("@c"), client, "acc1", _quick_settings())


# ------------------------------------------------------------------
# INVITE link handling
# ------------------------------------------------------------------


class TestInviteResolution:
    @pytest.mark.asyncio
    async def test_invite_hash_expired_is_dead(self) -> None:
        client = _client_with_resolve_exception(errors.InviteHashExpiredError(request=None))
        # invite-shaped chat_ref
        r = await process_chat(
            _chat("https://t.me/+abcdef123"), client, "acc1", _quick_settings()
        )
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.DEAD.value

    @pytest.mark.asyncio
    async def test_invite_hash_invalid_is_dead(self) -> None:
        client = _client_with_resolve_exception(errors.InviteHashInvalidError(request=None))
        r = await process_chat(
            _chat("https://t.me/+zxc"), client, "acc1", _quick_settings()
        )
        assert r.status == GroupChatStatus.DONE.value
        assert r.chat_type == ChatTypeEnum.DEAD.value


# ------------------------------------------------------------------
# PARSE errors (our fault) — ERROR, not DEAD.
# ------------------------------------------------------------------


class TestInvalidChatRef:
    @pytest.mark.asyncio
    async def test_garbage_chat_ref_is_error_not_dead(self) -> None:
        """Unparseable chat_ref — our parse failure, not Telegram's — ERROR.

        ERROR is NOT billable and CAN be retried; DEAD is billable. Misclassifying
        our parse errors as DEAD would charge the user for nothing.
        """
        client = AsyncMock()  # never called — fails at parse
        r = await process_chat(
            _chat("not a valid telegram reference at all"),
            client,
            "acc1",
            _quick_settings(),
        )
        assert r.status == GroupChatStatus.ERROR.value
        assert r.chat_type == ChatTypeEnum.PENDING.value


# ------------------------------------------------------------------
# ChatResult shape — status values must be enum members.
# ------------------------------------------------------------------


class TestChatResultShape:
    def test_status_default_is_done(self) -> None:
        r = ChatResult(chat_ref="@x", chat_type=ChatTypeEnum.GROUP.value)
        assert r.status == GroupChatStatus.DONE.value

    @pytest.mark.asyncio
    async def test_successful_result_never_has_error_field(self) -> None:
        ch = _mock_channel(broadcast=False, megagroup=True, forum=False)
        client = _client_with_channel(ch)
        r = await process_chat(_chat("@ok"), client, "acc1", _quick_settings())
        assert r.status == GroupChatStatus.DONE.value
        assert r.error is None

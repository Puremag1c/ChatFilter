"""Single chat worker — processes one chat end-to-end.

Resolves chat metadata, joins and analyzes activity if needed,
returns all metrics in a single dict. Used by GroupAnalysisEngine.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from telethon import errors
from telethon.tl.functions.channels import GetFullChannelRequest
from telethon.tl.functions.messages import CheckChatInviteRequest
from telethon.tl.types import Channel, ChatInvite, ChatInviteAlready, ChatInvitePeek
from telethon.tl.types import Chat as TelegramChat

from chatfilter.models.group import ChatTypeEnum, GroupSettings
from chatfilter.telegram.client import (
    _parse_chat_reference,
    _telethon_message_to_model,
    join_chat,
    leave_chat,
)
from chatfilter.telegram.rate_limiter import get_rate_limiter

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)

CAPTCHA_BOTS = frozenset({
    "missrose_bot", "shieldy_bot", "join_captcha_bot",
    "grouphelpbot", "combot",
})


@dataclass
class ChatResult:
    """Result of processing a single chat."""

    chat_ref: str
    chat_type: str
    title: str | None = None
    subscribers: int | None = None
    moderation: bool | None = None
    numeric_id: int | None = None
    linked_chat_id: int | None = None
    messages_per_hour: float | str | None = None
    unique_authors_per_hour: float | str | None = None
    captcha: bool | str | None = None
    partial_data: bool = False
    status: str = "done"
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "chat_type": self.chat_type,
            "title": self.title,
            "subscribers": self.subscribers,
            "moderation": self.moderation,
            "numeric_id": self.numeric_id,
            "linked_chat_id": self.linked_chat_id,
            "messages_per_hour": self.messages_per_hour,
            "unique_authors_per_hour": self.unique_authors_per_hour,
            "captcha": self.captcha,
            "partial_data": self.partial_data,
        }


def _result_from_resolved(resolved: _ResolvedChat, **overrides) -> ChatResult:
    """Build ChatResult from _ResolvedChat, applying overrides."""
    base = {
        "chat_ref": resolved.chat_ref,
        "chat_type": resolved.chat_type,
        "title": resolved.title,
        "subscribers": resolved.subscribers,
        "moderation": resolved.moderation,
        "numeric_id": resolved.numeric_id,
        "linked_chat_id": resolved.linked_chat_id,
    }
    base.update(overrides)
    return ChatResult(**base)


async def process_chat(
    chat: dict,
    client: TelegramClient,
    account_id: str,
    settings: GroupSettings,
) -> ChatResult:
    """Process a single chat end-to-end.

    Resolves metadata, joins if needed, analyzes activity, always leaves.
    """
    chat_ref = chat["chat_ref"]

    try:
        resolved = await _resolve_chat(client, chat, account_id)
    except errors.FloodWaitError:
        raise

    if resolved.status in ("dead", "banned"):
        return _result_from_resolved(resolved, status=resolved.status, error=resolved.error)

    needs_join = settings.needs_join()
    if resolved.moderation is True:
        return _result_from_resolved(
            resolved, moderation=True,
            messages_per_hour="N/A" if needs_join else None,
            unique_authors_per_hour="N/A" if needs_join else None,
            captcha="N/A" if needs_join and settings.detect_captcha else None,
        )

    if not needs_join:
        return _result_from_resolved(resolved)

    try:
        activity = await _analyze_chat_activity(client, resolved, account_id, settings)
        return _result_from_resolved(resolved, **activity)
    except errors.FloodWaitError:
        raise
    except Exception as e:
        logger.error(f"Account '{account_id}': failed to analyze '{chat_ref}': {e}", exc_info=True)
        return _result_from_resolved(resolved, status="error", error=str(e))


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------


@dataclass
class _ResolvedChat:
    """Metadata resolution result."""

    chat_ref: str
    chat_type: str
    title: str | None
    subscribers: int | None
    moderation: bool | None
    numeric_id: int | None
    linked_chat_id: int | None = None
    status: str = "done"
    error: str | None = None


def _dead_chat(chat_ref: str, *, status: str = "dead", **kw) -> _ResolvedChat:
    """Shorthand for a dead/banned/failed _ResolvedChat."""
    return _ResolvedChat(
        chat_ref=chat_ref, chat_type=ChatTypeEnum.DEAD.value,
        title=kw.get("title"), subscribers=None, moderation=None,
        numeric_id=kw.get("numeric_id"), status=status, error=kw.get("error"),
    )


async def _resolve_chat(
    client: TelegramClient,
    chat: dict,
    account_id: str,
) -> _ResolvedChat:
    """Resolve chat metadata without joining."""
    chat_ref = chat["chat_ref"]
    username, invite_hash = _parse_chat_reference(chat_ref)

    if username:
        return await _resolve_by_username(client, chat_ref, username, account_id)
    if invite_hash:
        return await _resolve_by_invite(client, chat_ref, invite_hash, account_id)
    return _dead_chat(chat_ref, status="failed", error=f"Invalid chat reference: {chat_ref}")


async def _resolve_by_username(
    client: TelegramClient,
    chat_ref: str,
    username: str,
    account_id: str,
) -> _ResolvedChat:
    """Resolve chat via get_entity(username)."""
    rate_limiter = get_rate_limiter()
    try:
        await rate_limiter.wait_if_needed("get_entity")
        entity = await client.get_entity(username)

        if isinstance(entity, Channel):
            title = entity.title
            subscribers = getattr(entity, "participants_count", None)
            linked_chat_id = None
            is_megagroup = getattr(entity, "megagroup", False)

            if (not is_megagroup) or (subscribers is None):
                try:
                    await rate_limiter.wait_if_needed("get_full_channel")
                    full_channel = await client(GetFullChannelRequest(entity))
                    if subscribers is None:
                        subscribers = getattr(full_channel.full_chat, "participants_count", None)
                    if not is_megagroup:
                        linked_chat_id = getattr(full_channel.full_chat, "linked_chat_id", None)
                except errors.FloodWaitError:
                    raise
                except Exception:
                    pass

            chat_type = _channel_to_chat_type(entity, linked_chat_id)
            moderation = getattr(entity, "join_request", None) or False
            numeric_id = abs(entity.id)
        elif isinstance(entity, TelegramChat):
            chat_type = ChatTypeEnum.GROUP.value
            title = entity.title
            subscribers = getattr(entity, "participants_count", None)
            moderation = False
            numeric_id = abs(entity.id)
            linked_chat_id = None
        else:
            return _dead_chat(
                chat_ref, title=getattr(entity, "first_name", None),
                numeric_id=abs(entity.id) if hasattr(entity, "id") else None,
            )

        logger.info(
            f"Account '{account_id}': resolved '{chat_ref}' "
            f"(type={chat_type}, subs={subscribers})"
        )
        return _ResolvedChat(
            chat_ref=chat_ref, chat_type=chat_type, title=title,
            subscribers=subscribers, moderation=moderation,
            numeric_id=numeric_id, linked_chat_id=linked_chat_id,
        )

    except errors.FloodWaitError:
        raise

    except (
        errors.ChatForbiddenError, errors.ChannelPrivateError,
        errors.ChatRestrictedError, errors.ChannelBannedError,
        errors.UserBannedInChannelError,
    ) as e:
        logger.info(f"Account '{account_id}': '{chat_ref}' inaccessible ({type(e).__name__})")
        return _dead_chat(chat_ref, status="banned", error=str(e))

    except Exception as e:
        logger.error(f"Account '{account_id}': failed to resolve '{chat_ref}': {e}", exc_info=True)
        return _dead_chat(chat_ref, error=str(e))


async def _resolve_by_invite(
    client: TelegramClient,
    chat_ref: str,
    invite_hash: str,
    account_id: str,
) -> _ResolvedChat:
    """Resolve chat via CheckChatInviteRequest (no join)."""
    rate_limiter = get_rate_limiter()
    try:
        result = await client(CheckChatInviteRequest(hash=invite_hash))

        if isinstance(result, ChatInviteAlready):
            entity = result.chat
            if isinstance(entity, Channel):
                chat_type = _channel_to_chat_type(entity)
                title = entity.title
                subscribers = getattr(entity, "participants_count", None)
                if subscribers is None:
                    try:
                        await rate_limiter.wait_if_needed("get_full_channel")
                        full_channel = await client(GetFullChannelRequest(entity))
                        subscribers = getattr(full_channel.full_chat, "participants_count", None)
                    except errors.FloodWaitError:
                        raise
                    except Exception:
                        pass
                moderation = getattr(entity, "join_request", None) or False
                numeric_id = abs(entity.id)
            else:
                chat_type = ChatTypeEnum.GROUP.value
                title = getattr(entity, "title", None)
                subscribers = getattr(entity, "participants_count", None)
                moderation = False
                numeric_id = abs(entity.id) if hasattr(entity, "id") else None

            return _ResolvedChat(
                chat_ref=chat_ref, chat_type=chat_type, title=title,
                subscribers=subscribers, moderation=moderation, numeric_id=numeric_id,
            )

        elif isinstance(result, (ChatInvite, ChatInvitePeek)):
            title = getattr(result, "title", None)
            subscribers = getattr(result, "participants_count", None)
            is_broadcast = getattr(result, "broadcast", False)
            is_megagroup = getattr(result, "megagroup", False)
            if getattr(result, "channel", False) and is_broadcast and not is_megagroup:
                chat_type = ChatTypeEnum.CHANNEL_NO_COMMENTS.value
            else:
                chat_type = ChatTypeEnum.GROUP.value
            moderation = getattr(result, "request_needed", False)
            return _ResolvedChat(
                chat_ref=chat_ref, chat_type=chat_type, title=title,
                subscribers=subscribers, moderation=moderation, numeric_id=None,
            )

        else:
            return _dead_chat(chat_ref, error=f"Unknown invite result: {type(result).__name__}")

    except errors.FloodWaitError:
        raise

    except (errors.InviteHashExpiredError, errors.InviteHashInvalidError) as e:
        return _dead_chat(chat_ref, error=str(e))

    except Exception as e:
        logger.error(f"Account '{account_id}': failed to resolve invite '{chat_ref}': {e}", exc_info=True)
        return _dead_chat(chat_ref, error=str(e))


async def _analyze_chat_activity(
    client: TelegramClient,
    resolved: _ResolvedChat,
    account_id: str,
    settings: GroupSettings,
) -> dict:
    """Join chat, analyze activity, always leave."""
    chat_ref = resolved.chat_ref
    numeric_id = None
    rate_limiter = get_rate_limiter()

    try:
        joined = await join_chat(client, chat_ref)
        numeric_id = joined.id
        cutoff_time = datetime.now(UTC) - timedelta(hours=settings.time_window)

        msg_count = 0
        authors: set[int] = set()
        messages = []
        has_timeout = False

        async def _fetch_messages():
            nonlocal msg_count, authors, messages
            await rate_limiter.wait_if_needed("get_messages")
            async for msg in client.iter_messages(numeric_id, limit=5000):
                converted = _telethon_message_to_model(msg, numeric_id)
                if converted is None:
                    continue
                if converted.timestamp < cutoff_time:
                    break
                msg_count += 1
                authors.add(converted.author_id)
                messages.append(converted)

        try:
            await asyncio.wait_for(_fetch_messages(), timeout=60)
        except asyncio.TimeoutError:
            has_timeout = True

        hours = settings.time_window
        messages_per_hour = round(msg_count / hours, 2) if hours > 0 else 0
        unique_authors_per_hour = round(len(authors) / hours, 2) if hours > 0 else 0
        has_captcha = False
        if settings.detect_captcha:
            has_captcha = await _detect_captcha(client, numeric_id, messages)

        return {
            "messages_per_hour": messages_per_hour,
            "unique_authors_per_hour": unique_authors_per_hour,
            "captcha": has_captcha,
            "partial_data": has_timeout,
        }

    finally:
        if numeric_id is not None:
            try:
                await leave_chat(client, numeric_id)
            except Exception:
                pass


async def _detect_captcha(
    client: TelegramClient,
    chat_id: int,
    messages: list,
) -> bool:
    """Detect captcha bots in messages."""
    rate_limiter = get_rate_limiter()
    for msg in messages:
        try:
            await rate_limiter.wait_if_needed("get_entity")
            sender = await client.get_entity(msg.author_id)
            username = getattr(sender, "username", None)
            if username and username.lower() in CAPTCHA_BOTS:
                return True
            if getattr(sender, "bot", False) and username:
                lower = username.lower()
                if "captcha" in lower or "verify" in lower:
                    return True
        except Exception:
            continue
    return False


def _channel_to_chat_type(entity: Channel, linked_chat_id: int | None = None) -> str:
    """Map Channel to ChatTypeEnum."""
    if getattr(entity, "megagroup", False):
        return ChatTypeEnum.FORUM.value if getattr(entity, "forum", False) else ChatTypeEnum.GROUP.value
    return ChatTypeEnum.CHANNEL_COMMENTS.value if linked_chat_id is not None else ChatTypeEnum.CHANNEL_NO_COMMENTS.value

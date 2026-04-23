"""Single chat worker — processes one chat end-to-end.

Resolves chat metadata, joins and analyzes activity if needed,
returns all metrics in a single dict. Used by GroupAnalysisEngine.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from telethon import errors
from telethon.tl.functions.channels import GetFullChannelRequest
from telethon.tl.functions.messages import CheckChatInviteRequest
from telethon.tl.types import Channel, ChatInvite, ChatInviteAlready, ChatInvitePeek
from telethon.tl.types import Chat as TelegramChat

from chatfilter.models.catalog import AnalysisModeEnum, CatalogChat
from chatfilter.models.group import (
    UNUSABLE_CHAT_TYPES,
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
)
from chatfilter.telegram.client.membership import (
    _parse_chat_reference,
    join_chat,
    leave_chat,
)
from chatfilter.telegram.client.messages import _telethon_message_to_model
from chatfilter.telegram.rate_limiter import get_rate_limiter
from chatfilter.utils.network import detect_network_error

if TYPE_CHECKING:
    from telethon import TelegramClient

    from chatfilter.storage.group_database import GroupDatabase

logger = logging.getLogger(__name__)

CAPTCHA_BOTS = frozenset(
    {
        "missrose_bot",
        "shieldy_bot",
        "join_captcha_bot",
        "grouphelpbot",
        "combot",
    }
)


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

    def to_dict(self) -> dict[str, Any]:
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


def _result_from_resolved(resolved: _ResolvedChat, **overrides: Any) -> ChatResult:
    """Build ChatResult from _ResolvedChat, applying overrides."""
    return ChatResult(
        chat_ref=overrides.get("chat_ref", resolved.chat_ref),
        chat_type=overrides.get("chat_type", resolved.chat_type),
        title=overrides.get("title", resolved.title),
        subscribers=overrides.get("subscribers", resolved.subscribers),
        moderation=overrides.get("moderation", resolved.moderation),
        numeric_id=overrides.get("numeric_id", resolved.numeric_id),
        linked_chat_id=overrides.get("linked_chat_id", resolved.linked_chat_id),
        messages_per_hour=overrides.get("messages_per_hour"),
        unique_authors_per_hour=overrides.get("unique_authors_per_hour"),
        captcha=overrides.get("captcha"),
        partial_data=overrides.get("partial_data", False),
        status=overrides.get("status", resolved.status),
        error=overrides.get("error", resolved.error),
    )


async def process_chat(
    chat: dict[str, Any],
    client: TelegramClient,
    account_id: str,
    settings: GroupSettings,
    db: GroupDatabase | None = None,
) -> ChatResult:
    """Process a single chat end-to-end.

    Two orthogonal outcomes:
      * ``status`` — whether we got a response from Telegram at all
        (``DONE`` = yes, ``ERROR`` = no).
      * ``chat_type`` — what kind of chat it turned out to be (may be
        DEAD/BANNED/PRIVATE/RESTRICTED even when ``status=DONE``).

    Rotation triggers (FloodWait, UserBannedInChannel, network errors,
    unknown exceptions) are re-raised so retry.py can pick the next
    account.  Everything Telegram actually answers becomes a DONE result.
    """
    chat_ref = chat["chat_ref"]

    resolved = await _resolve_chat(client, chat, account_id)

    if resolved.status == GroupChatStatus.ERROR.value:
        return _result_from_resolved(resolved)

    # Unusable chat types (dead, banned, restricted, private) — DONE, no join.
    if resolved.chat_type in {t.value for t in UNUSABLE_CHAT_TYPES}:
        return _result_from_resolved(resolved)

    needs_join = settings.needs_join()
    if resolved.moderation is True:
        return _result_from_resolved(
            resolved,
            moderation=True,
            messages_per_hour="N/A" if needs_join else None,
            unique_authors_per_hour="N/A" if needs_join else None,
            captcha="N/A" if needs_join and settings.detect_captcha else None,
        )

    if not needs_join:
        result = _result_from_resolved(resolved)
        if db is not None:
            _save_catalog_entry(db, result, resolved, chat, AnalysisModeEnum.QUICK)
        return result

    try:
        activity = await _analyze_chat_activity(client, resolved, account_id, settings, db)
        result = _result_from_resolved(resolved, **activity)
        if db is not None:
            _save_catalog_entry(db, result, resolved, chat, AnalysisModeEnum.DEEP)
        return result
    except errors.FloodWaitError:
        raise
    except errors.UserBannedInChannelError:
        raise
    except Exception as e:
        if detect_network_error(e):
            # Network hiccup — propagate, retry.py will rotate account.
            raise
        logger.error(f"Account '{account_id}': failed to analyze '{chat_ref}': {e}", exc_info=True)
        return _result_from_resolved(resolved, status=GroupChatStatus.ERROR.value, error=str(e))


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
    username: str | None = None
    status: str = "done"
    error: str | None = None


def _typed_failure(
    chat_ref: str,
    chat_type: ChatTypeEnum,
    *,
    status: GroupChatStatus = GroupChatStatus.DONE,
    error: str | None = None,
    title: str | None = None,
    numeric_id: int | None = None,
) -> _ResolvedChat:
    """Build a _ResolvedChat for any negative / non-analyzable outcome.

    By default ``status=DONE`` (Telegram answered — billable) and
    ``chat_type`` records the verdict (DEAD / BANNED / RESTRICTED /
    PRIVATE).  ``status=ERROR`` is used only when our own parsing fails,
    never for Telegram responses.
    """
    return _ResolvedChat(
        chat_ref=chat_ref,
        chat_type=chat_type.value,
        title=title,
        subscribers=None,
        moderation=None,
        numeric_id=numeric_id,
        status=status.value,
        error=error,
    )


async def _resolve_chat(
    client: TelegramClient,
    chat: dict[str, Any],
    account_id: str,
) -> _ResolvedChat:
    """Resolve chat metadata without joining."""
    chat_ref = chat["chat_ref"]
    username, invite_hash = _parse_chat_reference(chat_ref)

    if username:
        return await _resolve_by_username(client, chat_ref, username, account_id)
    if invite_hash:
        return await _resolve_by_invite(client, chat_ref, invite_hash, account_id)
    # Our own parse failure — not Telegram's answer. Not billable, retriable.
    return _typed_failure(
        chat_ref,
        ChatTypeEnum.PENDING,
        status=GroupChatStatus.ERROR,
        error=f"Invalid chat reference: {chat_ref}",
    )


async def _resolve_by_username(
    client: TelegramClient,
    chat_ref: str,
    username: str,
    account_id: str,
) -> _ResolvedChat:
    """Resolve chat via get_entity(username).

    Telegram tells us *what* the chat is.  This function maps that
    verdict to a (status, chat_type) pair:

      Exception                                  →  status/chat_type
      UsernameNotOccupied / UsernameInvalid      →  DONE / DEAD
      ChannelPrivate                             →  DONE / PRIVATE
      ChannelBanned / ChatForbidden              →  DONE / BANNED
      ChatRestricted                             →  DONE / RESTRICTED
      Channel.restricted=True  platform='all'    →  DONE / RESTRICTED
      FloodWait / UserBanned / network / unknown →  re-raise (rotate)
    """
    rate_limiter = get_rate_limiter()
    try:
        await rate_limiter.wait_if_needed("get_entity")
        entity = await client.get_entity(username)

        if isinstance(entity, Channel):
            # Globally-restricted channels: Channel.restricted=True with
            # restriction_reason entries targeting platform='all'.
            if getattr(entity, "restricted", False) and _has_global_restriction(entity):
                title = getattr(entity, "title", None)
                return _typed_failure(
                    chat_ref,
                    ChatTypeEnum.RESTRICTED,
                    title=title,
                    numeric_id=abs(entity.id) if hasattr(entity, "id") else None,
                )

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
            # Non-chat entity (User etc.) — treated as dead for group-analysis purposes.
            return _typed_failure(
                chat_ref,
                ChatTypeEnum.DEAD,
                title=getattr(entity, "first_name", None),
                numeric_id=abs(entity.id) if hasattr(entity, "id") else None,
            )

        logger.info(
            f"Account '{account_id}': resolved '{chat_ref}' (type={chat_type}, subs={subscribers})"
        )
        return _ResolvedChat(
            chat_ref=chat_ref,
            chat_type=chat_type,
            title=title,
            subscribers=subscribers,
            moderation=moderation,
            numeric_id=numeric_id,
            linked_chat_id=linked_chat_id,
            username=username,
        )

    except errors.FloodWaitError:
        raise
    except errors.UserBannedInChannelError:
        # Our account is banned here — rotate to another account.
        raise

    except (errors.UsernameNotOccupiedError, errors.UsernameInvalidError) as e:
        logger.info(f"Account '{account_id}': '{chat_ref}' does not exist ({type(e).__name__})")
        return _typed_failure(chat_ref, ChatTypeEnum.DEAD, error=str(e))

    except ValueError as e:
        # Telethon ≥1.42 ``client.get_entity`` wraps UsernameNotOccupiedError
        # in ValueError('No user has "X" as username') and UsernameInvalidError
        # in ValueError('Cannot find any entity corresponding to "X"').
        # Translate those to DEAD instead of letting them propagate.
        msg = str(e)
        if 'No user has "' in msg or "Cannot find any entity corresponding to" in msg:
            logger.info(
                f"Account '{account_id}': '{chat_ref}' does not exist (ValueError from get_entity)"
            )
            return _typed_failure(chat_ref, ChatTypeEnum.DEAD, error=msg)
        raise

    except errors.ChannelPrivateError as e:
        logger.info(f"Account '{account_id}': '{chat_ref}' is private")
        return _typed_failure(chat_ref, ChatTypeEnum.PRIVATE, error=str(e))

    except (errors.ChannelBannedError, errors.ChatForbiddenError) as e:
        logger.info(f"Account '{account_id}': '{chat_ref}' closed by Telegram ({type(e).__name__})")
        return _typed_failure(chat_ref, ChatTypeEnum.BANNED, error=str(e))

    except errors.ChatRestrictedError as e:
        logger.info(f"Account '{account_id}': '{chat_ref}' restricted by Telegram")
        return _typed_failure(chat_ref, ChatTypeEnum.RESTRICTED, error=str(e))

    except Exception as e:
        if detect_network_error(e):
            # Connectivity problem — re-raise so retry.py rotates account.
            raise
        logger.error(f"Account '{account_id}': failed to resolve '{chat_ref}': {e}", exc_info=True)
        raise


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
                chat_ref=chat_ref,
                chat_type=chat_type,
                title=title,
                subscribers=subscribers,
                moderation=moderation,
                numeric_id=numeric_id,
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
                chat_ref=chat_ref,
                chat_type=chat_type,
                title=title,
                subscribers=subscribers,
                moderation=moderation,
                numeric_id=None,
            )

        else:
            return _typed_failure(
                chat_ref,
                ChatTypeEnum.DEAD,
                error=f"Unknown invite result: {type(result).__name__}",
            )

    except errors.FloodWaitError:
        raise
    except errors.UserBannedInChannelError:
        raise

    except (errors.InviteHashExpiredError, errors.InviteHashInvalidError) as e:
        return _typed_failure(chat_ref, ChatTypeEnum.DEAD, error=str(e))

    except errors.ChannelPrivateError as e:
        return _typed_failure(chat_ref, ChatTypeEnum.PRIVATE, error=str(e))

    except (errors.ChannelBannedError, errors.ChatForbiddenError) as e:
        return _typed_failure(chat_ref, ChatTypeEnum.BANNED, error=str(e))

    except errors.ChatRestrictedError as e:
        return _typed_failure(chat_ref, ChatTypeEnum.RESTRICTED, error=str(e))

    except Exception as e:
        if detect_network_error(e):
            raise
        logger.error(
            f"Account '{account_id}': failed to resolve invite '{chat_ref}': {e}", exc_info=True
        )
        raise


async def _analyze_chat_activity(
    client: TelegramClient,
    resolved: _ResolvedChat,
    account_id: str,
    settings: GroupSettings,
    db: GroupDatabase | None = None,
) -> dict[str, Any]:
    """Join chat, analyze activity.

    On success: account stays in chat, subscription is tracked, eviction if over limit.
    On failure: account leaves the chat.
    """
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

        async def _fetch_messages() -> None:
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
        except TimeoutError:
            has_timeout = True

        hours = settings.time_window
        messages_per_hour = round(msg_count / hours, 2) if hours > 0 else 0
        unique_authors_per_hour = round(len(authors) / hours, 2) if hours > 0 else 0
        has_captcha = False
        if settings.detect_captcha:
            has_captcha = await _detect_captcha(client, numeric_id, messages)

        # Success: account stays in chat — track subscription and evict if over limit
        if db is not None and numeric_id is not None:
            try:
                db.add_subscription(account_id, chat_ref, numeric_id)
                count = db.count_subscriptions(account_id)
                max_chats = db.get_max_chats_per_account()
                if count > max_chats:
                    await _evict_oldest_subscription(client, db, account_id)
            except Exception as e:
                logger.warning(f"Failed to add subscription for account {account_id}: {e}")

        return {
            "messages_per_hour": messages_per_hour,
            "unique_authors_per_hour": unique_authors_per_hour,
            "captcha": has_captcha,
            "partial_data": has_timeout,
        }

    except Exception:
        # Analysis failed — leave the chat (no point staying)
        if numeric_id is not None:
            try:
                await leave_chat(client, numeric_id)
            except Exception as e:
                logger.warning(f"Failed to leave chat {numeric_id} during error handling: {e}")
        raise


def _save_catalog_entry(
    db: GroupDatabase,
    result: ChatResult,
    resolved: _ResolvedChat,
    chat: dict[str, Any],
    mode: AnalysisModeEnum,
) -> None:
    """Save ChatResult to chat_catalog and link to group_chat."""
    now = datetime.now(UTC)
    mph = result.messages_per_hour
    uaph = result.unique_authors_per_hour
    catalog_chat = CatalogChat(
        id=resolved.chat_ref,
        telegram_id=resolved.numeric_id or 0,
        title=resolved.title or "",
        username=resolved.username,
        chat_type=ChatTypeEnum(resolved.chat_type),
        subscribers=resolved.subscribers or 0,
        moderation=resolved.moderation or False,
        messages_per_hour=float(mph) if isinstance(mph, (int, float)) else 0.0,
        unique_authors_per_hour=float(uaph) if isinstance(uaph, (int, float)) else 0.0,
        captcha=bool(result.captcha) if isinstance(result.captcha, bool) else False,
        partial_data=result.partial_data,
        last_check=now,
        analysis_mode=mode,
        created_at=now,
    )
    try:
        db.save_catalog_chat(catalog_chat)
    except Exception as e:
        logger.warning(f"Failed to save catalog chat {resolved.chat_ref}: {e}")
    group_chat_id = chat.get("id")
    if group_chat_id is not None:
        try:
            db.link_to_group(resolved.chat_ref, int(group_chat_id))
        except Exception as e:
            logger.warning(f"Failed to link chat {resolved.chat_ref} to group {group_chat_id}: {e}")


async def _evict_oldest_subscription(
    client: TelegramClient,
    db: GroupDatabase,
    account_id: str,
) -> None:
    """Leave the oldest subscribed chat and remove its subscription record."""
    oldest = db.get_oldest_subscription(account_id)
    if oldest is None:
        return
    try:
        await leave_chat(client, oldest.telegram_chat_id)
    except Exception as e:
        logger.warning(f"Failed to leave chat {oldest.telegram_chat_id} during eviction: {e}")
    try:
        db.remove_subscription(account_id, oldest.catalog_chat_id)
    except Exception as e:
        logger.warning(
            f"Failed to remove subscription {oldest.catalog_chat_id} for account {account_id}: {e}"
        )
    logger.info(f"Account '{account_id}': evicted oldest subscription '{oldest.catalog_chat_id}'")


async def _detect_captcha(
    client: TelegramClient,
    chat_id: int,
    messages: list[Any],
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
        return (
            ChatTypeEnum.FORUM.value
            if getattr(entity, "forum", False)
            else ChatTypeEnum.GROUP.value
        )
    return (
        ChatTypeEnum.CHANNEL_COMMENTS.value
        if linked_chat_id is not None
        else ChatTypeEnum.CHANNEL_NO_COMMENTS.value
    )


def _has_global_restriction(entity: Channel) -> bool:
    """True if channel carries a platform='all' restriction reason.

    Channel.restricted alone is insufficient — a reason targeting only
    'ios' or 'android' still lets the channel work on every other
    platform. Only ``platform == 'all'`` means Telegram globally hid it.
    """
    reasons = getattr(entity, "restriction_reason", None) or []
    return any(getattr(r, "platform", "") == "all" for r in reasons)

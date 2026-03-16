"""Telegram chat fetching and dialog management."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from telethon.errors import (
    ChannelBannedError,
    ChannelPrivateError,
    ChatForbiddenError,
    ChatRestrictedError,
    UserBannedInChannelError,
)
from telethon.tl.functions.channels import GetFullChannelRequest
from telethon.tl.types import Channel, User
from telethon.tl.types import Chat as TelegramChat

from chatfilter.models.chat import Chat, ChatType
from chatfilter.telegram.rate_limiter import get_rate_limiter
from chatfilter.telegram.retry import with_retry_for_reads

if TYPE_CHECKING:
    from telethon import TelegramClient as TelegramClientType
    from telethon.tl.custom import Dialog

logger = logging.getLogger(__name__)


def _dialog_to_chat(
    dialog: Dialog, is_archived: bool = False, current_user_id: int | None = None
) -> Chat | None:
    """Convert Telethon Dialog to our Chat model.

    Args:
        dialog: Telethon Dialog object
        is_archived: Whether the dialog is from the archived folder
        current_user_id: Current user's ID to detect Saved Messages

    Returns:
        Chat model or None if dialog type is not supported
    """
    entity = dialog.entity

    # Determine chat type from entity
    is_saved_messages = False
    if isinstance(entity, User):
        chat_type = ChatType.PRIVATE
        # Check if this is Saved Messages (chat with yourself)
        is_saved_messages = current_user_id is not None and entity.id == current_user_id
        if is_saved_messages:
            title = "Saved Messages"
        else:
            title = dialog.name or entity.first_name or "Private Chat"
        username = entity.username
        member_count = None
    elif isinstance(entity, Channel):
        if entity.megagroup:
            chat_type = ChatType.FORUM if getattr(entity, "forum", False) else ChatType.SUPERGROUP
        else:
            chat_type = ChatType.CHANNEL
        title = dialog.title or entity.title or "Unknown Channel"
        username = entity.username
        member_count = getattr(entity, "participants_count", None)
    elif isinstance(entity, TelegramChat):
        chat_type = ChatType.GROUP
        title = dialog.title or entity.title or "Unknown Group"
        username = None  # Basic groups don't have usernames
        member_count = getattr(entity, "participants_count", None)
    else:
        # Unknown entity type
        return None

    # Telegram IDs can be negative for groups/channels, we store absolute value
    chat_id = abs(dialog.id) if dialog.id else abs(entity.id)

    return Chat(
        id=chat_id,
        title=title,
        chat_type=chat_type,
        username=username,
        member_count=member_count,
        is_archived=is_archived,
        is_saved_messages=is_saved_messages,
    )


@with_retry_for_reads(max_attempts=3, base_delay=1.0, max_delay=30.0)
async def get_chat_slowmode(client: TelegramClientType, chat_id: int) -> int | None:
    """Get slowmode delay in seconds for a chat.

    Args:
        client: Telethon client
        chat_id: Chat ID (can be negative or positive)

    Returns:
        Slowmode delay in seconds, or None if:
        - Chat is not a channel/supergroup
        - Slowmode is disabled (0 seconds)
        - Cannot access full channel info

    Note:
        Only channels and supergroups can have slowmode.
        Private chats and basic groups return None.
    """
    try:
        # Get the entity first
        entity = await client.get_entity(chat_id)

        # Only channels/supergroups can have slowmode
        if not isinstance(entity, Channel):
            return None

        # Get full channel info
        full_channel_result = await client(GetFullChannelRequest(channel=entity))
        full_chat = full_channel_result.full_chat

        # Get slowmode_seconds (None if not set, 0 if disabled)
        slowmode = getattr(full_chat, "slowmode_seconds", None)

        # Return None if slowmode is 0 (disabled) or None (not available)
        return slowmode if slowmode else None

    except Exception as e:
        # Log but don't fail - slowmode is optional metadata
        logger.debug(f"Could not fetch slowmode for chat {chat_id}: {e}")
        return None


@with_retry_for_reads(max_attempts=3, base_delay=1.0, max_delay=30.0)
async def get_dialogs(
    client: TelegramClientType,
    chat_types: set[ChatType] | None = None,
    *,
    _cache: dict[int, list[Chat]] | None = None,
) -> list[Chat]:
    """Get list of user's dialogs (chats) from Telegram.

    Fetches all dialogs from both main and archived folders and converts them
    to Chat models. Archived chats are marked with is_archived=True.
    Results are deduplicated by chat_id to handle edge cases during pagination.

    Network errors (ConnectionError, TimeoutError, OSError, SSL errors) are
    automatically retried with exponential backoff (up to 3 attempts).

    Args:
        client: Connected TelegramClient instance
        chat_types: Optional set of chat types to filter by.
            If None, returns all chat types.
        _cache: Internal cache dict (used for session-scoped caching).
            Pass the same dict across calls to enable caching.

    Returns:
        List of Chat models, sorted by dialog order (most recent first).
        Includes both main and archived chats.

    Example:
        ```python
        async with loader.create_client() as client:
            # Get all chats
            all_chats = await get_dialogs(client)

            # Get only groups and supergroups
            groups = await get_dialogs(
                client,
                chat_types={ChatType.GROUP, ChatType.SUPERGROUP}
            )
        ```
    """
    # Check cache if provided
    cache_key = id(client)
    if _cache is not None and cache_key in _cache:
        cached = _cache[cache_key]
        if chat_types is None:
            return cached
        return [c for c in cached if c.chat_type in chat_types]

    # Proactive rate limiting to prevent FloodWaitError
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("get_dialogs")

    # Get current user ID to detect Saved Messages
    current_user_id: int | None = None
    try:
        me = await client.get_me()
        current_user_id = me.id
    except Exception as e:
        logger.debug(f"Could not fetch current user ID: {e}")
        # Continue without Saved Messages detection

    # Fetch all dialogs from both main (folder=0) and archived (folder=1) folders
    chats: list[Chat] = []
    seen_ids: set[int] = set()

    try:
        # Fetch from main folder (folder=0)
        async for dialog in client.iter_dialogs(folder=0):
            try:
                chat = _dialog_to_chat(dialog, is_archived=False, current_user_id=current_user_id)
                if chat is None:
                    continue

                # Deduplicate by chat_id (handles edge case of duplicates during pagination)
                if chat.id in seen_ids:
                    continue
                seen_ids.add(chat.id)
                chats.append(chat)
            except (
                ChatForbiddenError,
                ChannelPrivateError,
                UserBannedInChannelError,
                ChatRestrictedError,
                ChannelBannedError,
            ) as e:
                # Skip inaccessible chats (user kicked/banned/left, or chat deleted/private)
                logger.info(f"Skipping inaccessible dialog: {type(e).__name__}")
                continue

        # Fetch from archived folder (folder=1)
        async for dialog in client.iter_dialogs(folder=1):
            try:
                chat = _dialog_to_chat(dialog, is_archived=True, current_user_id=current_user_id)
                if chat is None:
                    continue

                # Deduplicate by chat_id (handles edge case of duplicates)
                if chat.id in seen_ids:
                    continue
                seen_ids.add(chat.id)
                chats.append(chat)
            except (
                ChatForbiddenError,
                ChannelPrivateError,
                UserBannedInChannelError,
                ChatRestrictedError,
                ChannelBannedError,
            ) as e:
                # Skip inaccessible chats (user kicked/banned/left, or chat deleted/private)
                logger.info(f"Skipping inaccessible archived dialog: {type(e).__name__}")
                continue
    except (
        ChatForbiddenError,
        ChannelPrivateError,
        UserBannedInChannelError,
        ChatRestrictedError,
        ChannelBannedError,
    ):
        # If iter_dialogs itself fails with access error, that's unusual but handle it
        logger.warning("Access error while iterating dialogs, returning partial results")
        pass

    # Store in cache if provided
    if _cache is not None:
        _cache[cache_key] = chats

    # Apply type filter
    if chat_types is not None:
        return [c for c in chats if c.chat_type in chat_types]

    return chats

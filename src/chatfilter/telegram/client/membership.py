"""Telegram chat membership operations (join, leave, account info)."""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from telethon.errors import FloodWaitError
from telethon.tl.functions.channels import JoinChannelRequest, LeaveChannelRequest
from telethon.tl.functions.messages import DeleteChatUserRequest, ImportChatInviteRequest
from telethon.tl.types import Channel, User
from telethon.tl.types import Chat as TelegramChat

from chatfilter.models.chat import Chat, ChatType
from chatfilter.telegram.rate_limiter import get_rate_limiter
from chatfilter.telegram.retry import with_retry_for_reads

if TYPE_CHECKING:
    from telethon import TelegramClient as TelegramClientType

    from chatfilter.models.account import AccountInfo

logger = logging.getLogger(__name__)


class JoinChatError(Exception):
    """Raised when joining a chat fails."""


class RateLimitedJoinError(JoinChatError):
    """Raised when joining a chat fails due to rate limiting (FloodWait).

    Preserves the wait time in seconds specified by Telegram.

    Attributes:
        wait_seconds: Number of seconds to wait before retrying (int or float > 0)
    """

    def __init__(self, message: str = "", wait_seconds: int | float = 60) -> None:
        """Initialize RateLimitedJoinError with validated wait_seconds.

        Args:
            message: Error message
            wait_seconds: Seconds to wait (must be int/float > 0, defaults to 60 if invalid)
        """
        super().__init__(message)

        # Validate wait_seconds: must be int or float > 0
        if isinstance(wait_seconds, (int, float)) and wait_seconds > 0:
            self.wait_seconds = wait_seconds
        else:
            # Invalid input - default to 60 seconds
            self.wait_seconds = 60


class LeaveChatError(Exception):
    """Raised when leaving a chat fails."""


# Regex patterns for parsing Telegram links
_INVITE_HASH_PATTERN = re.compile(
    r"(?:https?://)?(?:t\.me|telegram\.me)/(?:joinchat/|\+)([a-zA-Z0-9_-]+)"
)
_PUBLIC_LINK_PATTERN = re.compile(r"(?:https?://)?(?:t\.me|telegram\.me)/([a-zA-Z0-9_]+)")


def _parse_chat_reference(ref: str) -> tuple[str | None, str | None]:
    """Parse a chat reference (username, link, or invite hash).

    Args:
        ref: Chat reference - can be:
            - Username: "@channelname" or "channelname"
            - Public link: "https://t.me/channelname" or "t.me/channelname"
            - Private invite: "https://t.me/joinchat/XXXXX" or "https://t.me/+XXXXX"

    Returns:
        Tuple of (username, invite_hash) where only one is set.
        If input is invalid, both are None.
    """
    ref = ref.strip()
    if not ref:
        return None, None

    # Check for invite links first (more specific pattern)
    match = _INVITE_HASH_PATTERN.match(ref)
    if match:
        return None, match.group(1)

    # Check for public links
    match = _PUBLIC_LINK_PATTERN.match(ref)
    if match:
        return match.group(1), None

    # Check for @username format
    if ref.startswith("@"):
        username = ref[1:]
        if username and username.isalnum() or "_" in username:
            return username, None

    # Assume bare username
    if ref.replace("_", "").isalnum():
        return ref, None

    return None, None


@with_retry_for_reads(max_attempts=3, base_delay=2.0, max_delay=30.0)
async def join_chat(
    client: TelegramClientType,
    chat_ref: str,
) -> Chat:
    """Join a public chat/channel by username or invite link.

    Supports joining chats via:
    - Username: "@channelname" or "channelname"
    - Public link: "https://t.me/channelname" or "t.me/channelname"
    - Private invite: "https://t.me/joinchat/XXXXX" or "https://t.me/+XXXXX"

    Args:
        client: Connected TelegramClient instance
        chat_ref: Chat reference (username or link)

    Returns:
        Chat model of the joined chat

    Raises:
        JoinChatError: If joining fails (invalid link, already banned, etc.)
        ValueError: If chat_ref format is invalid

    Example:
        ```python
        async with loader.create_client() as client:
            # Join by username
            chat = await join_chat(client, "@python_ru")

            # Join by link
            chat = await join_chat(client, "https://t.me/python_ru")

            # Join by invite link
            chat = await join_chat(client, "https://t.me/+XXXXXX")
        ```
    """
    username, invite_hash = _parse_chat_reference(chat_ref)

    if username is None and invite_hash is None:
        raise ValueError(f"Invalid chat reference format: {chat_ref}")

    # Proactive rate limiting to prevent FloodWaitError
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("join_chat")

    try:
        if invite_hash:
            # Private invite link
            updates = await client(ImportChatInviteRequest(invite_hash))
            # ImportChatInviteRequest returns Updates with chats
            if hasattr(updates, "chats") and updates.chats:
                entity = updates.chats[0]
            else:
                raise JoinChatError("Failed to get chat info after joining")
        else:
            # Public channel/group by username
            updates = await client(JoinChannelRequest(username))
            # JoinChannelRequest returns Updates with chats
            if hasattr(updates, "chats") and updates.chats:
                entity = updates.chats[0]
            else:
                raise JoinChatError("Failed to get chat info after joining")

        # Convert to our Chat model
        if isinstance(entity, Channel):
            if entity.megagroup:
                chat_type = (
                    ChatType.FORUM if getattr(entity, "forum", False) else ChatType.SUPERGROUP
                )
            else:
                chat_type = ChatType.CHANNEL
            title = entity.title or "Unknown"
            chat_username = entity.username
            member_count = getattr(entity, "participants_count", None)
        elif isinstance(entity, TelegramChat):
            chat_type = ChatType.GROUP
            title = entity.title or "Unknown"
            chat_username = None
            member_count = getattr(entity, "participants_count", None)
        else:
            chat_type = ChatType.GROUP
            title = getattr(entity, "title", "Unknown")
            chat_username = getattr(entity, "username", None)
            member_count = None

        chat_id = abs(entity.id)

        return Chat(
            id=chat_id,
            title=title,
            chat_type=chat_type,
            username=chat_username,
            member_count=member_count,
        )

    except ValueError:
        # Re-raise our own ValueError
        raise
    except JoinChatError:
        # Re-raise our own errors
        raise
    except FloodWaitError as e:
        # FloodWait when joining chat - preserve wait time in specialized exception
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        raise RateLimitedJoinError(
            f"Rate limited by Telegram when joining {chat_ref}. {friendly_msg}",
            wait_seconds=e.seconds,
        ) from e
    except Exception as e:
        error_msg = str(e).lower()
        if "invite" in error_msg and "expired" in error_msg:
            raise JoinChatError(f"Invite link has expired: {chat_ref}") from e
        if "invite" in error_msg and "invalid" in error_msg:
            raise JoinChatError(f"Invalid invite link: {chat_ref}") from e
        if "banned" in error_msg or "kicked" in error_msg:
            raise JoinChatError(f"You are banned from this chat: {chat_ref}") from e
        if "private" in error_msg:
            raise JoinChatError(f"Chat is private and requires an invite link: {chat_ref}") from e
        if "username" in error_msg and ("invalid" in error_msg or "not" in error_msg):
            raise JoinChatError(f"Username not found: {chat_ref}") from e
        raise JoinChatError(f"Failed to join chat: {e}") from e


@with_retry_for_reads(max_attempts=3, base_delay=1.0, max_delay=30.0)
async def get_account_info(
    client: TelegramClientType,
) -> AccountInfo:
    """Get account information including Premium status and subscription count.

    Fetches the current user's account info and counts their chat subscriptions
    to track against Telegram's limits (500 for standard, 1000 for Premium).

    Args:
        client: Connected TelegramClient instance

    Returns:
        AccountInfo with Premium status and chat subscription count

    Example:
        ```python
        async with loader.create_client() as client:
            info = await get_account_info(client)
            print(f"Account: {info.display_name}")
            print(f"Premium: {info.is_premium}")
            print(f"Chats: {info.chat_count}/{info.chat_limit}")
            print(f"Remaining: {info.remaining_slots}")

            if info.is_near_limit:
                print("Warning: Approaching subscription limit!")
        ```
    """
    from chatfilter.models.account import AccountInfo

    # Proactive rate limiting
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("get_account_info")

    try:
        # Get current user info
        me = await client.get_me()

        # Count chat subscriptions (excluding Saved Messages and private chats)
        # We count all dialogs from both main and archived folders
        chat_count = 0
        seen_ids: set[int] = set()

        # Count from main folder
        async for dialog in client.iter_dialogs(folder=0):
            entity = dialog.entity
            # Skip private chats (User entities) - they don't count toward limit
            if isinstance(entity, User):
                continue
            # Deduplicate
            dialog_id = abs(dialog.id) if dialog.id else abs(entity.id)
            if dialog_id in seen_ids:
                continue
            seen_ids.add(dialog_id)
            chat_count += 1

        # Count from archived folder
        async for dialog in client.iter_dialogs(folder=1):
            entity = dialog.entity
            # Skip private chats
            if isinstance(entity, User):
                continue
            # Deduplicate
            dialog_id = abs(dialog.id) if dialog.id else abs(entity.id)
            if dialog_id in seen_ids:
                continue
            seen_ids.add(dialog_id)
            chat_count += 1

        return AccountInfo(
            user_id=me.id,
            username=me.username,
            first_name=me.first_name,
            last_name=me.last_name,
            is_premium=getattr(me, "premium", False) or False,
            chat_count=chat_count,
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        from chatfilter.telegram.client.messages import MessageFetchError

        raise MessageFetchError(f"Rate limited by Telegram. {friendly_msg}") from e
    except Exception as e:
        from chatfilter.telegram.client.messages import MessageFetchError

        raise MessageFetchError(f"Failed to get account info: {e}") from e


@with_retry_for_reads(max_attempts=3, base_delay=2.0, max_delay=30.0)
async def leave_chat(
    client: TelegramClientType,
    chat_id: int,
) -> bool:
    """Leave a chat/channel to free up a subscription slot.

    This function handles different chat types appropriately:
    - Channels and supergroups: Uses LeaveChannelRequest
    - Basic groups: Uses DeleteChatUserRequest (removes self from group)

    Args:
        client: Connected TelegramClient instance
        chat_id: ID of the chat to leave (can be negative or positive)

    Returns:
        True if successfully left the chat

    Raises:
        LeaveChatError: If leaving fails (not a member, chat doesn't exist, etc.)

    Example:
        ```python
        async with loader.create_client() as client:
            # Leave a channel to free up a slot
            await leave_chat(client, 123456789)

            # Now we can join a new chat
            new_chat = await join_chat(client, "@newchannel")
        ```
    """
    # Proactive rate limiting
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("leave_chat")

    try:
        # Get the entity to determine chat type
        entity = await client.get_entity(chat_id)

        if isinstance(entity, Channel):
            # Channel or supergroup - use LeaveChannelRequest
            await client(LeaveChannelRequest(channel=entity))
            logger.info(f"Left channel/supergroup: {chat_id} ({entity.title})")
            return True
        elif isinstance(entity, TelegramChat):
            # Basic group - use DeleteChatUserRequest (remove self)
            me = await client.get_me()
            await client(DeleteChatUserRequest(chat_id=chat_id, user_id=me.id))
            logger.info(f"Left basic group: {chat_id} ({entity.title})")
            return True
        else:
            raise LeaveChatError(
                f"Cannot leave chat {chat_id}: unsupported chat type {type(entity).__name__}"
            )

    except LeaveChatError:
        raise
    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        raise LeaveChatError(f"Rate limited by Telegram when leaving chat. {friendly_msg}") from e
    except Exception as e:
        error_msg = str(e).lower()
        if "not a member" in error_msg or "user_not_participant" in error_msg:
            raise LeaveChatError(f"Not a member of chat {chat_id}") from e
        if "peer" in error_msg or "invalid" in error_msg:
            raise LeaveChatError(f"Chat not found or invalid: {chat_id}") from e
        if "private" in error_msg or "forbidden" in error_msg:
            raise LeaveChatError(f"Cannot leave private chat: {chat_id}") from e
        raise LeaveChatError(f"Failed to leave chat: {e}") from e


async def join_chat_with_rotation(
    client: TelegramClientType,
    chat_ref: str,
    chats_to_leave: list[int] | None = None,
) -> tuple[Chat, list[int]]:
    """Join a chat, automatically leaving old chats if at subscription limit.

    This function implements smart rotation for bulk chat analysis workflows:
    1. Checks if account is at subscription limit
    2. If at limit and chats_to_leave provided, leaves those chats first
    3. Joins the new chat

    Args:
        client: Connected TelegramClient instance
        chat_ref: Chat reference to join (username or link)
        chats_to_leave: Optional list of chat IDs to leave if at limit.
                       If None and at limit, raises JoinChatError.

    Returns:
        Tuple of (joined_chat, actually_left_chat_ids)

    Raises:
        JoinChatError: If joining fails or at limit with no chats to leave

    Example:
        ```python
        async with loader.create_client() as client:
            # Get account info
            info = await get_account_info(client)

            if info.is_at_limit:
                # Get list of old/inactive chats to rotate out
                chats_to_leave = [old_chat_id_1, old_chat_id_2]

                # Join new chat, leaving old ones if needed
                new_chat, left_ids = await join_chat_with_rotation(
                    client,
                    "@newchannel",
                    chats_to_leave=chats_to_leave
                )
                print(f"Joined {new_chat.title}, left {len(left_ids)} chats")
            else:
                new_chat = await join_chat(client, "@newchannel")
        ```
    """

    # Check current account status
    account_info = await get_account_info(client)
    left_chat_ids: list[int] = []

    if account_info.is_at_limit:
        if not chats_to_leave:
            raise JoinChatError(
                f"At subscription limit ({account_info.chat_count}/{account_info.chat_limit}). "
                f"Provide chats_to_leave to enable rotation."
            )

        # Leave chats to make room (leave 1 more than needed for buffer)
        needed_slots = 1
        for chat_id in chats_to_leave[:needed_slots]:
            try:
                await leave_chat(client, chat_id)
                left_chat_ids.append(chat_id)
                logger.info(f"Left chat {chat_id} to make room for new subscription")
            except LeaveChatError as e:
                logger.warning(f"Failed to leave chat {chat_id}: {e}")
                # Continue trying other chats
                continue

        if not left_chat_ids:
            raise JoinChatError(
                f"At subscription limit and could not leave any of the provided chats. "
                f"Current: {account_info.chat_count}/{account_info.chat_limit}"
            )

    # Join the new chat
    joined_chat = await join_chat(client, chat_ref)
    return joined_chat, left_chat_ids

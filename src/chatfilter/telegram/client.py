"""Telegram client initialization from session and config files."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import socks
from telethon import TelegramClient
from telethon.errors import (
    ChannelBannedError,
    ChannelPrivateError,
    ChatForbiddenError,
    ChatRestrictedError,
    UserBannedInChannelError,
)
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.tl.functions.messages import GetForumTopicsRequest, ImportChatInviteRequest
from telethon.tl.types import Channel, User
from telethon.tl.types import Chat as TelegramChat

from chatfilter.config import ProxyConfig, ProxyType, load_proxy_config
from chatfilter.models.chat import Chat, ChatType
from chatfilter.models.message import Message
from chatfilter.telegram.retry import with_retry_for_reads

if TYPE_CHECKING:
    from telethon import TelegramClient as TelegramClientType
    from telethon.tl.custom import Dialog
    from telethon.tl.types import Message as TelegramMessage

logger = logging.getLogger(__name__)


class TelegramConfigError(Exception):
    """Raised when config file is invalid or missing required fields."""


class SessionFileError(Exception):
    """Raised when session file is invalid, incompatible, or locked."""


@dataclass(frozen=True)
class TelegramConfig:
    """Telegram API configuration loaded from JSON file.

    Attributes:
        api_id: Telegram API ID (integer)
        api_hash: Telegram API hash (string)
    """

    api_id: int
    api_hash: str

    @classmethod
    def from_json_file(cls, path: Path) -> TelegramConfig:
        """Load config from JSON file.

        Args:
            path: Path to JSON config file

        Returns:
            TelegramConfig instance

        Raises:
            TelegramConfigError: If file is invalid or missing required fields
            FileNotFoundError: If config file doesn't exist
        """
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise TelegramConfigError(f"Invalid JSON in config file: {e}") from e

        # Validate required fields
        missing = []
        if "api_id" not in data:
            missing.append("api_id")
        if "api_hash" not in data:
            missing.append("api_hash")

        if missing:
            raise TelegramConfigError(f"Missing required fields in config: {', '.join(missing)}")

        # Validate types
        api_id = data["api_id"]
        api_hash = data["api_hash"]

        if not isinstance(api_id, int):
            try:
                api_id = int(api_id)
            except (ValueError, TypeError) as e:
                raise TelegramConfigError(
                    f"api_id must be an integer, got: {type(api_id).__name__}"
                ) from e

        if not isinstance(api_hash, str):
            raise TelegramConfigError(
                f"api_hash must be a string, got: {type(api_hash).__name__}"
            )

        if not api_hash:
            raise TelegramConfigError("api_hash cannot be empty")

        return cls(api_id=api_id, api_hash=api_hash)


def validate_session_file(session_path: Path) -> None:
    """Validate Telethon session file format and accessibility.

    Checks:
    - File exists
    - File is a valid SQLite database
    - Session format is compatible with Telethon 1.x (current library version)
    - File is not locked by another process

    Args:
        session_path: Path to .session file

    Raises:
        FileNotFoundError: If session file doesn't exist
        SessionFileError: If session is invalid, incompatible, or locked
    """
    if not session_path.exists():
        raise FileNotFoundError(f"Session file not found: {session_path}")

    # Check if it's a valid SQLite database
    try:
        conn = sqlite3.connect(f"file:{session_path}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.OperationalError as e:
        error_msg = str(e).lower()
        if "locked" in error_msg or "database is locked" in error_msg:
            raise SessionFileError(
                f"Session file is locked by another process. "
                f"Make sure no other application is using this session: {session_path}"
            ) from e
        raise SessionFileError(f"Invalid session file (not a valid database): {e}") from e

    try:
        cursor = conn.cursor()

        # Check for Telethon 1.x session format (has 'sessions' and 'entities' tables)
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        except sqlite3.DatabaseError as e:
            raise SessionFileError(f"Invalid session file (not a valid database): {e}") from e
        tables = {row[0] for row in cursor.fetchall()}

        # Telethon 1.x required tables
        required_tables = {"sessions", "entities"}

        # Telethon 2.x has different schema (different table structure)
        # We're using telethon>=1.34.0 which is 1.x series
        if not required_tables.issubset(tables):
            if "version" in tables:
                # Likely Telethon 2.x format
                raise SessionFileError(
                    "Session file appears to be from Telethon 2.x which is incompatible. "
                    "Please export a new session using Telethon 1.x (>=1.34.0)"
                )
            raise SessionFileError(
                f"Invalid session file format. Expected tables {required_tables}, "
                f"found: {tables}"
            )

        # Verify session has data
        cursor.execute("SELECT COUNT(*) FROM sessions")
        count = cursor.fetchone()[0]
        if count == 0:
            raise SessionFileError(
                "Session file is empty (no session data). "
                "Please use a session that has been authenticated."
            )

    except sqlite3.OperationalError as e:
        error_msg = str(e).lower()
        if "locked" in error_msg:
            raise SessionFileError(
                f"Session file is locked by another process. "
                f"Make sure no other application is using this session: {session_path}"
            ) from e
        raise SessionFileError(f"Error reading session file: {e}") from e
    finally:
        conn.close()


class TelegramClientLoader:
    """Loader for creating Telethon client from session and config files.

    Example:
        ```python
        loader = TelegramClientLoader(
            session_path=Path("my_account.session"),
            config_path=Path("telegram_config.json"),
        )
        async with loader.create_client() as client:
            me = await client.get_me()
            print(f"Logged in as {me.username}")
        ```
    """

    def __init__(self, session_path: Path, config_path: Path) -> None:
        """Initialize loader with session and config file paths.

        Args:
            session_path: Path to Telethon .session file
            config_path: Path to JSON config file with api_id and api_hash
        """
        self._session_path = session_path
        self._config_path = config_path
        self._config: TelegramConfig | None = None

    @property
    def session_path(self) -> Path:
        """Path to session file."""
        return self._session_path

    @property
    def config_path(self) -> Path:
        """Path to config file."""
        return self._config_path

    def validate(self) -> None:
        """Validate both session and config files.

        Call this before create_client() to get early validation errors.

        Raises:
            FileNotFoundError: If session or config file doesn't exist
            SessionFileError: If session file is invalid
            TelegramConfigError: If config file is invalid
        """
        # Validate config first (cheaper operation)
        self._config = TelegramConfig.from_json_file(self._config_path)

        # Validate session file
        validate_session_file(self._session_path)

    def create_client(
        self,
        proxy: ProxyConfig | None = None,
        use_saved_proxy: bool = True,
    ) -> TelegramClientType:
        """Create and return a Telethon client instance.

        Validates files if not already validated. The returned client
        should be used as an async context manager.

        Args:
            proxy: Explicit proxy configuration to use. If None and
                use_saved_proxy is True, loads config from saved settings.
            use_saved_proxy: If True and no explicit proxy provided,
                loads proxy settings from data/config/proxy.json.
                Set to False to disable proxy entirely.

        Returns:
            TelegramClient instance (not connected yet)

        Raises:
            FileNotFoundError: If session or config file doesn't exist
            SessionFileError: If session file is invalid
            TelegramConfigError: If config file is invalid

        Example:
            ```python
            client = loader.create_client()
            async with client:
                # client is connected here
                me = await client.get_me()
            ```
        """
        if self._config is None:
            self.validate()

        assert self._config is not None  # for type checker

        # Telethon expects session path without .session extension
        session_name = str(self._session_path)
        if session_name.endswith(".session"):
            session_name = session_name[:-8]

        # Resolve proxy configuration
        telethon_proxy = None
        effective_proxy = proxy
        if effective_proxy is None and use_saved_proxy:
            effective_proxy = load_proxy_config()

        if effective_proxy is not None and effective_proxy.enabled and effective_proxy.host:
            proxy_type_map = {
                ProxyType.SOCKS5: socks.SOCKS5,
                ProxyType.HTTP: socks.HTTP,
            }
            telethon_proxy = (
                proxy_type_map[effective_proxy.proxy_type],
                effective_proxy.host,
                effective_proxy.port,
                True,  # rdns (resolve DNS remotely)
                effective_proxy.username or None,
                effective_proxy.password or None,
            )

        return TelegramClient(
            session_name,
            self._config.api_id,
            self._config.api_hash,
            proxy=telethon_proxy,
        )


def _dialog_to_chat(dialog: Dialog) -> Chat | None:
    """Convert Telethon Dialog to our Chat model.

    Args:
        dialog: Telethon Dialog object

    Returns:
        Chat model or None if dialog type is not supported
    """
    entity = dialog.entity

    # Determine chat type from entity
    if isinstance(entity, User):
        chat_type = ChatType.PRIVATE
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
    )


@with_retry_for_reads(max_attempts=3, base_delay=1.0, max_delay=30.0)
async def get_dialogs(
    client: TelegramClientType,
    chat_types: set[ChatType] | None = None,
    *,
    _cache: dict[int, list[Chat]] | None = None,
) -> list[Chat]:
    """Get list of user's dialogs (chats) from Telegram.

    Fetches all dialogs and converts them to Chat models. Results are
    deduplicated by chat_id to handle edge cases during pagination.

    Network errors (ConnectionError, TimeoutError, OSError, SSL errors) are
    automatically retried with exponential backoff (up to 3 attempts).

    Args:
        client: Connected TelegramClient instance
        chat_types: Optional set of chat types to filter by.
            If None, returns all chat types.
        _cache: Internal cache dict (used for session-scoped caching).
            Pass the same dict across calls to enable caching.

    Returns:
        List of Chat models, sorted by dialog order (most recent first)

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

    # Fetch all dialogs
    chats: list[Chat] = []
    seen_ids: set[int] = set()

    try:
        async for dialog in client.iter_dialogs():
            try:
                chat = _dialog_to_chat(dialog)
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


# Maximum messages to fetch to protect against OOM
MAX_MESSAGES_LIMIT = 10_000

# Telegram API returns max 100 messages per request
TELEGRAM_BATCH_SIZE = 100


class MessageFetchError(Exception):
    """Raised when fetching messages fails."""


class ChatAccessDeniedError(MessageFetchError):
    """Raised when access to a chat is denied (kicked, banned, left, or chat is private/deleted)."""


class JoinChatError(Exception):
    """Raised when joining a chat fails."""


def _telethon_message_to_model(msg: TelegramMessage, chat_id: int) -> Message | None:
    """Convert Telethon Message to our Message model.

    Args:
        msg: Telethon Message object
        chat_id: Chat ID this message belongs to

    Returns:
        Message model or None if message is empty/deleted or has no sender
    """
    from datetime import UTC

    # Skip empty/deleted messages (Telethon represents them as MessageEmpty)
    # Check if this is a MessageEmpty (deleted message)
    if (
        getattr(msg, "message", None) is None
        and getattr(msg, "media", None) is None
        and (not hasattr(msg, "date") or msg.date is None)
    ):
        return None

    # Get sender ID - can be None for channel posts without author
    sender_id = getattr(msg, "sender_id", None) or getattr(msg, "from_id", None)
    if sender_id is None:
        # For channel posts, use the chat's ID as author
        sender_id = chat_id

    # Handle from_id being a PeerUser/PeerChannel object
    if hasattr(sender_id, "user_id"):
        sender_id = sender_id.user_id
    elif hasattr(sender_id, "channel_id"):
        sender_id = sender_id.channel_id

    # Ensure positive IDs
    sender_id = abs(sender_id) if sender_id else chat_id

    # Get message timestamp
    timestamp = msg.date
    if timestamp is None:
        return None

    # Ensure timezone-aware (Telethon returns UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)

    # Get message text
    text = msg.message or ""

    return Message(
        id=msg.id,
        chat_id=chat_id,
        author_id=sender_id,
        timestamp=timestamp,
        text=text,
    )


async def _get_forum_topics(
    client: TelegramClientType,
    chat_id: int,
) -> list[int]:
    """Get list of forum topic IDs from a Telegram forum chat.

    Args:
        client: Connected TelegramClient instance
        chat_id: ID of the forum chat

    Returns:
        List of topic IDs (message IDs of the first message in each topic)

    Raises:
        Exception: If fetching topics fails
    """
    try:
        # Get forum topics using Telegram API
        result = await client(GetForumTopicsRequest(
            channel=chat_id,
            offset_date=0,
            offset_id=0,
            offset_topic=0,
            limit=100,  # Should be enough for most forums
        ))

        # Extract topic IDs from the result
        # Each topic has an ID which is the message ID of the first message
        topic_ids = []
        if hasattr(result, 'topics'):
            for topic in result.topics:
                # Topic ID is stored in the 'id' attribute
                if hasattr(topic, 'id'):
                    topic_ids.append(topic.id)

        return topic_ids
    except Exception as e:
        # If we can't get topics, log and return empty list
        # This allows graceful fallback to default behavior
        logger.debug(f"Failed to get forum topics for chat {chat_id}: {e}")
        return []


@with_retry_for_reads(max_attempts=3, base_delay=1.0, max_delay=30.0)
async def get_messages(
    client: TelegramClientType,
    chat_id: int,
    limit: int = 100,
) -> list[Message]:
    """Get messages from a Telegram chat.

    Fetches messages from the specified chat and converts them to Message models.
    Handles pagination automatically for limits > 100.

    For forum chats (supergroups with topics enabled), this function automatically
    fetches messages from ALL topics and aggregates them. This ensures complete
    statistics and avoids the limitation where get_messages() by default only
    returns messages from the "General" topic.

    Network errors (ConnectionError, TimeoutError, OSError, SSL errors) are
    automatically retried with exponential backoff (up to 3 attempts).

    Args:
        client: Connected TelegramClient instance
        chat_id: ID of the chat to fetch messages from
        limit: Maximum number of messages to fetch (default 100, max 10000)
               For forums, this is applied per-topic to ensure coverage across all topics.

    Returns:
        List of Message models, sorted by timestamp (oldest first)

    Raises:
        ChatAccessDeniedError: If access to chat is denied (user kicked/banned/left,
                                or chat is private/deleted)
        MessageFetchError: If chat doesn't exist or other error
        ValueError: If limit is invalid

    Example:
        ```python
        async with loader.create_client() as client:
            # Get last 50 messages (per topic if forum)
            messages = await get_messages(client, chat_id=123, limit=50)

            # Process messages
            for msg in messages:
                print(f"{msg.timestamp}: {msg.text[:50]}")
        ```
    """
    if limit <= 0:
        raise ValueError("limit must be positive")

    # Cap at maximum to prevent OOM
    effective_limit = min(limit, MAX_MESSAGES_LIMIT)

    messages: list[Message] = []
    seen_ids: set[int] = set()

    try:
        # Check if this is a forum chat by getting the entity
        entity = await client.get_entity(chat_id)
        is_forum = (
            isinstance(entity, Channel)
            and getattr(entity, "megagroup", False)
            and getattr(entity, "forum", False)
        )

        if is_forum:
            # For forums, fetch messages from all topics
            logger.info(f"Chat {chat_id} is a forum, fetching from all topics")

            # Get all topics
            topic_ids = await _get_forum_topics(client, chat_id)

            if topic_ids:
                logger.info(f"Found {len(topic_ids)} topics in forum {chat_id}")

                # Fetch messages from each topic
                for topic_id in topic_ids:
                    try:
                        async for telethon_msg in client.iter_messages(
                            chat_id,
                            limit=effective_limit,
                            reply_to=topic_id,
                        ):
                            msg = _telethon_message_to_model(telethon_msg, chat_id)
                            if msg is None:
                                continue

                            # Deduplicate (handles edge case of duplicates)
                            if msg.id in seen_ids:
                                continue
                            seen_ids.add(msg.id)
                            messages.append(msg)
                    except Exception as e:
                        # Log error but continue with other topics
                        logger.warning(f"Failed to fetch messages from topic {topic_id}: {e}")
            else:
                # No topics found or error getting topics, fall back to default behavior
                logger.info(f"No topics found for forum {chat_id}, using default fetch")
                async for telethon_msg in client.iter_messages(chat_id, limit=effective_limit):
                    msg = _telethon_message_to_model(telethon_msg, chat_id)
                    if msg is None:
                        continue
                    if msg.id in seen_ids:
                        continue
                    seen_ids.add(msg.id)
                    messages.append(msg)
        else:
            # Regular chat, use standard fetch
            async for telethon_msg in client.iter_messages(chat_id, limit=effective_limit):
                msg = _telethon_message_to_model(telethon_msg, chat_id)
                if msg is None:
                    continue

                # Deduplicate (handles edge case of duplicates during pagination)
                if msg.id in seen_ids:
                    continue
                seen_ids.add(msg.id)
                messages.append(msg)

    except (
        ChatForbiddenError,
        ChannelPrivateError,
        UserBannedInChannelError,
        ChatRestrictedError,
        ChannelBannedError,
    ) as e:
        # User has limited access to this chat (kicked, banned, left, or chat is private/deleted)
        raise ChatAccessDeniedError(f"Access denied to chat {chat_id}: {type(e).__name__}") from e
    except Exception as e:
        error_msg = str(e).lower()
        if "peer" in error_msg or "invalid" in error_msg:
            raise MessageFetchError(f"Chat not found or invalid: {chat_id}") from e
        if "flood" in error_msg:
            raise MessageFetchError(
                f"Rate limited by Telegram. Please wait and try again: {e}"
            ) from e
        if "private" in error_msg or "forbidden" in error_msg or "permission" in error_msg:
            raise MessageFetchError(f"Access denied to chat {chat_id}") from e
        raise MessageFetchError(f"Failed to fetch messages: {e}") from e

    # Sort by timestamp (oldest first) to handle out-of-order pagination
    messages.sort(key=lambda m: m.timestamp)

    return messages


# Regex patterns for parsing Telegram links
_INVITE_HASH_PATTERN = re.compile(
    r"(?:https?://)?(?:t\.me|telegram\.me)/(?:joinchat/|\+)([a-zA-Z0-9_-]+)"
)
_PUBLIC_LINK_PATTERN = re.compile(
    r"(?:https?://)?(?:t\.me|telegram\.me)/([a-zA-Z0-9_]+)"
)


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
                chat_type = ChatType.FORUM if getattr(entity, "forum", False) else ChatType.SUPERGROUP
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
    except Exception as e:
        error_msg = str(e).lower()
        if "invite" in error_msg and "expired" in error_msg:
            raise JoinChatError(f"Invite link has expired: {chat_ref}") from e
        if "invite" in error_msg and "invalid" in error_msg:
            raise JoinChatError(f"Invalid invite link: {chat_ref}") from e
        if "banned" in error_msg or "kicked" in error_msg:
            raise JoinChatError(f"You are banned from this chat: {chat_ref}") from e
        if "flood" in error_msg:
            raise JoinChatError(
                f"Rate limited by Telegram. Please wait and try again: {e}"
            ) from e
        if "private" in error_msg:
            raise JoinChatError(
                f"Chat is private and requires an invite link: {chat_ref}"
            ) from e
        if "username" in error_msg and ("invalid" in error_msg or "not" in error_msg):
            raise JoinChatError(f"Username not found: {chat_ref}") from e
        raise JoinChatError(f"Failed to join chat: {e}") from e

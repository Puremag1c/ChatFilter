"""Telegram client initialization from session and config files."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from collections.abc import AsyncGenerator
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
    FloodWaitError,
    UserBannedInChannelError,
)
from telethon.tl.functions.channels import (
    GetFullChannelRequest,
    JoinChannelRequest,
    LeaveChannelRequest,
)
from telethon.tl.functions.messages import (
    DeleteChatUserRequest,
    GetForumTopicsRequest,
    ImportChatInviteRequest,
)
from telethon.tl.types import Channel, MessageService, User
from telethon.tl.types import Chat as TelegramChat

from chatfilter.config import ProxyConfig, ProxyType, load_proxy_config
from chatfilter.models.chat import Chat, ChatType
from chatfilter.models.message import Message
from chatfilter.telegram.rate_limiter import get_rate_limiter
from chatfilter.telegram.retry import with_retry_for_reads

if TYPE_CHECKING:
    from telethon import TelegramClient as TelegramClientType
    from telethon.tl.custom import Dialog
    from telethon.tl.types import Message as TelegramMessage

    from chatfilter.models.account import AccountInfo

logger = logging.getLogger(__name__)


class TelegramConfigError(Exception):
    """Raised when config file is invalid or missing required fields."""


class SessionFileError(Exception):
    """Raised when session file is invalid, incompatible, or locked."""


class SessionBlockedError(Exception):
    """Raised when session cannot connect due to missing required configuration.

    This includes cases where proxy_id is set but the proxy is not found in pool.
    """


@dataclass(frozen=True)
class TelegramConfig:
    """Telegram API configuration with secure storage support.

    Credentials are stored securely using:
    1. OS Keyring (preferred) - native system credential storage
    2. Encrypted file (fallback) - for systems without keyring
    3. Environment variables (read-only) - for containers

    Attributes:
        api_id: Telegram API ID (integer)
        api_hash: Telegram API hash (string) - redacted in logs
    """

    api_id: int
    api_hash: str

    def __repr__(self) -> str:
        """Redact api_hash in repr for security."""
        return f"TelegramConfig(api_id={self.api_id}, api_hash='***REDACTED***')"

    def __str__(self) -> str:
        """Redact api_hash in str for security."""
        return f"TelegramConfig(api_id={self.api_id})"

    @classmethod
    def from_secure_storage(cls, session_id: str, storage_dir: Path) -> TelegramConfig:
        """Load config from secure credential storage.

        Args:
            session_id: Unique session identifier
            storage_dir: Directory containing secure credentials

        Returns:
            TelegramConfig instance

        Raises:
            TelegramConfigError: If credentials cannot be loaded
        """
        from chatfilter.security import CredentialNotFoundError, SecureCredentialManager

        try:
            manager = SecureCredentialManager(storage_dir)
            api_id, api_hash, _proxy_id = manager.retrieve_credentials(session_id)
            return cls(api_id=api_id, api_hash=api_hash)
        except CredentialNotFoundError as e:
            raise TelegramConfigError(
                f"Credentials not found in secure storage for session '{session_id}'. "
                f"Please ensure credentials are properly configured."
            ) from e
        except Exception as e:
            raise TelegramConfigError(f"Failed to load credentials: {e}") from e

    @classmethod
    def from_json_file(cls, path: Path, *, migrate_to_secure: bool = False) -> TelegramConfig:
        """Load config from JSON file (legacy/fallback method).

        DEPRECATED: This method loads credentials from plaintext JSON.
        Use from_secure_storage() for secure credential access.

        Args:
            path: Path to JSON config file
            migrate_to_secure: If True, migrate credentials to secure storage
                and delete the plaintext file

        Returns:
            TelegramConfig instance

        Raises:
            TelegramConfigError: If file is invalid or missing required fields
            FileNotFoundError: If config file doesn't exist

        Warning:
            Storing credentials in plaintext JSON is insecure. Consider using
            secure storage via from_secure_storage() instead.
        """
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        logger.warning(
            "Loading credentials from plaintext JSON (DEPRECATED). "
            "Consider migrating to secure storage for better security."
        )

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
            raise TelegramConfigError(f"api_hash must be a string, got: {type(api_hash).__name__}")

        if not api_hash:
            raise TelegramConfigError("api_hash cannot be empty")

        config = cls(api_id=api_id, api_hash=api_hash)

        # Auto-migrate to secure storage if requested
        if migrate_to_secure:
            try:
                _migrate_plaintext_to_secure(path, api_id, api_hash)
            except Exception as e:
                logger.error(f"Failed to migrate credentials to secure storage: {e}")
                # Don't fail the config load, just log the error

        return config


def _secure_delete_file(file_path: Path) -> None:
    """Securely delete a file by overwriting before removal.

    Args:
        file_path: Path to file to securely delete
    """
    if not file_path.exists() or not file_path.is_file():
        return

    try:
        # Get file size
        file_size = file_path.stat().st_size

        # Overwrite with random data then zeros
        with file_path.open("r+b") as f:
            f.write(b"\x00" * file_size)
            f.flush()
            import os

            os.fsync(f.fileno())

        # Delete the file
        file_path.unlink()
        logger.info(f"Securely deleted plaintext config: {file_path}")
    except Exception as e:
        logger.warning(f"Failed to securely delete file, falling back to regular delete: {e}")
        # Fallback to regular deletion
        file_path.unlink(missing_ok=True)


def _migrate_plaintext_to_secure(config_path: Path, api_id: int, api_hash: str) -> None:
    """Migrate plaintext credentials to secure storage and delete plaintext file.

    Args:
        config_path: Path to plaintext config.json file
        api_id: Telegram API ID
        api_hash: Telegram API hash
    """
    from chatfilter.security import SecureCredentialManager

    # Determine session_id from path (parent directory name)
    session_id = config_path.parent.name

    # Determine storage directory (sessions directory)
    storage_dir = config_path.parent.parent

    # Store credentials securely
    manager = SecureCredentialManager(storage_dir)
    manager.store_credentials(session_id, api_id, api_hash)

    # Securely delete plaintext file
    _secure_delete_file(config_path)

    # Create a migration marker file to prevent re-migration attempts
    marker_file = config_path.parent / ".migrated"
    marker_file.write_text(
        "Credentials migrated to secure storage.\n"
        "Original plaintext config.json has been securely deleted.\n"
    )
    logger.info(f"Migrated credentials to secure storage for session: {session_id}")


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
            error_msg = str(e).lower()
            if "locked" in error_msg or "database is locked" in error_msg:
                raise SessionFileError(
                    f"Session file is locked by another process. "
                    f"Make sure no other application is using this session: {session_path}"
                ) from e
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
                    "Session file is from Telethon 2.x which is incompatible with this application. "
                    "Please generate a new session file using Telethon 1.x (version 1.34.0 or later). "
                    "Telethon 1.x and 2.x use different session formats that are not interchangeable."
                )
            raise SessionFileError(
                f"Invalid session file format. Expected Telethon 1.x session with tables "
                f"{required_tables}, but found: {tables}. "
                "Please ensure you're using a valid Telethon session file."
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
    """Loader for creating Telethon client from session and secure credentials.

    Supports both secure credential storage (preferred) and legacy plaintext
    config files with auto-migration.

    Example:
        ```python
        # Using secure storage (preferred)
        loader = TelegramClientLoader(
            session_path=Path("sessions/my_account/session.session"),
            use_secure_storage=True,
        )
        async with loader.create_client() as client:
            me = await client.get_me()
            print(f"Logged in as {me.username}")

        # Legacy mode with plaintext config (deprecated)
        loader = TelegramClientLoader(
            session_path=Path("my_account.session"),
            config_path=Path("telegram_config.json"),
        )
        ```
    """

    def __init__(
        self,
        session_path: Path,
        config_path: Path | None = None,
        *,
        use_secure_storage: bool = True,
    ) -> None:
        """Initialize loader with session and credential configuration.

        Args:
            session_path: Path to Telethon .session file
            config_path: Path to JSON config file (legacy mode). If None,
                uses secure storage based on session directory structure.
            use_secure_storage: If True, prefer secure storage over plaintext.
                When True and config_path exists, will auto-migrate to secure
                storage.
        """
        self._session_path = session_path
        self._config_path = config_path
        self._use_secure_storage = use_secure_storage
        self._config: TelegramConfig | None = None
        self._proxy_id: str | None = None

    @property
    def session_path(self) -> Path:
        """Path to session file."""
        return self._session_path

    @property
    def config_path(self) -> Path | None:
        """Path to config file (legacy)."""
        return self._config_path

    def validate(self) -> None:
        """Validate session file and load credentials.

        Call this before create_client() to get early validation errors.

        Raises:
            FileNotFoundError: If session file doesn't exist
            SessionFileError: If session file is invalid
            TelegramConfigError: If credentials cannot be loaded
        """
        # Validate session file first
        validate_session_file(self._session_path)

        # Load credentials based on configuration
        if self._use_secure_storage:
            # Try secure storage first
            session_id = self._session_path.parent.name
            storage_dir = self._session_path.parent.parent

            try:
                from chatfilter.security import CredentialNotFoundError, SecureCredentialManager

                manager = SecureCredentialManager(storage_dir)
                api_id, api_hash, proxy_id = manager.retrieve_credentials(session_id)
                self._config = TelegramConfig(api_id=api_id, api_hash=api_hash)
                self._proxy_id = proxy_id
                logger.debug(f"Loaded credentials from secure storage for: {session_id}")
                return
            except CredentialNotFoundError as e:
                # If secure storage fails and we have a config_path, try plaintext
                if self._config_path and self._config_path.exists():
                    logger.warning(f"Secure storage failed ({e}), falling back to plaintext config")
                    self._config = TelegramConfig.from_json_file(
                        self._config_path,
                        migrate_to_secure=True,  # Auto-migrate
                    )
                    self._proxy_id = None  # Legacy mode has no proxy_id
                    return
                # No fallback available
                raise TelegramConfigError(
                    f"Credentials not found in secure storage for session '{session_id}'. "
                    f"Please ensure credentials are properly configured."
                ) from e
            except Exception as e:
                raise TelegramConfigError(f"Failed to load credentials: {e}") from e

        # Legacy mode: use plaintext config
        if self._config_path is not None:
            migrate = self._use_secure_storage  # Auto-migrate if secure storage enabled
            self._config = TelegramConfig.from_json_file(
                self._config_path,
                migrate_to_secure=migrate,
            )
        else:
            raise TelegramConfigError(
                "No config_path provided and secure storage is disabled. "
                "Either provide config_path or enable use_secure_storage=True."
            )

    def create_client(
        self,
        proxy: ProxyConfig | None = None,
        use_saved_proxy: bool = True,
        *,
        timeout: float | None = None,
        connection_retries: int | None = None,
        retry_delay: int | None = None,
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
            timeout: Timeout in seconds for network operations (default: 30s).
                Increased from Telethon default of 10s to handle slow connections
                and MTProto handshake through proxies.
            connection_retries: Number of retries for connection attempts (default: 5).
            retry_delay: Delay in seconds between retry attempts (default: 1).

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

        # Priority: 1) explicit proxy arg, 2) session's proxy_id from pool, 3) global proxy config
        if proxy is not None:
            # Explicit proxy passed - use it directly
            if proxy.enabled and proxy.host:
                proxy_type_map = {
                    ProxyType.SOCKS5: socks.SOCKS5,
                    ProxyType.HTTP: socks.HTTP,
                }
                telethon_proxy = (
                    proxy_type_map[proxy.proxy_type],
                    proxy.host,
                    proxy.port,
                    True,  # rdns (resolve DNS remotely)
                    proxy.username or None,
                    proxy.password or None,
                )
        elif self._proxy_id is not None:
            # Session has a specific proxy_id - load from pool
            from chatfilter.storage.errors import StorageNotFoundError
            from chatfilter.storage.proxy_pool import get_proxy_by_id

            try:
                proxy_entry = get_proxy_by_id(self._proxy_id)
                telethon_proxy = proxy_entry.to_telethon_proxy()
                logger.debug(f"Using proxy from pool: {proxy_entry.name} ({proxy_entry.id})")
            except StorageNotFoundError as e:
                session_id = self._session_path.parent.name
                raise SessionBlockedError(
                    f"Session '{session_id}' requires proxy '{self._proxy_id}' which is not found in proxy pool. "
                    f"Please add the proxy to the pool or update the session configuration."
                ) from e
        elif use_saved_proxy:
            # Fallback to global proxy config
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

        # Load default timeouts from settings if not explicitly provided
        from chatfilter.config import get_settings

        settings = get_settings()
        effective_timeout = timeout if timeout is not None else int(settings.connect_timeout)
        effective_connection_retries = connection_retries if connection_retries is not None else 5
        effective_retry_delay = retry_delay if retry_delay is not None else 1

        return TelegramClient(
            session_name,
            self._config.api_id,
            self._config.api_hash,
            proxy=telethon_proxy,
            timeout=effective_timeout,
            connection_retries=effective_connection_retries,
            retry_delay=effective_retry_delay,
        )


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


class LeaveChatError(Exception):
    """Raised when leaving a chat fails."""


def _telethon_message_to_model(msg: TelegramMessage, chat_id: int) -> Message | None:
    """Convert Telethon Message to our Message model.

    Args:
        msg: Telethon Message object
        chat_id: Chat ID this message belongs to

    Returns:
        Message model or None if message is empty/deleted, is a service message,
        or has no sender

    Note:
        Service messages (join, leave, pin, etc.) are filtered out as they are
        system-generated events rather than user-authored content. This ensures
        metrics reflect actual user participation.
    """
    from datetime import UTC

    # Skip service messages (join/leave/pin/etc.)
    # MessageService represents system-generated events, not user messages
    if isinstance(msg, MessageService):
        return None

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
        # For channel posts and anonymous admins, use the chat's ID as author.
        # This means all anonymous messages in a chat are attributed to one "author"
        # (the chat itself) for unique_authors counting. This is a deliberate design
        # decision to handle anonymous posts consistently without skipping them.
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
        result = await client(
            GetForumTopicsRequest(
                channel=chat_id,
                offset_date=0,
                offset_id=0,
                offset_topic=0,
                limit=100,  # Should be enough for most forums
            )
        )

        # Extract topic IDs from the result
        # Each topic has an ID which is the message ID of the first message
        topic_ids = []
        if hasattr(result, "topics"):
            for topic in result.topics:
                # Topic ID is stored in the 'id' attribute
                if hasattr(topic, "id"):
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

    # Proactive rate limiting to prevent FloodWaitError
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("get_messages")

    # Cap at maximum to prevent OOM
    effective_limit = min(limit, MAX_MESSAGES_LIMIT)

    messages: list[Message] = []
    seen_ids: set[int] = set()
    fetch_interrupted = False

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

                # Fetch messages from each topic with resume capability
                for topic_id in topic_ids:
                    # Check if we've reached the message limit
                    if len(messages) >= effective_limit:
                        logger.info(
                            f"Reached message limit ({effective_limit}), "
                            f"stopping forum topic fetch at topic {topic_id}"
                        )
                        break
                    max_retries = 3
                    retry_count = 0
                    topic_messages_before = len(messages)

                    while retry_count < max_retries:
                        try:
                            # Determine offset for this topic (min message ID among topic messages)
                            topic_msgs = [m for m in messages if m.id not in seen_ids]
                            offset_id = (
                                min(
                                    m.id
                                    for m in topic_msgs
                                    if m in messages[topic_messages_before:]
                                )
                                if len(messages) > topic_messages_before
                                else 0
                            )

                            # Calculate remaining messages to fetch
                            remaining = effective_limit - len(messages)

                            async for telethon_msg in client.iter_messages(
                                chat_id,
                                limit=remaining,
                                reply_to=topic_id,
                                offset_id=offset_id if offset_id > 0 else None,
                            ):
                                msg = _telethon_message_to_model(telethon_msg, chat_id)
                                if msg is None:
                                    continue

                                # Deduplicate (handles edge case of duplicates)
                                if msg.id in seen_ids:
                                    continue
                                seen_ids.add(msg.id)
                                messages.append(msg)

                                # Stop if we've reached the limit
                                if len(messages) >= effective_limit:
                                    break

                            # Successfully fetched from this topic
                            break

                        except (ConnectionError, TimeoutError, OSError) as e:
                            retry_count += 1
                            fetch_interrupted = True
                            topic_msg_count = len(messages) - topic_messages_before
                            logger.warning(
                                f"Connection interrupted while fetching topic {topic_id} "
                                f"(collected {topic_msg_count} messages from this topic, "
                                f"attempt {retry_count}/{max_retries}): {e}"
                            )

                            if retry_count < max_retries:
                                import asyncio

                                wait_time = 1.0 * (2 ** (retry_count - 1))
                                logger.info(
                                    f"Retrying topic {topic_id} in {wait_time}s with offset..."
                                )
                                await asyncio.sleep(wait_time)
                            else:
                                logger.warning(
                                    f"Max retries reached for topic {topic_id}. "
                                    f"Moving to next topic."
                                )
                                # Continue with other topics to maximize data recovery
                                break
                        except Exception as e:
                            # Log error but continue with other topics
                            logger.warning(f"Failed to fetch messages from topic {topic_id}: {e}")
                            break
            else:
                # No topics found or error getting topics, fall back to default behavior
                logger.info(f"No topics found for forum {chat_id}, using default fetch")
                max_retries = 3
                retry_count = 0

                while retry_count < max_retries and len(messages) < effective_limit:
                    try:
                        offset_id = min(messages, key=lambda m: m.id).id if messages else 0
                        remaining = effective_limit - len(messages)

                        async for telethon_msg in client.iter_messages(
                            chat_id,
                            limit=remaining,
                            offset_id=offset_id if offset_id > 0 else None,
                        ):
                            msg = _telethon_message_to_model(telethon_msg, chat_id)
                            if msg is None:
                                continue
                            if msg.id in seen_ids:
                                continue
                            seen_ids.add(msg.id)
                            messages.append(msg)

                        break

                    except (ConnectionError, TimeoutError, OSError) as e:
                        retry_count += 1
                        fetch_interrupted = True
                        logger.warning(
                            f"Connection interrupted while fetching forum {chat_id} "
                            f"(collected {len(messages)}/{effective_limit} messages, "
                            f"attempt {retry_count}/{max_retries}): {e}"
                        )

                        if retry_count < max_retries:
                            import asyncio

                            wait_time = 1.0 * (2 ** (retry_count - 1))
                            logger.info(
                                f"Retrying in {wait_time}s with offset from last message..."
                            )
                            await asyncio.sleep(wait_time)
                        else:
                            logger.warning(
                                f"Max retries reached for forum {chat_id}. "
                                f"Returning {len(messages)} partial messages."
                            )
        else:
            # Regular chat, use standard fetch with resume capability
            max_retries = 3
            retry_count = 0

            while retry_count < max_retries and len(messages) < effective_limit:
                try:
                    # Determine offset for resume (use min message ID if resuming)
                    offset_id = min(messages, key=lambda m: m.id).id if messages else 0
                    remaining = effective_limit - len(messages)

                    async for telethon_msg in client.iter_messages(
                        chat_id,
                        limit=remaining,
                        offset_id=offset_id if offset_id > 0 else None,
                    ):
                        msg = _telethon_message_to_model(telethon_msg, chat_id)
                        if msg is None:
                            continue

                        # Deduplicate (handles edge case of duplicates during pagination)
                        if msg.id in seen_ids:
                            continue
                        seen_ids.add(msg.id)
                        messages.append(msg)

                    # Successfully completed fetch
                    break

                except (ConnectionError, TimeoutError, OSError) as e:
                    retry_count += 1
                    fetch_interrupted = True
                    logger.warning(
                        f"Connection interrupted while fetching chat {chat_id} "
                        f"(collected {len(messages)}/{effective_limit} messages, "
                        f"attempt {retry_count}/{max_retries}): {e}"
                    )

                    if retry_count < max_retries:
                        # Wait before retry with exponential backoff
                        import asyncio

                        wait_time = 1.0 * (2 ** (retry_count - 1))
                        logger.info(f"Retrying in {wait_time}s with offset from last message...")
                        await asyncio.sleep(wait_time)
                    else:
                        logger.warning(
                            f"Max retries reached for chat {chat_id}. "
                            f"Returning {len(messages)} partial messages."
                        )

    except (
        ChatForbiddenError,
        ChannelPrivateError,
        UserBannedInChannelError,
        ChatRestrictedError,
        ChannelBannedError,
    ) as e:
        # User has limited access to this chat (kicked, banned, left, or chat is private/deleted)
        raise ChatAccessDeniedError(f"Access denied to chat {chat_id}: {type(e).__name__}") from e
    except FloodWaitError as e:
        # FloodWait that persisted through retries - inform user with exact wait time
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        raise MessageFetchError(
            f"Rate limited by Telegram for chat {chat_id}. {friendly_msg}"
        ) from e
    except Exception as e:
        error_msg = str(e).lower()
        if "peer" in error_msg or "invalid" in error_msg:
            raise MessageFetchError(f"Chat not found or invalid: {chat_id}") from e
        if "private" in error_msg or "forbidden" in error_msg or "permission" in error_msg:
            raise MessageFetchError(f"Access denied to chat {chat_id}") from e
        raise MessageFetchError(f"Failed to fetch messages: {e}") from e

    # Sort by timestamp (oldest first) to handle out-of-order pagination
    messages.sort(key=lambda m: m.timestamp)

    # Clear seen_ids to free memory (no longer needed after deduplication)
    seen_ids.clear()

    # Log if fetch was interrupted but we're returning partial results
    if fetch_interrupted:
        logger.info(
            f"Returning {len(messages)} partial messages for chat {chat_id} "
            f"(fetch was interrupted, requested limit was {effective_limit})"
        )

    return messages


async def get_messages_streaming(
    client: TelegramClientType,
    chat_id: int,
    batch_size: int = 1000,
    max_messages: int | None = None,
) -> AsyncGenerator[list[Message], None]:
    """Stream messages from a Telegram chat in batches (generator).

    Similar to get_messages() but yields batches of messages instead of loading
    all messages into memory. Ideal for processing large chats (>100k messages)
    with memory constraints.

    For forum chats (supergroups with topics enabled), this function automatically
    fetches messages from ALL topics and aggregates them.

    Network errors (ConnectionError, TimeoutError, OSError, SSL errors) are
    automatically retried with exponential backoff (up to 3 attempts per batch).

    Args:
        client: Connected TelegramClient instance
        chat_id: ID of the chat to fetch messages from
        batch_size: Number of messages per batch (default 1000)
        max_messages: Maximum total messages to fetch (None = unlimited)
                     For forums, this is the total across all topics.

    Yields:
        Batches of Message models as list[Message], sorted by timestamp within batch

    Raises:
        ChatAccessDeniedError: If access to chat is denied (user kicked/banned/left,
                                or chat is private/deleted)
        MessageFetchError: If chat doesn't exist or other error
        ValueError: If batch_size is invalid

    Example:
        ```python
        from chatfilter.analyzer.metrics import StreamingMetricsAggregator

        async with loader.create_client() as client:
            aggregator = StreamingMetricsAggregator()

            # Process messages in batches
            async for batch in get_messages_streaming(client, chat_id=123):
                aggregator.add_batch(batch)
                print(f"Processed batch of {len(batch)} messages")

            # Get final metrics without storing all messages
            metrics = aggregator.get_metrics()
            print(f"Total: {metrics.message_count} messages")
        ```
    """
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    if max_messages is not None and max_messages <= 0:
        raise ValueError("max_messages must be positive or None")

    # Proactive rate limiting
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("get_messages")

    total_fetched = 0
    seen_ids: set[int] = set()

    try:
        # Check if this is a forum chat
        entity = await client.get_entity(chat_id)
        is_forum = (
            isinstance(entity, Channel)
            and getattr(entity, "megagroup", False)
            and getattr(entity, "forum", False)
        )

        if is_forum:
            # For forums, fetch messages from all topics
            logger.info(f"Chat {chat_id} is a forum, streaming from all topics")

            # Get all topics
            topic_ids = await _get_forum_topics(client, chat_id)

            if topic_ids:
                logger.info(f"Found {len(topic_ids)} topics in forum {chat_id}")

                # Stream messages from each topic
                for topic_id in topic_ids:
                    # Check if we've reached max_messages limit
                    if max_messages and total_fetched >= max_messages:
                        logger.info(
                            f"Reached max_messages limit ({max_messages}), "
                            f"stopping forum topic fetch"
                        )
                        return

                    max_retries = 3
                    retry_count = 0
                    batch: list[Message] = []

                    while retry_count < max_retries:
                        try:
                            # Calculate remaining messages to fetch
                            remaining = max_messages - total_fetched if max_messages else batch_size
                            fetch_limit = min(batch_size, remaining)

                            async for telethon_msg in client.iter_messages(
                                chat_id,
                                limit=fetch_limit,
                                reply_to=topic_id,
                            ):
                                msg = _telethon_message_to_model(telethon_msg, chat_id)
                                if msg is None:
                                    continue

                                # Deduplicate
                                if msg.id in seen_ids:
                                    continue
                                seen_ids.add(msg.id)
                                batch.append(msg)

                                # Yield batch when it reaches batch_size
                                if len(batch) >= batch_size:
                                    batch.sort(key=lambda m: m.timestamp)
                                    yield batch
                                    total_fetched += len(batch)
                                    batch = []

                                    # Check if we've reached max_messages
                                    if max_messages and total_fetched >= max_messages:
                                        return

                            # Yield remaining messages in final batch for this topic
                            if batch:
                                batch.sort(key=lambda m: m.timestamp)
                                yield batch
                                total_fetched += len(batch)

                            # Successfully fetched from this topic
                            break

                        except (ConnectionError, TimeoutError, OSError) as e:
                            retry_count += 1
                            logger.warning(
                                f"Connection interrupted while streaming topic {topic_id} "
                                f"(attempt {retry_count}/{max_retries}): {e}"
                            )

                            if retry_count < max_retries:
                                import asyncio

                                wait_time = 1.0 * (2 ** (retry_count - 1))
                                logger.info(f"Retrying topic {topic_id} in {wait_time}s...")
                                await asyncio.sleep(wait_time)
                            else:
                                logger.warning(
                                    f"Max retries reached for topic {topic_id}. "
                                    f"Moving to next topic."
                                )
                                break
                        except Exception as e:
                            logger.warning(f"Failed to stream from topic {topic_id}: {e}")
                            break
            else:
                # No topics found, fall back to default behavior
                logger.info(f"No topics found for forum {chat_id}, using default streaming")

        # Regular chat or forum fallback: stream messages
        max_retries = 3
        retry_count = 0
        current_batch: list[Message] = []

        while retry_count < max_retries:
            try:
                # Calculate remaining messages to fetch
                if max_messages:
                    remaining = max_messages - total_fetched
                    if remaining <= 0:
                        # Yield final batch if any
                        if current_batch:
                            current_batch.sort(key=lambda m: m.timestamp)
                            yield current_batch
                        return
                    fetch_limit = min(batch_size * 10, remaining)  # Fetch larger chunks
                else:
                    fetch_limit = batch_size * 10

                async for telethon_msg in client.iter_messages(
                    chat_id,
                    limit=fetch_limit,
                ):
                    msg = _telethon_message_to_model(telethon_msg, chat_id)
                    if msg is None:
                        continue

                    # Deduplicate
                    if msg.id in seen_ids:
                        continue
                    seen_ids.add(msg.id)
                    current_batch.append(msg)

                    # Yield batch when it reaches batch_size
                    if len(current_batch) >= batch_size:
                        current_batch.sort(key=lambda m: m.timestamp)
                        yield current_batch
                        total_fetched += len(current_batch)
                        current_batch = []

                        # Check if we've reached max_messages
                        if max_messages and total_fetched >= max_messages:
                            return

                # Yield remaining messages in final batch
                if current_batch:
                    current_batch.sort(key=lambda m: m.timestamp)
                    yield current_batch
                    total_fetched += len(current_batch)

                # Successfully completed streaming
                break

            except (ConnectionError, TimeoutError, OSError) as e:
                retry_count += 1
                logger.warning(
                    f"Connection interrupted while streaming chat {chat_id} "
                    f"(fetched {total_fetched} so far, "
                    f"attempt {retry_count}/{max_retries}): {e}"
                )

                if retry_count < max_retries:
                    import asyncio

                    wait_time = 1.0 * (2 ** (retry_count - 1))
                    logger.info(f"Retrying in {wait_time}s...")
                    await asyncio.sleep(wait_time)
                else:
                    logger.warning(
                        f"Max retries reached for chat {chat_id}. Yielding final partial batch."
                    )
                    # Yield any remaining batch
                    if batch:
                        batch.sort(key=lambda m: m.timestamp)
                        yield batch
                    break

    except (
        ChatForbiddenError,
        ChannelPrivateError,
        UserBannedInChannelError,
        ChatRestrictedError,
        ChannelBannedError,
    ) as e:
        raise ChatAccessDeniedError(f"Access denied to chat {chat_id}: {type(e).__name__}") from e
    except FloodWaitError as e:
        # FloodWait that persisted through retries - inform user with exact wait time
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        raise MessageFetchError(
            f"Rate limited by Telegram for chat {chat_id}. {friendly_msg}"
        ) from e
    except Exception as e:
        error_msg = str(e).lower()
        if "peer" in error_msg or "invalid" in error_msg:
            raise MessageFetchError(f"Chat not found or invalid: {chat_id}") from e
        if "private" in error_msg or "forbidden" in error_msg or "permission" in error_msg:
            raise MessageFetchError(f"Access denied to chat {chat_id}") from e
        raise MessageFetchError(f"Failed to stream messages: {e}") from e
    finally:
        # Clear seen_ids to free memory
        seen_ids.clear()


@with_retry_for_reads(max_attempts=3, base_delay=1.0, max_delay=30.0)
async def get_messages_since(
    client: TelegramClientType,
    chat_id: int,
    min_id: int,
    limit: int = 10000,
) -> list[Message]:
    """Get messages from a chat newer than a specified message ID.

    Used for incremental/delta sync to fetch only new messages since the
    last sync. This is efficient for continuous monitoring as it avoids
    re-fetching the entire message history.

    For forum chats, this fetches from all topics.

    Args:
        client: Connected TelegramClient instance
        chat_id: ID of the chat to fetch messages from
        min_id: Minimum message ID - only fetch messages with ID > min_id
        limit: Maximum number of messages to fetch (default 10000)

    Returns:
        List of Message models with ID > min_id, sorted by timestamp (oldest first)

    Raises:
        ChatAccessDeniedError: If access to chat is denied
        MessageFetchError: If chat doesn't exist or other error
        ValueError: If min_id or limit is invalid

    Example:
        ```python
        async with loader.create_client() as client:
            # Initial sync - get last 1000 messages
            messages = await get_messages(client, chat_id, limit=1000)
            last_id = max(m.id for m in messages)

            # Later - get only new messages
            new_messages = await get_messages_since(client, chat_id, min_id=last_id)
            print(f"Found {len(new_messages)} new messages")
        ```
    """
    if min_id < 0:
        raise ValueError("min_id must be non-negative")
    if limit <= 0:
        raise ValueError("limit must be positive")

    # Proactive rate limiting
    rate_limiter = get_rate_limiter()
    await rate_limiter.wait_if_needed("get_messages")

    effective_limit = min(limit, MAX_MESSAGES_LIMIT)
    messages: list[Message] = []
    seen_ids: set[int] = set()

    try:
        # Check if this is a forum chat
        entity = await client.get_entity(chat_id)
        is_forum = (
            isinstance(entity, Channel)
            and getattr(entity, "megagroup", False)
            and getattr(entity, "forum", False)
        )

        if is_forum:
            # For forums, fetch from all topics
            logger.info(f"Chat {chat_id} is a forum, fetching new messages from all topics")

            topic_ids = await _get_forum_topics(client, chat_id)

            if topic_ids:
                for topic_id in topic_ids:
                    if len(messages) >= effective_limit:
                        break

                    remaining = effective_limit - len(messages)

                    try:
                        async for telethon_msg in client.iter_messages(
                            chat_id,
                            limit=remaining,
                            reply_to=topic_id,
                            min_id=min_id,
                        ):
                            msg = _telethon_message_to_model(telethon_msg, chat_id)
                            if msg is None:
                                continue

                            if msg.id in seen_ids:
                                continue
                            seen_ids.add(msg.id)
                            messages.append(msg)

                            if len(messages) >= effective_limit:
                                break

                    except Exception as e:
                        logger.warning(f"Failed to fetch new messages from topic {topic_id}: {e}")
                        continue
            else:
                # No topics found, fall back to default behavior
                async for telethon_msg in client.iter_messages(
                    chat_id,
                    limit=effective_limit,
                    min_id=min_id,
                ):
                    msg = _telethon_message_to_model(telethon_msg, chat_id)
                    if msg is None:
                        continue

                    if msg.id in seen_ids:
                        continue
                    seen_ids.add(msg.id)
                    messages.append(msg)
        else:
            # Regular chat - fetch messages with min_id filter
            async for telethon_msg in client.iter_messages(
                chat_id,
                limit=effective_limit,
                min_id=min_id,
            ):
                msg = _telethon_message_to_model(telethon_msg, chat_id)
                if msg is None:
                    continue

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
        raise ChatAccessDeniedError(f"Access denied to chat {chat_id}: {type(e).__name__}") from e
    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        raise MessageFetchError(
            f"Rate limited by Telegram for chat {chat_id}. {friendly_msg}"
        ) from e
    except Exception as e:
        error_msg = str(e).lower()
        if "peer" in error_msg or "invalid" in error_msg:
            raise MessageFetchError(f"Chat not found or invalid: {chat_id}") from e
        if "private" in error_msg or "forbidden" in error_msg or "permission" in error_msg:
            raise MessageFetchError(f"Access denied to chat {chat_id}") from e
        raise MessageFetchError(f"Failed to fetch messages: {e}") from e
    finally:
        seen_ids.clear()

    # Sort by timestamp (oldest first)
    messages.sort(key=lambda m: m.timestamp)

    logger.info(f"Fetched {len(messages)} new messages from chat {chat_id} (min_id={min_id})")

    return messages


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
        # FloodWait when joining chat - inform user with exact wait time
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        friendly_msg = get_user_friendly_message(e)
        raise JoinChatError(
            f"Rate limited by Telegram when joining {chat_ref}. {friendly_msg}"
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
        raise MessageFetchError(f"Rate limited by Telegram. {friendly_msg}") from e
    except Exception as e:
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

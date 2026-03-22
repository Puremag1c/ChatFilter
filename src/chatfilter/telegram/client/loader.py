"""Telegram client loader with secure credential support."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import socks
from telethon import TelegramClient

from chatfilter.config_proxy import ProxyConfig, ProxyType
from chatfilter.i18n.translations import _ as gettext

from .config import (
    SessionBlockedError,
    SessionFileError,
    TelegramConfig,
    TelegramConfigError,
    validate_session_file,
)

if TYPE_CHECKING:
    from telethon import TelegramClient as TelegramClientType

logger = logging.getLogger(__name__)


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

    @property
    def user_id(self) -> str:
        """Derive user_id from path: sessions_dir / user_id / session_name / session.session."""
        return self._session_path.parent.parent.name

    def validate(self) -> None:
        """Validate session file and load credentials.

        Call this before create_client() to get early validation errors.
        Validates all required fields for connecting:
        - Session file exists and is valid
        - api_id is set
        - api_hash is set
        - proxy_id is set
        - proxy exists in pool

        Raises:
            FileNotFoundError: If session file doesn't exist
            SessionFileError: If session file is invalid
            TelegramConfigError: If credentials cannot be loaded
            SessionBlockedError: If api_id, api_hash, or proxy_id is missing,
                or if proxy_id references a non-existent proxy
        """
        # Validate session file first
        validate_session_file(self._session_path)

        session_id = self._session_path.parent.name

        # Load credentials based on configuration
        if self._use_secure_storage:
            # Try secure storage first
            storage_dir = self._session_path.parent.parent

            try:
                from chatfilter.security import CredentialNotFoundError, SecureCredentialManager

                manager = SecureCredentialManager(storage_dir)
                api_id, api_hash, proxy_id = manager.retrieve_credentials(session_id)
                self._config = TelegramConfig(api_id=api_id, api_hash=api_hash)
                self._proxy_id = proxy_id
                logger.debug(f"Loaded credentials from secure storage for: {session_id}")
            except CredentialNotFoundError as e:
                # If secure storage fails and we have a config_path, try plaintext
                if self._config_path and self._config_path.exists():
                    logger.warning(f"Secure storage failed ({e}), falling back to plaintext config")
                    self._config = TelegramConfig.from_json_file(
                        self._config_path,
                        migrate_to_secure=True,  # Auto-migrate
                    )
                    self._proxy_id = None  # Legacy mode has no proxy_id
                else:
                    # No fallback available
                    raise TelegramConfigError(
                        f"Credentials not found in secure storage for session '{session_id}'. "
                        f"Please ensure credentials are properly configured."
                    ) from e
            except Exception as e:
                raise TelegramConfigError(f"Failed to load credentials: {e}") from e
        else:
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

        # Validate required fields for connect
        assert self._config is not None  # for type checker

        # Check api_id is valid
        if not self._config.api_id:
            raise SessionBlockedError(
                gettext(
                    "Session '{session_id}' has no api_id configured. "
                    "Please configure api_id before connecting."
                ).format(session_id=session_id)
            )

        # Check api_hash is valid
        if not self._config.api_hash or not self._config.api_hash.strip():
            raise SessionBlockedError(
                gettext(
                    "Session '{session_id}' has no api_hash configured. "
                    "Please configure api_hash before connecting."
                ).format(session_id=session_id)
            )

        # Check proxy_id is set
        if not self._proxy_id:
            raise SessionBlockedError(
                gettext(
                    "Session '{session_id}' has no proxy configured. "
                    "Please configure a proxy for this session before connecting."
                ).format(session_id=session_id)
            )

        # Verify proxy exists in pool
        from chatfilter.storage.errors import StorageNotFoundError
        from chatfilter.storage.proxy_pool import get_proxy_by_id

        try:
            get_proxy_by_id(self._proxy_id, user_id=self.user_id)
        except StorageNotFoundError as e:
            raise SessionBlockedError(
                gettext(
                    "Session '{session_id}' requires proxy '{proxy_id}' which is not found "
                    "in proxy pool. Please add the proxy to the pool or update the session "
                    "configuration."
                ).format(session_id=session_id, proxy_id=self._proxy_id)
            ) from e

        logger.debug(
            f"Session '{session_id}' validated successfully: "
            f"api_id={self._config.api_id}, proxy_id={self._proxy_id}"
        )

    def create_client(
        self,
        proxy: ProxyConfig | None = None,
        *,
        timeout: float | None = None,
        connection_retries: int | None = None,
        retry_delay: int | None = None,
    ) -> TelegramClientType:
        """Create and return a Telethon client instance.

        Validates files and configuration if not already validated via validate().
        The returned client should be used as an async context manager.

        Sessions require all of the following to be configured:
        - api_id: Telegram API ID
        - api_hash: Telegram API hash
        - proxy_id: Reference to a proxy in the proxy pool

        If any required field is missing, SessionBlockedError will be raised
        with a clear error message.

        Args:
            proxy: Explicit proxy configuration to use. If None, uses the
                session's configured proxy_id from the proxy pool.
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
            SessionBlockedError: If api_id, api_hash, or proxy_id is missing,
                or if proxy_id references a non-existent proxy

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
                proxy_entry = get_proxy_by_id(self._proxy_id, user_id=self.user_id)
                telethon_proxy = proxy_entry.to_telethon_proxy()
                logger.debug(f"Using proxy from pool: {proxy_entry.name} ({proxy_entry.id})")
            except StorageNotFoundError as e:
                session_id = self._session_path.parent.name
                raise SessionBlockedError(
                    gettext(
                        "Session '{session_id}' requires proxy '{proxy_id}' which is not found "
                        "in proxy pool. Please add the proxy to the pool or update the session "
                        "configuration."
                    ).format(session_id=session_id, proxy_id=self._proxy_id)
                ) from e
        else:
            # Session has no proxy_id configured - this is required
            session_id = self._session_path.parent.name
            raise SessionBlockedError(
                gettext(
                    "Session '{session_id}' has no proxy configured. "
                    "Please configure a proxy for this session before connecting."
                ).format(session_id=session_id)
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

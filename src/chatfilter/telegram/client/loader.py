"""Telegram client loader with secure credential support."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import socks
from telethon import TelegramClient

from chatfilter.config_proxy import ProxyConfig, ProxyType
from chatfilter.i18n.translations import _ as gettext

from .config import (
    SessionBlockedError,
    TelegramConfig,
    TelegramConfigError,
    validate_session_file,
)

if TYPE_CHECKING:
    from telethon import TelegramClient as TelegramClientType

logger = logging.getLogger(__name__)


class TelegramClientLoader:
    """Loader for creating Telethon client from session and global config.

    Uses global Settings for api_id/api_hash and SecureCredentialManager
    for per-session proxy_id.

    Example:
        ```python
        loader = TelegramClientLoader(
            session_path=Path("sessions/my_account/session.session"),
        )
        async with loader.create_client() as client:
            me = await client.get_me()
            print(f"Logged in as {me.username}")
        ```
    """

    def __init__(
        self,
        session_path: Path,
    ) -> None:
        """Initialize loader with session path.

        Args:
            session_path: Path to Telethon .session file
        """
        self._session_path = session_path
        self._config: TelegramConfig | None = None
        self._proxy_id: str | None = None
        self._web_user_id: str = "default"

    @property
    def session_path(self) -> Path:
        """Path to session file."""
        return self._session_path

    def validate(self) -> None:
        """Validate session file and load credentials.

        Call this before create_client() to get early validation errors.
        Validates all required fields for connecting:
        - Session file exists and is valid
        - proxy_id is set (from SecureCredentialManager)
        - proxy exists in pool

        api_id/api_hash come from global Settings and are guaranteed valid.

        Raises:
            FileNotFoundError: If session file doesn't exist
            SessionFileError: If session file is invalid
            TelegramConfigError: If credentials cannot be loaded
            SessionBlockedError: If proxy_id is missing or proxy not in pool
        """
        # Validate session file first
        validate_session_file(self._session_path)

        session_id = self._session_path.parent.name

        # Get api_id/api_hash from global settings (guaranteed valid)
        from chatfilter.config import get_settings

        settings = get_settings()
        self._config = settings.telegram_config

        # Load proxy_id from secure credential manager
        storage_dir = self._session_path.parent.parent

        try:
            from chatfilter.security import SecureCredentialManager

            manager = SecureCredentialManager(storage_dir)
            self._proxy_id = manager.retrieve_session_config(session_id)
        except Exception as e:
            raise TelegramConfigError(f"Failed to load session config: {e}") from e

        # Load web_user_id from session config for per-user proxy isolation
        config_json_path = self._session_path.parent / "config.json"
        if config_json_path.exists():
            try:
                with config_json_path.open("r") as f:
                    cfg = json.load(f)
                    self._web_user_id = cfg.get("web_user_id", "default")
            except Exception:
                pass

        logger.debug(f"Loaded session config for: {session_id}")

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
            get_proxy_by_id(self._proxy_id, self._web_user_id)
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

        Args:
            proxy: Explicit proxy configuration to use. If None, uses the
                session's configured proxy_id from the proxy pool.
            timeout: Timeout in seconds for network operations (default: 30s).
            connection_retries: Number of retries for connection attempts (default: 5).
            retry_delay: Delay in seconds between retry attempts (default: 1).

        Returns:
            TelegramClient instance (not connected yet)

        Raises:
            FileNotFoundError: If session file doesn't exist
            SessionFileError: If session file is invalid
            TelegramConfigError: If config file is invalid
            SessionBlockedError: If proxy_id is missing or proxy not in pool
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

        # Priority: 1) explicit proxy arg, 2) session's proxy_id from pool, 3) no proxy
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
                proxy_entry = get_proxy_by_id(self._proxy_id, self._web_user_id)
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

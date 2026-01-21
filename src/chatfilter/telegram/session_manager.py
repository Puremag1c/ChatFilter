"""Session manager for Telethon client lifecycle management."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Protocol

from telethon import errors

from chatfilter.telegram.retry import with_retry_for_reads

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)

# Default timeouts
DEFAULT_CONNECT_TIMEOUT = 30.0
DEFAULT_OPERATION_TIMEOUT = 60.0
DEFAULT_DISCONNECT_TIMEOUT = 10.0
DEFAULT_HEALTH_CHECK_TIMEOUT = 5.0


class SessionState(str, Enum):
    """State machine for session lifecycle."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    ERROR = "error"


class ClientFactory(Protocol):
    """Protocol for creating Telegram clients (for dependency injection)."""

    def create_client(self) -> TelegramClient:
        """Create a new TelegramClient instance."""
        ...


@dataclass
class SessionInfo:
    """Information about a managed session."""

    session_id: str
    state: SessionState
    connected_at: float | None = None
    last_activity: float | None = None
    error_message: str | None = None
    # Heartbeat metrics
    last_ping_at: float | None = None
    last_ping_success: float | None = None
    consecutive_ping_failures: int = 0


@dataclass
class ManagedSession:
    """Internal state for a managed Telethon session."""

    client: TelegramClient
    state: SessionState = SessionState.DISCONNECTED
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    connected_at: float | None = None
    last_activity: float | None = None
    error_message: str | None = None
    # Heartbeat metrics
    last_ping_at: float | None = None
    last_ping_success: float | None = None
    consecutive_ping_failures: int = 0


class SessionError(Exception):
    """Base exception for session management errors."""


class SessionConnectError(SessionError):
    """Raised when connection fails."""


class SessionTimeoutError(SessionError):
    """Raised when an operation times out."""


class SessionNotConnectedError(SessionError):
    """Raised when trying to use a disconnected session."""


class SessionInvalidError(SessionError):
    """Raised when session is permanently invalid and requires new session file.

    This indicates issues like:
    - Session was revoked/logged out from another device
    - Auth key is unregistered or invalid
    - Account is banned

    User must provide a new session file to continue.
    """


class SessionReauthRequiredError(SessionError):
    """Raised when session requires re-authorization but may be recoverable.

    This indicates issues like:
    - 2FA password needed
    - Session expired but can be refreshed

    The session file itself may still be valid after re-authentication.
    """


class SessionManager:
    """Manager for Telethon client connections with proper lifecycle handling.

    Features:
    - Async context manager for safe connect/disconnect
    - Per-session locking for serialized access
    - Health check mechanism
    - Configurable timeouts
    - Dependency injection for testability

    Example:
        ```python
        from chatfilter.telegram.client import TelegramClientLoader

        loader = TelegramClientLoader(session_path, config_path)
        manager = SessionManager()

        session_id = "my_session"
        manager.register(session_id, loader)

        async with manager.session(session_id) as client:
            me = await client.get_me()
            dialogs = await client.iter_dialogs()
        ```
    """

    def __init__(
        self,
        *,
        connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
        operation_timeout: float = DEFAULT_OPERATION_TIMEOUT,
        disconnect_timeout: float = DEFAULT_DISCONNECT_TIMEOUT,
        health_check_timeout: float = DEFAULT_HEALTH_CHECK_TIMEOUT,
        heartbeat_interval: float = 60.0,
        heartbeat_timeout: float = 10.0,
        heartbeat_max_failures: int = 3,
    ) -> None:
        """Initialize SessionManager.

        Args:
            connect_timeout: Timeout for connection attempts
            operation_timeout: Default timeout for operations
            disconnect_timeout: Timeout for disconnect
            health_check_timeout: Timeout for health checks
            heartbeat_interval: Interval between heartbeat checks
            heartbeat_timeout: Timeout for heartbeat ping operations
            heartbeat_max_failures: Max consecutive failures before reconnection
        """
        self._sessions: dict[str, ManagedSession] = {}
        self._factories: dict[str, ClientFactory] = {}
        self._connect_timeout = connect_timeout
        self._operation_timeout = operation_timeout
        self._disconnect_timeout = disconnect_timeout
        self._health_check_timeout = health_check_timeout
        self._global_lock = asyncio.Lock()
        # Heartbeat monitoring
        self._heartbeat_interval = heartbeat_interval
        self._heartbeat_timeout = heartbeat_timeout
        self._heartbeat_max_failures = heartbeat_max_failures
        self._monitor_task: asyncio.Task[None] | None = None
        self._monitor_stop_event = asyncio.Event()

    def register(self, session_id: str, factory: ClientFactory) -> None:
        """Register a client factory for a session.

        Args:
            session_id: Unique identifier for this session
            factory: Factory that can create TelegramClient instances

        Example:
            ```python
            loader = TelegramClientLoader(session_path, config_path)
            manager.register("my_session", loader)
            ```
        """
        self._factories[session_id] = factory

    def unregister(self, session_id: str) -> None:
        """Unregister a session. Must be disconnected first.

        Args:
            session_id: Session to unregister

        Raises:
            SessionError: If session is still connected
        """
        if session_id in self._sessions:
            session = self._sessions[session_id]
            if session.state == SessionState.CONNECTED:
                raise SessionError(
                    f"Cannot unregister connected session '{session_id}'. Disconnect first."
                )
            del self._sessions[session_id]
        self._factories.pop(session_id, None)

    @with_retry_for_reads(max_attempts=3, base_delay=1.0, max_delay=30.0)
    async def _do_connect(self, client: TelegramClient, session_id: str, timeout: float) -> None:
        """Execute connection with retry logic and timeout.

        This method wraps client.connect() with automatic retry on network errors.
        It will retry ConnectionError, TimeoutError, OSError, and SSL errors.

        Args:
            client: TelegramClient to connect
            session_id: Session identifier (for logging)
            timeout: Connection timeout in seconds

        Raises:
            asyncio.TimeoutError: If connection times out after all retries
            ConnectionError, OSError: If connection fails after all retries
        """
        try:
            await asyncio.wait_for(client.connect(), timeout=timeout)
        except TimeoutError:
            # Convert asyncio.TimeoutError to TimeoutError for retry decorator
            raise TimeoutError(f"Connection timeout for session '{session_id}' after {timeout}s")

    async def connect(self, session_id: str) -> TelegramClient:
        """Connect a session and return the client.

        Prefer using `session()` context manager instead for automatic cleanup.

        Args:
            session_id: Session to connect

        Returns:
            Connected TelegramClient

        Raises:
            SessionConnectError: If connection fails
            SessionTimeoutError: If connection times out
            KeyError: If session_id not registered
        """
        if session_id not in self._factories:
            raise KeyError(f"Session '{session_id}' not registered")

        async with self._global_lock:
            if session_id not in self._sessions:
                client = self._factories[session_id].create_client()
                self._sessions[session_id] = ManagedSession(client=client)

        session = self._sessions[session_id]

        async with session.lock:
            if session.state == SessionState.CONNECTED:
                return session.client

            session.state = SessionState.CONNECTING
            session.error_message = None

            try:
                # Use retry-enabled connection helper
                await self._do_connect(session.client, session_id, self._connect_timeout)
                session.state = SessionState.CONNECTED
                session.connected_at = asyncio.get_event_loop().time()
                session.last_activity = session.connected_at
                logger.info(f"Session '{session_id}' connected")
                return session.client

            except TimeoutError as e:
                session.state = SessionState.ERROR
                session.error_message = "Connection timeout"
                raise SessionTimeoutError(f"Connection timeout for session '{session_id}'") from e
            except (
                errors.SessionRevokedError,
                errors.AuthKeyUnregisteredError,
                errors.AuthKeyInvalidError,
                errors.AuthKeyNotFound,
                errors.AuthKeyPermEmptyError,
                errors.PhoneNumberBannedError,
                errors.UserDeactivatedBanError,
            ) as e:
                # Permanently invalid session - requires new session file
                session.state = SessionState.ERROR
                error_type = type(e).__name__

                # Provide specific message for account deactivation/ban
                if isinstance(e, (errors.UserDeactivatedBanError, errors.PhoneNumberBannedError)):
                    session.error_message = (
                        f"Account is deactivated or banned ({error_type}). "
                        "This Telegram account has been banned, deactivated, or deleted. "
                        "Please use a different account."
                    )
                    raise SessionInvalidError(
                        f"Session '{session_id}' cannot be used: {error_type}. "
                        "The Telegram account associated with this session is banned, "
                        "deactivated, or deleted. Please generate and upload a new "
                        "session file from a different, active Telegram account."
                    ) from e
                else:
                    session.error_message = (
                        f"Session is invalid ({error_type}). Please provide a new session file."
                    )
                    raise SessionInvalidError(
                        f"Session '{session_id}' is permanently invalid: {error_type}. "
                        "The session has been revoked, the auth key is unregistered, "
                        "or the account is inaccessible. Please generate and upload a new "
                        "session file from an authenticated Telegram client."
                    ) from e
            except (
                errors.SessionPasswordNeededError,
                errors.SessionExpiredError,
            ) as e:
                # Session needs re-authorization but may be recoverable
                session.state = SessionState.ERROR
                error_type = type(e).__name__
                if isinstance(e, errors.SessionPasswordNeededError):
                    session.error_message = (
                        "Two-factor authentication (2FA) is enabled. Re-authorization required."
                    )
                    raise SessionReauthRequiredError(
                        f"Session '{session_id}' requires 2FA password. "
                        "The account has two-factor authentication enabled. "
                        "Please re-authorize with your 2FA password, or provide "
                        "a new session file that includes 2FA authorization."
                    ) from e
                else:
                    session.error_message = "Session has expired. Re-authorization required."
                    raise SessionReauthRequiredError(
                        f"Session '{session_id}' has expired: {error_type}. "
                        "Please re-authorize your Telegram account or provide "
                        "a new session file."
                    ) from e
            except Exception as e:
                session.state = SessionState.ERROR
                session.error_message = str(e)
                raise SessionConnectError(f"Failed to connect session '{session_id}': {e}") from e

    async def disconnect(self, session_id: str) -> None:
        """Disconnect a session.

        Args:
            session_id: Session to disconnect

        Note:
            This method is safe to call even if not connected.
        """
        if session_id not in self._sessions:
            return

        session = self._sessions[session_id]

        async with session.lock:
            if session.state not in (SessionState.CONNECTED, SessionState.ERROR):
                return

            session.state = SessionState.DISCONNECTING

            try:
                await asyncio.wait_for(
                    session.client.disconnect(),
                    timeout=self._disconnect_timeout,
                )
            except TimeoutError:
                logger.warning(f"Disconnect timeout for session '{session_id}', forcing...")
            except Exception as e:
                logger.warning(f"Error during disconnect of session '{session_id}': {e}")

            session.state = SessionState.DISCONNECTED
            session.connected_at = None
            logger.info(f"Session '{session_id}' disconnected")

    async def is_healthy(self, session_id: str) -> bool:
        """Check if a session is healthy (connected and responsive).

        Args:
            session_id: Session to check

        Returns:
            True if session is connected and responds to ping

        Note:
            If session auth errors are detected, session state is updated
            with appropriate error message.
        """
        if session_id not in self._sessions:
            return False

        session = self._sessions[session_id]
        if session.state != SessionState.CONNECTED:
            return False

        try:
            # Use get_me() as a health check - lightweight and confirms auth
            await asyncio.wait_for(
                session.client.get_me(),
                timeout=self._health_check_timeout,
            )
            session.last_activity = asyncio.get_event_loop().time()
            return True
        except (
            errors.SessionRevokedError,
            errors.AuthKeyUnregisteredError,
            errors.AuthKeyInvalidError,
            errors.AuthKeyNotFound,
            errors.AuthKeyPermEmptyError,
            errors.PhoneNumberBannedError,
            errors.UserDeactivatedBanError,
        ) as e:
            error_type = type(e).__name__
            session.state = SessionState.ERROR
            session.error_message = (
                f"Session is invalid ({error_type}). Please provide a new session file."
            )
            logger.error(f"Session '{session_id}' is permanently invalid: {error_type}")
            return False
        except (
            errors.SessionPasswordNeededError,
            errors.SessionExpiredError,
        ) as e:
            error_type = type(e).__name__
            session.state = SessionState.ERROR
            if isinstance(e, errors.SessionPasswordNeededError):
                session.error_message = (
                    "Two-factor authentication (2FA) is enabled. Re-authorization required."
                )
            else:
                session.error_message = "Session has expired. Re-authorization required."
            logger.error(f"Session '{session_id}' requires re-authorization: {error_type}")
            return False
        except Exception as e:
            logger.warning(f"Health check failed for session '{session_id}': {e}")
            return False

    def get_info(self, session_id: str) -> SessionInfo | None:
        """Get information about a session.

        Args:
            session_id: Session to get info for

        Returns:
            SessionInfo or None if session not found
        """
        if session_id not in self._sessions:
            if session_id in self._factories:
                return SessionInfo(
                    session_id=session_id,
                    state=SessionState.DISCONNECTED,
                )
            return None

        session = self._sessions[session_id]
        return SessionInfo(
            session_id=session_id,
            state=session.state,
            connected_at=session.connected_at,
            last_activity=session.last_activity,
            error_message=session.error_message,
            last_ping_at=session.last_ping_at,
            last_ping_success=session.last_ping_success,
            consecutive_ping_failures=session.consecutive_ping_failures,
        )

    def list_sessions(self) -> list[str]:
        """List all registered session IDs.

        Returns:
            List of session IDs
        """
        return list(self._factories.keys())

    async def disconnect_all(self) -> None:
        """Disconnect all sessions. Useful for graceful shutdown."""
        for session_id in list(self._sessions.keys()):
            await self.disconnect(session_id)

    def start_monitor(self) -> None:
        """Start the connection monitor background task.

        The monitor periodically checks all connected sessions for health
        and automatically reconnects zombie connections (connected but unresponsive).
        """
        if self._monitor_task is not None and not self._monitor_task.done():
            logger.warning("Connection monitor already running")
            return

        self._monitor_stop_event.clear()
        self._monitor_task = asyncio.create_task(self._monitor_connections())
        logger.info(
            f"Connection monitor started (interval={self._heartbeat_interval}s, "
            f"timeout={self._heartbeat_timeout}s, "
            f"max_failures={self._heartbeat_max_failures})"
        )

    async def stop_monitor(self) -> None:
        """Stop the connection monitor background task."""
        if self._monitor_task is None or self._monitor_task.done():
            return

        self._monitor_stop_event.set()
        try:
            await asyncio.wait_for(self._monitor_task, timeout=5.0)
        except TimeoutError:
            logger.warning("Connection monitor did not stop gracefully, cancelling...")
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Connection monitor stopped")

    async def _monitor_connections(self) -> None:
        """Background task that monitors connection health.

        This task runs continuously, checking all connected sessions
        at regular intervals and attempting to recover zombie connections.
        """
        logger.debug("Connection monitor loop started")
        while not self._monitor_stop_event.is_set():
            try:
                # Check all sessions
                session_ids = list(self._sessions.keys())
                for session_id in session_ids:
                    try:
                        await self._check_session_health(session_id)
                    except Exception as e:
                        logger.error(
                            f"Error checking health for session '{session_id}': {e}",
                            exc_info=True,
                        )

                # Wait for next check interval or stop event
                try:
                    await asyncio.wait_for(
                        self._monitor_stop_event.wait(),
                        timeout=self._heartbeat_interval,
                    )
                    # Stop event was set
                    break
                except TimeoutError:
                    # Timeout is normal - time for next check
                    continue

            except Exception as e:
                logger.error(
                    f"Unexpected error in connection monitor: {e}",
                    exc_info=True,
                )
                # Continue monitoring despite errors
                await asyncio.sleep(5.0)

        logger.debug("Connection monitor loop ended")

    async def _check_session_health(self, session_id: str) -> None:
        """Check health of a single session and handle reconnection if needed.

        Args:
            session_id: Session to check
        """
        if session_id not in self._sessions:
            return

        session = self._sessions[session_id]

        # Only monitor connected sessions
        if session.state != SessionState.CONNECTED:
            return

        current_time = asyncio.get_event_loop().time()
        session.last_ping_at = current_time

        # Perform health check with timeout
        try:
            is_healthy = await asyncio.wait_for(
                self.is_healthy(session_id),
                timeout=self._heartbeat_timeout,
            )

            if is_healthy:
                # Success - reset failure counter
                session.consecutive_ping_failures = 0
                session.last_ping_success = current_time
                logger.debug(f"Heartbeat OK for session '{session_id}'")
            else:
                # Health check failed
                session.consecutive_ping_failures += 1
                logger.warning(
                    f"Heartbeat failed for session '{session_id}' "
                    f"({session.consecutive_ping_failures}/{self._heartbeat_max_failures})"
                )

                # Check if we've reached max failures - this is a zombie connection
                if session.consecutive_ping_failures >= self._heartbeat_max_failures:
                    logger.error(
                        f"Session '{session_id}' is a zombie connection "
                        f"({session.consecutive_ping_failures} consecutive failures). "
                        "Attempting reconnection..."
                    )
                    await self._recover_zombie_connection(session_id)

        except TimeoutError:
            # Ping timed out
            session.consecutive_ping_failures += 1
            logger.warning(
                f"Heartbeat timeout for session '{session_id}' "
                f"({session.consecutive_ping_failures}/{self._heartbeat_max_failures})"
            )

            if session.consecutive_ping_failures >= self._heartbeat_max_failures:
                logger.error(
                    f"Session '{session_id}' is a zombie connection "
                    f"(timeout after {self._heartbeat_max_failures} attempts). "
                    "Attempting reconnection..."
                )
                await self._recover_zombie_connection(session_id)

        except Exception as e:
            logger.error(
                f"Error during health check for session '{session_id}': {e}",
                exc_info=True,
            )

    async def _recover_zombie_connection(self, session_id: str) -> None:
        """Attempt to recover a zombie connection by disconnecting and reconnecting.

        Args:
            session_id: Session to recover
        """
        try:
            logger.info(f"Disconnecting zombie session '{session_id}'...")
            await self.disconnect(session_id)

            logger.info(f"Reconnecting session '{session_id}'...")
            await self.connect(session_id)

            logger.info(f"Successfully recovered session '{session_id}'")

        except Exception as e:
            logger.error(
                f"Failed to recover zombie session '{session_id}': {e}",
                exc_info=True,
            )

    class _SessionContext:
        """Context manager for session access with automatic cleanup."""

        def __init__(self, manager: SessionManager, session_id: str, auto_disconnect: bool) -> None:
            self._manager = manager
            self._session_id = session_id
            self._auto_disconnect = auto_disconnect
            self._client: TelegramClient | None = None

        async def __aenter__(self) -> TelegramClient:
            self._client = await self._manager.connect(self._session_id)
            return self._client

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: object | None,
        ) -> None:
            if self._auto_disconnect:
                await self._manager.disconnect(self._session_id)

    def session(self, session_id: str, *, auto_disconnect: bool = True) -> _SessionContext:
        """Get a context manager for accessing a session.

        Args:
            session_id: Session to access
            auto_disconnect: Whether to disconnect when exiting context

        Returns:
            Async context manager that yields the TelegramClient

        Example:
            ```python
            async with manager.session("my_session") as client:
                me = await client.get_me()
            # Automatically disconnected here
            ```
        """
        return self._SessionContext(self, session_id, auto_disconnect)

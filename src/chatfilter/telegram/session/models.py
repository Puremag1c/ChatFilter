"""Session management data models and exceptions."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from telethon import TelegramClient

# Default timeouts
DEFAULT_CONNECT_TIMEOUT = 30.0
DEFAULT_OPERATION_TIMEOUT = 60.0
DEFAULT_DISCONNECT_TIMEOUT = 30.0
DEFAULT_HEALTH_CHECK_TIMEOUT = 5.0


class SessionState(StrEnum):
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
    # Network switch detection
    last_network_error_at: float | None = None
    network_error_count: int = 0
    is_recovering_from_switch: bool = False


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
    # Network switch detection
    last_network_error_at: float | None = None
    network_error_count: int = 0
    is_recovering_from_switch: bool = False


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


class SessionBusyError(SessionError):
    """Raised when session is already busy with another operation.

    This indicates that a concurrent operation is in progress.
    The client should retry later or wait for the current operation to complete.
    """

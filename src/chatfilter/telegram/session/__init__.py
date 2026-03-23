"""Session management package for Telethon client lifecycle.

This package provides session management functionality for Telegram clients,
including connection lifecycle, health monitoring, and error handling.
"""

from .manager import SessionManager
from .models import (
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_DISCONNECT_TIMEOUT,
    DEFAULT_HEALTH_CHECK_TIMEOUT,
    DEFAULT_OPERATION_TIMEOUT,
    ClientFactory,
    ManagedSession,
    SessionBusyError,
    SessionConnectError,
    SessionError,
    SessionInfo,
    SessionInvalidError,
    SessionNotConnectedError,
    SessionReauthRequiredError,
    SessionState,
    SessionTimeoutError,
)

__all__ = [
    # Main manager
    "SessionManager",
    # Data models
    "SessionState",
    "SessionInfo",
    "ManagedSession",
    "ClientFactory",
    # Exceptions
    "SessionError",
    "SessionConnectError",
    "SessionTimeoutError",
    "SessionNotConnectedError",
    "SessionInvalidError",
    "SessionReauthRequiredError",
    "SessionBusyError",
    # Constants
    "DEFAULT_CONNECT_TIMEOUT",
    "DEFAULT_OPERATION_TIMEOUT",
    "DEFAULT_DISCONNECT_TIMEOUT",
    "DEFAULT_HEALTH_CHECK_TIMEOUT",
]

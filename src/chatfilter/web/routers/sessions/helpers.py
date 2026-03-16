"""Session helpers and utilities."""

from __future__ import annotations

import asyncio
import logging
import re
import shutil
from pathlib import Path

from pydantic import BaseModel

from chatfilter.storage.file import secure_delete_file

logger = logging.getLogger(__name__)


# Per-session locks to prevent race conditions on parallel operations
_session_locks: dict[str, asyncio.Lock] = {}
_locks_lock = asyncio.Lock()  # Lock for _session_locks dict access


class SessionListItem(BaseModel):
    """Session info for list response."""

    session_id: str
    state: str
    error_message: str | None = None
    auth_id: str | None = None
    has_session_file: bool = False  # True if session.session exists (cached auth)
    retry_available: bool | None = None  # True if error is transient and user can retry
    flood_wait_until: str | None = None  # ISO timestamp when FloodWait expires (for countdown)


async def _get_session_lock(session_id: str) -> asyncio.Lock:
    """Get or create a lock for a specific session.

    This prevents race conditions when multiple requests operate on the same session.
    Example: User double-clicks Connect → only one background task runs.
    """
    async with _locks_lock:
        if session_id not in _session_locks:
            _session_locks[session_id] = asyncio.Lock()
        return _session_locks[session_id]


def _get_flood_wait_until(session_id: str) -> str | None:
    """Return ISO timestamp when FloodWait expires, or None if not blocked."""
    from datetime import datetime, timezone

    from chatfilter.telegram.flood_tracker import get_flood_tracker

    flood_tracker = get_flood_tracker()
    wait_until_ts = flood_tracker.get_wait_until(session_id)
    if wait_until_ts:
        # Convert timestamp to ISO format
        wait_until_dt = datetime.fromtimestamp(wait_until_ts, tz=timezone.utc)
        return wait_until_dt.isoformat()
    return None


def classify_error_state(error_message: str | None, exception: Exception | None = None) -> str:
    """Classify an error message or exception into a specific state.

    Simplified 3-state model (8-state model is handled by connect flow):
    - session_expired, corrupted_session → handled by auto-reauth/auto-delete in connect flow
    - flood_wait → merged into 'error' (with tooltip)
    - proxy_error → merged into 'needs_config' or 'error' based on context

    Args:
        error_message: The error message from the session
        exception: The original exception object (if available)

    Returns:
        One of: 'banned', 'needs_config', 'error'
    """
    # First check exception type if provided
    if exception is not None:
        error_class = type(exception).__name__

        # Banned/deactivated account (terminal state)
        if error_class in {
            "UserDeactivatedError",
            "UserDeactivatedBanError",
            "PhoneNumberBannedError",
        }:
            return "banned"

        # Proxy/connection errors → needs_config (proxy misconfigured)
        if error_class in {"OSError", "ConnectionError", "ConnectionRefusedError"}:
            return "needs_config"

        # For wrapper exceptions (SessionConnectError, etc.), check the cause
        if exception.__cause__ is not None:
            cause_result = classify_error_state(error_message, exception.__cause__)
            if cause_result != "error":
                return cause_result

    # Fall back to string matching if no exception or class didn't match
    if not error_message:
        return "error"

    error_lower = error_message.lower()

    # Check for banned/deactivated account
    if any(
        phrase in error_lower
        for phrase in ["banned", "deactivated", "phonenumberbanned", "userdeactivatedban"]
    ):
        return "banned"

    # Check for proxy/connection errors → needs_config
    if any(
        phrase in error_lower
        for phrase in ["proxy", "socks", "connection refused", "cannot connect"]
    ):
        return "needs_config"

    return "error"


def sanitize_error_message_for_client(error_message: str, error_state: str) -> str:
    """Sanitize error message for client, preventing technical info disclosure."""
    # Map error states to safe fallback messages
    SAFE_MESSAGES = {
        "needs_config": "Configuration error. Please check your proxy settings.",
        "proxy_error": "Connection failed. Please check your proxy settings and try again.",
        "network_error": "Network connection error. Please check your internet connection and try again.",
        "timeout": "Connection timeout. Please try again.",
        "banned": "Account restricted. Please check your Telegram account status.",
        "error": "An error occurred. Please try again or contact support.",
    }

    # Patterns that indicate technical/sensitive information
    SENSITIVE_PATTERNS = [
        r"/[\w/\\. -]+",  # Unix file paths
        r"[A-Z]:\\[\w\\. -]+",  # Windows paths
        r"\b[0-9a-f]{8,}\b",  # IDs/hashes
        r"\bTraceback\b",  # Stack traces
        r'File ".*?"',  # Python file references
        r"line \d+",  # Line numbers
        r"\w+Error\b",  # Error class names
        r"\w+Exception\b",  # Exception class names
        r"'[\w-]+'.*not found",  # Internal IDs (e.g., "Proxy 'abc123' not found")
    ]

    # Check if message contains sensitive information
    has_sensitive = any(re.search(pattern, error_message) for pattern in SENSITIVE_PATTERNS)

    if has_sensitive:
        # Use safe fallback based on error_state
        return SAFE_MESSAGES.get(error_state, SAFE_MESSAGES["error"])

    # Message looks safe, pass through
    return error_message


def secure_delete_dir(dir_path: Path | str) -> None:
    """Securely delete a directory by overwriting all files before removal."""
    dir_path = Path(dir_path)
    if not dir_path.exists() or not dir_path.is_dir():
        return

    try:
        # Recursively secure delete all files
        for file_path in dir_path.rglob("*"):
            if file_path.is_file():
                secure_delete_file(file_path)

        # Remove empty directory tree
        shutil.rmtree(dir_path, ignore_errors=False)
    except Exception as e:
        logger.warning(f"Failed to securely delete directory, falling back to regular delete: {e}")
        # Fallback to regular deletion
        shutil.rmtree(dir_path, ignore_errors=True)


# Re-export from validation.py (for backward compatibility)
from .validation import (
    sanitize_session_name,
    validate_config_file_format,
    validate_phone_number,
    validate_session_file_format,
    validate_telegram_credentials_with_retry,
)

# Re-export from io.py and listing.py - lazy import to avoid circular dependency
def __getattr__(name: str):
    """Lazy import for backward compatibility with existing imports."""
    if name in {
        "read_upload_with_size_limit",
        "get_account_info_from_session",
        "save_account_info",
        "load_account_info",
        "_save_session_to_disk",
        "find_duplicate_accounts",
        "migrate_legacy_sessions",
        "ensure_data_dir",
        "secure_file_permissions",
        "MAX_SESSION_SIZE",
        "MAX_JSON_SIZE",
        "MAX_CONFIG_SIZE",
        "READ_CHUNK_SIZE",
    }:
        from . import io
        return getattr(io, name)
    elif name in {
        "get_session_config_status",
        "list_stored_sessions",
        "_save_error_to_config",
    }:
        from . import listing
        return getattr(listing, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


# Ensure __all__ is defined for star imports
__all__ = [
    # Core helpers
    "SessionListItem",
    "classify_error_state",
    "sanitize_error_message_for_client",
    "_get_session_lock",
    "_get_flood_wait_until",
    "secure_delete_dir",
    # From validation.py
    "sanitize_session_name",
    "validate_config_file_format",
    "validate_phone_number",
    "validate_session_file_format",
    "validate_telegram_credentials_with_retry",
    # From io.py
    "read_upload_with_size_limit",
    "get_account_info_from_session",
    "save_account_info",
    "load_account_info",
    "_save_session_to_disk",
    "find_duplicate_accounts",
    "migrate_legacy_sessions",
    "ensure_data_dir",
    "secure_file_permissions",
    "MAX_SESSION_SIZE",
    "MAX_JSON_SIZE",
    "MAX_CONFIG_SIZE",
    "READ_CHUNK_SIZE",
    # From listing.py
    "get_session_config_status",
    "list_stored_sessions",
    "_save_error_to_config",
]

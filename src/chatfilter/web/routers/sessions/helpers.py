"""Session helpers and utilities."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import sqlite3
import stat
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import UploadFile
from pydantic import BaseModel

from chatfilter.config import get_settings
from chatfilter.i18n import _
from chatfilter.storage.file import secure_delete_file
from chatfilter.storage.helpers import atomic_write
from chatfilter.telegram.flood_tracker import get_flood_tracker
from chatfilter.telegram.session_manager import SessionState

# Import validation functions from validation module
from .validation import (
    sanitize_session_name,
    validate_config_file_format,
    validate_phone_number,
    validate_session_file_format,
    validate_telegram_credentials_with_retry,
)

if TYPE_CHECKING:
    from telethon import TelegramClient

    from chatfilter.models.proxy import ProxyEntry
    from chatfilter.telegram.session_manager import SessionManager
    from chatfilter.web.auth_state import AuthStateManager

logger = logging.getLogger(__name__)


# Maximum file sizes (security limit)
MAX_SESSION_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_JSON_SIZE = 10 * 1024  # 10 KB (account info JSON)
MAX_CONFIG_SIZE = 1024  # 1 KB
# Chunk size for reading uploaded files (to prevent memory exhaustion)
READ_CHUNK_SIZE = 8192  # 8 KB chunks


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


def ensure_data_dir() -> Path:
    """Ensure sessions directory exists with proper permissions."""
    sessions_dir = get_settings().sessions_dir
    sessions_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return sessions_dir


def secure_file_permissions(file_path: Path) -> None:
    """Set file permissions to 600 (owner read/write only)."""
    # chmod 600: owner read/write, no access for group/others
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)


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


async def read_upload_with_size_limit(
    upload_file: UploadFile, max_size: int, file_type: str = "file"
) -> bytes:
    """Read uploaded file with size limit enforcement.

    Reads file in chunks to prevent loading large files into memory.
    Raises ValueError if file exceeds size limit.

    Args:
        upload_file: FastAPI UploadFile object
        max_size: Maximum allowed file size in bytes
        file_type: Description of file type for error messages

    Returns:
        File content as bytes

    Raises:
        ValueError: If file size exceeds max_size
    """
    chunks = []
    total_size = 0

    # Read file in chunks to enforce size limit without loading entire file
    while True:
        chunk = await upload_file.read(READ_CHUNK_SIZE)
        if not chunk:
            break

        total_size += len(chunk)
        if total_size > max_size:
            # Stop reading immediately to prevent memory exhaustion
            raise ValueError(
                f"{file_type.capitalize()} file too large "
                f"(max {max_size:,} bytes, got {total_size:,}+ bytes)"
            )

        chunks.append(chunk)

    return b"".join(chunks)


async def get_account_info_from_session(
    session_path: Path, api_id: int, api_hash: str
) -> dict[str, int | str] | None:
    """Extract account info from a session by connecting to Telegram.
    session_path: Path, api_id: int, api_hash: str
) -> dict[str, int | str] | None:
    """Extract account info from a session by connecting to Telegram.

    Args:
        session_path: Path to the session file
        api_id: Telegram API ID
        api_hash: Telegram API hash

    Returns:
        Dict with user_id, phone, first_name, last_name if successful, None otherwise
    """
    from telethon import TelegramClient

    try:
        # Create a temporary client to get account info
        client = TelegramClient(str(session_path), api_id, api_hash)

        # Connect with a timeout to avoid hanging
        await asyncio.wait_for(client.connect(), timeout=30.0)

        if not await client.is_user_authorized():
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
            return None

        # Get user info
        me = await asyncio.wait_for(client.get_me(), timeout=30.0)
        await asyncio.wait_for(client.disconnect(), timeout=30.0)

        return {
            "user_id": me.id,
            "phone": me.phone or "",
            "first_name": me.first_name or "",
            "last_name": me.last_name or "",
        }
    except Exception as e:
        logger.warning(f"Failed to extract account info from session: {e}")
        return None


def save_account_info(session_dir: Path, account_info: dict[str, int | str]) -> None:
    """Save account info metadata to session directory."""
    metadata_file = session_dir / ".account_info.json"
    metadata_content = json.dumps(account_info, indent=2).encode("utf-8")
    atomic_write(metadata_file, metadata_content)
    secure_file_permissions(metadata_file)


def load_account_info(session_dir: Path) -> dict[str, int | str] | None:
    """Load account info metadata from session directory, or None if not found."""
    metadata_file = session_dir / ".account_info.json"
    if not metadata_file.exists():
        return None

    try:
        with metadata_file.open("r") as f:
            data = json.load(f)
            # Type narrowing: ensure it's a dict before returning
            if isinstance(data, dict):
                return data
            return None
    except Exception as e:
        logger.warning(f"Failed to load account info from {metadata_file}: {e}")
        return None


def _save_session_to_disk(
    session_dir: Path,
    session_content: bytes,
    api_id: int | None,
    api_hash: str | None,
    proxy_id: str | None,
    account_info: dict[str, int | str] | None,
    source: str = "file",
) -> None:
    """Save session files to disk with secure credentials.

    Uses atomic transaction pattern:
    1. Write all files to temp directory
    2. On success → rename temp dir to final name (POSIX atomic)
    3. On failure → delete temp dir (no orphaned files)

    Creates:
    - session.session file (atomic write, secure permissions)
    - config.json with api_id, api_hash, proxy_id, source
    - .secure_storage marker
    - .account_info.json if account_info provided

    Also stores credentials in secure storage.

    Args:
        session_dir: Session directory path (must NOT exist)
        session_content: Session file content bytes
        api_id: Telegram API ID (can be None for source=phone)
        api_hash: Telegram API hash (can be None for source=phone)
        proxy_id: Proxy ID (can be None)
        account_info: Account info dict or None
        source: Source of credentials ('file' or 'phone')

    Raises:
        DiskSpaceError: If not enough disk space
        TelegramConfigError: If validation fails
        Exception: On other failures (temp dir is cleaned up)
    """
    import tempfile

    from chatfilter.security import SecureCredentialManager
    from chatfilter.utils.disk import ensure_space_available

    safe_name = session_dir.name

    marker_text = (
        "Credentials are stored in secure storage (OS keyring or encrypted file).\n"
        "Do not create a plaintext config.json file.\n"
    )

    # Calculate total space needed (session file + marker file)
    total_bytes_needed = len(session_content) + len(marker_text.encode("utf-8"))

    # Check disk space before writing (use parent dir since session_dir doesn't exist yet)
    ensure_space_available(session_dir.parent / ".space_check", total_bytes_needed)

    # Create temporary directory for atomic transaction
    # Use parent directory to ensure same filesystem (for atomic rename)
    temp_dir = None
    try:
        temp_dir = Path(tempfile.mkdtemp(prefix=f".tmp_{safe_name}_", dir=session_dir.parent))

        # Write all files to temp directory
        session_path = temp_dir / "session.session"
        atomic_write(session_path, session_content)
        secure_file_permissions(session_path)

        # Store credentials securely (NOT in plaintext)
        # Only store if api_id and api_hash are provided
        if api_id is not None and api_hash is not None:
            storage_dir = session_dir.parent
            manager = SecureCredentialManager(storage_dir)
            manager.store_credentials(safe_name, api_id, api_hash, proxy_id)
            logger.info(f"Stored credentials securely for session: {safe_name}")
        else:
            logger.info(f"Session {safe_name} created without api_id/api_hash (source=phone)")

        # Create per-session config.json
        session_config: dict[str, int | str | None] = {
            "api_id": api_id,
            "api_hash": api_hash,
            "proxy_id": proxy_id,
            "source": source,
        }
        session_config_path = temp_dir / "config.json"
        session_config_content = json.dumps(session_config, indent=2).encode("utf-8")
        atomic_write(session_config_path, session_config_content)
        secure_file_permissions(session_config_path)
        logger.info(f"Created per-session config for session: {safe_name}")

        # Create migration marker to indicate we're using secure storage
        marker_file = temp_dir / ".secure_storage"
        atomic_write(marker_file, marker_text)

        # Save account info if we successfully extracted it
        if account_info:
            save_account_info(temp_dir, account_info)
            # user_id might not be available if get_account_info_from_session failed
            if "user_id" in account_info:
                logger.info(
                    f"Saved account info for session '{safe_name}': "
                    f"user_id={account_info['user_id']}, phone=[REDACTED]"
                )
            else:
                logger.info(
                    f"Saved account info for session '{safe_name}' (user_id not available): "
                    f"phone=[REDACTED]"
                )

        # All writes succeeded → atomic rename (POSIX atomic operation)
        temp_dir.rename(session_dir)
        temp_dir = None  # Prevent cleanup
        logger.info(f"Session '{safe_name}' saved successfully (atomic transaction)")

    except Exception:
        # Cleanup temp directory on any failure
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.info(f"Cleaned up temp directory after failed write: {temp_dir}")
        raise


def find_duplicate_accounts(target_user_id: int, exclude_session: str | None = None) -> list[str]:
    """Find all sessions that belong to the same Telegram account (by user_id)."""
    duplicates = []
    data_dir = ensure_data_dir()

    for session_dir in data_dir.iterdir():
        if not session_dir.is_dir():
            continue

        # Skip the excluded session
        if exclude_session and session_dir.name == exclude_session:
            continue

        # Load account info
        account_info = load_account_info(session_dir)
        if account_info and account_info.get("user_id") == target_user_id:
            duplicates.append(session_dir.name)

    return duplicates


def migrate_legacy_sessions() -> list[str]:
    """Migrate legacy sessions (v0.4) to per-session config format (v0.5).

    Legacy sessions have:
    - session.session file
    - .secure_storage marker (or credentials in keyring)
    - No config.json

    Migration creates config.json with api_id, api_hash from keyring
    and proxy_id=null.

    Returns:
        List of migrated session IDs
    """
    from chatfilter.security import CredentialNotFoundError, SecureCredentialManager

    migrated = []
    data_dir = ensure_data_dir()

    for session_dir in data_dir.iterdir():
        if not session_dir.is_dir():
            continue

        session_file = session_dir / "session.session"
        config_file = session_dir / "config.json"

        # Skip if not a valid session directory
        if not session_file.exists():
            continue

        # Skip if already has config.json (already migrated or new format)
        if config_file.exists():
            continue

        session_id = session_dir.name
        logger.info(f"Found legacy session without config.json: {session_id}")

        # Try to read credentials from keyring
        try:
            manager = SecureCredentialManager(data_dir)
            api_id, api_hash, proxy_id = manager.retrieve_credentials(session_id)

            # Create config.json with credentials
            # Default to 'file' source for migrated sessions
            config_data: dict[str, int | str | None] = {
                "api_id": api_id,
                "api_hash": api_hash,
                "proxy_id": proxy_id,  # Will be None for legacy sessions
                "source": "file",
            }

            config_content = json.dumps(config_data, indent=2).encode("utf-8")
            atomic_write(config_file, config_content)
            secure_file_permissions(config_file)

            migrated.append(session_id)
            logger.info(f"Migrated legacy session '{session_id}' to per-session config format")

        except CredentialNotFoundError:
            logger.warning(
                f"Legacy session '{session_id}' has no credentials in keyring. "
                f"Session will be invisible until credentials are configured."
            )
        except Exception as e:
            logger.error(f"Failed to migrate legacy session '{session_id}': {e}")

    if migrated:
        logger.info(f"Migrated {len(migrated)} legacy sessions: {migrated}")

    return migrated


def get_session_config_status(session_dir: Path) -> tuple[str, str | None]:
    """Check session configuration status.

    Validates that the session has required configuration:
    - api_id and api_hash can be null (source=phone means user will provide via auth)
    - If api_id and api_hash are null, source must be 'phone'
    - If api_id and api_hash are set, source can be 'file' or 'phone'
    - proxy_id must be set (sessions require proxy for operation)
    - If proxy_id is set, the proxy must exist in the pool

    Args:
        session_dir: Path to session directory

    Returns:
        Tuple of (status, reason):
        - ("disconnected", None): Configuration is valid
        - ("needs_config", reason): Missing credentials or proxy configuration
          where reason is a specific message like "API credentials required"
    """
    config_file = session_dir / "config.json"

    if not config_file.exists():
        return ("needs_config", "Configuration file missing")

    try:
        with config_file.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to read config for session {session_dir.name}: {e}")
        return ("needs_config", "Configuration file corrupted")

    # Check fields
    api_id = config.get("api_id")
    api_hash = config.get("api_hash")
    proxy_id = config.get("proxy_id")

    # If api_id or api_hash are null, check encrypted storage first
    if api_id is None or api_hash is None:
        # Bug 1 fix: Check if credentials exist in SecureCredentialManager (Pattern A)
        try:
            from chatfilter.security import SecureCredentialManager

            storage_dir = session_dir.parent  # Pattern A: credentials stored at parent level

            # Guard: storage_dir must exist (addresses ChatFilter-hv39r)
            if not storage_dir.exists():
                return ("needs_config", "API credentials required")

            manager = SecureCredentialManager(storage_dir)
            session_name = session_dir.name

            # Check if encrypted credentials exist
            if manager.has_credentials(session_name):
                # Credentials exist in encrypted storage - continue to proxy check
                logger.debug(
                    f"Session '{session_name}' has credentials in encrypted storage, "
                    "continuing to proxy check"
                )
            else:
                # No credentials in encrypted storage or plaintext config
                return ("needs_config", "API credentials required")
        except Exception as e:
            # Handle corrupted .credentials.enc gracefully (addresses ChatFilter-f540m)
            # Treat as credentials absent
            # Redact exception message to prevent credential leakage
            logger.warning(
                f"Failed to check encrypted credentials for session '{session_dir.name}': "
                f"{type(e).__name__} [REDACTED]"
            )
            return ("needs_config", "API credentials required")

    # proxy_id is required for session to be connectable
    if not proxy_id:
        return ("needs_config", "Proxy configuration required")

    # Verify proxy exists in pool
    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id

    try:
        get_proxy_by_id(proxy_id)
    except StorageNotFoundError:
        return ("needs_config", "Proxy not found in pool")

    return ("disconnected", None)


def list_stored_sessions(
    session_manager: SessionManager | None = None,
    auth_manager: AuthStateManager | None = None,
) -> list[SessionListItem]:
    """List all stored sessions with runtime state when available.

    Each session is validated for configuration status:
    - "disconnected": Ready to connect
    - "connected": Currently connected
    - "connecting": Connection in progress
    - "needs_code": Waiting for verification code (runtime state during auth)
    - "needs_2fa": Waiting for 2FA password (runtime state during auth)
    - "error": Connection error (generic)
    - "banned": Account banned by Telegram
    - "flood_wait": Temporary rate limit
    - "proxy_error": Proxy connection failed
    - "needs_config": Missing configuration (API credentials or proxy)

    Args:
        session_manager: Optional session manager to check runtime state
        auth_manager: Optional auth state manager to check auth flow state

    Returns:
        List of session info items
    """
    from datetime import datetime, timezone
    from chatfilter.telegram.flood_tracker import get_flood_tracker
    from chatfilter.web.auth_state import AuthStep

    sessions = []
    data_dir = ensure_data_dir()
    flood_tracker = get_flood_tracker()

    for session_dir in data_dir.iterdir():
        if session_dir.is_dir():
            session_file = session_dir / "session.session"
            config_file = session_dir / "config.json"
            account_info_file = session_dir / ".account_info.json"

            if config_file.exists() or account_info_file.exists():
                session_id = session_dir.name

                # Handle missing account_info.json (old sessions)
                if not account_info_file.exists():
                    sessions.append(
                        SessionListItem(
                            session_id=session_id,
                            state="needs_config",
                            error_message="Account information missing",
                            auth_id=None,
                            has_session_file=session_file.is_file(),
                            flood_wait_until=_get_flood_wait_until(session_id),
                        )
                    )
                    continue

                # First check config status
                config_status, config_reason = get_session_config_status(session_dir)

                # For list display, map needs_config to disconnected.
                # Sessions saved without credentials are valid (spec: Save-only flow).
                # The connect_session endpoint will check credentials at connect time.
                if config_status == "needs_config":
                    config_status = "disconnected"
                    config_reason = None

                # If session manager available, check runtime state
                state = config_status
                error_message = config_reason if config_status == "needs_config" else None
                retry_available = None

                # If state is an error state from config, read error_message and retry_available
                if state in ("proxy_error", "banned", "flood_wait", "error"):
                    try:
                        with config_file.open("r", encoding="utf-8") as f:
                            config = json.load(f)
                        error_message = config.get("error_message")
                        retry_available = config.get("retry_available")
                    except Exception:
                        pass

                # Check if session has an active auth flow (highest priority)
                auth_id = None
                if auth_manager is not None:
                    auth_state = auth_manager.get_auth_state_by_session(session_id)
                    if auth_state:
                        auth_id = auth_state.auth_id
                        if auth_state.step in (AuthStep.PHONE_SENT, AuthStep.CODE_INVALID):
                            state = "needs_code"
                        elif auth_state.step == AuthStep.NEED_2FA:
                            state = "needs_2fa"
                        elif auth_state.step == AuthStep.NEED_CONFIRMATION:
                            state = "needs_confirmation"

                # Check runtime session state only if no auth flow and config is ready
                if (
                    session_manager is not None
                    and config_status == "disconnected"
                    and state == config_status
                ):
                    # Session is configured - check if it has runtime state
                    info = session_manager.get_info(session_id)
                    if info:
                        if info.state == SessionState.CONNECTED:
                            state = "connected"
                        elif info.state == SessionState.CONNECTING or info.state == SessionState.DISCONNECTING:
                            state = "connecting"
                        elif info.state == SessionState.ERROR:
                            error_message = info.error_message
                            state = classify_error_state(error_message)
                        # DISCONNECTED keeps config_status

                sessions.append(
                    SessionListItem(
                        session_id=session_id,
                        state=state,
                        error_message=error_message,
                        auth_id=auth_id,
                        has_session_file=session_file.is_file(),
                        retry_available=retry_available,
                        flood_wait_until=_get_flood_wait_until(session_id),
                    )
                )

    return sessions


def _save_error_to_config(config_path: Path, error_message: str, retry_available: bool) -> None:
    """Save error message to config.json for UI display."""
    try:
        with config_path.open("r") as f:
            config = json.load(f)
        config["error_message"] = error_message
        config["retry_available"] = retry_available
        config_content = json.dumps(config, indent=2).encode("utf-8")
        atomic_write(config_path, config_content)
    except Exception:
        logger.exception("Failed to save error message to config.json")


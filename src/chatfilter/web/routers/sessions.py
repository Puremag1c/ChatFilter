"""Sessions router for session file upload and management.

Session Status State Machine
============================

This module implements a finite state machine for session status transitions.
Each transition triggers both an HTML response update and an SSE event publication.

States
------
- disconnected: Session is ready but not connected to Telegram
- connected: Session is actively connected to Telegram
- connecting: Transient state during connection establishment
- disconnecting: Transient state during disconnection
- needs_code: Waiting for SMS/app verification code
- needs_2fa: Waiting for 2FA password
- needs_api_id: Missing API ID/hash configuration
- proxy_missing: Configured proxy not found in pool
- corrupted_session: Session file is corrupt, cannot recover
- banned: Account banned by Telegram
- flood_wait: Rate limited, temporary wait required
- proxy_error: Proxy connection failed
- error: Generic error state

Transition Matrix
-----------------
From State          | Action/Event           | To State      | SSE Event | Endpoint
--------------------|------------------------|---------------|-----------|----------------------------------
disconnected        | connect button         | connecting    | -         | POST /api/sessions/{id}/connect
connecting          | connection success     | connected     | connected | POST /api/sessions/{id}/connect
connecting          | connection failure     | error/*       | error/*   | POST /api/sessions/{id}/connect
connected           | disconnect button      | disconnecting | -         | POST /api/sessions/{id}/disconnect
disconnecting       | disconnect success     | disconnected  | disconn.  | POST /api/sessions/{id}/disconnect
disconnecting       | disconnect failure     | error         | error     | POST /api/sessions/{id}/disconnect
needs_code          | code verified          | connected     | connected | POST /api/sessions/{id}/verify-code
needs_code          | code verified + 2FA    | needs_2fa     | needs_2fa | POST /api/sessions/{id}/verify-code
needs_code          | code invalid           | needs_code    | -         | POST /api/sessions/{id}/verify-code
needs_code          | modal cancelled        | needs_code    | -         | UI only (no API call)
needs_2fa           | password verified      | connected     | connected | POST /api/sessions/{id}/verify-2fa
needs_2fa           | password invalid       | needs_2fa     | -         | POST /api/sessions/{id}/verify-2fa
needs_2fa           | modal cancelled        | needs_2fa     | -         | UI only (no API call)
error               | retry button           | connecting    | -         | POST /api/sessions/{id}/connect
proxy_error         | retry button           | connecting    | -         | POST /api/sessions/{id}/connect
flood_wait          | retry button           | connecting    | -         | POST /api/sessions/{id}/connect

Error State Classification
--------------------------
Errors are classified by `classify_error_state()` function:
- disconnected: AuthKeyUnregistered, SessionRevoked, SessionExpired (treated as disconnected, Connect triggers send_code)
- banned: UserDeactivated, UserDeactivatedBan, PhoneNumberBanned
- flood_wait: FloodWaitError, SlowModeWaitError
- proxy_error: OSError, ConnectionError, ConnectionRefused
- corrupted_session: SessionFileError, invalid database
- error: Generic/unknown errors

SSE Event Publishing
--------------------
Events are published via `get_event_bus().publish(session_id, status)`.
The SSE endpoint is at GET /api/sessions/events.

All status-changing endpoints publish SSE events:
- connect_session: publishes on success (connected) or failure (error state)
- disconnect_session: publishes on success (disconnected) or failure (error)
- verify_code: publishes connected or needs_2fa on success
- verify_2fa: publishes connected on success

Loading States in UI (session_row.html)
---------------------------------------
The template shows spinner indicators via htmx:
- hx-indicator="#connection-spinner-{id}" on connect/disconnect buttons
- hx-disabled-elt="this" disables button during request
- connecting/disconnecting states show disabled button with spinner

Template State Handling:
- Each state has specific button rendering (connect/disconnect/retry/configure)
- Error states show title attribute with error message
- needs_code/needs_2fa show modal trigger buttons
- banned/corrupted show disabled buttons (non-recoverable)

Modal Cancel Behavior (modal_code.html, modal_2fa.html)
--------------------------------------------------------
When user cancels code/2FA modals:
- Session state remains unchanged (stays in needs_code or needs_2fa)
- User sees confirmation: "Authentication cancelled. Session remains disconnected. You can try again anytime."
- No API call is made (client-side only)
- User can re-open modal and retry authentication without data loss
- This is the least destructive option: session stays stable, user can retry later
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, BackgroundTasks, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from chatfilter.config import get_settings
from chatfilter.i18n import _
from chatfilter.web.events import get_event_bus
from chatfilter.storage.file import robust_delete_session_file, secure_delete_file
from chatfilter.storage.helpers import atomic_write
from chatfilter.telegram.client import SessionFileError, TelegramClientLoader, TelegramConfigError
from chatfilter.telegram.session_manager import SessionBusyError, SessionState
from chatfilter.web.events import get_event_bus
from chatfilter.parsers.telegram_expert import parse_telegram_expert_json, validate_account_info_json

if TYPE_CHECKING:
    from starlette.templating import Jinja2Templates

    from chatfilter.models.proxy import ProxyEntry
    from chatfilter.web.auth_state import AuthState, AuthStateManager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sessions"])

# Maximum file sizes (security limit)
MAX_SESSION_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_JSON_SIZE = 10 * 1024  # 10 KB (account info JSON)
MAX_CONFIG_SIZE = 1024  # 1 KB
# Chunk size for reading uploaded files (to prevent memory exhaustion)
READ_CHUNK_SIZE = 8192  # 8 KB chunks


def validate_phone_number(phone: str) -> None:
    """Validate phone number format for manual phone input.

    This is a simple validation for start_auth_flow endpoint.
    For JSON import, use parsers.telegram_expert module instead.

    Args:
        phone: Phone number to validate

    Raises:
        ValueError: If phone format is invalid
    """
    if not phone.startswith("+"):
        raise ValueError(_("Phone number must start with +"))

    # Remove common formatting characters and check digits
    digits_only = phone[1:].replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if not digits_only.isdigit():
        raise ValueError(_("Phone number must contain only digits after +"))


class SessionListItem(BaseModel):
    """Session info for list response."""

    session_id: str
    state: str
    error_message: str | None = None
    auth_id: str | None = None
    has_session_file: bool = False  # True if session.session exists (cached auth)
    retry_available: bool | None = None  # True if error is transient and user can retry


def classify_error_state(error_message: str | None, exception: Exception | None = None) -> str:
    """Classify an error message or exception into a specific state.

    Args:
        error_message: The error message from the session
        exception: The original exception object (if available)

    Returns:
        One of: 'disconnected', 'banned', 'flood_wait', 'proxy_error', 'corrupted_session', 'error'
    """
    # First check exception type if provided
    if exception is not None:
        error_class = type(exception).__name__

        # Corrupted session file
        if error_class == "SessionFileError":
            return "corrupted_session"

        # Session expired/auth errors (both Telethon and custom errors)
        # Treated as 'disconnected' — Connect button will trigger send_code flow
        if error_class in {
            "SessionExpiredError",
            "AuthKeyUnregisteredError",
            "SessionRevokedError",
            "UnauthorizedError",
            "AuthKeyInvalidError",
            "SessionReauthRequiredError",  # Custom error for expired sessions
            "SessionInvalidError",  # Wrapper error from session_manager
        }:
            return "disconnected"

        # Banned/deactivated account
        if error_class in {
            "UserDeactivatedError",
            "UserDeactivatedBanError",
            "PhoneNumberBannedError",
        }:
            return "banned"

        # Rate limiting
        if error_class in {"FloodWaitError", "SlowModeWaitError"}:
            return "flood_wait"

        # Proxy/connection errors
        if error_class in {"OSError", "ConnectionError", "ConnectionRefusedError"}:
            return "proxy_error"

        # For wrapper exceptions (SessionConnectError, etc.), check the cause
        if exception.__cause__ is not None:
            cause_result = classify_error_state(error_message, exception.__cause__)
            if cause_result != "error":
                return cause_result

    # Fall back to string matching if no exception or class didn't match
    if not error_message:
        return "error"

    error_lower = error_message.lower()

    # Check for corrupted session file
    if any(
        phrase in error_lower
        for phrase in [
            "invalid session file",
            "not a valid database",
            "corrupted",
            "session file is locked",
            "incompatible",
            "database error",
        ]
    ):
        return "corrupted_session"

    # Check for expired/revoked session (dead session)
    # Treated as 'disconnected' — Connect button will trigger send_code flow
    if any(
        phrase in error_lower
        for phrase in [
            "sessionexpired",
            "authkeyunregistered",
            "sessionrevoked",
            "session expired",
            "session has expired",
            "session revoked",
            "re-authorization required",
            "reauthentication",
            "auth key",
            "unauthorized",
        ]
    ):
        return "disconnected"

    # Check for banned/deactivated account
    if any(
        phrase in error_lower
        for phrase in ["banned", "deactivated", "phonenumberbanned", "userdeactivatedban"]
    ):
        return "banned"

    # Check for flood wait
    if "floodwait" in error_lower or "flood" in error_lower:
        return "flood_wait"

    # Check for proxy errors
    if any(
        phrase in error_lower
        for phrase in ["proxy", "socks", "connection refused", "cannot connect"]
    ):
        return "proxy_error"

    return "error"


def ensure_data_dir() -> Path:
    """Ensure sessions directory exists with proper permissions."""
    sessions_dir = get_settings().sessions_dir
    sessions_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    return sessions_dir


def secure_file_permissions(file_path: Path) -> None:
    """Set file permissions to 600 (owner read/write only).

    Args:
        file_path: Path to file to secure
    """
    import os
    import stat

    # chmod 600: owner read/write, no access for group/others
    os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)


def secure_delete_dir(dir_path: Path | str) -> None:
    """Securely delete a directory by overwriting all files before removal.

    Args:
        dir_path: Path to directory to securely delete
    """
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


def sanitize_session_name(name: str) -> str:
    """Sanitize session name to prevent path traversal.

    Args:
        name: User-provided session name

    Returns:
        Sanitized name (alphanumeric, underscore, hyphen only)

    Raises:
        ValueError: If name is invalid or empty after sanitization
    """
    # Remove any path components and keep only safe characters
    sanitized = re.sub(r"[^a-zA-Z0-9_-]", "", name)
    if not sanitized:
        raise ValueError("Session name must contain at least one alphanumeric character")
    if len(sanitized) > 64:
        sanitized = sanitized[:64]
    return sanitized


def validate_session_file_format(content: bytes) -> None:
    """Validate that content is a valid SQLite database with Telethon schema.

    Args:
        content: File content as bytes

    Raises:
        ValueError: If file is not a valid Telethon session or has incompatible version
    """
    # Check SQLite header
    if not content.startswith(b"SQLite format 3"):
        raise ValueError("Not a valid SQLite database file")

    # Check for required Telethon tables by creating a temp database
    import tempfile

    # Use delete=False and manually delete on Windows, as NamedTemporaryFile
    # with delete=True keeps the file locked and prevents SQLite from opening it.
    # We can't use a context manager here because we need to close the file
    # before SQLite can access it on Windows.
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)  # noqa: SIM115
    tmp_path = Path(tmp.name)
    try:
        tmp.write(content)
        tmp.close()  # Close before SQLite can access it (required on Windows)

        try:
            conn = sqlite3.connect(str(tmp_path))
            cursor = conn.cursor()

            # Get all tables in the database
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = {row[0] for row in cursor.fetchall()}

            # Telethon 1.x required tables
            required_tables = {"sessions", "entities"}

            # Check for Telethon 2.x format (incompatible)
            if "version" in tables and not required_tables.issubset(tables):
                conn.close()
                raise ValueError(
                    "Session file is from Telethon 2.x which is incompatible with this application. "
                    "Please generate a new session file using Telethon 1.x (version 1.34.0 or later). "
                    "Telethon 1.x and 2.x use different session formats that are not interchangeable."
                )

            # Check for required Telethon 1.x tables
            if not required_tables.issubset(tables):
                conn.close()
                raise ValueError(
                    f"Invalid session file format. Expected Telethon 1.x session with tables "
                    f"{required_tables}, but found: {tables}. "
                    "Please ensure you're uploading a valid Telethon session file."
                )

            # Check for session data
            cursor.execute("SELECT COUNT(*) FROM sessions")
            count = cursor.fetchone()[0]
            if count == 0:
                conn.close()
                raise ValueError(
                    "Session file is empty (no active session found). "
                    "Please use a session file that has been authenticated with Telegram."
                )

            conn.close()
        except sqlite3.Error as e:
            # Log the actual database error for debugging
            logger.error(f"SQLite database validation error: {e}")
            raise ValueError("Invalid database file") from e
    finally:
        # Always clean up the temp file
        tmp_path.unlink(missing_ok=True)


def validate_config_file_format(content: bytes) -> dict[str, str | int | None]:
    """Validate that content is a valid Telegram config JSON.

    Performs quick structural validation before parsing to prevent
    expensive parsing of obviously invalid files.

    Args:
        content: File content as bytes

    Returns:
        Parsed config dict

    Raises:
        ValueError: If file is not a valid config
    """
    # Quick structural validation before attempting to parse
    # This prevents expensive JSON parsing of obviously invalid files
    if len(content) == 0:
        raise ValueError("Config file is empty")

    # Decode and trim
    try:
        text = content.decode("utf-8").strip()
    except UnicodeDecodeError as e:
        raise ValueError("Config file contains invalid UTF-8 encoding") from e

    if not text:
        raise ValueError("Config file is empty or contains only whitespace")

    # Quick check: valid JSON objects must start with '{' and end with '}'
    if not text.startswith("{") or not text.endswith("}"):
        raise ValueError(
            "Config file does not appear to be a JSON object (must start with '{' and end with '}')"
        )

    # Now attempt full JSON parsing
    try:
        config = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError("Invalid JSON format in config file") from e

    if not isinstance(config, dict):
        raise ValueError("Config must be a JSON object")

    # api_id and api_hash are now optional (nullable)
    # Validate api_id type if present
    api_id = config.get("api_id")
    if api_id is not None:
        if isinstance(api_id, str):
            try:
                int(api_id)
            except ValueError:
                raise ValueError("api_id must be an integer or numeric string") from None
        elif not isinstance(api_id, int):
            raise ValueError("api_id must be an integer")

    # Validate api_hash type if present
    api_hash = config.get("api_hash")
    if api_hash is not None and (not isinstance(api_hash, str) or not api_hash.strip()):
        raise ValueError("api_hash must be a non-empty string")

    # Validate source field if present
    source = config.get("source")
    if source is not None and source not in ("file", "phone"):
        raise ValueError("source must be 'file' or 'phone'")

    # Check for unknown fields and warn (lenient mode)
    known_fields = {"api_id", "api_hash", "proxy_id", "source"}
    unknown_fields = set(config.keys()) - known_fields
    if unknown_fields:
        logger.warning(
            "Config file contains unknown fields that will be ignored: %s",
            ", ".join(sorted(unknown_fields)),
        )

    return config


async def get_account_info_from_session(
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
    import asyncio

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


def validate_account_info_json(json_data: object) -> str | None:
    """Validate account info JSON from uploaded file.

    Validates:
    - Must be a dict (no arrays at root)
    - Only allowed fields: phone, first_name, last_name, twoFA
    - No nested objects or arrays as values
    - Phone must be in E.164 format (optional + prefix, 7-15 digits)

    Args:
        json_data: Parsed JSON data to validate

    Returns:
        Error message string if invalid, None if valid
    """
    # Must be a dict
    if not isinstance(json_data, dict):
        return "JSON must be an object, not an array or primitive"

    # Allowed fields only
    allowed_fields = {"phone", "first_name", "last_name", "twoFA"}
    unknown_fields = set(json_data.keys()) - allowed_fields
    if unknown_fields:
        return f"Unknown fields not allowed: {', '.join(sorted(unknown_fields))}"

    # No nested objects or arrays
    for key, value in json_data.items():
        if isinstance(value, (dict, list)):
            return f"Field '{key}' cannot contain nested objects or arrays"

    # Validate phone field (required)
    if "phone" not in json_data or not json_data["phone"]:
        return "JSON file must contain 'phone' field"

    phone = str(json_data["phone"])
    # E.164 format: optional +, then 7-15 digits
    # Examples: +14385515736, 14385515736, +79001234567
    if not re.match(r"^\+?[1-9]\d{6,14}$", phone):
        return f"Invalid phone format: '{phone}'. Expected E.164 format (e.g., +14385515736)"

    return None


def save_account_info(session_dir: Path, account_info: dict[str, int | str]) -> None:
    """Save account info metadata to session directory.

    Args:
        session_dir: Session directory path
        account_info: Account info dict with user_id, phone, etc.
    """
    metadata_file = session_dir / ".account_info.json"
    metadata_content = json.dumps(account_info, indent=2).encode("utf-8")
    atomic_write(metadata_file, metadata_content)
    secure_file_permissions(metadata_file)


def load_account_info(session_dir: Path) -> dict[str, int | str] | None:
    """Load account info metadata from session directory.

    Args:
        session_dir: Session directory path

    Returns:
        Account info dict or None if not found
    """
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
    from chatfilter.security import SecureCredentialManager
    from chatfilter.utils.disk import ensure_space_available
    import tempfile

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
                    f"user_id={account_info['user_id']}, phone={account_info.get('phone', 'N/A')}"
                )
            else:
                logger.info(
                    f"Saved account info for session '{safe_name}' (user_id not available): "
                    f"phone={account_info.get('phone', 'N/A')}"
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
    """Find all sessions that belong to the same Telegram account.

    Args:
        target_user_id: The user_id to search for
        exclude_session: Optional session name to exclude from search

    Returns:
        List of session names that have the same user_id
    """
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


def get_session_config_status(session_dir: Path) -> str:
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
        Status string:
        - "disconnected": Configuration is valid
        - "needs_api_id": Missing api_id/api_hash (auth credentials needed)
        - "proxy_missing": proxy_id is set but proxy not found in pool
    """
    config_file = session_dir / "config.json"

    if not config_file.exists():
        return "needs_api_id"

    try:
        with config_file.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to read config for session {session_dir.name}: {e}")
        return "needs_api_id"

    # Check fields
    api_id = config.get("api_id")
    api_hash = config.get("api_hash")
    proxy_id = config.get("proxy_id")

    # If api_id or api_hash are null, check if we need them
    if api_id is None or api_hash is None:
        # For source=phone, missing credentials means needs_api_id
        # (user will provide them via auth flow)
        return "needs_api_id"

    # proxy_id is required for session to be connectable
    if not proxy_id:
        return "needs_api_id"

    # Verify proxy exists in pool
    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id

    try:
        get_proxy_by_id(proxy_id)
    except StorageNotFoundError:
        return "proxy_missing"

    return "disconnected"


async def validate_telegram_credentials_with_retry(
    api_id: int,
    api_hash: str,
    proxy_entry: ProxyEntry,
    session_name: str,
    max_attempts: int = 3,
) -> tuple[bool, str]:
    """Validate Telegram API credentials with retry logic for transient errors.

    Attempts to connect to Telegram with the provided credentials.
    Retries transient network errors (ConnectionError, TimeoutError) up to max_attempts.
    Returns immediately on non-retryable errors (ApiIdInvalidError).

    Args:
        api_id: Telegram API ID
        api_hash: Telegram API hash
        proxy_entry: Proxy configuration to use
        session_name: Session name (for logging and temp session file)
        max_attempts: Maximum number of connection attempts (default: 3)

    Returns:
        Tuple of (is_valid: bool, error_message: str)
        - (True, "") if credentials are valid
        - (False, error_message) if validation failed
    """
    import asyncio
    import tempfile
    from pathlib import Path
    from telethon import TelegramClient
    from telethon.errors import ApiIdInvalidError

    from chatfilter.telegram.retry import calculate_backoff_delay

    telethon_proxy = proxy_entry.to_telethon_proxy()
    temp_dir = None
    client = None

    for attempt in range(max_attempts):
        try:
            # Create temp session file for validation
            temp_dir = Path(tempfile.mkdtemp(prefix="validate_creds_"))
            temp_session_path = temp_dir / "temp_validate_session"

            client = TelegramClient(
                str(temp_session_path),
                api_id,
                api_hash,
                proxy=telethon_proxy,
            )

            # Try to connect with timeout
            await asyncio.wait_for(client.connect(), timeout=30.0)
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
            secure_delete_dir(temp_dir)

            logger.info(f"API credentials validated for session '{session_name}'")
            return (True, "")

        except ApiIdInvalidError:
            # Invalid credentials - don't retry, fail immediately
            if client and client.is_connected():
                await asyncio.wait_for(client.disconnect(), timeout=30.0)
            if temp_dir:
                secure_delete_dir(temp_dir)
            logger.warning(f"Invalid API credentials for session '{session_name}'")
            return (False, "Invalid API ID or API Hash. Credentials not saved.")

        except (OSError, ConnectionError, TimeoutError, asyncio.TimeoutError) as e:
            # Transient network error - retry with backoff
            if client and client.is_connected():
                await asyncio.wait_for(client.disconnect(), timeout=30.0)
            if temp_dir:
                secure_delete_dir(temp_dir)

            is_final_attempt = attempt == max_attempts - 1
            if is_final_attempt:
                logger.error(
                    f"Failed to validate credentials for '{session_name}' after {max_attempts} attempts: {e}"
                )
                return (
                    False,
                    f"Network error after {max_attempts} attempts. Please check your proxy and internet connection.",
                )

            # Calculate backoff and retry
            delay = calculate_backoff_delay(attempt)
            logger.warning(
                f"Credential validation attempt {attempt + 1}/{max_attempts} failed "
                f"with {type(e).__name__}: {e}. Retrying in {delay:.2f}s..."
            )
            await asyncio.sleep(delay)

        except Exception as e:
            # Unexpected error - don't retry
            if client and client.is_connected():
                await asyncio.wait_for(client.disconnect(), timeout=30.0)
            if temp_dir:
                secure_delete_dir(temp_dir)
            logger.exception(f"Unexpected error validating credentials for '{session_name}'")
            return (False, f"Unexpected error: {e}")

    # Should never reach here
    return (False, "Validation failed after all retries")


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
    - "needs_account_info": Missing account_info.json (old session format)
    - "error": Connection error (generic)
    - "banned": Account banned by Telegram
    - "flood_wait": Temporary rate limit
    - "proxy_error": Proxy connection failed
    - "needs_api_id": Missing required configuration (api_id, api_hash, or proxy_id)
    - "proxy_missing": proxy_id references a proxy that no longer exists in pool

    Args:
        session_manager: Optional session manager to check runtime state
        auth_manager: Optional auth state manager to check auth flow state

    Returns:
        List of session info items
    """
    from chatfilter.web.auth_state import AuthStep

    sessions = []
    data_dir = ensure_data_dir()

    for session_dir in data_dir.iterdir():
        if session_dir.is_dir():
            session_file = session_dir / "session.session"
            config_file = session_dir / "config.json"
            account_info_file = session_dir / ".account_info.json"

            if config_file.exists():
                session_id = session_dir.name

                # Handle missing account_info.json (old sessions)
                if not account_info_file.exists():
                    sessions.append(
                        SessionListItem(
                            session_id=session_id,
                            state="needs_account_info",
                            error_message=None,
                            auth_id=None,
                            has_session_file=session_file.exists(),
                        )
                    )
                    continue

                # First check config status
                config_status = get_session_config_status(session_dir)

                # If session manager available, check runtime state
                state = config_status
                error_message = None
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
                        elif info.state == SessionState.CONNECTING:
                            state = "connecting"
                        elif info.state == SessionState.DISCONNECTING:
                            state = "disconnecting"
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
                        has_session_file=session_file.exists(),
                        retry_available=retry_available,
                    )
                )

    return sessions


if TYPE_CHECKING:
    from chatfilter.telegram.session_manager import SessionManager
    from chatfilter.web.auth_state import AuthStateManager


@router.get("/api/sessions", response_class=HTMLResponse)
async def get_sessions(request: Request) -> HTMLResponse:
    """List all registered sessions as HTML partial."""
    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import get_auth_state_manager
    from chatfilter.web.dependencies import get_session_manager

    session_manager = get_session_manager()
    auth_manager = get_auth_state_manager()
    sessions = list_stored_sessions(session_manager, auth_manager)
    templates = get_templates()

    return templates.TemplateResponse(
        request=request,
        name="partials/sessions_list.html",
        context={"sessions": sessions},
    )


@router.post("/api/sessions/upload", response_class=HTMLResponse)
async def upload_session(
    request: Request,
    session_name: Annotated[str, Form()],
    session_file: Annotated[UploadFile, File()],
    config_file: Annotated[UploadFile, File()],
    json_file: Annotated[UploadFile | None, File()] = None,
) -> HTMLResponse:
    """Upload a new session with config file.

    Args:
        json_file: Optional JSON file with account info (TelegramExpert format).
                   Expected fields: phone (required), first_name, last_name, twoFA.

    Returns HTML partial for HTMX to display result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Sanitize session name (path traversal protection)
        try:
            safe_name = sanitize_session_name(session_name)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        # Atomically create session directory to prevent TOCTOU race
        session_dir = ensure_data_dir() / safe_name
        try:
            session_dir.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Session '{name}' already exists").format(name=safe_name),
                },
            )

        # Read and validate session file with size limit enforcement
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid session: {error}").format(error=e)},
            )

        # Read and validate config file with size limit enforcement
        try:
            config_content = await read_upload_with_size_limit(
                config_file, MAX_CONFIG_SIZE, "config"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            config_data = validate_config_file_format(config_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid config: {error}").format(error=e)},
            )

        # Parse JSON file if provided (TelegramExpert format)
        json_account_info = None
        twofa_password = None
        if json_file:
            try:
                # Read JSON with size limit (10KB max)
                MAX_JSON_SIZE = 10 * 1024  # 10KB
                json_content = await read_upload_with_size_limit(
                    json_file, MAX_JSON_SIZE, "JSON"
                )
            except ValueError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={"success": False, "error": str(e)},
                )

            try:
                json_data = json.loads(json_content)
                # Security: Zero plaintext JSON after parsing to prevent memory dumps
                json_content = b'\x00' * len(json_content)
                del json_content
            except json.JSONDecodeError as e:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={"success": False, "error": _("Invalid JSON format: {error}").format(error=str(e))},
                )

            # Validate JSON structure, fields, and phone format
            validation_error = validate_account_info_json(json_data)
            if validation_error:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/upload_result.html",
                    context={"success": False, "error": _(validation_error)},
                )

            # Extract account info from JSON (validated above)
            json_account_info = {
                "phone": str(json_data["phone"]),
                "first_name": str(json_data.get("first_name", "")),
                "last_name": str(json_data.get("last_name", "")),
            }

            # Extract 2FA password if present (will encrypt later)
            if "twoFA" in json_data and json_data["twoFA"]:
                twofa_password = str(json_data["twoFA"])
                # Security: Zero plaintext 2FA in JSON dict to prevent memory leaks
                json_data["twoFA"] = "\x00" * len(json_data["twoFA"])
                del json_data["twoFA"]

        # Extract account info from session to check for duplicates
        import tempfile

        account_info = None
        duplicate_sessions = []

        # Create a temporary session file to test connection
        with tempfile.NamedTemporaryFile(suffix=".session", delete=False) as tmp_session:
            tmp_session.write(session_content)
            tmp_session.flush()
            tmp_session_path = Path(tmp_session.name)

        try:
            api_id_value = config_data.get("api_id")
            api_hash_value = config_data.get("api_hash")

            # Convert to appropriate types, handling None
            api_id = int(api_id_value) if api_id_value is not None else None
            api_hash = str(api_hash_value) if api_hash_value is not None else None

            # Try to get account info from the session only if both api_id and api_hash are available
            account_info = None
            if api_id is not None and api_hash is not None:
                account_info = await get_account_info_from_session(
                    tmp_session_path, api_id, api_hash
                )

            if account_info:
                # Check for duplicate accounts
                user_id = account_info["user_id"]
                if isinstance(user_id, int):
                    duplicate_sessions = find_duplicate_accounts(user_id, exclude_session=safe_name)
        finally:
            # Clean up temporary session file
            import contextlib

            with contextlib.suppress(Exception):
                tmp_session_path.unlink()

        # Save session with atomic transaction (no orphaned files on failure)
        # session_dir already created (mkdir exist_ok=False) to prevent TOCTOU race
        # _save_session_to_disk() creates temp dir, writes files, then renames over empty session_dir
        try:
            from chatfilter.utils.disk import DiskSpaceError

            # proxy_id is None - user must configure it after upload
            # source is 'file' because config was uploaded
            # Use json_account_info if provided, otherwise use account_info from session
            final_account_info = json_account_info if json_account_info else account_info
            _save_session_to_disk(
                session_dir=session_dir,
                session_content=session_content,
                api_id=api_id,
                api_hash=api_hash,
                proxy_id=None,
                account_info=final_account_info,
                source="file",
            )

        except DiskSpaceError:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Insufficient disk space. Please free up disk space and try again.")},
            )
        except TelegramConfigError:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Configuration error. Please check your session file and credentials."),
                },
            )
        except Exception:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            logger.exception("Failed to save session files")
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Failed to save session files. Please try again."),
                },
            )

        logger.info(f"Session '{safe_name}' uploaded successfully")

        # Store encrypted 2FA password if provided in JSON
        if twofa_password:
            try:
                from chatfilter.security import SecureCredentialManager

                storage_dir = session_dir
                manager = SecureCredentialManager(storage_dir)
                manager.store_2fa(safe_name, twofa_password)
                logger.info(f"Stored encrypted 2FA password for session: {safe_name}")
            except Exception:
                logger.exception("Failed to store 2FA password")
                # Don't fail the upload if 2FA storage fails
            finally:
                # Security: Zero plaintext 2FA password in memory after encryption
                if twofa_password:
                    twofa_password = "\x00" * len(twofa_password)
                    del twofa_password

        # Prepare response with duplicate account warning if needed
        response_data = {
            "request": request,
            "success": True,
            "message": _("Session '{name}' uploaded successfully").format(name=safe_name),
            "duplicate_sessions": duplicate_sessions,
            "account_info": account_info,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context=response_data,
            headers={"HX-Trigger": "refreshSessions"},
        )

    except Exception:
        logger.exception("Unexpected error during session upload")
        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context={
                "success": False,
                "error": _("An unexpected error occurred during upload. Please try again."),
            },
        )


@router.delete("/api/sessions/{session_id}", response_class=HTMLResponse)
async def delete_session(session_id: str) -> HTMLResponse:
    """Delete a session.

    Returns empty response for HTMX to remove the element.
    """
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session name",
        ) from e

    session_dir = ensure_data_dir() / safe_name

    if not session_dir.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    try:
        # Delete credentials from secure storage
        from chatfilter.security import SecureCredentialManager

        storage_dir = session_dir.parent
        try:
            manager = SecureCredentialManager(storage_dir)
            manager.delete_credentials(safe_name)
            logger.info(f"Deleted credentials from secure storage for session: {safe_name}")
        except Exception as e:
            logger.warning(f"Error deleting credentials from secure storage: {e}")

        # Securely delete session file
        session_file = session_dir / "session.session"
        secure_delete_file(session_file)

        # Delete any legacy plaintext config file (if it exists)
        config_file = session_dir / "config.json"
        if config_file.exists():
            secure_delete_file(config_file)

        # Remove directory
        shutil.rmtree(session_dir, ignore_errors=True)
        logger.info(f"Session '{safe_name}' deleted successfully")
    except Exception as e:
        logger.exception(f"Failed to delete session '{safe_name}'")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete session: {e}",
        ) from e

    # Return empty response - HTMX will remove the element
    return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": "refreshSessions"})


@router.post("/api/sessions/import/validate", response_class=HTMLResponse)
async def validate_import_session(
    request: Request,
    session_file: Annotated[UploadFile, File()],
    json_file: Annotated[UploadFile, File()],
) -> HTMLResponse:
    """Validate session and JSON files for import.

    Args:
        json_file: JSON file with account info (TelegramExpert format).
                   Expected fields: phone (required), first_name, last_name, twoFA.

    Returns HTML partial with validation result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Read and validate session file with size limit enforcement
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": str(e)},
            )

        # Validate session file format
        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": str(e)},
            )

        # Validate JSON file
        try:
            json_content = await read_upload_with_size_limit(
                json_file, MAX_JSON_SIZE, "JSON"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            json_data = json.loads(json_content)

            # Validate JSON structure and fields using dedicated parser module
            validation_error = validate_account_info_json(json_data)
            if validation_error:
                return templates.TemplateResponse(
                    request=request,
                    name="partials/import_validation_result.html",
                    context={"success": False, "error": validation_error},
                )

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/import_validation_result.html",
                context={"success": False, "error": _("Invalid JSON format: {error}").format(error=str(e))},
            )

        # Validation successful
        logger.info("Session and JSON files validated successfully for import")
        return templates.TemplateResponse(
            request=request,
            name="partials/import_validation_result.html",
            context={"success": True},
        )

    except Exception:
        logger.exception("Unexpected error during session validation")
        return templates.TemplateResponse(
            request=request,
            name="partials/import_validation_result.html",
            context={
                "success": False,
                "error": _("An unexpected error occurred during validation."),
            },
        )


@router.get("/api/sessions/{session_id}/config", response_class=HTMLResponse)
async def get_session_config(
    request: Request,
    session_id: str,
) -> HTMLResponse:
    """Get session configuration form.

    Returns HTML partial with proxy dropdown showing current selection.
    """
    from chatfilter.storage.proxy_pool import load_proxy_pool
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session name",
        ) from e

    session_dir = ensure_data_dir() / safe_name
    config_file = session_dir / "config.json"

    if not session_dir.exists() or not config_file.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found",
        )

    # Load current config
    current_api_id = None
    current_api_hash = None
    current_proxy_id = None
    try:
        with config_file.open("r", encoding="utf-8") as f:
            config = json.load(f)
            current_api_id = config.get("api_id")
            current_api_hash = config.get("api_hash")
            current_proxy_id = config.get("proxy_id")
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"Failed to read config for session {safe_name}: {e}")

    # Load proxy pool
    proxies = load_proxy_pool()

    return templates.TemplateResponse(
        request=request,
        name="partials/session_config.html",
        context={
            "session_id": safe_name,
            "current_api_id": current_api_id,
            "current_api_hash": current_api_hash,
            "current_proxy_id": current_proxy_id,
            "proxies": proxies,
        },
    )


@router.put("/api/sessions/{session_id}/config", response_class=HTMLResponse)
async def update_session_config(
    request: Request,
    session_id: str,
    api_id: Annotated[int, Form()],
    api_hash: Annotated[str, Form()],
    proxy_id: Annotated[str, Form()],
) -> HTMLResponse:
    """Update session configuration.

    Updates api_id, api_hash, and proxy_id for a session.
    All fields are required.
    """
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return HTMLResponse(
            content=f'<div class="alert alert-error">{e}</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_dir = ensure_data_dir() / safe_name
    config_file = session_dir / "config.json"

    if not session_dir.exists() or not config_file.exists():
        return HTMLResponse(
            content='<div class="alert alert-error">Session not found</div>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Validate api_id
    if api_id < 1:
        return HTMLResponse(
            content='<div class="alert alert-error">API ID must be a positive number</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Validate api_hash format (32-char hex string)
    api_hash = api_hash.strip()
    if len(api_hash) != 32 or not all(c in "0123456789abcdefABCDEF" for c in api_hash):
        return HTMLResponse(
            content='<div class="alert alert-error">API hash must be a 32-character hexadecimal string</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Validate proxy_id (required)
    if not proxy_id:
        return HTMLResponse(
            content='<div class="alert alert-error">Proxy selection is required</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id

    try:
        get_proxy_by_id(proxy_id)
    except StorageNotFoundError:
        return HTMLResponse(
            content='<div class="alert alert-error">Selected proxy not found in pool</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Load existing config
    try:
        with config_file.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read config for session {safe_name}: {e}")
        return HTMLResponse(
            content='<div class="alert alert-error">Failed to read session config</div>',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Check if API credentials changed
    old_api_id = config.get("api_id")
    old_api_hash = config.get("api_hash")
    credentials_changed = (old_api_id != api_id) or (old_api_hash != api_hash)

    # If credentials changed, validate them with Telegram API
    if credentials_changed:
        from chatfilter.storage.proxy_pool import get_proxy_by_id

        # Get proxy for validation
        try:
            proxy_entry = get_proxy_by_id(proxy_id)
        except StorageNotFoundError:
            return HTMLResponse(
                content='<div class="alert alert-error">Selected proxy not found</div>',
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Validate credentials with retry logic
        is_valid, error_message = await validate_telegram_credentials_with_retry(
            api_id=api_id,
            api_hash=api_hash,
            proxy_entry=proxy_entry,
            session_name=safe_name,
        )

        if not is_valid:
            # Validation failed after retries
            status_code = (
                status.HTTP_400_BAD_REQUEST
                if "Invalid API" in error_message
                else status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            return HTMLResponse(
                content=f'<div class="alert alert-error">{error_message}</div>',
                status_code=status_code,
            )

        # Credentials valid - disconnect current session if connected
        from chatfilter.web.dependencies import get_session_manager

        session_manager = get_session_manager()
        try:
            await session_manager.disconnect(safe_name)
            logger.info(f"Disconnected session '{safe_name}' after credentials change")
        except Exception as e:
            logger.warning(f"Failed to disconnect session '{safe_name}': {e}")
            # Non-fatal - continue with config update

    # Update all config fields
    config["api_id"] = api_id
    config["api_hash"] = api_hash
    config["proxy_id"] = proxy_id

    # Save updated config
    try:
        config_content = json.dumps(config, indent=2).encode("utf-8")
        atomic_write(config_file, config_content)
        secure_file_permissions(config_file)
        logger.info(
            f"Updated config for session '{safe_name}': api_id={api_id}, proxy_id={proxy_id}"
        )
    except Exception:
        logger.exception(f"Failed to save config for session {safe_name}")
        return HTMLResponse(
            content='<div class="alert alert-error">Failed to save session config</div>',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Also update secure credential storage
    try:
        from chatfilter.security import SecureCredentialManager

        storage_dir = session_dir.parent
        manager = SecureCredentialManager(storage_dir)
        manager.store_credentials(safe_name, api_id, api_hash, proxy_id)
        logger.info(f"Updated credentials in secure storage for session: {safe_name}")
    except Exception as e:
        logger.warning(f"Failed to update secure storage for session {safe_name}: {e}")
        # Non-fatal: config.json is the primary source

    # If credentials changed, trigger reconnect flow
    if credentials_changed:
        # Return success message with auto-trigger for reconnect
        return HTMLResponse(
            content=f'''
                <div class="alert alert-success">
                    Credentials updated. Re-authorization required...
                </div>
                <form hx-post="/api/sessions/{safe_name}/reconnect/start"
                      hx-target="#session-config-result-{safe_name}"
                      hx-swap="innerHTML"
                      hx-trigger="load">
                </form>
            ''',
            headers={"HX-Trigger": "refreshSessions"},
        )

    # Return success message with HX-Trigger to refresh sessions list
    return HTMLResponse(
        content='<div class="alert alert-success">Configuration saved</div>',
        headers={"HX-Trigger": "refreshSessions"},
    )




@router.put("/api/sessions/{session_id}/credentials", response_class=HTMLResponse)
async def update_session_credentials(
    request: Request,
    session_id: str,
    api_id: Annotated[int, Form()],
    api_hash: Annotated[str, Form()],
) -> HTMLResponse:
    """Update session API credentials.

    Updates api_id and api_hash for a session that was created without credentials
    (e.g., from phone auth flow). Does not change proxy_id or other fields.
    """
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return HTMLResponse(
            content=f'<div class="alert alert-error">{e}</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_dir = ensure_data_dir() / safe_name
    config_file = session_dir / "config.json"

    if not session_dir.exists() or not config_file.exists():
        return HTMLResponse(
            content='<div class="alert alert-error">Session not found</div>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Validate api_id
    if api_id < 1:
        return HTMLResponse(
            content='<div class="alert alert-error">API ID must be a positive number</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Validate api_hash format (32-char hex string)
    api_hash = api_hash.strip()
    if len(api_hash) != 32 or not all(c in "0123456789abcdefABCDEF" for c in api_hash):
        return HTMLResponse(
            content='<div class="alert alert-error">API hash must be a 32-character hexadecimal string</div>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Load existing config
    try:
        with config_file.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read config for session {safe_name}: {e}")
        return HTMLResponse(
            content='<div class="alert alert-error">Failed to read session config</div>',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Check if API credentials changed
    old_api_id = config.get("api_id")
    old_api_hash = config.get("api_hash")
    credentials_changed = (old_api_id != api_id) or (old_api_hash != api_hash)

    # If credentials changed, validate them with Telegram API
    if credentials_changed:
        from chatfilter.storage.errors import StorageNotFoundError
        from chatfilter.storage.proxy_pool import get_proxy_by_id

        # Get proxy for validation
        proxy_id = config.get("proxy_id")
        if not proxy_id:
            return HTMLResponse(
                content='<div class="alert alert-error">Session has no proxy configured. Please use the full config form to set both credentials and proxy.</div>',
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        try:
            proxy_entry = get_proxy_by_id(proxy_id)
        except StorageNotFoundError:
            return HTMLResponse(
                content='<div class="alert alert-error">Session proxy not found in pool</div>',
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Validate credentials with retry logic
        is_valid, error_message = await validate_telegram_credentials_with_retry(
            api_id=api_id,
            api_hash=api_hash,
            proxy_entry=proxy_entry,
            session_name=safe_name,
        )

        if not is_valid:
            # Validation failed after retries
            status_code = (
                status.HTTP_400_BAD_REQUEST
                if "Invalid API" in error_message
                else status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            return HTMLResponse(
                content=f'<div class="alert alert-error">{error_message}</div>',
                status_code=status_code,
            )

        # Credentials valid - disconnect current session if connected
        from chatfilter.web.dependencies import get_session_manager

        session_manager = get_session_manager()
        try:
            await session_manager.disconnect(safe_name)
            logger.info(f"Disconnected session '{safe_name}' after credentials change")
        except Exception as e:
            logger.warning(f"Failed to disconnect session '{safe_name}': {e}")
            # Non-fatal - continue with config update

    # Update only api_id and api_hash (preserve proxy_id and source)
    config["api_id"] = api_id
    config["api_hash"] = api_hash

    # Save updated config
    try:
        config_content = json.dumps(config, indent=2).encode("utf-8")
        atomic_write(config_file, config_content)
        secure_file_permissions(config_file)
        logger.info(
            f"Updated credentials for session '{safe_name}': api_id={api_id}"
        )
    except Exception:
        logger.exception(f"Failed to save config for session {safe_name}")
        return HTMLResponse(
            content='<div class="alert alert-error">Failed to save session config</div>',
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    # Also update secure credential storage
    proxy_id = config.get("proxy_id")
    try:
        from chatfilter.security import SecureCredentialManager

        storage_dir = session_dir.parent
        manager = SecureCredentialManager(storage_dir)
        manager.store_credentials(safe_name, api_id, api_hash, proxy_id)
        logger.info(f"Updated credentials in secure storage for session: {safe_name}")
    except Exception as e:
        logger.warning(f"Failed to update secure storage for session {safe_name}: {e}")
        # Non-fatal: config.json is the primary source

    # If credentials changed, need to trigger reconnect flow
    if credentials_changed:
        # Return success message indicating re-auth is needed
        # The session will be disconnected already, user needs to reconnect with new credentials
        return HTMLResponse(
            content=f'''
                <div class="alert alert-success">
                    Credentials updated successfully. Session disconnected - please reconnect to re-authorize.
                </div>
            ''',
            headers={"HX-Trigger": "refreshSessions"},
        )

    # Get updated session status
    config_status = get_session_config_status(session_dir)
    session_info = SessionListItem(
        session_id=safe_name,
        state=config_status,
        error_message=config.get("error_message"),
        retry_available=config.get("retry_available"),
    )

    # Return session row HTML with updated status
    from chatfilter.web.app import get_templates

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="partials/session_row.html",
        context={"session": session_info},
        headers={"HX-Trigger": "refreshSessions"},
    )

# =============================================================================
# Session Auth Flow (Create New Session from Phone)
# =============================================================================


@router.get("/api/sessions/auth/form", response_class=HTMLResponse)
async def get_auth_form(request: Request) -> HTMLResponse:
    """Get the auth flow start form.

    Returns HTML form for starting a new session auth flow.
    """
    from chatfilter.storage.proxy_pool import load_proxy_pool
    from chatfilter.web.app import get_templates

    templates = get_templates()
    proxies = load_proxy_pool()

    return templates.TemplateResponse(
        request=request,
        name="partials/auth_start_form.html",
        context={"proxies": proxies},
    )


@router.post("/api/sessions/auth/start", response_class=HTMLResponse)
async def start_auth_flow(
    request: Request,
    session_name: Annotated[str, Form()],
    phone: Annotated[str, Form()],
    api_id: Annotated[int, Form()],
    api_hash: Annotated[str, Form()],
    proxy_id: Annotated[str, Form()],
) -> HTMLResponse:
    """Start a new session auth flow by sending code to phone.

    Creates a temporary Telethon client and sends verification code.
    Returns HTML partial with code input form or error message.
    """
    import asyncio
    import tempfile

    from telethon import TelegramClient
    from telethon.errors import (
        ApiIdInvalidError,
        FloodWaitError,
        PhoneNumberBannedError,
        PhoneNumberInvalidError,
    )

    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id
    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import DuplicateOperationError, get_auth_state_manager

    templates = get_templates()

    # Validate session name
    try:
        safe_name = sanitize_session_name(session_name)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": str(e)},
        )

    # Check if session already exists
    session_dir = ensure_data_dir() / safe_name
    if session_dir.exists():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Session '{name}' already exists").format(name=safe_name),
            },
        )

    # Validate api_hash format
    api_hash = api_hash.strip()
    if len(api_hash) != 32 or not all(c in "0123456789abcdefABCDEF" for c in api_hash):
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Invalid API hash format. Must be a 32-character hexadecimal string."),
            },
        )

    # Validate and sanitize phone format
    phone = phone.strip()
    try:
        validate_phone_number(phone)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": str(e),
            },
        )

    # Sanitize phone: remove spaces, dashes, parentheses for Telegram API
    phone = "+" + "".join(c for c in phone[1:] if c.isdigit())

    # Validate proxy exists and get it
    try:
        proxy_entry = get_proxy_by_id(proxy_id)
    except StorageNotFoundError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Selected proxy not found.")},
        )

    # Create temporary session file for auth flow
    temp_dir = tempfile.mkdtemp(prefix="chatfilter_auth_")
    temp_session_path = Path(temp_dir) / "auth_session"

    try:
        # Create Telethon client with proxy
        telethon_proxy = proxy_entry.to_telethon_proxy()
        client = TelegramClient(
            str(temp_session_path),
            api_id,
            api_hash,
            proxy=telethon_proxy,
        )

        # Connect and send code
        await asyncio.wait_for(client.connect(), timeout=30.0)

        # Send verification code
        sent_code = await asyncio.wait_for(
            client.send_code_request(phone),
            timeout=30.0,
        )

        phone_code_hash = sent_code.phone_code_hash

        # Store auth state in memory
        auth_manager = get_auth_state_manager()
        auth_state = await auth_manager.create_auth_state(
            session_name=safe_name,
            api_id=api_id,
            api_hash=api_hash,
            proxy_id=proxy_id,
            phone=phone,
            phone_code_hash=phone_code_hash,
            client=client,
        )

        # Store temp dir path for cleanup later
        # Dynamic attribute for temp session files; cleaned up in complete/cancel handlers
        auth_state.temp_dir = temp_dir  # type: ignore[attr-defined]

        logger.info(f"Auth flow started for '{safe_name}', code sent to {phone}")

        # Return code input form
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_state.auth_id,
                "phone": phone,
                "session_name": safe_name,
            },
        )

    except PhoneNumberInvalidError:
        # Clean up
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid phone number.")},
        )
    except PhoneNumberBannedError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("This phone number is banned by Telegram.")},
        )
    except ApiIdInvalidError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid API ID or API Hash.")},
        )
    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": get_user_friendly_message(e),
            },
        )
    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
        secure_delete_dir(temp_dir)

        # Update session state to proxy_error
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = f"Proxy connection failed: {type(e).__name__}"
        save_account_info(session_dir, account_info)

        logger.error(f"Proxy connection failed for session '{safe_name}': {e}")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Proxy connection failed. Please check your proxy settings and try again."),
            },
        )
    except TimeoutError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
        secure_delete_dir(temp_dir)

        # Update session state to proxy_error for timeout
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = "Proxy connection timeout"
        save_account_info(session_dir, account_info)

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection timeout. Please check your proxy settings and try again."),
            },
        )
    except Exception:
        logger.exception(f"Failed to start auth flow for '{safe_name}'")
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=30.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Failed to send code. Please check your settings and try again.")},
        )


@router.post("/api/sessions/auth/code", response_class=HTMLResponse)
async def submit_auth_code(
    request: Request,
    auth_id: Annotated[str, Form()],
    code: Annotated[str, Form()],
) -> HTMLResponse:
    """Submit verification code to complete auth or request 2FA.

    Returns HTML partial with:
    - Success message if auth completed
    - 2FA form if password required
    - Error message if code invalid
    """
    import asyncio

    from telethon.errors import (
        PhoneCodeEmptyError,
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        SessionPasswordNeededError,
    )

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import AuthStep, get_auth_state_manager

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session expired or not found. Please start over."),
            },
        )

    # Validate code format (digits only)
    code = code.strip().replace(" ", "").replace("-", "")
    if not code.isdigit() or len(code) < 5:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Invalid code format. Please enter the numeric code you received."),
            },
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection lost. Please start over."),
            },
        )

    try:
        # Try to sign in with code
        await asyncio.wait_for(
            client.sign_in(
                phone=auth_state.phone,
                code=code,
                phone_code_hash=auth_state.phone_code_hash,
            ),
            timeout=30.0,
        )

        # Success! Save the session
        return await _complete_auth_flow(request, auth_state, templates, auth_manager)

    except SessionPasswordNeededError:
        # 2FA required
        await auth_manager.update_auth_state(auth_id, step=AuthStep.NEED_2FA)
        logger.info(f"2FA required for auth '{auth_id}'")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
            },
        )

    except PhoneCodeInvalidError:
        await auth_manager.update_auth_state(auth_id, step=AuthStep.CODE_INVALID)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Invalid code. Please check and try again."),
            },
        )

    except PhoneCodeExpiredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Code has expired. Please start over."),
            },
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": get_user_friendly_message(e),
            },
        )

    except PhoneCodeEmptyError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Please enter the verification code."),
            },
        )

    except TimeoutError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Request timeout. Please try again."),
            },
        )

    except Exception:
        logger.exception(f"Failed to verify code for auth '{auth_id}'")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "error": _("Failed to verify code. Please check the code and try again."),
            },
        )


@router.post("/api/sessions/auth/2fa", response_class=HTMLResponse)
async def submit_auth_2fa(
    request: Request,
    auth_id: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> HTMLResponse:
    """Submit 2FA password to complete auth.

    Returns HTML partial with success message or error.
    """
    import asyncio

    from telethon.errors import FloodWaitError, PasswordHashInvalidError

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import AuthStep, get_auth_state_manager

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Validate input parameters
    if not isinstance(password, str) or len(password) > 256:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid password: must be at most 256 characters.")},
        )

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session expired or not found. Please start over."),
            },
        )

    if auth_state.step != AuthStep.NEED_2FA:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Invalid auth state. Please start over."),
            },
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection lost. Please start over."),
            },
        )

    try:
        # Try to sign in with 2FA password
        await asyncio.wait_for(
            client.sign_in(password=password),
            timeout=30.0,
        )

        # Success! Save the session
        return await _complete_auth_flow(request, auth_state, templates, auth_manager)

    except PasswordHashInvalidError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": _("Incorrect password. Please try again."),
            },
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": get_user_friendly_message(e),
            },
        )

    except TimeoutError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": _("Request timeout. Please try again."),
            },
        )

    except Exception:
        logger.exception(f"Failed to verify 2FA for auth '{auth_id}'")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": auth_state.session_name,
                "error": _("Failed to verify password. Please try again."),
            },
        )


async def _complete_auth_flow(
    request: Request,
    auth_state: AuthState,
    templates: Jinja2Templates,
    auth_manager: AuthStateManager,
) -> HTMLResponse:
    """Complete auth flow by saving session and credentials.

    Args:
        request: FastAPI request
        auth_state: Current auth state
        templates: Jinja2 templates
        auth_manager: Auth state manager

    Returns:
        HTML response with success or error message
    """
    import shutil

    from chatfilter.security import SecureCredentialManager

    client = auth_state.client
    if client is None:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Client connection lost. Please start over.")},
        )

    session_name = auth_state.session_name
    api_id = auth_state.api_id
    api_hash = auth_state.api_hash
    proxy_id = auth_state.proxy_id

    try:
        # Get account info
        me = await asyncio.wait_for(client.get_me(), timeout=30.0)
        account_info = {
            "user_id": me.id,
            "phone": me.phone or "",
            "first_name": me.first_name or "",
            "last_name": me.last_name or "",
        }

        # Check for duplicates
        duplicate_sessions = []
        if isinstance(me.id, int):
            duplicate_sessions = find_duplicate_accounts(me.id, exclude_session=session_name)

        # Create session directory
        session_dir = ensure_data_dir() / session_name
        session_dir.mkdir(parents=True, exist_ok=True)
        session_path = session_dir / "session.session"

        # Disconnect client before copying session file
        await asyncio.wait_for(client.disconnect(), timeout=30.0)

        # Copy session file from temp location
        temp_dir = getattr(auth_state, "temp_dir", None)
        if temp_dir:
            temp_session_file = Path(temp_dir) / "auth_session.session"
            if temp_session_file.exists():
                shutil.copy2(temp_session_file, session_path)
                secure_file_permissions(session_path)

        # Store credentials securely
        storage_dir = session_dir.parent
        manager = SecureCredentialManager(storage_dir)
        manager.store_credentials(session_name, api_id, api_hash)

        # Create per-session config.json
        # source is 'phone' because credentials came from auth flow
        session_config: dict[str, int | str | None] = {
            "api_id": api_id,
            "api_hash": api_hash,
            "proxy_id": proxy_id,
            "source": "phone",
        }
        session_config_path = session_dir / "config.json"
        session_config_content = json.dumps(session_config, indent=2).encode("utf-8")
        atomic_write(session_config_path, session_config_content)
        secure_file_permissions(session_config_path)

        # Create secure storage marker
        marker_text = (
            "Credentials are stored in secure storage (OS keyring or encrypted file).\n"
            "Do not create a plaintext config.json file.\n"
        )
        marker_file = session_dir / ".secure_storage"
        atomic_write(marker_file, marker_text)

        # Save account info
        save_account_info(session_dir, account_info)

        # Clean up temp dir
        if temp_dir:
            secure_delete_dir(temp_dir)

        # Remove auth state
        await auth_manager.remove_auth_state(auth_state.auth_id)

        logger.info(f"Session '{session_name}' created successfully via auth flow")

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": True,
                "message": _("Session '{name}' created successfully!").format(name=session_name),
                "account_info": account_info,
                "duplicate_sessions": duplicate_sessions,
            },
            headers={"HX-Trigger": "refreshSessions"},
        )

    except Exception as e:
        logger.exception(f"Failed to complete auth flow for '{session_name}'")
        # Clean up on failure
        session_dir = ensure_data_dir() / session_name
        if session_dir.exists():
            shutil.rmtree(session_dir, ignore_errors=True)
        temp_dir = getattr(auth_state, "temp_dir", None)
        if temp_dir:
            secure_delete_dir(temp_dir)
        await auth_manager.remove_auth_state(auth_state.auth_id)

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Failed to save session. Please try again or contact support."),
            },
        )



async def _do_connect_in_background_v2(session_id: str) -> None:
    """Background task that performs the actual Telegram connection (v2 - no registration).

    This version assumes the loader is already registered and state is already CONNECTING.
    This prevents race conditions from parallel requests.

    This runs after HTTP response is sent. Results are delivered via SSE.
    session_manager.connect() already publishes SSE events for all outcomes.

    If session.session is missing or invalid (AuthKeyUnregistered), automatically
    deletes session file and triggers send_code flow.
    """
    import asyncio

    from telethon.errors import AuthKeyUnregisteredError, SessionRevokedError, SessionExpiredError

    from chatfilter.telegram.error_mapping import get_user_friendly_message
    from chatfilter.web.dependencies import get_session_manager
    from chatfilter.web.events import get_event_bus

    session_manager = get_session_manager()
    session_path: Path | None = None
    config_path: Path | None = None

    try:
        # Get session info to extract paths (loader is already registered)
        session = session_manager._sessions.get(session_id)
        if not session:
            logger.error(f"Session '{session_id}' not found in _do_connect_in_background_v2")
            await get_event_bus().publish(session_id, "error")
            return

        # Extract paths from the registered client (TelegramClient has .session.filename)
        session_filename = session.client.session.filename
        if session_filename:
            session_path = Path(session_filename)
            config_path = session_path.parent / "config.json"

        # Connect with timeout (30 seconds)
        # session_manager.connect() publishes SSE events on success/failure
        await asyncio.wait_for(
            session_manager.connect(session_id),
            timeout=30.0
        )
        # Success - SSE "connected" event already published by session_manager

    except (AuthKeyUnregisteredError, SessionRevokedError, SessionExpiredError) as e:
        # Session file is invalid (expired/revoked auth key)
        # Auto-recover: delete session file and trigger send_code flow
        logger.info(f"Session '{session_id}' has invalid auth key ({type(e).__name__}), triggering reauth")

        if not session_path or not config_path:
            logger.error(f"Cannot reauth session '{session_id}': paths not available")
            await get_event_bus().publish(session_id, "error")
            return

        # Securely delete invalid session file (overwrite with random data before unlink)
        # secure_delete_file has internal fallback to regular unlink if secure deletion fails
        secure_delete_file(session_path)

        # Load account_info
        session_dir = session_path.parent
        account_info = load_account_info(session_dir)
        if not account_info or "phone" not in account_info:
            logger.error(f"Cannot reauth session '{session_id}': phone number unknown")
            await get_event_bus().publish(session_id, "error")
            return

        phone = str(account_info["phone"])

        # Trigger send_code flow
        await _send_verification_code_and_create_auth(
            session_id,
            session_path,
            config_path,
            phone,
        )

    except asyncio.TimeoutError:
        logger.warning(f"Connection timeout for session '{session_id}'")
        # Ensure session state is set to error
        if session_id in session_manager._sessions:
            session_manager._sessions[session_id].state = SessionState.ERROR
            session_manager._sessions[session_id].error_message = "Connection timeout"
        # Publish error via SSE
        await get_event_bus().publish(session_id, "error")

    except SessionBusyError:
        # Session is already busy - publish current state
        logger.warning(f"Session busy during background connect: {session_id}")
        info = session_manager.get_info(session_id)
        if info:
            await get_event_bus().publish(session_id, info.state.value)

    except Exception as e:
        logger.exception(f"Failed to connect session '{session_id}' in background")
        # Get classified error state
        error_message = get_user_friendly_message(e)
        error_state = classify_error_state(error_message, exception=e)
        # Publish error state via SSE
        await get_event_bus().publish(session_id, error_state)


async def _send_verification_code_and_create_auth(
    session_id: str,
    session_path: Path,
    config_path: Path,
    phone: str,
) -> None:
    """Helper: send verification code and create AuthState for reconnect.

    This is the minimal difference from normal connection flow.
    Publishes 'needs_code' via SSE, then user completes auth via existing /api/sessions/auth/code.

    Retries transient network errors (ConnectionError, TimeoutError) with exponential backoff.
    Does NOT retry on permanent errors (AuthKeyUnregistered, PhoneNumberInvalid).
    """
    import asyncio
    import json

    from telethon import TelegramClient
    from telethon.errors import AuthKeyUnregisteredError, PhoneNumberInvalidError

    from chatfilter.telegram.error_mapping import get_user_friendly_message
    from chatfilter.telegram.retry import calculate_backoff_delay
    from chatfilter.web.auth_state import get_auth_state_manager
    from chatfilter.web.dependencies import get_proxy_manager
    from chatfilter.web.events import get_event_bus

    def save_error_metadata(error_message: str, retry_available: bool) -> None:
        """Save error metadata to config.json for SSE/UI display."""
        try:
            with config_path.open("r") as f:
                config = json.load(f)
            config["error_message"] = error_message
            config["retry_available"] = retry_available
            config_content = json.dumps(config, indent=2).encode("utf-8")
            atomic_write(config_path, config_content)
        except Exception:
            logger.exception(f"Failed to save error metadata for session '{session_id}'")

    # Load config once (no retry needed for local file read)
    try:
        with config_path.open("r") as f:
            config = json.load(f)
        api_id = config["api_id"]
        api_hash = config["api_hash"]
        proxy_id = config["proxy_id"]
    except Exception as e:
        logger.exception(f"Failed to load config for session '{session_id}'")
        error_message = get_user_friendly_message(e)
        error_state = classify_error_state(error_message, exception=e)
        # Config read failure is permanent (file corruption/missing)
        save_error_metadata(error_message, retry_available=False)
        await get_event_bus().publish(session_id, error_state)
        return

    # Get proxy once (no retry needed)
    proxy_manager = get_proxy_manager()
    proxy_info = proxy_manager.get_proxy(proxy_id)
    if not proxy_info:
        await get_event_bus().publish(session_id, "proxy_error")
        return

    # Retry configuration
    max_attempts = 3
    retryable_exceptions = (ConnectionError, TimeoutError, asyncio.TimeoutError, OSError)
    non_retryable_exceptions = (AuthKeyUnregisteredError, PhoneNumberInvalidError)

    # Retry loop for network operations
    last_exception: Exception | None = None
    for attempt in range(max_attempts):
        try:
            # Create client, send code
            client = TelegramClient(
                str(session_path),
                api_id,
                api_hash,
                proxy=proxy_info.to_telethon_proxy(),
            )
            await asyncio.wait_for(client.connect(), timeout=15.0)

            result = await asyncio.wait_for(
                client.send_code_request(phone),
                timeout=15.0,
            )

            # Success - create auth state and publish
            auth_manager = get_auth_state_manager()
            await auth_manager.create_auth_state(
                session_name=session_id,
                api_id=api_id,
                api_hash=api_hash,
                proxy_id=proxy_id,
                phone=phone,
                phone_code_hash=result.phone_code_hash,
                client=client,
            )

            await get_event_bus().publish(session_id, "needs_code")
            return  # Success, exit

        except non_retryable_exceptions as e:
            # Permanent errors - do not retry
            logger.error(f"Non-retryable error for session '{session_id}': {type(e).__name__}")
            error_message = get_user_friendly_message(e)
            error_state = classify_error_state(error_message, exception=e)
            save_error_metadata(error_message, retry_available=False)
            await get_event_bus().publish(session_id, error_state)
            return

        except retryable_exceptions as e:
            last_exception = e
            is_final_attempt = attempt == max_attempts - 1

            if is_final_attempt:
                # All retries exhausted - transient error
                logger.error(
                    f"Failed to send code for session '{session_id}' after {max_attempts} attempts: {e}"
                )
                error_message = get_user_friendly_message(e)
                error_state = classify_error_state(error_message, exception=e)
                save_error_metadata(error_message, retry_available=True)
                await get_event_bus().publish(session_id, error_state)
                return
            else:
                # Retry with exponential backoff
                delay = calculate_backoff_delay(attempt, base_delay=1.0, max_delay=4.0, jitter=0.1)
                logger.warning(
                    f"Send code attempt {attempt + 1}/{max_attempts} failed for session '{session_id}' "
                    f"with {type(e).__name__}: {e}. Retrying in {delay:.2f}s..."
                )
                await asyncio.sleep(delay)

        except Exception as e:
            # Unexpected error - treat as non-retryable
            logger.exception(f"Unexpected error sending code for session '{session_id}'")
            error_message = get_user_friendly_message(e)
            error_state = classify_error_state(error_message, exception=e)
            save_error_metadata(error_message, retry_available=False)
            await get_event_bus().publish(session_id, error_state)
            return


@router.post("/api/sessions/{session_id}/connect", response_class=HTMLResponse)
async def connect_session(
    request: Request,
    session_id: str,
    background_tasks: BackgroundTasks,
) -> HTMLResponse:
    """Connect a session to Telegram.

    Returns immediately with 'connecting' state. Actual connection happens
    in background task, with final state delivered via SSE.
    """
    from chatfilter.web.app import get_templates
    from chatfilter.web.dependencies import get_session_manager

    templates = get_templates()

    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return HTMLResponse(
            content=f'<span class="error">{e}</span>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_dir = ensure_data_dir() / safe_name
    session_path = session_dir / "session.session"
    config_path = session_dir / "config.json"
    
    # Check if session exists (must have at least config.json)
    # Note: session.session can be missing (will trigger send_code flow)
    if not config_path.exists():
        return HTMLResponse(
            content='<span class="error">Session not found</span>',
            status_code=status.HTTP_404_NOT_FOUND,
        )

    # Check if session is properly configured
    config_status = get_session_config_status(session_dir)
    if config_status == "needs_api_id":
        return HTMLResponse(
            content='<span class="error">Session needs API credentials</span>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    if config_status == "proxy_missing":
        return HTMLResponse(
            content='<span class="error">Proxy not found</span>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_manager = get_session_manager()

    # Check current session state before attempting connect
    info = session_manager.get_info(safe_name)
    if info and info.state.value in ("connected", "connecting"):
        # Session is already connected or connecting
        session_data = {
            "session_id": safe_name,
            "state": info.state.value,
            "error_message": None,
        }
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context={"session": session_data},
            headers={"HX-Trigger": "refreshSessions"},
        )

    # FIX RACE CONDITION: Register loader and set state BEFORE scheduling background task
    # This prevents parallel requests from both seeing DISCONNECTED and scheduling duplicate tasks
    from chatfilter.telegram.client import TelegramClientLoader
    from chatfilter.telegram.session_manager import SessionState

    try:
        loader = TelegramClientLoader(session_path, config_path)
        loader.validate()
    except FileNotFoundError:
        # AC2: Session file doesn't exist - trigger send_code flow instead of error
        account_info = load_account_info(session_dir)
        if not account_info or not account_info.get("phone"):
            return HTMLResponse(
                content='<span class="error">Phone number is required for new session</span>',
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        phone = account_info["phone"]
        if not isinstance(phone, str):
            return HTMLResponse(
                content='<span class="error">Invalid phone number format</span>',
                status_code=status.HTTP_400_BAD_REQUEST,
            )

        # Trigger send_code flow in background
        background_tasks.add_task(
            _send_verification_code_and_create_auth,
            safe_name,
            session_path,
            config_path,
            phone,
        )

        # Return connecting state (will transition to needs_code via SSE)
        session_data = {
            "session_id": safe_name,
            "state": "connecting",
            "error_message": None,
        }
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context={"session": session_data},
            headers={"HX-Trigger": "refreshSessions"},
        )
    except Exception as e:
        # Validation error (bad config, missing files, etc.)
        from chatfilter.telegram.error_mapping import get_user_friendly_message
        error_message = get_user_friendly_message(e)
        return HTMLResponse(
            content=f'<span class="error">{error_message}</span>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # Register loader — this creates session entry in session_manager._sessions
    session_manager.register(safe_name, loader)

    # Set state to CONNECTING synchronously (prevents race condition)
    session = session_manager._sessions.get(safe_name)
    if session:
        # Use lock to ensure atomic state transition
        async with session.lock:
            if session.state in (SessionState.CONNECTED, SessionState.CONNECTING):
                # Another request beat us to it — return current state
                session_data = {
                    "session_id": safe_name,
                    "state": session.state.value,
                    "error_message": None,
                }
                return templates.TemplateResponse(
                    request=request,
                    name="partials/session_row.html",
                    context={"session": session_data},
                    headers={"HX-Trigger": "refreshSessions"},
                )
            # Transition to CONNECTING
            session.state = SessionState.CONNECTING

    # Now schedule background task (loader already registered, state already CONNECTING)
    background_tasks.add_task(
        _do_connect_in_background_v2,
        safe_name,
    )

    # Return immediately with 'connecting' state (template shows spinner)
    session_data = {
        "session_id": safe_name,
        "state": "connecting",
        "error_message": None,
    }

    return templates.TemplateResponse(
        request=request,
        name="partials/session_row.html",
        context={"session": session_data},
    )


@router.post("/api/sessions/{session_id}/disconnect", response_class=HTMLResponse)
async def disconnect_session(
    request: Request,
    session_id: str,
) -> HTMLResponse:
    """Disconnect a session from Telegram.

    Returns HTML partial with updated button state.
    """
    from chatfilter.web.app import get_templates
    from chatfilter.web.dependencies import get_session_manager

    templates = get_templates()

    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return HTMLResponse(
            content=f'<span class="error">{e}</span>',
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    session_manager = get_session_manager()

    # Check current session state before attempting disconnect
    info = session_manager.get_info(safe_name)
    if info and info.state.value in ("disconnected", "disconnecting"):
        # Session is already disconnected or disconnecting
        session_dir = ensure_data_dir() / safe_name
        config_status = get_session_config_status(session_dir)
        session_data = {
            "session_id": safe_name,
            "state": config_status,
            "error_message": None,
        }
        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context={"session": session_data},
            headers={"HX-Trigger": "refreshSessions"},
        )

    try:
        # Disconnect
        await session_manager.disconnect(safe_name)

        # Get updated state - check config status since session might not be registered anymore
        session_dir = ensure_data_dir() / safe_name
        config_status = get_session_config_status(session_dir)

        # Publish state change event for SSE
        await get_event_bus().publish(safe_name, config_status)

        # Create session object for template
        session_data = {
            "session_id": safe_name,
            "state": config_status,
            "error_message": None,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context={"session": session_data},
            headers={"HX-Trigger": "refreshSessions"},
        )

    except Exception as e:
        logger.exception(f"Failed to disconnect session '{safe_name}'")

        # Get user-friendly error message
        from chatfilter.telegram.error_mapping import get_user_friendly_message
        error_message = get_user_friendly_message(e)

        # Publish state change event for SSE
        await get_event_bus().publish(safe_name, "error")

        # Create session object for template with error
        session_data = {
            "session_id": safe_name,
            "state": "error",
            "error_message": error_message,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context={"session": session_data},
        )


@router.post("/api/sessions/{session_id}/verify-code", response_class=HTMLResponse)
async def verify_code(
    request: Request,
    session_id: str,
    auth_id: Annotated[str, Form()],
    code: Annotated[str, Form()],
) -> HTMLResponse:
    """Verify authentication code for an existing session.

    For sessions with needs_code status, verifies the code sent to the phone.
    Updates the session file on success and sets status to connected or needs_2fa.

    Returns HTML partial with:
    - Success message if auth completed (status -> connected)
    - 2FA form if password required (status -> needs_2fa)
    - Error message if code invalid
    """
    import asyncio
    import shutil

    from telethon.errors import (
        FloodWaitError,
        PhoneCodeEmptyError,
        PhoneCodeExpiredError,
        PhoneCodeInvalidError,
        SessionPasswordNeededError,
    )

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import AuthStep, get_auth_state_manager

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Validate input parameters
    if not isinstance(code, str):
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid code format.")},
        )

    # Security: Telegram codes are always 5-6 digits, reject any other format
    if not code.isdigit() or len(code) not in (5, 6):
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Code must be 5-6 digits.")},
        )

    # Sanitize session name
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": str(e)},
        )

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session expired or not found. Please start over."),
            },
        )

    # Check if auth is locked due to too many failed attempts
    is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)
    if is_locked:
        remaining_minutes = (remaining_seconds + 59) // 60  # Round up to nearest minute
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                    minutes=remaining_minutes
                ),
            },
        )

    # Verify this auth state is for the correct session
    if auth_state.session_name != safe_name:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session mismatch. Please start over."),
            },
        )

    # Validate code format (digits only)
    code = code.strip().replace(" ", "").replace("-", "")
    if not code.isdigit() or len(code) < 5:
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Invalid code format. Please enter the numeric code you received."),
            },
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection lost. Please start over."),
            },
        )

    try:
        # Try to sign in with code
        await asyncio.wait_for(
            client.sign_in(
                phone=auth_state.phone,
                code=code,
                phone_code_hash=auth_state.phone_code_hash,
            ),
            timeout=30.0,
        )

        # Success! Update the existing session
        session_dir = ensure_data_dir() / safe_name
        if not session_dir.exists():
            await auth_manager.remove_auth_state(auth_id)
            return templates.TemplateResponse(
                request=request,
                name="partials/auth_result.html",
                context={"success": False, "error": _("Session directory not found.")},
            )

        session_path = session_dir / "session.session"

        # Get account info
        me = await asyncio.wait_for(client.get_me(), timeout=30.0)
        account_info = {
            "user_id": me.id,
            "phone": me.phone or "",
            "first_name": me.first_name or "",
            "last_name": me.last_name or "",
        }

        # Disconnect client before copying session file
        await asyncio.wait_for(client.disconnect(), timeout=30.0)

        # Copy session file from temp location to existing session
        temp_dir = getattr(auth_state, "temp_dir", None)
        if temp_dir:
            temp_session_file = Path(temp_dir) / "auth_session.session"
            if temp_session_file.exists():
                shutil.copy2(temp_session_file, session_path)
                secure_file_permissions(session_path)
            # Clean up temp dir
            secure_delete_dir(temp_dir)

        # Update account info
        save_account_info(session_dir, account_info)

        # Remove auth state
        await auth_manager.remove_auth_state(auth_id)

        logger.info(f"Session '{safe_name}' re-authenticated successfully (code verified)")

        # Emit event for auth completion (connected)
        await get_event_bus().publish(safe_name, "connected")

        # Use reconnect success template with toast notification
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_success.html",
            context={
                "message": _("Session '{name}' reconnected successfully").format(name=safe_name),
                "session_id": safe_name,
            },
            headers={"HX-Trigger": "refreshSessions"},
        )

    except SessionPasswordNeededError:
        # 2FA required
        await auth_manager.update_auth_state(auth_id, step=AuthStep.NEED_2FA)
        logger.info(f"2FA required for session '{safe_name}' auth")
        # Emit event for 2FA requirement
        await get_event_bus().publish(safe_name, "needs_2fa")
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "session_id": session_id,
            },
            headers={"HX-Trigger": "refreshSessions"},
        )

    except PhoneCodeInvalidError:
        # Increment failed attempts and check if locked
        await auth_manager.increment_failed_attempts(auth_id)
        is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)

        if is_locked:
            remaining_minutes = (remaining_seconds + 59) // 60
            error_msg = _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                minutes=remaining_minutes
            )
        else:
            error_msg = _("Invalid code. Please check and try again.")

        await auth_manager.update_auth_state(auth_id, step=AuthStep.CODE_INVALID)
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": error_msg,
            },
        )

    except PhoneCodeExpiredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Code has expired. Please start over."),
            },
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": auth_state.session_name,
                "session_id": session_id,
                "error": get_user_friendly_message(e),
            },
        )

    except PhoneCodeEmptyError:
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Please enter the verification code."),
            },
        )

    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        # Update session state to proxy_error and notify SSE subscribers
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = f"Proxy connection failed during code verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "proxy_error")

        logger.error(f"Proxy connection failed during code verification for session '{safe_name}': {e}")
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Proxy connection failed. Please check your proxy settings and try again."),
            },
        )

    except TimeoutError:
        # Update session state to proxy_error for timeout and notify SSE subscribers
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = "Proxy connection timeout during code verification"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "proxy_error")

        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Request timeout. Please try again."),
            },
        )

    except Exception:
        logger.exception(f"Failed to verify code for session '{safe_name}'")

        # Publish error state to SSE
        await get_event_bus().publish(safe_name, "error")

        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "phone": auth_state.phone,
                "session_name": safe_name,
                "session_id": session_id,
                "error": _("Failed to verify code. Please check the code and try again."),
            },
        )



@router.post("/api/sessions/{session_id}/verify-2fa", response_class=HTMLResponse)
async def verify_2fa(
    request: Request,
    session_id: str,
    auth_id: Annotated[str, Form()],
    password: Annotated[str, Form()],
) -> HTMLResponse:
    """Verify 2FA password for an existing session.

    For sessions with needs_2fa status, verifies the 2FA password.
    Updates the session file on success and sets status to connected.

    Returns HTML partial with:
    - Success message if auth completed (status -> connected)
    - Error message if password invalid
    """
    import asyncio
    import shutil

    from telethon.errors import (
        FloodWaitError,
        AuthKeyInvalidError,
        AuthKeyUnregisteredError,
        PasswordHashInvalidError,
        SessionRevokedError,
        UserDeactivatedBanError,
        UserDeactivatedError,
    )

    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import get_auth_state_manager

    templates = get_templates()
    auth_manager = get_auth_state_manager()

    # Validate input parameters
    if not isinstance(password, str) or len(password) > 256:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid password: must be at most 256 characters.")},
        )

    # Security: Reject empty or whitespace-only passwords
    if not password or not password.strip():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Password cannot be empty.")},
        )

    # Sanitize session name
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": str(e)},
        )

    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)
    if not auth_state:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session expired or not found. Please start over."),
            },
        )

    # Check if auth is locked due to too many failed attempts
    is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)
    if is_locked:
        remaining_minutes = (remaining_seconds + 59) // 60  # Round up to nearest minute
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                    minutes=remaining_minutes
                ),
            },
        )

    # Verify this auth state is for the correct session
    if auth_state.session_name != safe_name:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Auth session mismatch. Please start over."),
            },
        )

    client = auth_state.client
    if not client or not client.is_connected():
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Connection lost. Please start over."),
            },
        )

    try:
        # Try to sign in with 2FA password
        await asyncio.wait_for(
            client.sign_in(password=password),
            timeout=30.0,
        )

        # Success! Update the existing session
        session_dir = ensure_data_dir() / safe_name
        if not session_dir.exists():
            await auth_manager.remove_auth_state(auth_id)
            return templates.TemplateResponse(
                request=request,
                name="partials/auth_result.html",
                context={"success": False, "error": _("Session directory not found.")},
            )

        session_path = session_dir / "session.session"

        # Get account info
        me = await asyncio.wait_for(client.get_me(), timeout=30.0)
        account_info = {
            "user_id": me.id,
            "phone": me.phone or "",
            "first_name": me.first_name or "",
            "last_name": me.last_name or "",
        }

        # Disconnect client before copying session file
        await asyncio.wait_for(client.disconnect(), timeout=30.0)

        # Copy session file from temp location to existing session
        temp_dir = getattr(auth_state, "temp_dir", None)
        if temp_dir:
            temp_session_file = Path(temp_dir) / "auth_session.session"
            if temp_session_file.exists():
                shutil.copy2(temp_session_file, session_path)
                secure_file_permissions(session_path)
            # Clean up temp dir
            secure_delete_dir(temp_dir)

        # Update account info
        save_account_info(session_dir, account_info)

        # Remove auth state
        await auth_manager.remove_auth_state(auth_id)

        logger.info(f"Session '{safe_name}' re-authenticated successfully (2FA verified)")

        # Emit event for auth completion (connected)
        await get_event_bus().publish(safe_name, "connected")

        # Use reconnect success template with toast notification
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_success.html",
            context={
                "message": _("Session '{name}' reconnected successfully").format(name=safe_name),
                "session_id": safe_name,
            },
            headers={"HX-Trigger": "refreshSessions"},
        )

    except SessionRevokedError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("This session has been revoked. Please delete and recreate the session.")},
        )

    except AuthKeyUnregisteredError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Authorization key is unregistered. Please delete and recreate the session.")},
        )

    except AuthKeyInvalidError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Authorization key is invalid. Please delete and recreate the session.")},
        )

    except UserDeactivatedError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("This account has been deactivated.")},
        )

    except UserDeactivatedBanError:
        await auth_manager.remove_auth_state(auth_id)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("This account has been banned.")},
        )

    except PasswordHashInvalidError:
        # Increment failed attempts and check if locked
        await auth_manager.increment_failed_attempts(auth_id)
        is_locked, remaining_seconds = await auth_manager.check_auth_lock(auth_id)

        if is_locked:
            remaining_minutes = (remaining_seconds + 59) // 60
            error_msg = _("Too many failed attempts. Please try again in {minutes} minutes.").format(
                minutes=remaining_minutes
            )
        else:
            error_msg = _("Incorrect password. Please try again.")

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": error_msg,
            },
        )

    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": get_user_friendly_message(e),
            },
        )

    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        # Update session state to proxy_error and notify SSE subscribers
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = f"Proxy connection failed during 2FA verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "proxy_error")

        logger.error(f"Proxy connection failed during 2FA verification for session '{safe_name}': {e}")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Proxy connection failed. Please check your proxy settings and try again."),
            },
        )

    except TimeoutError:
        # Update session state to proxy_error for timeout and notify SSE subscribers
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = "Proxy connection timeout during 2FA verification"
        save_account_info(session_dir, account_info)
        await get_event_bus().publish(safe_name, "proxy_error")

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Request timeout. Please try again."),
            },
        )

    except Exception:
        logger.exception(f"Failed to verify 2FA for session '{safe_name}'")

        # Publish error state to SSE
        await get_event_bus().publish(safe_name, "error")

        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "error": _("Failed to verify password. Please try again."),
            },
        )

@router.post("/api/sessions/import/save", response_class=HTMLResponse)
async def save_import_session(
    request: Request,
    session_name: Annotated[str, Form()],
    session_file: Annotated[UploadFile, File()],
    json_file: Annotated[UploadFile, File()],
    api_id: Annotated[int, Form()],
    api_hash: Annotated[str, Form()],
    proxy_id: Annotated[str, Form()],
) -> HTMLResponse:
    """Save an imported session with configuration.

    Args:
        json_file: JSON file with account info (TelegramExpert format).
                   Expected fields: phone (required), first_name, last_name, twoFA.

    Returns HTML partial with save result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Sanitize session name (path traversal protection)
        try:
            safe_name = sanitize_session_name(session_name)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        # Check if session already exists
        session_dir = ensure_data_dir() / safe_name
        if session_dir.exists():
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Session '{name}' already exists").format(name=safe_name),
                },
            )

        # Read and validate session file
        try:
            session_content = await read_upload_with_size_limit(
                session_file, MAX_SESSION_SIZE, "session"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            validate_session_file_format(session_content)
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid session: {error}").format(error=e)},
            )

        # Validate api_hash format (32-char hex string)
        api_hash = api_hash.strip()
        if len(api_hash) != 32 or not all(c in "0123456789abcdefABCDEF" for c in api_hash):
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _(
                        "Invalid API hash format. Must be a 32-character hexadecimal string."
                    ),
                },
            )

        # Validate proxy exists
        from chatfilter.storage.errors import StorageNotFoundError
        from chatfilter.storage.proxy_pool import get_proxy_by_id

        try:
            get_proxy_by_id(proxy_id)
        except StorageNotFoundError:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Selected proxy not found. Please select a valid proxy."),
                },
            )

        # Parse JSON file for account info (TelegramExpert format)
        twofa_password = None

        try:
            json_content = await read_upload_with_size_limit(
                json_file, MAX_JSON_SIZE, "JSON"
            )
        except ValueError as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )

        try:
            json_data = json.loads(json_content)

            # Parse and validate JSON using dedicated parser module
            account_info, twofa_password = parse_telegram_expert_json(json_content, json_data)

        except ValueError as e:
            # Validation error from parser
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": str(e)},
            )
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Invalid JSON format: {error}").format(error=str(e))},
            )

        # Try to get user_id from session for duplicate check
        # JSON account_info is already prepared above as primary source
        import tempfile

        duplicate_sessions = []

        # Create a temporary session file to try extracting user_id
        with tempfile.NamedTemporaryFile(suffix=".session", delete=False) as tmp_session:
            tmp_session.write(session_content)
            tmp_session.flush()
            tmp_session_path = Path(tmp_session.name)

        try:
            # Try to get user_id from session (best effort)
            session_account_info = await get_account_info_from_session(tmp_session_path, api_id, api_hash)

            # Add user_id to account_info if available from session
            if session_account_info and "user_id" in session_account_info:
                account_info["user_id"] = session_account_info["user_id"]

                # Check for duplicate accounts only if we have user_id
                user_id = session_account_info["user_id"]
                if isinstance(user_id, int):
                    duplicate_sessions = find_duplicate_accounts(user_id, exclude_session=safe_name)

        finally:
            # Clean up temporary session file
            import contextlib

            with contextlib.suppress(Exception):
                tmp_session_path.unlink()

        # Save session files (directory created atomically by _save_session_to_disk)
        try:
            from chatfilter.utils.disk import DiskSpaceError

            # source is 'file' because session was imported from file
            _save_session_to_disk(
                session_dir=session_dir,
                session_content=session_content,
                api_id=api_id,
                api_hash=api_hash,
                proxy_id=proxy_id,
                account_info=account_info,
                source="file",
            )

            # Encrypt and save 2FA password if provided in JSON
            if twofa_password:
                from chatfilter.security import SecureCredentialManager

                storage_dir = session_dir.parent
                manager = SecureCredentialManager(storage_dir)
                manager.store_2fa(safe_name, twofa_password)
                logger.info(f"Stored encrypted 2FA for session: {safe_name}")

                # Update account_info to indicate 2FA is available
                if account_info:
                    account_info_data = load_account_info(session_dir) or {}
                    account_info_data["has_2fa"] = True
                    save_account_info(session_dir, account_info_data)

        except DiskSpaceError:
            shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Insufficient disk space. Please free up disk space and try again.")},
            )
        except TelegramConfigError:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Configuration error. Please check your session file and credentials."),
                },
            )
        except Exception:
            # temp_dir cleanup already done by _save_session_to_disk()
            # If rename succeeded, session_dir exists and should be removed
            if session_dir.exists():
                shutil.rmtree(session_dir, ignore_errors=True)
            logger.exception("Failed to save session files")
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={
                    "success": False,
                    "error": _("Failed to save session files. Please try again."),
                },
            )

        logger.info(f"Session '{safe_name}' imported successfully")

        # Prepare response with duplicate account warning if needed
        response_data = {
            "request": request,
            "success": True,
            "message": _("Session '{name}' imported successfully").format(name=safe_name),
            "duplicate_sessions": duplicate_sessions,
            "account_info": account_info,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context=response_data,
            headers={"HX-Trigger": "refreshSessions"},
        )

    except Exception:
        logger.exception("Unexpected error during session import")
        return templates.TemplateResponse(
            request=request,
            name="partials/upload_result.html",
            context={
                "success": False,
                "error": _("An unexpected error occurred during import. Please try again."),
            },
        )


@router.get("/api/sessions/events")
async def session_events(request: Request):
    """SSE endpoint for real-time session status updates.

    This endpoint provides Server-Sent Events (SSE) for session status changes.
    Clients can connect to receive real-time updates when session statuses change.

    Returns:
        StreamingResponse: SSE stream with session status events
    """
    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import get_auth_state_manager
    from chatfilter.web.dependencies import get_session_manager

    templates = get_templates()
    session_manager = get_session_manager()
    auth_manager = get_auth_state_manager()

    # Queue for this client's events
    event_queue: asyncio.Queue[tuple[str, str] | None] = asyncio.Queue()

    async def event_generator():
        """Generate SSE events from the queue."""
        try:
            # Send initial connection message
            yield 'data: {"type": "connected"}\n\n'

            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    logger.debug("SSE client disconnected")
                    break

                try:
                    # Wait for events with timeout to check disconnect status
                    event = await asyncio.wait_for(event_queue.get(), timeout=30.0)

                    if event is None:  # Shutdown signal
                        break

                    session_id, new_status = event

                    # Get full session data for this session
                    all_sessions = list_stored_sessions(session_manager, auth_manager)
                    session_data = next(
                        (s for s in all_sessions if s.session_id == session_id),
                        None
                    )

                    if session_data:
                        # Render session row HTML with hx-swap-oob
                        html = templates.get_template("partials/session_row.html").render(
                            session=session_data
                        )
                        # Add hx-swap-oob="true" to both rows (main row + config row)
                        # The template renders two <tr> elements that need OOB swaps
                        html_with_oob = html.replace(
                            f'<tr id="session-{session_id}"',
                            f'<tr id="session-{session_id}" hx-swap-oob="true"'
                        ).replace(
                            f'<tr class="config-row" id="session-config-row-{session_id}"',
                            f'<tr class="config-row" id="session-config-row-{session_id}" hx-swap-oob="true"'
                        )
                        # Minify: remove newlines for SSE single-line data format
                        html_compact = html_with_oob.replace('\n', ' ').replace('  ', ' ')
                        yield f"event: message\ndata: {html_compact}\n\n"

                except asyncio.TimeoutError:
                    # Send keepalive comment to prevent timeout
                    yield ": keepalive\n\n"

        except asyncio.CancelledError:
            logger.debug("SSE event generator cancelled")
        finally:
            # Unsubscribe from event bus
            get_event_bus().unsubscribe(event_handler)
            logger.debug("SSE client unsubscribed from event bus")

    async def event_handler(session_id: str, new_status: str):
        """Handler for event bus messages."""
        try:
            await event_queue.put((session_id, new_status))
        except Exception:
            logger.exception("Error putting event in queue")

    # Subscribe to event bus
    get_event_bus().subscribe(event_handler)
    logger.debug("SSE client subscribed to event bus")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )

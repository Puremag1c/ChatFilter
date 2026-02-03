"""Sessions router for session file upload and management."""

from __future__ import annotations

import json
import logging
import re
import shutil
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING, Annotated

from fastapi import APIRouter, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from chatfilter.config import get_settings
from chatfilter.i18n import _
from chatfilter.storage.file import secure_delete_file
from chatfilter.storage.helpers import atomic_write
from chatfilter.telegram.client import SessionFileError, TelegramClientLoader, TelegramConfigError

if TYPE_CHECKING:
    from starlette.templating import Jinja2Templates

    from chatfilter.models.proxy import ProxyEntry
    from chatfilter.web.auth_state import AuthState, AuthStateManager

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sessions"])

# Maximum file sizes (security limit)
MAX_SESSION_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_CONFIG_SIZE = 1024  # 1 KB
# Chunk size for reading uploaded files (to prevent memory exhaustion)
READ_CHUNK_SIZE = 8192  # 8 KB chunks


class SessionListItem(BaseModel):
    """Session info for list response."""

    session_id: str
    state: str
    error_message: str | None = None
    auth_id: str | None = None


def classify_error_state(error_message: str | None, exception: Exception | None = None) -> str:
    """Classify an error message or exception into a specific state.

    Args:
        error_message: The error message from the session
        exception: The original exception object (if available)

    Returns:
        One of: 'session_expired', 'banned', 'flood_wait', 'proxy_error', 'corrupted_session', 'error'
    """
    # First check exception type if provided
    if exception is not None:
        error_class = type(exception).__name__

        # Corrupted session file
        if error_class == "SessionFileError":
            return "corrupted_session"

        # Session expired/auth errors (both Telethon and custom errors)
        if error_class in {
            "SessionExpiredError",
            "AuthKeyUnregisteredError",
            "SessionRevokedError",
            "UnauthorizedError",
            "AuthKeyInvalidError",
            "SessionReauthRequiredError",  # Custom error for expired sessions
            "SessionInvalidError",  # Wrapper error from session_manager
        }:
            return "session_expired"

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
        return "session_expired"

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
        await asyncio.wait_for(client.connect(), timeout=10.0)

        if not await client.is_user_authorized():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
            return None

        # Get user info
        me = await asyncio.wait_for(client.get_me(), timeout=10.0)
        await asyncio.wait_for(client.disconnect(), timeout=10.0)

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

    Creates:
    - session.session file (atomic write, secure permissions)
    - config.json with api_id, api_hash, proxy_id, source
    - .secure_storage marker
    - .account_info.json if account_info provided

    Also stores credentials in secure storage.

    Args:
        session_dir: Session directory path (must exist)
        session_content: Session file content bytes
        api_id: Telegram API ID (can be None for source=phone)
        api_hash: Telegram API hash (can be None for source=phone)
        proxy_id: Proxy ID (can be None)
        account_info: Account info dict or None
        source: Source of credentials ('file' or 'phone')

    Raises:
        DiskSpaceError: If not enough disk space
        TelegramConfigError: If validation fails
        Exception: On other failures
    """
    from chatfilter.security import SecureCredentialManager
    from chatfilter.utils.disk import ensure_space_available

    session_path = session_dir / "session.session"
    safe_name = session_dir.name

    marker_text = (
        "Credentials are stored in secure storage (OS keyring or encrypted file).\n"
        "Do not create a plaintext config.json file.\n"
    )

    # Calculate total space needed (session file + marker file)
    total_bytes_needed = len(session_content) + len(marker_text.encode("utf-8"))

    # Check disk space before writing
    ensure_space_available(session_path, total_bytes_needed)

    # Atomic write to prevent corruption on crash
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
    session_config_path = session_dir / "config.json"
    session_config_content = json.dumps(session_config, indent=2).encode("utf-8")
    atomic_write(session_config_path, session_config_content)
    secure_file_permissions(session_config_path)
    logger.info(f"Created per-session config for session: {safe_name}")

    # Create migration marker to indicate we're using secure storage
    marker_file = session_dir / ".secure_storage"
    atomic_write(marker_file, marker_text)

    # Validate that TelegramClientLoader can use secure storage
    # Only validate if api_id and api_hash are provided
    if api_id and api_hash:
        loader = TelegramClientLoader(session_path, use_secure_storage=True)
        loader.validate()

    # Save account info if we successfully extracted it
    if account_info:
        save_account_info(session_dir, account_info)
        logger.info(
            f"Saved account info for session '{safe_name}': "
            f"user_id={account_info['user_id']}, phone={account_info.get('phone', 'N/A')}"
        )


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
            await asyncio.wait_for(client.connect(), timeout=15.0)
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
            secure_delete_dir(temp_dir)

            logger.info(f"API credentials validated for session '{session_name}'")
            return (True, "")

        except ApiIdInvalidError:
            # Invalid credentials - don't retry, fail immediately
            if client and client.is_connected():
                await asyncio.wait_for(client.disconnect(), timeout=10.0)
            if temp_dir:
                secure_delete_dir(temp_dir)
            logger.warning(f"Invalid API credentials for session '{session_name}'")
            return (False, "Invalid API ID or API Hash. Credentials not saved.")

        except (OSError, ConnectionError, TimeoutError, asyncio.TimeoutError) as e:
            # Transient network error - retry with backoff
            if client and client.is_connected():
                await asyncio.wait_for(client.disconnect(), timeout=10.0)
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
                await asyncio.wait_for(client.disconnect(), timeout=10.0)
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
    from chatfilter.telegram.session_manager import SessionState
    from chatfilter.web.auth_state import AuthStep

    sessions = []
    data_dir = ensure_data_dir()

    for session_dir in data_dir.iterdir():
        if session_dir.is_dir():
            session_file = session_dir / "session.session"
            config_file = session_dir / "config.json"

            if session_file.exists() and config_file.exists():
                session_id = session_dir.name
                # First check config status
                config_status = get_session_config_status(session_dir)

                # If session manager available, check runtime state
                state = config_status
                error_message = None

                # If state is an error state from config, read error_message
                if state in ("proxy_error", "banned", "flood_wait", "error"):
                    try:
                        with config_file.open("r", encoding="utf-8") as f:
                            config = json.load(f)
                        error_message = config.get("error_message")
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
) -> HTMLResponse:
    """Upload a new session with config file.

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

        # Create session directory and save files
        session_dir.mkdir(parents=True, exist_ok=True)

        try:
            from chatfilter.utils.disk import DiskSpaceError

            # proxy_id is None - user must configure it after upload
            # source is 'file' because config was uploaded
            _save_session_to_disk(
                session_dir=session_dir,
                session_content=session_content,
                api_id=api_id,
                api_hash=api_hash,
                proxy_id=None,
                account_info=account_info,
                source="file",
            )

        except DiskSpaceError:
            shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Insufficient disk space. Please free up disk space and try again.")},
            )
        except TelegramConfigError:
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
    return HTMLResponse(content="", status_code=200)


@router.post("/api/sessions/import/validate", response_class=HTMLResponse)
async def validate_import_session(
    request: Request,
    session_file: Annotated[UploadFile, File()],
) -> HTMLResponse:
    """Validate a session file for import.

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

        # Validation successful
        logger.info("Session file validated successfully for import")
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
    if not phone.startswith("+") or not phone[1:].replace(" ", "").replace("-", "").replace("(", "").replace(")", "").isdigit():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _(
                    "Invalid phone number format. Must start with + and country code (e.g., +1234567890)."
                ),
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
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid phone number.")},
        )
    except PhoneNumberBannedError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("This phone number is banned by Telegram.")},
        )
    except ApiIdInvalidError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid API ID or API Hash.")},
        )
    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
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
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
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
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
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
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
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
        me = await client.get_me()
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
        await asyncio.wait_for(client.disconnect(), timeout=10.0)

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


@router.get("/api/sessions/{session_id}/reconnect-form", response_class=HTMLResponse)
async def get_reconnect_form(
    request: Request,
    session_id: str,
) -> HTMLResponse:
    """Get reconnect form for expired session.

    Shows modal form with phone (read-only) and API credentials input.
    Submits to send-code endpoint to initiate re-authentication.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_modal.html",
            context={
                "show": True,
                "title": _("Reconnect Session"),
                "error": str(e),
            },
        )

    session_dir = ensure_data_dir() / safe_name
    if not session_dir.exists():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_modal.html",
            context={
                "show": True,
                "title": _("Reconnect Session"),
                "error": _("Session not found"),
            },
        )

    # Load phone from account_info
    account_info = load_account_info(session_dir)
    phone = ""
    if account_info and "phone" in account_info:
        phone = str(account_info["phone"])

    # Load current API credentials if available
    config_file = session_dir / "config.json"
    current_api_id = None
    current_api_hash = None
    if config_file.exists():
        try:
            with config_file.open("r", encoding="utf-8") as f:
                config = json.load(f)
                current_api_id = config.get("api_id")
                current_api_hash = config.get("api_hash")
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read config for session {safe_name}: {e}")

    return templates.TemplateResponse(
        request=request,
        name="partials/reconnect_modal.html",
        context={
            "show": True,
            "session_id": safe_name,
            "phone": phone,
            "current_api_id": current_api_id,
            "current_api_hash": current_api_hash,
        },
    )


@router.post("/api/sessions/{session_id}/connect", response_class=HTMLResponse)
async def connect_session(
    request: Request,
    session_id: str,
) -> HTMLResponse:
    """Connect a session to Telegram.

    Returns HTML partial with updated button state.
    """
    import asyncio

    from chatfilter.telegram.client import TelegramClientLoader
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

    if not session_path.exists():
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

    try:
        # Create and register loader if not already registered
        loader = TelegramClientLoader(session_path, config_path)
        loader.validate()
        session_manager.register(safe_name, loader)

        # Connect with timeout (30 seconds)
        await asyncio.wait_for(
            session_manager.connect(safe_name),
            timeout=30.0
        )

        # Get updated state
        info = session_manager.get_info(safe_name)
        state = info.state.value if info else "disconnected"

        # Create session object for template
        session_data = {
            "session_id": safe_name,
            "state": state,
            "error_message": None,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context={"session": session_data},
            headers={"HX-Trigger": "refreshSessions"},
        )

    except asyncio.TimeoutError:
        logger.warning(f"Connection timeout for session '{safe_name}'")
        error_message = _("Connection timeout: Telegram API did not respond within 30 seconds. Please try again.")
        error_state = "error"

        # Create session object for template with error
        session_data = {
            "session_id": safe_name,
            "state": error_state,
            "error_message": error_message,
        }

        return templates.TemplateResponse(
            request=request,
            name="partials/session_row.html",
            context={"session": session_data},
        )

    except Exception as e:
        logger.exception(f"Failed to connect session '{safe_name}'")

        # Get user-friendly error message
        from chatfilter.telegram.error_mapping import get_user_friendly_message
        error_message = get_user_friendly_message(e)

        # Classify error state based on exception type
        error_state = classify_error_state(error_message, exception=e)

        # Create session object for template with error
        session_data = {
            "session_id": safe_name,
            "state": error_state,
            "error_message": error_message,
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


@router.post("/api/sessions/{session_id}/send-code", response_class=HTMLResponse)
async def send_code(
    request: Request,
    session_id: str,
    api_id: Annotated[int, Form()],
    api_hash: Annotated[str, Form()],
) -> HTMLResponse:
    """Send verification code to session's phone number.

    For sessions created with source=phone that need API credentials.
    Initiates Telegram auth flow, sends code to phone, sets session to needs_code status.

    Returns HTML partial with code input form or error message.
    """
    import asyncio
    import re
    import tempfile

    from telethon import TelegramClient
    from telethon.errors import (
        ApiIdInvalidError,
        AuthRestartError,
        FloodWaitError,
        PhoneNumberBannedError,
        PhoneNumberInvalidError,
        ServerError,
    )

    from chatfilter.storage.errors import StorageNotFoundError
    from chatfilter.storage.proxy_pool import get_proxy_by_id
    from chatfilter.web.app import get_templates
    from chatfilter.web.auth_state import DuplicateOperationError, get_auth_state_manager

    templates = get_templates()

    # Validate input parameters
    if api_id <= 0:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid API ID: must be a positive integer.")},
        )

    if not isinstance(api_hash, str) or len(api_hash) != 32:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid API Hash: must be exactly 32 characters.")},
        )

    if not re.match(r'^[a-zA-Z0-9]{32}$', api_hash):
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid API Hash: must contain only alphanumeric characters.")},
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

    # Get session directory
    session_dir = ensure_data_dir() / safe_name
    if not session_dir.exists():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Session not found.")},
        )

    # Read config to get phone and proxy_id
    config_file = session_dir / "config.json"
    if not config_file.exists():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Session configuration not found.")},
        )

    try:
        with config_file.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read config for session {safe_name}: {e}")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Failed to read session configuration.")},
        )

    # Extract phone from account_info
    account_info = load_account_info(session_dir)
    if not account_info or "phone" not in account_info:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Phone number not found in session metadata.")},
        )

    phone_value = account_info["phone"]
    if not phone_value:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Phone number is empty.")},
        )

    # Ensure phone is a string (account_info can have int or str)
    phone = str(phone_value)

    # Get proxy_id from config
    proxy_id = config.get("proxy_id")
    if not proxy_id:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Proxy not configured for this session.")},
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

    # Validate proxy exists and get it
    try:
        proxy_entry = get_proxy_by_id(proxy_id)
    except StorageNotFoundError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Proxy not found in pool.")},
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

        logger.info(f"Auth code sent for existing session '{safe_name}' to {phone}")

        # Return code input form (reconnect-specific template with correct endpoint)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_state.auth_id,
                "phone": phone,
                "session_name": safe_name,
                "session_id": session_id,
            },
        )

    except PhoneNumberInvalidError:
        # Clean up
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_result.html",
            context={"success": False, "error": _("Invalid phone number."), "allow_retry": True},
        )
    except PhoneNumberBannedError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_result.html",
            context={"success": False, "error": _("This phone number is banned by Telegram."), "allow_retry": False},
        )
    except ApiIdInvalidError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_result.html",
            context={"success": False, "error": _("Invalid API ID or API Hash."), "allow_retry": True},
        )
    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_result.html",
            context={
                "success": False,
                "error": get_user_friendly_message(e),
                "allow_retry": True,
            },
        )
    except (OSError, ConnectionError, ConnectionRefusedError) as e:
        # Proxy connection failure
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
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
            name="partials/reconnect_result.html",
            context={
                "success": False,
                "error": _("Proxy connection failed. Please check your proxy settings and try again."),
                "allow_retry": True,
            },
        )
    except TimeoutError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)

        # Update session state to proxy_error for timeout
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = "Proxy connection timeout"
        save_account_info(session_dir, account_info)

        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_result.html",
            context={
                "success": False,
                "error": _("Connection timeout. Please check your proxy settings and try again."),
                "allow_retry": True,
            },
        )
    except ServerError as e:
        # Temporary Telegram server error - allow retry
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)

        logger.warning(f"Telegram server error during reconnect for session '{safe_name}': {e}")
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_result.html",
            context={
                "success": False,
                "error": _("Telegram server is temporarily unavailable."),
                "suggestion": _("This is usually temporary. Please try again in a few moments."),
                "allow_retry": True,
            },
        )
    except AuthRestartError:
        # Session invalidated - cannot recover, suggest deletion
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)

        # Update session state to auth_restart
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "needs_auth"
        account_info["error_message"] = "Session invalidated by Telegram"
        save_account_info(session_dir, account_info)

        logger.error(f"Auth restart required for session '{safe_name}' - session invalidated")
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_result.html",
            context={
                "success": False,
                "error": _("Session has been invalidated by Telegram and cannot be recovered."),
                "suggestion": _("Please delete this session and add it again from scratch."),
                "allow_retry": False,
            },
        )
    except Exception:
        logger.exception(f"Failed to send code for session '{safe_name}'")
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_result.html",
            context={
                "success": False,
                "error": _("Failed to send code. Please check your settings and try again."),
                "allow_retry": True,
            },
        )



@router.post("/api/sessions/{session_id}/reconnect/start", response_class=HTMLResponse)
async def start_reconnect(
    request: Request,
    session_id: str,
) -> HTMLResponse:
    """Start reconnect flow for existing session with changed credentials.

    Reads API credentials from session config, sends verification code to phone.
    Used when user changes API_ID/API_HASH on existing session.

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

    # Sanitize session name
    try:
        safe_name = sanitize_session_name(session_id)
    except ValueError as e:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": str(e)},
        )

    # Get session directory
    session_dir = ensure_data_dir() / safe_name
    if not session_dir.exists():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Session not found.")},
        )

    # Read config to get credentials and proxy_id
    config_file = session_dir / "config.json"
    if not config_file.exists():
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Session configuration not found.")},
        )

    try:
        with config_file.open("r", encoding="utf-8") as f:
            config = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read config for session {safe_name}: {e}")
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Failed to read session configuration.")},
        )

    # Extract credentials from config
    api_id = config.get("api_id")
    api_hash = config.get("api_hash")
    if not api_id or not api_hash:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("API credentials not found in session config.")},
        )

    # Extract phone from account_info
    account_info = load_account_info(session_dir)
    if not account_info or "phone" not in account_info:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Phone number not found in session metadata.")},
        )

    phone_value = account_info["phone"]
    if not phone_value:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Phone number is empty.")},
        )

    # Ensure phone is a string (account_info can have int or str)
    phone = str(phone_value)

    # Get proxy_id from config
    proxy_id = config.get("proxy_id")
    if not proxy_id:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Proxy not configured for this session.")},
        )

    # Validate proxy exists and get it
    try:
        proxy_entry = get_proxy_by_id(proxy_id)
    except StorageNotFoundError:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Proxy not found in pool.")},
        )

    # Create temporary session file for auth flow
    temp_dir = tempfile.mkdtemp(prefix="chatfilter_reconnect_")
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

        logger.info(f"Reconnect flow started for session '{safe_name}', code sent to {phone}")

        # Return code input form (reconnect-specific template)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_code_form_reconnect.html",
            context={
                "auth_id": auth_state.auth_id,
                "phone": phone,
                "session_name": safe_name,
                "session_id": session_id,
            },
        )

    except PhoneNumberInvalidError:
        # Clean up
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid phone number.")},
        )
    except PhoneNumberBannedError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("This phone number is banned by Telegram.")},
        )
    except ApiIdInvalidError:
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid API ID or API Hash.")},
        )
    except FloodWaitError as e:
        from chatfilter.telegram.error_mapping import get_user_friendly_message

        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
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
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)

        # Update session state to proxy_error
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = f"Proxy connection failed: {type(e).__name__}"
        save_account_info(session_dir, account_info)

        logger.error(f"Proxy connection failed for reconnect of session '{safe_name}': {e}")
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
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
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
    except DuplicateOperationError:
        # Auth flow already in progress for this session
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("Authentication already in progress for this session."),
            },
        )
    except Exception:
        logger.exception(f"Failed to start reconnect for session '{safe_name}'")
        if "client" in dir() and client.is_connected():
            await asyncio.wait_for(client.disconnect(), timeout=10.0)
        secure_delete_dir(temp_dir)
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Failed to send code. Please check your settings and try again.")},
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
    if not isinstance(code, str) or len(code) > 10:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={"success": False, "error": _("Invalid code: must be at most 10 characters.")},
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
        me = await client.get_me()
        account_info = {
            "user_id": me.id,
            "phone": me.phone or "",
            "first_name": me.first_name or "",
            "last_name": me.last_name or "",
        }

        # Disconnect client before copying session file
        await asyncio.wait_for(client.disconnect(), timeout=10.0)

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

        # Use reconnect success template with toast notification
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_success.html",
            context={
                "message": _("Session '{name}' reconnected successfully").format(name=safe_name),
                "session_id": safe_name,
            },
        )

    except SessionPasswordNeededError:
        # 2FA required
        await auth_manager.update_auth_state(auth_id, step=AuthStep.NEED_2FA)
        logger.info(f"2FA required for session '{safe_name}' auth")
        # Use reconnect-specific template since we have session_id in the URL
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_2fa_form_reconnect.html",
            context={
                "auth_id": auth_id,
                "session_name": safe_name,
                "session_id": session_id,
            },
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
        # Update session state to proxy_error
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = f"Proxy connection failed during code verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)

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
        # Update session state to proxy_error for timeout
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = "Proxy connection timeout during code verification"
        save_account_info(session_dir, account_info)

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
        me = await client.get_me()
        account_info = {
            "user_id": me.id,
            "phone": me.phone or "",
            "first_name": me.first_name or "",
            "last_name": me.last_name or "",
        }

        # Disconnect client before copying session file
        await asyncio.wait_for(client.disconnect(), timeout=10.0)

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

        # Use reconnect success template with toast notification
        return templates.TemplateResponse(
            request=request,
            name="partials/reconnect_success.html",
            context={
                "message": _("Session '{name}' reconnected successfully").format(name=safe_name),
                "session_id": safe_name,
            },
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
        # Update session state to proxy_error
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = f"Proxy connection failed during 2FA verification: {type(e).__name__}"
        save_account_info(session_dir, account_info)

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
        # Update session state to proxy_error for timeout
        session_dir = ensure_data_dir() / safe_name
        account_info = load_account_info(session_dir) or {}
        account_info["status"] = "proxy_error"
        account_info["error_message"] = "Proxy connection timeout during 2FA verification"
        save_account_info(session_dir, account_info)

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
    api_id: Annotated[int, Form()],
    api_hash: Annotated[str, Form()],
    proxy_id: Annotated[str, Form()],
) -> HTMLResponse:
    """Save an imported session with configuration.

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
            # Try to get account info from the session
            account_info = await get_account_info_from_session(tmp_session_path, api_id, api_hash)

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

        # Create session directory and save files
        session_dir.mkdir(parents=True, exist_ok=True)

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

        except DiskSpaceError:
            shutil.rmtree(session_dir, ignore_errors=True)
            return templates.TemplateResponse(
                request=request,
                name="partials/upload_result.html",
                context={"success": False, "error": _("Insufficient disk space. Please free up disk space and try again.")},
            )
        except TelegramConfigError:
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

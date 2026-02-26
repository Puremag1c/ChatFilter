"""Validation utilities for session operations."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from chatfilter.i18n import _
from chatfilter.storage.helpers import atomic_write

if TYPE_CHECKING:
    from chatfilter.models.proxy import ProxyEntry

logger = logging.getLogger(__name__)


def validate_phone_number(phone: str) -> None:
    """Validate phone number format for manual phone input.

    For JSON import, use parsers.telegram_expert module instead.
    Raises ValueError if phone format is invalid.
    """
    if not phone.startswith("+"):
        raise ValueError(_("Phone number must start with +"))

    # Remove common formatting characters and check digits
    digits_only = phone[1:].replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if not digits_only.isdigit():
        raise ValueError(_("Phone number must contain only digits after +"))


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
    from telethon import TelegramClient
    from telethon.errors import ApiIdInvalidError

    from chatfilter.telegram.retry import calculate_backoff_delay
    from .helpers import secure_delete_dir

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

        except (OSError, ConnectionError, TimeoutError) as e:
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

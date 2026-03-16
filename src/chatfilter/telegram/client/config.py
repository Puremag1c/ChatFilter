"""Telegram API configuration with secure storage support."""

from __future__ import annotations

import json
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


class TelegramConfigError(Exception):
    """Raised when config file is invalid or missing required fields."""


class SessionFileError(Exception):
    """Raised when session file is invalid, incompatible, or locked."""


class SessionBlockedError(Exception):
    """Raised when session cannot connect due to missing required configuration.

    This includes cases where proxy_id is set but the proxy is not found in pool.
    """


@dataclass(frozen=True)
class TelegramConfig:
    """Telegram API configuration with secure storage support.

    Credentials are stored securely using:
    1. OS Keyring (preferred) - native system credential storage
    2. Encrypted file (fallback) - for systems without keyring
    3. Environment variables (read-only) - for containers

    Attributes:
        api_id: Telegram API ID (integer)
        api_hash: Telegram API hash (string) - redacted in logs
    """

    api_id: int
    api_hash: str

    def __repr__(self) -> str:
        """Redact api_hash in repr for security."""
        return f"TelegramConfig(api_id={self.api_id}, api_hash='***REDACTED***')"

    def __str__(self) -> str:
        """Redact api_hash in str for security."""
        return f"TelegramConfig(api_id={self.api_id})"

    @classmethod
    def from_secure_storage(cls, session_id: str, storage_dir: Path) -> TelegramConfig:
        """Load config from secure credential storage.

        Args:
            session_id: Unique session identifier
            storage_dir: Directory containing secure credentials

        Returns:
            TelegramConfig instance

        Raises:
            TelegramConfigError: If credentials cannot be loaded
        """
        from chatfilter.security import CredentialNotFoundError, SecureCredentialManager

        try:
            manager = SecureCredentialManager(storage_dir)
            api_id, api_hash, _proxy_id = manager.retrieve_credentials(session_id)
            return cls(api_id=api_id, api_hash=api_hash)
        except CredentialNotFoundError as e:
            raise TelegramConfigError(
                f"Credentials not found in secure storage for session '{session_id}'. "
                f"Please ensure credentials are properly configured."
            ) from e
        except Exception as e:
            raise TelegramConfigError(f"Failed to load credentials: {e}") from e

    @classmethod
    def from_json_file(cls, path: Path, *, migrate_to_secure: bool = False) -> TelegramConfig:
        """Load config from JSON file (legacy/fallback method).

        DEPRECATED: This method loads credentials from plaintext JSON.
        Use from_secure_storage() for secure credential access.

        Args:
            path: Path to JSON config file
            migrate_to_secure: If True, migrate credentials to secure storage
                and delete the plaintext file

        Returns:
            TelegramConfig instance

        Raises:
            TelegramConfigError: If file is invalid or missing required fields
            FileNotFoundError: If config file doesn't exist

        Warning:
            Storing credentials in plaintext JSON is insecure. Consider using
            secure storage via from_secure_storage() instead.
        """
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

        logger.warning(
            "Loading credentials from plaintext JSON (DEPRECATED). "
            "Consider migrating to secure storage for better security."
        )

        try:
            with path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise TelegramConfigError(f"Invalid JSON in config file: {e}") from e

        # Validate required fields
        missing = []
        if "api_id" not in data:
            missing.append("api_id")
        if "api_hash" not in data:
            missing.append("api_hash")

        if missing:
            raise TelegramConfigError(f"Missing required fields in config: {', '.join(missing)}")

        # Validate types
        api_id = data["api_id"]
        api_hash = data["api_hash"]

        if not isinstance(api_id, int):
            try:
                api_id = int(api_id)
            except (ValueError, TypeError) as e:
                raise TelegramConfigError(
                    f"api_id must be an integer, got: {type(api_id).__name__}"
                ) from e

        if not isinstance(api_hash, str):
            raise TelegramConfigError(f"api_hash must be a string, got: {type(api_hash).__name__}")

        if not api_hash:
            raise TelegramConfigError("api_hash cannot be empty")

        config = cls(api_id=api_id, api_hash=api_hash)

        # Auto-migrate to secure storage if requested
        if migrate_to_secure:
            try:
                _migrate_plaintext_to_secure(path, api_id, api_hash)
            except Exception as e:
                logger.error(f"Failed to migrate credentials to secure storage: {e}")
                # Don't fail the config load, just log the error

        return config


def _migrate_plaintext_to_secure(config_path: Path, api_id: int, api_hash: str) -> None:
    """Migrate plaintext credentials to secure storage and delete plaintext file.

    Args:
        config_path: Path to plaintext config.json file
        api_id: Telegram API ID
        api_hash: Telegram API hash
    """
    from chatfilter.security import SecureCredentialManager
    from chatfilter.storage.file import secure_delete_file

    # Determine session_id from path (parent directory name)
    session_id = config_path.parent.name

    # Determine storage directory (sessions directory)
    storage_dir = config_path.parent.parent

    # Store credentials securely
    manager = SecureCredentialManager(storage_dir)
    manager.store_credentials(session_id, api_id, api_hash)

    # Securely delete plaintext file
    secure_delete_file(config_path)

    # Create a migration marker file to prevent re-migration attempts
    marker_file = config_path.parent / ".migrated"
    marker_file.write_text(
        "Credentials migrated to secure storage.\n"
        "Original plaintext config.json has been securely deleted.\n"
    )
    logger.info(f"Migrated credentials to secure storage for session: {session_id}")


def validate_session_file(session_path: Path) -> None:
    """Validate Telethon session file format and accessibility.

    Checks:
    - File exists
    - File is a valid SQLite database
    - Session format is compatible with Telethon 1.x (current library version)
    - File is not locked by another process

    Args:
        session_path: Path to .session file

    Raises:
        FileNotFoundError: If session file doesn't exist
        SessionFileError: If session is invalid, incompatible, or locked
    """
    if not session_path.exists():
        raise FileNotFoundError(f"Session file not found: {session_path}")

    # Check if it's a valid SQLite database
    try:
        conn = sqlite3.connect(f"file:{session_path}?mode=ro", uri=True, timeout=1.0)
    except sqlite3.OperationalError as e:
        error_msg = str(e).lower()
        if "locked" in error_msg or "database is locked" in error_msg:
            raise SessionFileError(
                f"Session file is locked by another process. "
                f"Make sure no other application is using this session: {session_path}"
            ) from e
        raise SessionFileError(f"Invalid session file (not a valid database): {e}") from e

    try:
        cursor = conn.cursor()

        # Check for Telethon 1.x session format (has 'sessions' and 'entities' tables)
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        except sqlite3.DatabaseError as e:
            error_msg = str(e).lower()
            if "locked" in error_msg or "database is locked" in error_msg:
                raise SessionFileError(
                    f"Session file is locked by another process. "
                    f"Make sure no other application is using this session: {session_path}"
                ) from e
            raise SessionFileError(f"Invalid session file (not a valid database): {e}") from e
        tables = {row[0] for row in cursor.fetchall()}

        # Telethon 1.x required tables
        required_tables = {"sessions", "entities"}

        # Telethon 2.x has different schema (different table structure)
        # We're using telethon>=1.34.0 which is 1.x series
        if not required_tables.issubset(tables):
            if "version" in tables:
                # Likely Telethon 2.x format
                raise SessionFileError(
                    "Session file is from Telethon 2.x which is incompatible with this application. "
                    "Please generate a new session file using Telethon 1.x (version 1.34.0 or later). "
                    "Telethon 1.x and 2.x use different session formats that are not interchangeable."
                )
            raise SessionFileError(
                f"Invalid session file format. Expected Telethon 1.x session with tables "
                f"{required_tables}, but found: {tables}. "
                "Please ensure you're using a valid Telethon session file."
            )

        # Verify session has data
        cursor.execute("SELECT COUNT(*) FROM sessions")
        count = cursor.fetchone()[0]
        if count == 0:
            raise SessionFileError(
                "Session file is empty (no session data). "
                "Please use a session that has been authenticated."
            )

    except sqlite3.OperationalError as e:
        error_msg = str(e).lower()
        if "locked" in error_msg:
            raise SessionFileError(
                f"Session file is locked by another process. "
                f"Make sure no other application is using this session: {session_path}"
            ) from e
        raise SessionFileError(f"Error reading session file: {e}") from e
    finally:
        conn.close()

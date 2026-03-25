"""Telegram API configuration."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


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
    """Telegram API configuration.

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

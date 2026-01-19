"""Telegram client initialization from session and config files."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from telethon import TelegramClient

if TYPE_CHECKING:
    from telethon import TelegramClient as TelegramClientType


class TelegramConfigError(Exception):
    """Raised when config file is invalid or missing required fields."""


class SessionFileError(Exception):
    """Raised when session file is invalid, incompatible, or locked."""


@dataclass(frozen=True)
class TelegramConfig:
    """Telegram API configuration loaded from JSON file.

    Attributes:
        api_id: Telegram API ID (integer)
        api_hash: Telegram API hash (string)
    """

    api_id: int
    api_hash: str

    @classmethod
    def from_json_file(cls, path: Path) -> TelegramConfig:
        """Load config from JSON file.

        Args:
            path: Path to JSON config file

        Returns:
            TelegramConfig instance

        Raises:
            TelegramConfigError: If file is invalid or missing required fields
            FileNotFoundError: If config file doesn't exist
        """
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")

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
            raise TelegramConfigError(
                f"api_hash must be a string, got: {type(api_hash).__name__}"
            )

        if not api_hash:
            raise TelegramConfigError("api_hash cannot be empty")

        return cls(api_id=api_id, api_hash=api_hash)


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
                    "Session file appears to be from Telethon 2.x which is incompatible. "
                    "Please export a new session using Telethon 1.x (>=1.34.0)"
                )
            raise SessionFileError(
                f"Invalid session file format. Expected tables {required_tables}, "
                f"found: {tables}"
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


class TelegramClientLoader:
    """Loader for creating Telethon client from session and config files.

    Example:
        ```python
        loader = TelegramClientLoader(
            session_path=Path("my_account.session"),
            config_path=Path("telegram_config.json"),
        )
        async with loader.create_client() as client:
            me = await client.get_me()
            print(f"Logged in as {me.username}")
        ```
    """

    def __init__(self, session_path: Path, config_path: Path) -> None:
        """Initialize loader with session and config file paths.

        Args:
            session_path: Path to Telethon .session file
            config_path: Path to JSON config file with api_id and api_hash
        """
        self._session_path = session_path
        self._config_path = config_path
        self._config: TelegramConfig | None = None

    @property
    def session_path(self) -> Path:
        """Path to session file."""
        return self._session_path

    @property
    def config_path(self) -> Path:
        """Path to config file."""
        return self._config_path

    def validate(self) -> None:
        """Validate both session and config files.

        Call this before create_client() to get early validation errors.

        Raises:
            FileNotFoundError: If session or config file doesn't exist
            SessionFileError: If session file is invalid
            TelegramConfigError: If config file is invalid
        """
        # Validate config first (cheaper operation)
        self._config = TelegramConfig.from_json_file(self._config_path)

        # Validate session file
        validate_session_file(self._session_path)

    def create_client(self) -> TelegramClientType:
        """Create and return a Telethon client instance.

        Validates files if not already validated. The returned client
        should be used as an async context manager.

        Returns:
            TelegramClient instance (not connected yet)

        Raises:
            FileNotFoundError: If session or config file doesn't exist
            SessionFileError: If session file is invalid
            TelegramConfigError: If config file is invalid

        Example:
            ```python
            client = loader.create_client()
            async with client:
                # client is connected here
                me = await client.get_me()
            ```
        """
        if self._config is None:
            self.validate()

        assert self._config is not None  # for type checker

        # Telethon expects session path without .session extension
        session_name = str(self._session_path)
        if session_name.endswith(".session"):
            session_name = session_name[:-8]

        return TelegramClient(
            session_name,
            self._config.api_id,
            self._config.api_hash,
        )

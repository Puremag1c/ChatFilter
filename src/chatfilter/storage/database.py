"""Database module for persistent monitoring state."""

import json
import sqlite3
from abc import ABC, abstractmethod
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path


class SQLiteDatabase(ABC):
    """Base class for SQLite database operations with common utilities."""

    def __init__(self, db_path: Path | str):
        """Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    @abstractmethod
    def _initialize_schema(self) -> None:
        """Create database tables if they don't exist. Must be implemented by subclasses."""
        ...

    @staticmethod
    def _datetime_to_str(dt: datetime | None) -> str | None:
        """Convert datetime to ISO 8601 string for database storage.

        Args:
            dt: Datetime object to convert

        Returns:
            ISO 8601 string or None
        """
        return dt.isoformat() if dt is not None else None

    @staticmethod
    def _str_to_datetime(s: str | None) -> datetime | None:
        """Convert ISO 8601 string from database to datetime.

        Args:
            s: ISO 8601 string to convert

        Returns:
            Datetime object or None
        """
        return datetime.fromisoformat(s) if s is not None else None

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections with automatic commit/rollback."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        # Enable foreign key constraints (required for CASCADE DELETE)
        conn.execute("PRAGMA foreign_keys = ON")
        # Set busy timeout to prevent SQLITE_BUSY errors during concurrent operations
        conn.execute("PRAGMA busy_timeout = 30000")  # 30 seconds
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


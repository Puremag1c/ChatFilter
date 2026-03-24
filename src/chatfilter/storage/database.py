"""Abstract database base class.

All storage modules inherit from Database. The concrete backend
(SQLite, PostgreSQL, etc.) is selected by subclassing — see sqlite.py.
SQL in the mixin layers (group_database/, user_database.py) is standard
SQL and works with any backend.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from typing import Any


class Database(ABC):
    """Backend-agnostic base class for database operations.

    Subclasses must implement:
      - _connection() — context manager yielding a DB-API 2.0 connection
      - _initialize_schema() — create tables / run migrations
    """

    @abstractmethod
    def _initialize_schema(self) -> None:
        """Create database tables if they don't exist."""
        ...

    @abstractmethod
    @contextmanager
    def _connection(self) -> Generator[Any, None, None]:
        """Context manager for database connections with automatic commit/rollback.

        Must yield an object that supports:
          - .execute(sql, params) → cursor
          - cursor.fetchone() / cursor.fetchall() → dict-like rows
        """
        ...

    @staticmethod
    def _datetime_to_str(dt: datetime | None) -> str | None:
        """Convert datetime to ISO 8601 string for database storage."""
        return dt.isoformat() if dt is not None else None

    @staticmethod
    def _str_to_datetime(s: str | None) -> datetime | None:
        """Convert ISO 8601 string from database to datetime."""
        return datetime.fromisoformat(s) if s is not None else None

"""Database module for persistent monitoring state."""

import json
import sqlite3
from abc import ABC, abstractmethod
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from chatfilter.models.monitoring import ChatMonitorState, SyncSnapshot


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


class MonitoringDatabase(SQLiteDatabase):
    """SQLite database for persisting chat monitoring state and sync snapshots."""

    def _initialize_schema(self) -> None:
        """Create database tables if they don't exist."""
        with self._connection() as conn:
            # Chat monitor state table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_monitors (
                    session_id TEXT NOT NULL,
                    chat_id INTEGER NOT NULL,
                    last_message_id INTEGER,
                    last_message_at TIMESTAMP,
                    last_sync_at TIMESTAMP,
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    message_count INTEGER NOT NULL DEFAULT 0,
                    unique_author_ids TEXT NOT NULL DEFAULT '[]',
                    first_message_at TIMESTAMP,
                    created_at TIMESTAMP NOT NULL,
                    PRIMARY KEY (session_id, chat_id)
                )
            """)

            # Sync snapshots table for trend tracking
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    chat_id INTEGER NOT NULL,
                    sync_at TIMESTAMP NOT NULL,
                    message_count INTEGER NOT NULL,
                    unique_authors INTEGER NOT NULL,
                    new_messages INTEGER NOT NULL DEFAULT 0,
                    new_authors INTEGER NOT NULL DEFAULT 0,
                    sync_duration_seconds REAL,
                    FOREIGN KEY (session_id, chat_id)
                        REFERENCES chat_monitors (session_id, chat_id)
                        ON DELETE CASCADE
                )
            """)

            # Indexes for efficient queries
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_monitors_session
                ON chat_monitors (session_id)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_snapshots_chat
                ON sync_snapshots (session_id, chat_id, sync_at)
            """)

    def save_monitor_state(self, state: ChatMonitorState) -> None:
        """Save or update a chat monitor state.

        Args:
            state: Monitor state to save
        """
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO chat_monitors
                (session_id, chat_id, last_message_id, last_message_at,
                 last_sync_at, is_enabled, message_count, unique_author_ids,
                 first_message_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    state.session_id,
                    state.chat_id,
                    state.last_message_id,
                    self._datetime_to_str(state.last_message_at),
                    self._datetime_to_str(state.last_sync_at),
                    1 if state.is_enabled else 0,
                    state.message_count,
                    json.dumps(state.unique_author_ids),
                    self._datetime_to_str(state.first_message_at),
                    self._datetime_to_str(state.created_at),
                ),
            )

    def load_monitor_state(self, session_id: str, chat_id: int) -> ChatMonitorState | None:
        """Load a chat monitor state.

        Args:
            session_id: Session identifier
            chat_id: Chat ID

        Returns:
            ChatMonitorState if found, None otherwise
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM chat_monitors
                WHERE session_id = ? AND chat_id = ?
                """,
                (session_id, chat_id),
            )
            row = cursor.fetchone()

            if not row:
                return None

            return ChatMonitorState(
                session_id=row["session_id"],
                chat_id=row["chat_id"],
                last_message_id=row["last_message_id"],
                last_message_at=self._str_to_datetime(row["last_message_at"]),
                last_sync_at=self._str_to_datetime(row["last_sync_at"]),
                is_enabled=bool(row["is_enabled"]),
                message_count=row["message_count"],
                unique_author_ids=json.loads(row["unique_author_ids"]),
                first_message_at=self._str_to_datetime(row["first_message_at"]),
                created_at=self._str_to_datetime(row["created_at"]) or datetime.now(UTC),
            )

    def load_all_monitors(self, session_id: str) -> list[ChatMonitorState]:
        """Load all chat monitors for a session.

        Args:
            session_id: Session identifier

        Returns:
            List of ChatMonitorState objects
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM chat_monitors
                WHERE session_id = ?
                ORDER BY last_sync_at DESC
                """,
                (session_id,),
            )
            rows = cursor.fetchall()

        return [
            ChatMonitorState(
                session_id=row["session_id"],
                chat_id=row["chat_id"],
                last_message_id=row["last_message_id"],
                last_message_at=self._str_to_datetime(row["last_message_at"]),
                last_sync_at=self._str_to_datetime(row["last_sync_at"]),
                is_enabled=bool(row["is_enabled"]),
                message_count=row["message_count"],
                unique_author_ids=json.loads(row["unique_author_ids"]),
                first_message_at=self._str_to_datetime(row["first_message_at"]),
                created_at=self._str_to_datetime(row["created_at"]) or datetime.now(UTC),
            )
            for row in rows
        ]

    def load_enabled_monitors(self, session_id: str) -> list[ChatMonitorState]:
        """Load only enabled chat monitors for a session.

        Args:
            session_id: Session identifier

        Returns:
            List of enabled ChatMonitorState objects
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM chat_monitors
                WHERE session_id = ? AND is_enabled = 1
                ORDER BY last_sync_at DESC
                """,
                (session_id,),
            )
            rows = cursor.fetchall()

        return [
            ChatMonitorState(
                session_id=row["session_id"],
                chat_id=row["chat_id"],
                last_message_id=row["last_message_id"],
                last_message_at=self._str_to_datetime(row["last_message_at"]),
                last_sync_at=self._str_to_datetime(row["last_sync_at"]),
                is_enabled=bool(row["is_enabled"]),
                message_count=row["message_count"],
                unique_author_ids=json.loads(row["unique_author_ids"]),
                first_message_at=self._str_to_datetime(row["first_message_at"]),
                created_at=self._str_to_datetime(row["created_at"]) or datetime.now(UTC),
            )
            for row in rows
        ]

    def delete_monitor_state(self, session_id: str, chat_id: int) -> bool:
        """Delete a chat monitor state and its snapshots.

        Args:
            session_id: Session identifier
            chat_id: Chat ID

        Returns:
            True if deleted, False if not found
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                DELETE FROM chat_monitors
                WHERE session_id = ? AND chat_id = ?
                """,
                (session_id, chat_id),
            )
            return cursor.rowcount > 0

    def save_snapshot(self, session_id: str, snapshot: SyncSnapshot) -> None:
        """Save a sync snapshot.

        Args:
            session_id: Session identifier
            snapshot: Snapshot to save
        """
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO sync_snapshots
                (session_id, chat_id, sync_at, message_count, unique_authors,
                 new_messages, new_authors, sync_duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    snapshot.chat_id,
                    self._datetime_to_str(snapshot.sync_at),
                    snapshot.message_count,
                    snapshot.unique_authors,
                    snapshot.new_messages,
                    snapshot.new_authors,
                    snapshot.sync_duration_seconds,
                ),
            )

    def load_snapshots(
        self,
        session_id: str,
        chat_id: int,
        since: datetime | None = None,
        limit: int | None = None,
    ) -> list[SyncSnapshot]:
        """Load sync snapshots for a chat.

        Args:
            session_id: Session identifier
            chat_id: Chat ID
            since: Only load snapshots after this time (optional)
            limit: Maximum number of snapshots to return (optional)

        Returns:
            List of SyncSnapshot objects, newest first
        """
        with self._connection() as conn:
            query = """
                SELECT * FROM sync_snapshots
                WHERE session_id = ? AND chat_id = ?
            """
            params: list[str | int] = [session_id, chat_id]

            if since:
                query += " AND sync_at > ?"
                params.append(self._datetime_to_str(since) or "")

            query += " ORDER BY sync_at DESC"

            if limit:
                query += f" LIMIT {limit}"

            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        return [
            SyncSnapshot(
                chat_id=row["chat_id"],
                sync_at=self._str_to_datetime(row["sync_at"]) or datetime.now(UTC),
                message_count=row["message_count"],
                unique_authors=row["unique_authors"],
                new_messages=row["new_messages"],
                new_authors=row["new_authors"],
                sync_duration_seconds=row["sync_duration_seconds"],
            )
            for row in rows
        ]

    def count_snapshots(self, session_id: str, chat_id: int) -> int:
        """Count snapshots for a chat.

        Args:
            session_id: Session identifier
            chat_id: Chat ID

        Returns:
            Number of snapshots
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT COUNT(*) as count FROM sync_snapshots
                WHERE session_id = ? AND chat_id = ?
                """,
                (session_id, chat_id),
            )
            row = cursor.fetchone()
            return row["count"] if row else 0

    def delete_old_snapshots(self, session_id: str, chat_id: int, keep_count: int = 100) -> int:
        """Delete old snapshots, keeping the most recent ones.

        Args:
            session_id: Session identifier
            chat_id: Chat ID
            keep_count: Number of recent snapshots to keep

        Returns:
            Number of snapshots deleted
        """
        with self._connection() as conn:
            # Delete all but the most recent keep_count snapshots
            cursor = conn.execute(
                """
                DELETE FROM sync_snapshots
                WHERE session_id = ? AND chat_id = ? AND id NOT IN (
                    SELECT id FROM sync_snapshots
                    WHERE session_id = ? AND chat_id = ?
                    ORDER BY sync_at DESC
                    LIMIT ?
                )
                """,
                (session_id, chat_id, session_id, chat_id, keep_count),
            )
            return cursor.rowcount

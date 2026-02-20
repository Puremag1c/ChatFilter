"""Database module for persistent task storage and monitoring state."""

import json
import sqlite3
from abc import ABC, abstractmethod
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from chatfilter.analyzer.task_queue import AnalysisTask, TaskStatus
from chatfilter.models.analysis import AnalysisResult, ChatMetrics
from chatfilter.models.chat import Chat
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


class TaskDatabase(SQLiteDatabase):
    """SQLite database for persisting analysis tasks and results."""

    @staticmethod
    def _str_to_datetime_required(s: str | None) -> datetime:
        """Convert ISO 8601 string from database to datetime for required fields.

        Args:
            s: ISO 8601 string to convert

        Returns:
            Datetime object

        Raises:
            ValueError: If string is None or empty
        """
        if not s:
            raise ValueError("Required datetime field is missing from database")
        return datetime.fromisoformat(s)

    def _initialize_schema(self) -> None:
        """Create database tables if they don't exist."""
        with self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    chat_ids TEXT NOT NULL,
                    message_limit INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    error TEXT,
                    current_chat_index INTEGER NOT NULL DEFAULT 0
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS task_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    chat_data TEXT NOT NULL,
                    metrics_data TEXT NOT NULL,
                    analyzed_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES tasks (task_id)
                        ON DELETE CASCADE
                )
            """)

            # Create index for faster task lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tasks_status
                ON tasks (status)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_results_task_id
                ON task_results (task_id)
            """)

    def save_task(self, task: AnalysisTask) -> None:
        """Save or update a task in the database.

        Uses INSERT ... ON CONFLICT instead of INSERT OR REPLACE to avoid
        triggering ON DELETE CASCADE which would delete associated results.

        Args:
            task: Task to save
        """
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO tasks
                (task_id, session_id, chat_ids, message_limit, status,
                 created_at, started_at, completed_at, error, current_chat_index)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id) DO UPDATE SET
                    session_id = excluded.session_id,
                    chat_ids = excluded.chat_ids,
                    message_limit = excluded.message_limit,
                    status = excluded.status,
                    created_at = excluded.created_at,
                    started_at = excluded.started_at,
                    completed_at = excluded.completed_at,
                    error = excluded.error,
                    current_chat_index = excluded.current_chat_index
                """,
                (
                    str(task.task_id),
                    task.session_id,
                    json.dumps(task.chat_ids),
                    task.message_limit,
                    task.status.value,
                    self._datetime_to_str(task.created_at),
                    self._datetime_to_str(task.started_at),
                    self._datetime_to_str(task.completed_at),
                    task.error,
                    task.current_chat_index,
                ),
            )

    def load_task(self, task_id: UUID) -> AnalysisTask | None:
        """Load a task from the database.

        Args:
            task_id: ID of task to load

        Returns:
            Task if found, None otherwise
        """
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM tasks WHERE task_id = ?",
                (str(task_id),),
            )
            row = cursor.fetchone()

            if not row:
                return None

            # Load results for this task
            results = self._load_task_results(conn, task_id)

            return AnalysisTask(
                task_id=UUID(row["task_id"]),
                session_id=row["session_id"],
                chat_ids=json.loads(row["chat_ids"]),
                message_limit=row["message_limit"],
                status=TaskStatus(row["status"]),
                created_at=self._str_to_datetime_required(row["created_at"]),
                started_at=self._str_to_datetime(row["started_at"]),
                completed_at=self._str_to_datetime(row["completed_at"]),
                results=results,
                error=row["error"],
                current_chat_index=row["current_chat_index"],
            )

    def load_all_tasks(self) -> list[AnalysisTask]:
        """Load all tasks from the database.

        Returns:
            List of all tasks, sorted by creation time (newest first)
        """
        with self._connection() as conn:
            cursor = conn.execute("SELECT task_id FROM tasks ORDER BY created_at DESC")
            task_ids = [UUID(row["task_id"]) for row in cursor.fetchall()]

        return [task for task_id in task_ids if (task := self.load_task(task_id))]

    def load_incomplete_tasks(self) -> list[AnalysisTask]:
        """Load all tasks that are pending or in progress.

        Returns:
            List of incomplete tasks
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT task_id FROM tasks
                WHERE status IN (?, ?)
                ORDER BY created_at ASC
                """,
                (TaskStatus.PENDING.value, TaskStatus.IN_PROGRESS.value),
            )
            task_ids = [UUID(row["task_id"]) for row in cursor.fetchall()]

        return [task for task_id in task_ids if (task := self.load_task(task_id))]

    def load_completed_tasks(
        self,
        limit: int | None = None,
        offset: int = 0,
        status_filter: list[TaskStatus] | None = None,
    ) -> list[AnalysisTask]:
        """Load completed tasks from the database with optional filtering.

        Args:
            limit: Maximum number of tasks to return (None for all)
            offset: Number of tasks to skip (for pagination)
            status_filter: List of statuses to filter by (default: all completed statuses)

        Returns:
            List of completed tasks, sorted by completion time (newest first)
        """
        if status_filter is None:
            status_filter = [
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
                TaskStatus.TIMEOUT,
            ]

        with self._connection() as conn:
            # Build query with placeholders
            placeholders = ",".join("?" * len(status_filter))
            query = f"""
                SELECT task_id FROM tasks
                WHERE status IN ({placeholders})
                ORDER BY completed_at DESC, created_at DESC
            """  # nosec B608 - placeholders are safe, values are parameterized

            # Add pagination if specified
            if limit is not None:
                query += f" LIMIT {limit} OFFSET {offset}"

            cursor = conn.execute(
                query,
                [status.value for status in status_filter],
            )
            task_ids = [UUID(row["task_id"]) for row in cursor.fetchall()]

        return [task for task_id in task_ids if (task := self.load_task(task_id))]

    def count_completed_tasks(
        self,
        status_filter: list[TaskStatus] | None = None,
    ) -> int:
        """Count completed tasks in the database.

        Args:
            status_filter: List of statuses to count (default: all completed statuses)

        Returns:
            Number of matching tasks
        """
        if status_filter is None:
            status_filter = [
                TaskStatus.COMPLETED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
                TaskStatus.TIMEOUT,
            ]

        with self._connection() as conn:
            placeholders = ",".join("?" * len(status_filter))
            query = f"""
                SELECT COUNT(*) as count FROM tasks
                WHERE status IN ({placeholders})
            """  # nosec B608 - placeholders are safe, values are parameterized
            cursor = conn.execute(
                query,
                [status.value for status in status_filter],
            )
            row = cursor.fetchone()
            return row["count"] if row else 0

    def save_task_result(self, task_id: UUID, result: AnalysisResult) -> None:
        """Save an analysis result to the database.

        Args:
            task_id: ID of task this result belongs to
            result: Analysis result to save
        """
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO task_results
                (task_id, chat_data, metrics_data, analyzed_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    str(task_id),
                    result.chat.model_dump_json(),
                    # Exclude computed fields from serialization
                    result.metrics.model_dump_json(exclude={"messages_per_hour"}),
                    self._datetime_to_str(result.analyzed_at),
                ),
            )

    def _load_task_results(self, conn: sqlite3.Connection, task_id: UUID) -> list[AnalysisResult]:
        """Load all results for a task.

        Args:
            conn: Database connection
            task_id: ID of task

        Returns:
            List of analysis results
        """
        cursor = conn.execute(
            """
            SELECT chat_data, metrics_data, analyzed_at
            FROM task_results
            WHERE task_id = ?
            ORDER BY id ASC
            """,
            (str(task_id),),
        )

        results = []
        for row in cursor.fetchall():
            chat = Chat.model_validate_json(row["chat_data"])
            metrics = ChatMetrics.model_validate_json(row["metrics_data"])
            results.append(
                AnalysisResult(
                    chat=chat,
                    metrics=metrics,
                    analyzed_at=self._str_to_datetime_required(row["analyzed_at"]),
                )
            )

        return results

    def delete_task(self, task_id: UUID) -> None:
        """Delete a task and its results from the database.

        Args:
            task_id: ID of task to delete
        """
        with self._connection() as conn:
            # Results are deleted automatically via CASCADE
            conn.execute("DELETE FROM tasks WHERE task_id = ?", (str(task_id),))

    def delete_completed_tasks(self) -> int:
        """Delete all completed, failed, cancelled, and timeout tasks.

        Returns:
            Number of tasks deleted
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                DELETE FROM tasks
                WHERE status IN (?, ?, ?, ?)
                """,
                (
                    TaskStatus.COMPLETED.value,
                    TaskStatus.FAILED.value,
                    TaskStatus.CANCELLED.value,
                    TaskStatus.TIMEOUT.value,
                ),
            )
            return cursor.rowcount


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

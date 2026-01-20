"""Database module for persistent task storage."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator
from uuid import UUID

from chatfilter.analyzer.task_queue import AnalysisTask, TaskStatus
from chatfilter.models.analysis import AnalysisResult


class TaskDatabase:
    """SQLite database for persisting analysis tasks and results."""

    def __init__(self, db_path: Path | str):
        """Initialize database connection.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize_schema()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        conn = sqlite3.connect(
            self.db_path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        conn.row_factory = sqlite3.Row
        # Enable foreign key constraints (required for CASCADE DELETE)
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

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

        Args:
            task: Task to save
        """
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO tasks
                (task_id, session_id, chat_ids, message_limit, status,
                 created_at, started_at, completed_at, error, current_chat_index)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(task.task_id),
                    task.session_id,
                    json.dumps(task.chat_ids),
                    task.message_limit,
                    task.status.value,
                    task.created_at,
                    task.started_at,
                    task.completed_at,
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
                created_at=row["created_at"],
                started_at=row["started_at"],
                completed_at=row["completed_at"],
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
            cursor = conn.execute(
                "SELECT task_id FROM tasks ORDER BY created_at DESC"
            )
            task_ids = [UUID(row["task_id"]) for row in cursor.fetchall()]

        return [
            task for task_id in task_ids if (task := self.load_task(task_id))
        ]

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

        return [
            task for task_id in task_ids if (task := self.load_task(task_id))
        ]

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
            """

            # Add pagination if specified
            if limit is not None:
                query += f" LIMIT {limit} OFFSET {offset}"

            cursor = conn.execute(
                query,
                [status.value for status in status_filter],
            )
            task_ids = [UUID(row["task_id"]) for row in cursor.fetchall()]

        return [
            task for task_id in task_ids if (task := self.load_task(task_id))
        ]

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
            """
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
                    result.analyzed_at,
                ),
            )

    def _load_task_results(
        self, conn: sqlite3.Connection, task_id: UUID
    ) -> list[AnalysisResult]:
        """Load all results for a task.

        Args:
            conn: Database connection
            task_id: ID of task

        Returns:
            List of analysis results
        """
        from chatfilter.models.analysis import Chat, ChatMetrics

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
                    analyzed_at=row["analyzed_at"],
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

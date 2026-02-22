"""Task operations for GroupDatabase."""

import json
from datetime import UTC, datetime
from typing import Any


class TasksMixin:
    """Mixin providing group analysis task management."""

    def create_task(
        self,
        group_id: str,
        requested_metrics: dict[str, Any],
        time_window: int | None = None,
    ) -> str:
        """Create a new group analysis task.

        Args:
            group_id: Group identifier
            requested_metrics: Settings for requested metrics (serialized to JSON)
            time_window: Time window in hours for activity analysis (optional)

        Returns:
            Task ID
        """
        from chatfilter.models.group import TaskStatus

        task_id = f"task-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
        now = datetime.now(UTC)

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO group_tasks
                (id, group_id, requested_metrics, time_window, created_at, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    group_id,
                    json.dumps(requested_metrics),
                    str(time_window) if time_window is not None else None,
                    self._datetime_to_str(now),
                    TaskStatus.RUNNING.value,
                ),
            )

        return task_id

    def get_active_task(self, group_id: str) -> dict[str, Any] | None:
        """Get the active (running) task for a group.

        Args:
            group_id: Group identifier

        Returns:
            Task data dict or None if no active task
        """
        from chatfilter.models.group import TaskStatus

        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM group_tasks
                WHERE group_id = ? AND status = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (group_id, TaskStatus.RUNNING.value),
            )
            row = cursor.fetchone()

            if not row:
                return None

            return {
                "id": row["id"],
                "group_id": row["group_id"],
                "requested_metrics": json.loads(row["requested_metrics"]),
                "time_window": int(row["time_window"]) if row["time_window"] else None,
                "created_at": self._str_to_datetime(row["created_at"]),
                "status": row["status"],
            }

    def complete_task(self, task_id: str) -> None:
        """Mark a task as completed.

        Args:
            task_id: Task identifier
        """
        from chatfilter.models.group import TaskStatus

        with self._connection() as conn:
            conn.execute(
                "UPDATE group_tasks SET status = ? WHERE id = ?",
                (TaskStatus.COMPLETED.value, task_id),
            )

    def cancel_task(self, task_id: str) -> None:
        """Mark a task as cancelled.

        Args:
            task_id: Task identifier
        """
        from chatfilter.models.group import TaskStatus

        with self._connection() as conn:
            conn.execute(
                "UPDATE group_tasks SET status = ? WHERE id = ?",
                (TaskStatus.CANCELLED.value, task_id),
            )

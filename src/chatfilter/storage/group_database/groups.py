"""Group operations for GroupDatabase."""

import json
from datetime import UTC, datetime
from typing import Any


class GroupsMixin:
    """Mixin providing chat group CRUD operations."""

    def save_group(
        self,
        group_id: str,
        name: str,
        settings: dict[str, Any],
        status: str,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        """Save or update a chat group.

        Args:
            group_id: Unique group identifier
            name: Group name
            settings: Group settings as dict (will be serialized to JSON)
            status: Group status (pending/in_progress/paused/completed)
            created_at: Creation timestamp (default: now)
            updated_at: Last update timestamp (default: now)
        """
        now = datetime.now(UTC)
        created = created_at or now
        updated = updated_at or now

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    settings = excluded.settings,
                    status = excluded.status,
                    updated_at = excluded.updated_at
                """,
                (
                    group_id,
                    name,
                    json.dumps(settings),
                    status,
                    self._datetime_to_str(created),
                    self._datetime_to_str(updated),
                ),
            )

    def load_group(self, group_id: str) -> dict[str, Any] | None:
        """Load a chat group by ID.

        Args:
            group_id: Group identifier

        Returns:
            Group data as dict or None if not found
        """
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chat_groups WHERE id = ?",
                (group_id,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            return {
                "id": row["id"],
                "name": row["name"],
                "settings": json.loads(row["settings"]),
                "status": row["status"],
                "created_at": self._str_to_datetime(row["created_at"]),
                "updated_at": self._str_to_datetime(row["updated_at"]),
                "analysis_started_at": self._str_to_datetime(row["analysis_started_at"]) if row["analysis_started_at"] else None,
            }

    def load_all_groups(self) -> list[dict[str, Any]]:
        """Load all chat groups.

        Returns:
            List of group data dicts, sorted by creation time (newest first)
        """
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chat_groups ORDER BY created_at DESC"
            )
            rows = cursor.fetchall()

        return [
            {
                "id": row["id"],
                "name": row["name"],
                "settings": json.loads(row["settings"]),
                "status": row["status"],
                "created_at": self._str_to_datetime(row["created_at"]),
                "updated_at": self._str_to_datetime(row["updated_at"]),
                "analysis_started_at": self._str_to_datetime(row["analysis_started_at"]) if row["analysis_started_at"] else None,
            }
            for row in rows
        ]

    def set_analysis_started_at(
        self,
        group_id: str,
        started_at: datetime | None = None,
    ) -> None:
        """Set the analysis start timestamp for a group.

        Args:
            group_id: Group identifier
            started_at: Analysis start timestamp (default: now)
        """
        timestamp = started_at or datetime.now(UTC)

        with self._connection() as conn:
            conn.execute(
                """
                UPDATE chat_groups
                SET analysis_started_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (self._datetime_to_str(timestamp), self._datetime_to_str(datetime.now(UTC)), group_id),
            )

    def get_analysis_started_at(self, group_id: str) -> datetime | None:
        """Get the analysis start timestamp for a group.

        Args:
            group_id: Group identifier

        Returns:
            Analysis start timestamp or None if not set or group not found
        """
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT analysis_started_at FROM chat_groups WHERE id = ?",
                (group_id,),
            )
            row = cursor.fetchone()

            if not row or not row["analysis_started_at"]:
                return None

            return self._str_to_datetime(row["analysis_started_at"])

    def delete_group(self, group_id: str) -> None:
        """Delete a chat group and all associated data.

        Removes the group and all related chats and results via CASCADE.

        Args:
            group_id: Group identifier
        """
        with self._connection() as conn:
            conn.execute("DELETE FROM chat_groups WHERE id = ?", (group_id,))

    def update_status_atomic(
        self,
        group_id: str,
        new_status: str,
        expected_status: str,
    ) -> bool:
        """Atomically update group status only if current status matches expected.

        This provides compare-and-swap semantics for status updates.

        Args:
            group_id: Group identifier
            new_status: Status to set (pending/in_progress/paused/completed)
            expected_status: Expected current status (update only if matches)

        Returns:
            True if update succeeded, False if group not found or status mismatch

        Example:
            >>> db.update_status_atomic("group-123", "in_progress", "paused")
            True  # Updated if status was paused
            False  # No-op if status was not paused (another request won the race)
        """
        now = datetime.now(UTC)

        with self._connection() as conn:
            cursor = conn.execute(
                """
                UPDATE chat_groups
                SET status = ?, updated_at = ?
                WHERE id = ? AND status = ?
                """,
                (new_status, self._datetime_to_str(now), group_id, expected_status),
            )

            # Check if any rows were affected
            return cursor.rowcount > 0

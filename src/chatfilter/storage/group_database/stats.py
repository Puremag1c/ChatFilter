"""Statistics and aggregation operations for GroupDatabase."""

import json
from typing import Any


class StatsMixin:
    """Mixin providing group statistics and aggregation operations."""

    def compute_group_status(self, group_id: str) -> str:
        """Compute group status from chat statuses.

        Args:
            group_id: Group identifier

        Returns:
            GroupStatus value (pending/in_progress/completed/failed)
        """
        from chatfilter.models.group import GroupChatStatus, GroupStatus

        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT status, COUNT(*) as count
                FROM group_chats
                WHERE group_id = ?
                GROUP BY status
                """,
                (group_id,),
            )
            status_counts = {row["status"]: row["count"] for row in cursor.fetchall()}

            # Get total count
            total = sum(status_counts.values())
            if total == 0:
                return GroupStatus.PENDING.value

            # Count by status
            pending_count = status_counts.get(GroupChatStatus.PENDING.value, 0)
            done_count = status_counts.get(GroupChatStatus.DONE.value, 0)
            error_count = status_counts.get(GroupChatStatus.ERROR.value, 0)

            # All pending → PENDING
            if pending_count == total:
                return GroupStatus.PENDING.value

            # All error → FAILED
            if error_count == total:
                return GroupStatus.FAILED.value

            # All done or error → COMPLETED
            if (done_count + error_count) == total:
                return GroupStatus.COMPLETED.value

            # Mixed → IN_PROGRESS
            return GroupStatus.IN_PROGRESS.value

    def get_group_stats(self, group_id: str) -> dict[str, int]:
        """Get statistics for a group's chats.

        Args:
            group_id: Group identifier

        Returns:
            Dict with counts by chat_type and status
            {
                "total": 100,
                "by_type": {"group": 50, "channel": 30, ...},
                "by_status": {"pending": 10, "done": 80, ...}
            }
        """
        with self._connection() as conn:
            # Total count
            cursor = conn.execute(
                "SELECT COUNT(*) as count FROM group_chats WHERE group_id = ?",
                (group_id,),
            )
            total = cursor.fetchone()["count"]

            # Count by chat_type
            cursor = conn.execute(
                """
                SELECT chat_type, COUNT(*) as count
                FROM group_chats
                WHERE group_id = ?
                GROUP BY chat_type
                """,
                (group_id,),
            )
            by_type = {row["chat_type"]: row["count"] for row in cursor.fetchall()}

            # Count by status
            cursor = conn.execute(
                """
                SELECT status, COUNT(*) as count
                FROM group_chats
                WHERE group_id = ?
                GROUP BY status
                """,
                (group_id,),
            )
            by_status = {row["status"]: row["count"] for row in cursor.fetchall()}

            # Count chats with moderation (join approval required)
            cursor = conn.execute(
                """
                SELECT COUNT(*) as count
                FROM group_chats
                WHERE group_id = ?
                AND moderation = 1
                """,
                (group_id,),
            )
            skipped_moderation = cursor.fetchone()["count"]

        return {
            "total": total,
            "by_type": by_type,
            "by_status": by_status,
            "skipped_moderation": skipped_moderation,
        }

    def load_all_groups_with_stats(self) -> list[dict[str, Any]]:
        """Load all chat groups with their chat counts in a single query.

        Optimized version of load_all_groups that avoids N+1 queries by
        joining with group_chats to get counts in a single database roundtrip.

        Returns:
            List of group data dicts with 'chat_count' field, sorted by creation time (newest first)
        """
        with self._connection() as conn:
            cursor = conn.execute("""
                SELECT
                    g.id,
                    g.name,
                    g.settings,
                    g.status,
                    g.created_at,
                    g.updated_at,
                    g.analysis_started_at,
                    COUNT(gc.id) as chat_count
                FROM chat_groups g
                LEFT JOIN group_chats gc ON g.id = gc.group_id
                GROUP BY g.id
                ORDER BY g.created_at DESC
            """)
            rows = cursor.fetchall()

        return [
            {
                "id": row["id"],
                "name": row["name"],
                "settings": json.loads(row["settings"]),
                "status": row["status"],
                "created_at": self._str_to_datetime(row["created_at"]),
                "updated_at": self._str_to_datetime(row["updated_at"]),
                "chat_count": row["chat_count"],
                "analysis_started_at": self._str_to_datetime(row["analysis_started_at"]) if row["analysis_started_at"] else None,
            }
            for row in rows
        ]

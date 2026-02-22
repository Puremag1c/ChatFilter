"""Metrics operations for GroupDatabase."""

from typing import Any


class MetricsMixin:
    """Mixin providing chat metrics CRUD operations."""

    def save_chat_metrics(
        self,
        chat_id: int,
        metrics: dict[str, Any],
    ) -> None:
        """Save metrics for a chat in group_chats columns.

        Args:
            chat_id: Chat ID
            metrics: Metrics dict with keys: title, chat_type, moderation,
                    messages_per_hour, unique_authors_per_hour, captcha,
                    partial_data, metrics_version
        """
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE group_chats
                SET title = ?,
                    moderation = ?,
                    messages_per_hour = ?,
                    unique_authors_per_hour = ?,
                    captcha = ?,
                    partial_data = ?,
                    metrics_version = ?
                WHERE id = ?
                """,
                (
                    metrics.get("title"),
                    metrics.get("moderation"),
                    metrics.get("messages_per_hour"),
                    metrics.get("unique_authors_per_hour"),
                    metrics.get("captcha"),
                    metrics.get("partial_data"),
                    metrics.get("metrics_version"),
                    chat_id,
                ),
            )

    def get_chat_metrics(self, chat_id: int) -> dict[str, Any]:
        """Get metrics for a chat from group_chats columns.

        Args:
            chat_id: Chat ID

        Returns:
            Dict with metric values
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT title, chat_type, subscribers, moderation,
                       messages_per_hour, unique_authors_per_hour,
                       captcha, partial_data, metrics_version
                FROM group_chats
                WHERE id = ?
                """,
                (chat_id,),
            )
            row = cursor.fetchone()

            if not row:
                return {}

            return {
                "title": row["title"],
                "chat_type": row["chat_type"],
                "subscribers": row["subscribers"],
                "moderation": row["moderation"],
                "messages_per_hour": row["messages_per_hour"],
                "unique_authors_per_hour": row["unique_authors_per_hour"],
                "captcha": row["captcha"],
                "partial_data": row["partial_data"],
                "metrics_version": row["metrics_version"],
            }

    def get_chat_metrics_batch(self, chat_ids: list[int]) -> dict[int, dict[str, Any]]:
        """Get metrics for multiple chats in a single query.

        Optimized version of get_chat_metrics that fetches metrics for multiple
        chats at once, avoiding N+1 query problem.

        Args:
            chat_ids: List of chat IDs to fetch metrics for

        Returns:
            Dict mapping chat_id to metrics dict
        """
        if not chat_ids:
            return {}

        with self._connection() as conn:
            # Create placeholders for IN clause
            placeholders = ",".join("?" * len(chat_ids))
            cursor = conn.execute(
                f"""
                SELECT id, title, chat_type, subscribers, moderation,
                       messages_per_hour, unique_authors_per_hour,
                       captcha, partial_data, metrics_version
                FROM group_chats
                WHERE id IN ({placeholders})
                """,
                chat_ids,
            )
            rows = cursor.fetchall()

            return {
                row["id"]: {
                    "title": row["title"],
                    "chat_type": row["chat_type"],
                    "subscribers": row["subscribers"],
                    "moderation": row["moderation"],
                    "messages_per_hour": row["messages_per_hour"],
                    "unique_authors_per_hour": row["unique_authors_per_hour"],
                    "captcha": row["captcha"],
                    "partial_data": row["partial_data"],
                    "metrics_version": row["metrics_version"],
                }
                for row in rows
            }

    def update_chat_complete(
        self,
        chat_id: int,
        metrics: dict[str, Any],
    ) -> None:
        """Update chat with metrics and mark as done.

        Args:
            chat_id: Chat ID
            metrics: Metrics dict with all collected data
        """
        from chatfilter.models.group import GroupChatStatus

        with self._connection() as conn:
            conn.execute(
                """
                UPDATE group_chats
                SET title = ?,
                    moderation = ?,
                    messages_per_hour = ?,
                    unique_authors_per_hour = ?,
                    captcha = ?,
                    partial_data = ?,
                    metrics_version = ?,
                    status = ?
                WHERE id = ?
                """,
                (
                    metrics.get("title"),
                    metrics.get("moderation"),
                    metrics.get("messages_per_hour"),
                    metrics.get("unique_authors_per_hour"),
                    metrics.get("captcha"),
                    metrics.get("partial_data"),
                    metrics.get("metrics_version"),
                    GroupChatStatus.DONE.value,
                    chat_id,
                ),
            )

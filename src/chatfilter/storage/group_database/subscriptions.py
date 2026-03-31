"""Subscription CRUD operations for GroupDatabase."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ._base import DatabaseMixinBase


class SubscriptionsMixin(DatabaseMixinBase):
    """Mixin providing CRUD operations for account_subscriptions table."""

    def add_subscription(
        self, account_id: str, catalog_chat_id: str, telegram_chat_id: int
    ) -> None:
        """Insert subscription with joined_at=now. Ignores duplicates."""
        now = datetime.now(UTC).isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO account_subscriptions
                (account_id, catalog_chat_id, telegram_chat_id, joined_at)
                VALUES (?, ?, ?, ?)
                """,
                (account_id, catalog_chat_id, telegram_chat_id, now),
            )

    def remove_subscription(self, account_id: str, catalog_chat_id: str) -> None:
        """Delete a subscription."""
        with self._connection() as conn:
            conn.execute(
                "DELETE FROM account_subscriptions WHERE account_id = ? AND catalog_chat_id = ?",
                (account_id, catalog_chat_id),
            )

    def get_subscriptions(self, account_id: str) -> list[Any]:
        """List subscriptions for an account ordered by joined_at ASC."""
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT account_id, catalog_chat_id, telegram_chat_id, joined_at
                FROM account_subscriptions
                WHERE account_id = ?
                ORDER BY joined_at ASC
                """,
                (account_id,),
            )
            rows = cursor.fetchall()
        return [self._row_to_subscription(row) for row in rows]

    def count_subscriptions(self, account_id: str) -> int:
        """Count subscriptions for an account."""
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT COUNT(*) FROM account_subscriptions WHERE account_id = ?",
                (account_id,),
            )
            row = cursor.fetchone()
        return row[0] if row else 0

    def get_oldest_subscription(self, account_id: str) -> Any | None:
        """Get the oldest subscription (FIFO eviction candidate)."""
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT account_id, catalog_chat_id, telegram_chat_id, joined_at
                FROM account_subscriptions
                WHERE account_id = ?
                ORDER BY joined_at ASC
                LIMIT 1
                """,
                (account_id,),
            )
            row = cursor.fetchone()
        return self._row_to_subscription(row) if row else None

    def get_subscribed_chats(self) -> list[tuple[str, str, int]]:
        """Return all (account_id, catalog_chat_id, telegram_chat_id) tuples."""
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT account_id, catalog_chat_id, telegram_chat_id FROM account_subscriptions"
            )
            rows = cursor.fetchall()
        return [
            (row["account_id"], row["catalog_chat_id"], row["telegram_chat_id"]) for row in rows
        ]

    def _row_to_subscription(self, row: Any) -> Any:
        """Convert a database row to an AccountSubscription instance."""
        from chatfilter.models.catalog import AccountSubscription

        return AccountSubscription(
            account_id=row["account_id"],
            catalog_chat_id=row["catalog_chat_id"],
            telegram_chat_id=row["telegram_chat_id"],
            joined_at=self._str_to_datetime(row["joined_at"]),
        )

"""Catalog CRUD operations for GroupDatabase."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from ._base import DatabaseMixinBase

logger = logging.getLogger(__name__)


class CatalogMixin(DatabaseMixinBase):
    """Mixin providing CRUD operations for chat_catalog table."""

    def save_catalog_chat(self, chat: Any) -> None:
        """Upsert a catalog chat by id (chat_ref).

        Args:
            chat: CatalogChat model instance
        """
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO chat_catalog
                (id, telegram_id, title, username, chat_type, subscribers, moderation,
                 messages_per_hour, unique_authors_per_hour, captcha, partial_data,
                 last_check, analysis_mode, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    telegram_id = excluded.telegram_id,
                    title = excluded.title,
                    username = excluded.username,
                    chat_type = excluded.chat_type,
                    subscribers = excluded.subscribers,
                    moderation = excluded.moderation,
                    messages_per_hour = COALESCE(excluded.messages_per_hour, messages_per_hour),
                    unique_authors_per_hour = COALESCE(excluded.unique_authors_per_hour, unique_authors_per_hour),
                    captcha = excluded.captcha,
                    partial_data = excluded.partial_data,
                    last_check = excluded.last_check,
                    analysis_mode = excluded.analysis_mode
                """,
                (
                    chat.id,
                    chat.telegram_id,
                    chat.title,
                    chat.username,
                    str(chat.chat_type),
                    chat.subscribers,
                    chat.moderation,
                    chat.messages_per_hour,
                    chat.unique_authors_per_hour,
                    chat.captcha,
                    chat.partial_data,
                    self._datetime_to_str(chat.last_check),
                    str(chat.analysis_mode) if chat.analysis_mode else None,
                    self._datetime_to_str(chat.created_at or datetime.now(UTC)),
                ),
            )

    def get_catalog_chat(self, chat_ref: str) -> Any | None:
        """Get a catalog chat by chat_ref.

        Args:
            chat_ref: Chat reference identifier

        Returns:
            CatalogChat instance or None
        """

        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chat_catalog WHERE id = ?",
                (chat_ref,),
            )
            row = cursor.fetchone()

        if not row:
            return None

        return self._row_to_catalog_chat(row)

    def list_catalog_chats(
        self,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> tuple[list[Any], int]:
        """List catalog chats with optional filters and pagination.

        Args:
            filters: Optional dict with keys:
                - chat_type: str
                - min_subscribers: int
                - max_subscribers: int
                - has_moderation: bool
                - has_captcha: bool
                - min_activity: float (messages_per_hour)
                - max_activity: float
                - min_authors: float (unique_authors_per_hour)
                - max_authors: float
                - fresh_only: int (last_check within N days)
                - search: str (title or id LIKE search)
                - sort_by: str (title|subscribers|activity|authors|last_check)
                - sort_dir: str (asc|desc)
            page: 1-based page number
            page_size: number of rows per page

        Returns:
            Tuple of (list of CatalogChat instances, total_count)
        """

        filters = filters or {}
        base_join = (
            "FROM chat_catalog cc "
            "LEFT JOIN account_subscriptions acs ON acs.catalog_chat_id = cc.id "
            "WHERE 1=1"
        )
        params: list[Any] = []

        if "chat_type" in filters and filters["chat_type"] is not None:
            base_join += " AND cc.chat_type = ?"
            params.append(filters["chat_type"])

        if "min_subscribers" in filters and filters["min_subscribers"] is not None:
            base_join += " AND cc.subscribers >= ?"
            params.append(filters["min_subscribers"])

        if "max_subscribers" in filters and filters["max_subscribers"] is not None:
            base_join += " AND cc.subscribers <= ?"
            params.append(filters["max_subscribers"])

        if "has_moderation" in filters and filters["has_moderation"] is not None:
            base_join += " AND cc.moderation = ?"
            params.append(1 if filters["has_moderation"] else 0)

        if "has_captcha" in filters and filters["has_captcha"] is not None:
            if filters["has_captcha"]:
                base_join += " AND cc.captcha = 1"
            else:
                base_join += " AND (cc.captcha = 0 OR cc.captcha IS NULL)"

        if "min_activity" in filters and filters["min_activity"] is not None:
            base_join += " AND cc.messages_per_hour >= ?"
            params.append(filters["min_activity"])

        if "max_activity" in filters and filters["max_activity"] is not None:
            base_join += " AND cc.messages_per_hour <= ?"
            params.append(filters["max_activity"])

        if "min_authors" in filters and filters["min_authors"] is not None:
            base_join += " AND cc.unique_authors_per_hour >= ?"
            params.append(filters["min_authors"])

        if "max_authors" in filters and filters["max_authors"] is not None:
            base_join += " AND cc.unique_authors_per_hour <= ?"
            params.append(filters["max_authors"])

        if "fresh_only" in filters and filters["fresh_only"] is not None:
            cutoff = datetime.now(UTC) - timedelta(days=int(filters["fresh_only"]))
            base_join += " AND cc.last_check >= ?"
            params.append(cutoff.isoformat())

        if "search" in filters and filters["search"] is not None:
            pattern = f"%{filters['search']}%"
            base_join += " AND (cc.title LIKE ? OR cc.id LIKE ?)"
            params.extend([pattern, pattern])

        count_query = f"SELECT COUNT(*) FROM (SELECT cc.id {base_join} GROUP BY cc.id)"

        data_query = (
            "SELECT cc.*, "
            "CASE WHEN COUNT(acs.id) > 0 THEN 1 ELSE 0 END AS has_subscriber "
            + base_join
            + " GROUP BY cc.id"
        )

        _sort_field_map = {
            "title": "cc.title",
            "subscribers": "cc.subscribers",
            "activity": "cc.messages_per_hour",
            "authors": "cc.unique_authors_per_hour",
            "last_check": "cc.last_check",
        }
        sort_by = filters.get("sort_by")
        sort_dir = filters.get("sort_dir")
        if sort_by and sort_by in _sort_field_map:
            direction = "DESC" if sort_dir == "desc" else "ASC"
            col = _sort_field_map[sort_by]
            data_query += f" ORDER BY {col} {direction} NULLS LAST"

        offset = (max(1, page) - 1) * page_size
        data_query += " LIMIT ? OFFSET ?"

        with self._connection() as conn:
            total_count = conn.execute(count_query, params).fetchone()[0]
            rows = conn.execute(data_query, [*params, page_size, offset]).fetchall()

        return [self._row_to_catalog_chat(row) for row in rows], total_count

    def link_to_group(self, catalog_chat_id: str, group_chat_id: int) -> None:
        """Link a catalog chat to a group_chat via catalog_group_chats.

        Args:
            catalog_chat_id: Catalog chat id (chat_ref)
            group_chat_id: group_chats.id (integer FK)
        """
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO catalog_group_chats
                (catalog_chat_id, group_chat_id)
                VALUES (?, ?)
                """,
                (catalog_chat_id, group_chat_id),
            )

    def get_groups_for_chat(self, catalog_chat_id: str) -> list[str]:
        """Get group names linked to a catalog chat.

        Args:
            catalog_chat_id: Catalog chat id (chat_ref)

        Returns:
            List of group names
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT cg.name
                FROM catalog_group_chats cgc
                JOIN group_chats gc ON gc.id = cgc.group_chat_id
                JOIN chat_groups cg ON cg.id = gc.group_id
                WHERE cgc.catalog_chat_id = ?
                """,
                (catalog_chat_id,),
            )
            rows = cursor.fetchall()

        return [row["name"] for row in rows]

    def update_catalog_metrics(
        self,
        chat_ref: str,
        metrics_dict: dict[str, Any],
        use_ema: bool = True,
        alpha: float = 0.3,
    ) -> None:
        """Update metrics for a catalog chat using EMA averaging.

        When use_ema=True, applies exponential moving average:
            new_value = alpha * new + (1 - alpha) * old

        Uses a single atomic SQL UPDATE to avoid race conditions.

        Args:
            chat_ref: Chat reference identifier
            metrics_dict: Dict with optional keys:
                - messages_per_hour: float
                - unique_authors_per_hour: float
            use_ema: Whether to apply EMA smoothing
            alpha: EMA smoothing factor (0 < alpha <= 1)
        """
        now_str = datetime.now(UTC).isoformat()
        mph = metrics_dict.get("messages_per_hour")
        uaph = metrics_dict.get("unique_authors_per_hour")

        with self._connection() as conn:
            if use_ema:
                # Atomic EMA update — avoids read-then-write race condition
                params: list[Any] = []
                updates: list[str] = []

                if mph is not None:
                    updates.append(
                        "messages_per_hour = CASE WHEN messages_per_hour IS NULL "
                        f"THEN ? ELSE {alpha} * ? + {1 - alpha} * messages_per_hour END"
                    )
                    params.extend([mph, mph])

                if uaph is not None:
                    updates.append(
                        "unique_authors_per_hour = CASE WHEN unique_authors_per_hour IS NULL "
                        f"THEN ? ELSE {alpha} * ? + {1 - alpha} * unique_authors_per_hour END"
                    )
                    params.extend([uaph, uaph])

                updates.append("last_check = ?")
                params.append(now_str)
                params.append(chat_ref)

                if updates:
                    conn.execute(
                        f"UPDATE chat_catalog SET {', '.join(updates)} WHERE id = ?",
                        params,
                    )
            else:
                # Direct overwrite
                updates_direct: list[str] = []
                params_direct: list[Any] = []

                if mph is not None:
                    updates_direct.append("messages_per_hour = ?")
                    params_direct.append(mph)

                if uaph is not None:
                    updates_direct.append("unique_authors_per_hour = ?")
                    params_direct.append(uaph)

                updates_direct.append("last_check = ?")
                params_direct.append(now_str)
                params_direct.append(chat_ref)

                if updates_direct:
                    conn.execute(
                        f"UPDATE chat_catalog SET {', '.join(updates_direct)} WHERE id = ?",
                        params_direct,
                    )

    def get_fresh_chat(self, chat_ref: str, freshness_days: int) -> Any | None:
        """Get a catalog chat only if last_check is within freshness period.

        Args:
            chat_ref: Chat reference identifier
            freshness_days: Number of days within which data is considered fresh

        Returns:
            CatalogChat if fresh, None otherwise
        """
        cutoff = datetime.now(UTC) - timedelta(days=freshness_days)
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM chat_catalog WHERE id = ? AND last_check >= ?",
                (chat_ref, cutoff.isoformat()),
            )
            row = cursor.fetchone()

        if not row:
            return None

        return self._row_to_catalog_chat(row)

    def _row_to_catalog_chat(self, row: Any) -> Any:
        """Convert a database row to a CatalogChat instance."""
        from chatfilter.models.catalog import AnalysisModeEnum, CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        keys = row.keys() if hasattr(row, "keys") else []
        raw_chat_type = row["chat_type"]
        if raw_chat_type in ChatTypeEnum._value2member_map_:
            chat_type = ChatTypeEnum(raw_chat_type)
        else:
            logger.warning(
                "Unknown chat_type %r for row id=%s, defaulting to PENDING",
                raw_chat_type,
                row["id"],
            )
            chat_type = ChatTypeEnum.PENDING
        return CatalogChat(
            id=row["id"],
            telegram_id=row["telegram_id"] or 0,
            title=row["title"] or "",
            chat_type=chat_type,
            subscribers=row["subscribers"] or 0,
            moderation=bool(row["moderation"]),
            messages_per_hour=row["messages_per_hour"] or 0.0,
            unique_authors_per_hour=row["unique_authors_per_hour"] or 0.0,
            captcha=bool(row["captcha"]),
            partial_data=bool(row["partial_data"]),
            last_check=self._str_to_datetime(row["last_check"]),
            analysis_mode=AnalysisModeEnum(row["analysis_mode"])
            if row["analysis_mode"]
            else AnalysisModeEnum.QUICK,
            created_at=self._str_to_datetime(row["created_at"]),
            has_subscriber=bool(row["has_subscriber"]) if "has_subscriber" in keys else True,
            username=row["username"] if "username" in keys else None,
        )

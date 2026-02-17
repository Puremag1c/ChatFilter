"""Database module for chat group storage and analysis tracking."""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chatfilter.storage.database import SQLiteDatabase

# Sentinel value to distinguish "not provided" from None
_UNSET = object()


class GroupDatabase(SQLiteDatabase):
    """SQLite database for persisting chat group data and analysis results.

    Tables:
        - chat_groups: Group metadata and settings
        - group_chats: Individual chats within groups
        - group_results: Analysis results for group chats
    """

    def _initialize_schema(self) -> None:
        """Create database tables if they don't exist."""
        with self._connection() as conn:
            # Chat groups table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_groups (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    settings TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL
                )
            """)

            # Group chats table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS group_chats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id TEXT NOT NULL,
                    chat_ref TEXT NOT NULL,
                    chat_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_account TEXT,
                    error TEXT,
                    subscribers INTEGER,
                    FOREIGN KEY (group_id) REFERENCES chat_groups (id)
                        ON DELETE CASCADE
                )
            """)

            # Group results table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS group_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id TEXT NOT NULL,
                    chat_ref TEXT NOT NULL,
                    metrics_data TEXT NOT NULL,
                    analyzed_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (group_id) REFERENCES chat_groups (id)
                        ON DELETE CASCADE
                )
            """)

            # Create indexes for faster lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_group_chats_group_id
                ON group_chats (group_id)
            """)

            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_group_results_group_id
                ON group_results (group_id)
            """)

            # Run migrations
            self._run_migrations(conn)

    def _run_migrations(self, conn: Any) -> None:
        """Run database migrations to bring schema up to date.

        Args:
            conn: Active database connection
        """
        # Get current schema version
        cursor = conn.execute("PRAGMA user_version")
        current_version = cursor.fetchone()[0]

        # Migration 1: Add unique constraint on (group_id, chat_ref) for group_results
        if current_version < 1:
            self._migrate_to_v1_unique_constraint(conn)
            conn.execute("PRAGMA user_version = 1")

    def _migrate_to_v1_unique_constraint(self, conn: Any) -> None:
        """Migration v1: Add UNIQUE constraint on (group_id, chat_ref) for group_results.

        This migration:
        1. Identifies duplicate rows for same (group_id, chat_ref)
        2. Keeps the newest row (by analyzed_at), deletes older ones
        3. Creates unique index on (group_id, chat_ref)

        Args:
            conn: Active database connection
        """
        # Check if index already exists (for idempotency)
        cursor = conn.execute("""
            SELECT name FROM sqlite_master
            WHERE type='index' AND name='idx_group_results_unique_group_chat'
        """)
        if cursor.fetchone():
            return  # Already migrated

        # Delete duplicate rows, keeping the newest (by analyzed_at)
        conn.execute("""
            DELETE FROM group_results
            WHERE id NOT IN (
                SELECT MAX(id)
                FROM group_results
                GROUP BY group_id, chat_ref
            )
        """)

        # Create unique index
        conn.execute("""
            CREATE UNIQUE INDEX idx_group_results_unique_group_chat
            ON group_results (group_id, chat_ref)
        """)

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
            }
            for row in rows
        ]

    def save_chat(
        self,
        group_id: str,
        chat_ref: str,
        chat_type: str,
        status: str = "pending",
        assigned_account: str | None = None,
        error: str | None = None,
        chat_id: int | None = None,
        subscribers: int | None = None,
    ) -> int:
        """Save a chat within a group.

        Args:
            group_id: Group identifier
            chat_ref: Chat reference (username, link, or ID)
            chat_type: Chat type (pending/group/forum/channel_comments/channel_no_comments/dead)
            status: Chat status (pending/joining/analyzing/done/failed)
            assigned_account: Account assigned to analyze this chat
            error: Error message if status is failed
            chat_id: Optional explicit chat ID (for updates)
            subscribers: Optional subscriber count for channels

        Returns:
            Chat ID (auto-generated or provided)
        """
        with self._connection() as conn:
            if chat_id is None:
                # Insert new chat
                cursor = conn.execute(
                    """
                    INSERT INTO group_chats
                    (group_id, chat_ref, chat_type, status, assigned_account, error, subscribers)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (group_id, chat_ref, chat_type, status, assigned_account, error, subscribers),
                )
                return cursor.lastrowid
            else:
                # Update existing chat
                conn.execute(
                    """
                    INSERT INTO group_chats
                    (id, group_id, chat_ref, chat_type, status, assigned_account, error, subscribers)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        group_id = excluded.group_id,
                        chat_ref = excluded.chat_ref,
                        chat_type = excluded.chat_type,
                        status = excluded.status,
                        assigned_account = excluded.assigned_account,
                        error = excluded.error,
                        subscribers = excluded.subscribers
                    """,
                    (chat_id, group_id, chat_ref, chat_type, status, assigned_account, error, subscribers),
                )
                return chat_id

    def update_chat_status(
        self,
        chat_id: int,
        status: str,
        assigned_account: str | None = _UNSET,
        error: str | None = _UNSET,
    ) -> None:
        """Update the status of a group chat.

        Args:
            chat_id: Chat ID
            status: New status (pending/joining/analyzing/done/failed)
            assigned_account: Optional account assignment (pass None to clear)
            error: Optional error message (pass None to clear)
        """
        with self._connection() as conn:
            # Build UPDATE statement dynamically based on provided fields
            updates = ["status = ?"]
            params: list[Any] = [status]

            if assigned_account is not _UNSET:
                updates.append("assigned_account = ?")
                params.append(assigned_account)

            if error is not _UNSET:
                updates.append("error = ?")
                params.append(error)

            params.append(chat_id)

            conn.execute(
                f"UPDATE group_chats SET {', '.join(updates)} WHERE id = ?",
                params,
            )

    def save_result(
        self,
        group_id: str,
        chat_ref: str,
        metrics_data: dict[str, Any],
        analyzed_at: datetime | None = None,
    ) -> None:
        """Save analysis result for a group chat.

        Args:
            group_id: Group identifier
            chat_ref: Chat reference
            metrics_data: Analysis metrics as dict (will be serialized to JSON)
                Expected structure:
                {
                    "chat_type": str,  # group/forum/channel_comments/channel_no_comments/dead
                    "subscribers": int | None,  # participant count
                    "messages_per_hour": float | None,  # activity metric
                    "unique_authors_per_hour": float | None,  # unique authors metric
                    "moderation": bool | None,  # has join request
                    "captcha": bool | None,  # has captcha bot
                    "status": str,  # done/failed/n/a
                    "title": str | None,  # chat title
                    "chat_ref": str,  # chat reference
                }
            analyzed_at: Analysis timestamp (default: now)
        """
        analyzed = analyzed_at or datetime.now(UTC)

        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO group_results
                (group_id, chat_ref, metrics_data, analyzed_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    group_id,
                    chat_ref,
                    json.dumps(metrics_data),
                    self._datetime_to_str(analyzed),
                ),
            )

    def upsert_result(
        self,
        group_id: str,
        chat_ref: str,
        metrics_data: dict[str, Any],
        analyzed_at: datetime | None = None,
    ) -> None:
        """Upsert analysis result for a group chat (merge with existing data).

        If a result already exists for (group_id, chat_ref), merges new metrics
        with existing ones: new non-null values overwrite old, null values preserve old.

        Args:
            group_id: Group identifier
            chat_ref: Chat reference
            metrics_data: Analysis metrics as dict (will be serialized to JSON)
                Expected structure:
                {
                    "chat_type": str,  # group/forum/channel_comments/channel_no_comments/dead
                    "subscribers": int | None,  # participant count
                    "messages_per_hour": float | None,  # activity metric
                    "unique_authors_per_hour": float | None,  # unique authors metric
                    "moderation": bool | None,  # has join request
                    "captcha": bool | None,  # has captcha bot
                    "status": str,  # done/failed/n/a
                    "title": str | None,  # chat title
                    "chat_ref": str,  # chat reference
                }
            analyzed_at: Analysis timestamp (default: now)
        """
        analyzed = analyzed_at or datetime.now(UTC)

        # Load existing result to merge metrics
        existing = self.load_result(group_id, chat_ref)
        if existing:
            # Merge: new non-null values overwrite, null values preserve old
            existing_metrics = existing.get("metrics_data", {})
            merged_metrics = existing_metrics.copy()

            for key, new_value in metrics_data.items():
                if new_value is not None:
                    merged_metrics[key] = new_value
                # If new_value is None, keep existing value (or None if not in existing)

            final_metrics = merged_metrics
        else:
            # No existing result, use new metrics as-is
            final_metrics = metrics_data

        # INSERT OR REPLACE with merged data
        # Due to unique constraint on (group_id, chat_ref), this will:
        # - INSERT if no existing row
        # - REPLACE (delete + insert) if row exists
        with self._connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO group_results
                (group_id, chat_ref, metrics_data, analyzed_at)
                VALUES (?, ?, ?, ?)
                """,
                (
                    group_id,
                    chat_ref,
                    json.dumps(final_metrics),
                    self._datetime_to_str(analyzed),
                ),
            )

    def load_result(
        self,
        group_id: str,
        chat_ref: str,
    ) -> dict[str, Any] | None:
        """Load analysis result for a specific chat in a group.

        Args:
            group_id: Group identifier
            chat_ref: Chat reference

        Returns:
            Result data dict or None if not found
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT * FROM group_results
                WHERE group_id = ? AND chat_ref = ?
                ORDER BY analyzed_at DESC
                LIMIT 1
                """,
                (group_id, chat_ref),
            )
            row = cursor.fetchone()

            if not row:
                return None

            return {
                "id": row["id"],
                "group_id": row["group_id"],
                "chat_ref": row["chat_ref"],
                "metrics_data": json.loads(row["metrics_data"]),
                "analyzed_at": self._str_to_datetime(row["analyzed_at"]),
            }

    def load_results(
        self,
        group_id: str,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        """Load analysis results for a group.

        Args:
            group_id: Group identifier
            limit: Maximum number of results to return

        Returns:
            List of result data dicts, sorted by analysis time (newest first)
        """
        with self._connection() as conn:
            query = """
                SELECT * FROM group_results
                WHERE group_id = ?
                ORDER BY analyzed_at DESC
            """

            if limit is not None:
                query += f" LIMIT {limit}"

            cursor = conn.execute(query, (group_id,))
            rows = cursor.fetchall()

        return [
            {
                "id": row["id"],
                "group_id": row["group_id"],
                "chat_ref": row["chat_ref"],
                "metrics_data": json.loads(row["metrics_data"]),
                "analyzed_at": self._str_to_datetime(row["analyzed_at"]),
            }
            for row in rows
        ]

    def clear_results(self, group_id: str) -> None:
        """Clear all analysis results for a group.

        This allows re-running analysis on the same group.

        Args:
            group_id: Group identifier
        """
        with self._connection() as conn:
            conn.execute(
                "DELETE FROM group_results WHERE group_id = ?",
                (group_id,),
            )

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
                FROM group_results
                WHERE group_id = ?
                AND json_extract(metrics_data, '$.moderation') = 1
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
            }
            for row in rows
        ]

    def load_chats(
        self,
        group_id: str,
        status: str | None = None,
        chat_type: str | None = None,
        assigned_account: str | None = None,
    ) -> list[dict[str, Any]]:
        """Load chats for a group with optional filtering.

        Args:
            group_id: Group identifier
            status: Optional status filter (pending/joining/analyzing/done/failed)
            chat_type: Optional chat_type filter
            assigned_account: Optional assigned account filter

        Returns:
            List of chat data dicts matching the filters
        """
        with self._connection() as conn:
            # Build query with dynamic filters
            query = "SELECT * FROM group_chats WHERE group_id = ?"
            params: list[Any] = [group_id]

            if status is not None:
                query += " AND status = ?"
                params.append(status)

            if chat_type is not None:
                query += " AND chat_type = ?"
                params.append(chat_type)

            if assigned_account is not None:
                query += " AND assigned_account = ?"
                params.append(assigned_account)

            cursor = conn.execute(query, params)
            rows = cursor.fetchall()

        return [
            {
                "id": row["id"],
                "group_id": row["group_id"],
                "chat_ref": row["chat_ref"],
                "chat_type": row["chat_type"],
                "status": row["status"],
                "assigned_account": row["assigned_account"],
                "error": row["error"],
                "subscribers": row["subscribers"],
            }
            for row in rows
        ]

    def delete_group(self, group_id: str) -> None:
        """Delete a chat group and all associated data.

        Removes the group and all related chats and results via CASCADE.

        Args:
            group_id: Group identifier
        """
        with self._connection() as conn:
            conn.execute("DELETE FROM chat_groups WHERE id = ?", (group_id,))

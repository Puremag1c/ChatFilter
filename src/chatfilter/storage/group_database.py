"""Database module for chat group storage and analysis tracking."""

import json
import logging
import shutil
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chatfilter.storage.database import SQLiteDatabase

logger = logging.getLogger(__name__)

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
        # BACKUP before v5 migration (if needed)
        # We check schema version first to decide if backup is needed
        if self.db_path.exists():
            temp_conn = sqlite3.connect(self.db_path)
            temp_conn.row_factory = sqlite3.Row
            cursor = temp_conn.execute("PRAGMA user_version")
            current_version = cursor.fetchone()[0]
            temp_conn.close()

            # Create backup before v5 migration (only once)
            if current_version < 5:
                backup_path = self.db_path.parent / f"{self.db_path.name}.backup_before_v5"
                if not backup_path.exists():
                    try:
                        shutil.copy2(self.db_path, backup_path)
                        logger.info(f"Database backup created: {backup_path}")
                    except Exception as e:
                        logger.warning(f"Failed to create backup: {e}")

        with self._connection() as conn:
            # Chat groups table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS chat_groups (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    settings TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    analysis_started_at TIMESTAMP
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
                    tried_accounts TEXT,
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
                        ON DELETE CASCADE,
                    UNIQUE(group_id, chat_ref)
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

        # Migration 2: Add subscribers column to group_chats
        if current_version < 2:
            self._migrate_to_v2_add_subscribers(conn)
            conn.execute("PRAGMA user_version = 2")

        # Migration 3: Add analysis_started_at column to chat_groups
        if current_version < 3:
            self._migrate_to_v3_add_analysis_started_at(conn)
            conn.execute("PRAGMA user_version = 3")

        # Migration 4: Add tried_accounts column to group_chats
        if current_version < 4:
            self._migrate_to_v4_add_tried_accounts(conn)
            conn.execute("PRAGMA user_version = 4")

        # Migration 5: Refactor schema — merge group_results into group_chats, create group_tasks
        # NOTE: Backup is created OUTSIDE of this transaction (before _initialize_schema)
        # See _initialize_schema for backup logic
        if current_version < 5:
            self._migrate_to_v5_refactor(conn)
            conn.execute("PRAGMA user_version = 5")

        # Always ensure no duplicates and unique index exists.
        # Previous migration v1 had a SQL bug that failed to dedup rows with
        # identical analyzed_at timestamps — this catches any surviving duplicates.
        # NOTE: Only run if group_results table still exists (before v5 migration)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='group_results'"
        )
        if cursor.fetchone():
            self._ensure_group_results_unique(conn)

    def _migrate_to_v1_unique_constraint(self, conn: Any) -> None:
        """Migration v1: Add UNIQUE constraint on (group_id, chat_ref) for group_results.

        This migration:
        1. Identifies duplicate rows for same (group_id, chat_ref)
        2. Keeps one row per (group_id, chat_ref) with the highest rowid
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

        # Delete duplicate rows — keep exactly one per (group_id, chat_ref).
        # Uses MAX(rowid) to deterministically pick one survivor per group.
        conn.execute("""
            DELETE FROM group_results
            WHERE rowid NOT IN (
                SELECT MAX(rowid)
                FROM group_results
                GROUP BY group_id, chat_ref
            )
        """)

        # Create unique index
        conn.execute("""
            CREATE UNIQUE INDEX idx_group_results_unique_group_chat
            ON group_results (group_id, chat_ref)
        """)

    def _ensure_group_results_unique(self, conn: Any) -> None:
        """Unconditionally remove duplicates and ensure unique index exists.

        Runs on every startup to catch duplicates that survived a buggy v1
        migration (which failed when rows had identical analyzed_at timestamps).

        Args:
            conn: Active database connection
        """
        # Check if duplicates exist
        cursor = conn.execute("""
            SELECT COUNT(*) as dup_count FROM (
                SELECT group_id, chat_ref
                FROM group_results
                GROUP BY group_id, chat_ref
                HAVING COUNT(*) > 1
            )
        """)
        dup_count = cursor.fetchone()["dup_count"]

        if dup_count > 0:
            # Remove duplicates — keep the row with highest rowid per (group_id, chat_ref)
            conn.execute("""
                DELETE FROM group_results
                WHERE rowid NOT IN (
                    SELECT MAX(rowid)
                    FROM group_results
                    GROUP BY group_id, chat_ref
                )
            """)

        # Ensure unique index exists
        cursor = conn.execute("""
            SELECT name FROM sqlite_master
            WHERE type='index' AND name='idx_group_results_unique_group_chat'
        """)
        if not cursor.fetchone():
            conn.execute("""
                CREATE UNIQUE INDEX idx_group_results_unique_group_chat
                ON group_results (group_id, chat_ref)
            """)

    def _migrate_to_v2_add_subscribers(self, conn: Any) -> None:
        """Migration v2: Add subscribers column to group_chats.

        This migration:
        1. Checks if subscribers column exists
        2. Adds the column if missing (sets NULL for existing rows)

        Args:
            conn: Active database connection
        """
        # Check if column already exists (for idempotency)
        cursor = conn.execute("PRAGMA table_info(group_chats)")
        columns = [row[1] for row in cursor.fetchall()]

        if "subscribers" not in columns:
            # Add subscribers column with default NULL
            conn.execute("ALTER TABLE group_chats ADD COLUMN subscribers INTEGER")

    def _migrate_to_v3_add_analysis_started_at(self, conn: Any) -> None:
        """Migration v3: Add analysis_started_at column to chat_groups.

        This migration:
        1. Checks if analysis_started_at column exists
        2. Adds the column if missing (sets NULL for existing rows)

        Args:
            conn: Active database connection
        """
        # Check if column already exists (for idempotency)
        cursor = conn.execute("PRAGMA table_info(chat_groups)")
        columns = [row[1] for row in cursor.fetchall()]

        if "analysis_started_at" not in columns:
            # Add analysis_started_at column with default NULL
            conn.execute("ALTER TABLE chat_groups ADD COLUMN analysis_started_at TIMESTAMP")

    def _migrate_to_v4_add_tried_accounts(self, conn: Any) -> None:
        """Migration v4: Add tried_accounts column to group_chats.

        Stores JSON list of account_ids that failed (ban/forbidden) for this chat,
        enabling reassignment to other accounts.
        """
        cursor = conn.execute("PRAGMA table_info(group_chats)")
        columns = [row[1] for row in cursor.fetchall()]

        if "tried_accounts" not in columns:
            conn.execute("ALTER TABLE group_chats ADD COLUMN tried_accounts TEXT")

    def _migrate_to_v5_refactor(self, conn: Any) -> None:
        """Migration v5: Refactor schema — merge group_results into group_chats, create group_tasks.

        This migration:
        1. Backup created in _initialize_schema (before opening connection)
        2. Adds new columns to group_chats (title, moderation, messages_per_hour, etc.)
        3. Migrates data from group_results.metrics_data JSON into group_chats columns
        4. Maps old statuses: joining/analyzing->pending, failed->error
        5. Creates new group_tasks table
        6. Drops group_results table
        7. All operations are atomic within a transaction

        Args:
            conn: Active database connection (already in transaction from _run_migrations)
        """
        # 1. Get existing columns in group_chats
        cursor = conn.execute("PRAGMA table_info(group_chats)")
        existing_columns = {row[1] for row in cursor.fetchall()}

        # 2. ADD COLUMNS to group_chats (only if not exists)
        new_columns = {
            "title": "TEXT",
            "chat_type": "TEXT",  # verify if exists from v0
            "subscribers": "INTEGER",  # verify if exists from v2
            "moderation": "BOOLEAN",
            "messages_per_hour": "REAL",
            "unique_authors_per_hour": "REAL",
            "captcha": "BOOLEAN",
            "partial_data": "BOOLEAN",
            "metrics_version": "INTEGER",
        }

        for col_name, col_type in new_columns.items():
            if col_name not in existing_columns:
                conn.execute(f"ALTER TABLE group_chats ADD COLUMN {col_name} {col_type}")
                logger.info(f"Added column: {col_name} {col_type}")

        # 3. MIGRATE DATA from group_results.metrics_data JSON into group_chats columns
        # Check if group_results table exists first
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='group_results'"
        )
        if cursor.fetchone():
            # Count rows before migration
            cursor = conn.execute("SELECT COUNT(*) as count FROM group_results")
            results_count = cursor.fetchone()[0]
            logger.info(f"Migrating {results_count} rows from group_results")

            # Fetch all group_results data
            cursor = conn.execute(
                "SELECT group_id, chat_ref, metrics_data FROM group_results"
            )
            results = cursor.fetchall()

            for row in results:
                group_id, chat_ref, metrics_json = row[0], row[1], row[2]
                metrics = json.loads(metrics_json)

                # Extract fields from metrics_data, handle 'N/A' as NULL
                def parse_value(val: Any) -> Any:
                    """Convert 'N/A' string to None, otherwise return value."""
                    return None if val == "N/A" else val

                title = parse_value(metrics.get("title"))
                chat_type = parse_value(metrics.get("chat_type"))
                subscribers = parse_value(metrics.get("subscribers"))
                moderation = parse_value(metrics.get("moderation"))
                messages_per_hour = parse_value(metrics.get("messages_per_hour"))
                unique_authors_per_hour = parse_value(metrics.get("unique_authors_per_hour"))
                captcha = parse_value(metrics.get("captcha"))
                partial_data = parse_value(metrics.get("partial_data"))
                metrics_version = parse_value(metrics.get("metrics_version"))

                # UPDATE group_chats with metrics data
                conn.execute(
                    """
                    UPDATE group_chats
                    SET title = ?,
                        chat_type = ?,
                        subscribers = ?,
                        moderation = ?,
                        messages_per_hour = ?,
                        unique_authors_per_hour = ?,
                        captcha = ?,
                        partial_data = ?,
                        metrics_version = ?
                    WHERE group_id = ? AND chat_ref = ?
                    """,
                    (
                        title,
                        chat_type,
                        subscribers,
                        moderation,
                        messages_per_hour,
                        unique_authors_per_hour,
                        captcha,
                        partial_data,
                        metrics_version,
                        group_id,
                        chat_ref,
                    ),
                )

            logger.info(f"Migrated {results_count} metrics from group_results to group_chats")

        # 4. MAP STATUSES: joining->pending, analyzing->pending, failed->error
        conn.execute("""
            UPDATE group_chats
            SET status = CASE
                WHEN status = 'joining' THEN 'pending'
                WHEN status = 'analyzing' THEN 'pending'
                WHEN status = 'failed' THEN 'error'
                ELSE status
            END
        """)
        logger.info("Mapped old statuses to new schema")

        # 5. CREATE TABLE group_tasks
        conn.execute("""
            CREATE TABLE IF NOT EXISTS group_tasks (
                id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                requested_metrics TEXT,
                time_window TEXT,
                created_at TIMESTAMP NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY (group_id) REFERENCES chat_groups (id)
                    ON DELETE CASCADE
            )
        """)
        logger.info("Created group_tasks table")

        # 6. DROP TABLE group_results
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='group_results'"
        )
        if cursor.fetchone():
            conn.execute("DROP TABLE group_results")
            logger.info("Dropped group_results table")

        # 7. VERIFY migration
        cursor = conn.execute("SELECT COUNT(*) as count FROM group_chats")
        chats_count = cursor.fetchone()[0]
        logger.info(f"Migration v5 complete: {chats_count} chats in group_chats table")

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
        tried_accounts: list[str] | None = None,
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
            tried_accounts: Optional list of account_ids that failed (ban/forbidden)

        Returns:
            Chat ID (auto-generated or provided)
        """
        tried_accounts_json = json.dumps(tried_accounts) if tried_accounts else None

        with self._connection() as conn:
            if chat_id is None:
                # Insert new chat
                cursor = conn.execute(
                    """
                    INSERT INTO group_chats
                    (group_id, chat_ref, chat_type, status, assigned_account, error, subscribers, tried_accounts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (group_id, chat_ref, chat_type, status, assigned_account, error, subscribers, tried_accounts_json),
                )
                return cursor.lastrowid
            else:
                # Update existing chat
                conn.execute(
                    """
                    INSERT INTO group_chats
                    (id, group_id, chat_ref, chat_type, status, assigned_account, error, subscribers, tried_accounts)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(id) DO UPDATE SET
                        group_id = excluded.group_id,
                        chat_ref = excluded.chat_ref,
                        chat_type = excluded.chat_type,
                        status = excluded.status,
                        assigned_account = excluded.assigned_account,
                        error = excluded.error,
                        subscribers = excluded.subscribers,
                        tried_accounts = excluded.tried_accounts
                    """,
                    (chat_id, group_id, chat_ref, chat_type, status, assigned_account, error, subscribers, tried_accounts_json),
                )
                return chat_id

    def update_chat_status(
        self,
        chat_id: int,
        status: str,
        assigned_account: str | None = _UNSET,
        error: str | None = _UNSET,
        tried_accounts: list[str] | None = _UNSET,
    ) -> None:
        """Update the status of a group chat.

        Args:
            chat_id: Chat ID
            status: New status (pending/joining/analyzing/done/failed)
            assigned_account: Optional account assignment (pass None to clear)
            error: Optional error message (pass None to clear)
            tried_accounts: Optional list of account_ids that failed (ban/forbidden)
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

            if tried_accounts is not _UNSET:
                updates.append("tried_accounts = ?")
                params.append(json.dumps(tried_accounts) if tried_accounts else None)

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
                ON CONFLICT(group_id, chat_ref) DO NOTHING
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

        # INSERT ON CONFLICT DO UPDATE with merged data
        # Due to unique constraint on (group_id, chat_ref), this will:
        # - INSERT if no existing row
        # - UPDATE in-place if row exists (preserves rowid)
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO group_results
                (group_id, chat_ref, metrics_data, analyzed_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(group_id, chat_ref) DO UPDATE SET
                    metrics_data = excluded.metrics_data,
                    analyzed_at = excluded.analyzed_at
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
                "tried_accounts": json.loads(row["tried_accounts"]) if row["tried_accounts"] else [],
            }
            for row in rows
        ]

    def count_processed_chats(self, group_id: str) -> tuple[int, int]:
        """Count processed and total chats in a group.

        Args:
            group_id: Group identifier

        Returns:
            Tuple of (processed, total) where:
            - processed: count of chats with status in ('done', 'failed') OR chat_type = 'dead'
            - total: count of all chats in group
        """
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT
                    SUM(CASE
                        WHEN status IN ('done', 'failed') OR chat_type = 'dead'
                        THEN 1
                        ELSE 0
                    END) as processed,
                    COUNT(*) as total
                FROM group_chats
                WHERE group_id = ?
                """,
                (group_id,),
            )
            row = cursor.fetchone()

            # Handle empty result (no chats in group)
            processed = row["processed"] or 0
            total = row["total"] or 0

            return (processed, total)

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

"""Database schema and migration logic for GroupDatabase."""

import json
import logging
import shutil
import sqlite3
from typing import Any

logger = logging.getLogger(__name__)


class SchemaMixin:
    """Mixin providing database schema initialization and migrations."""

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

            # Create indexes for faster lookups
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_group_chats_group_id
                ON group_chats (group_id)
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

        # CLEANUP: Drop group_results table if it still exists (for databases that were
        # migrated to v5 before the DROP TABLE logic was added to _migrate_to_v5_refactor)
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='group_results'"
        )
        if cursor.fetchone():
            conn.execute("DROP TABLE group_results")
            logger.info("Dropped legacy group_results table during cleanup")

    def _migrate_to_v1_unique_constraint(self, conn: Any) -> None:
        """Migration v1: Add UNIQUE constraint on (group_id, chat_ref) for group_results.

        This migration:
        1. Identifies duplicate rows for same (group_id, chat_ref)
        2. Keeps one row per (group_id, chat_ref) with the highest rowid
        3. Creates unique index on (group_id, chat_ref)

        NOTE: Skips if group_results table doesn't exist (already migrated to v5).

        Args:
            conn: Active database connection
        """
        # Check if group_results table exists
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='group_results'"
        )
        if not cursor.fetchone():
            return  # Table already dropped (v5 migration), skip

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

"""One-time import of data from legacy split databases (groups.db + users.db).

Called automatically by ``chatfilter migrate`` when the old files are detected
next to a fresh chatfilter.db.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

logger = logging.getLogger(__name__)


def import_legacy_databases(db_path: Path) -> None:
    """Import data from legacy groups.db and users.db into chatfilter.db.

    Only runs if groups.db or users.db exist in the same directory.
    Uses INSERT OR IGNORE so it's safe to run multiple times.

    Args:
        db_path: Path to the new chatfilter.db file.
    """
    data_dir = db_path.parent
    groups_db = data_dir / "groups.db"
    users_db = data_dir / "users.db"

    if not groups_db.exists() and not users_db.exists():
        return

    conn = sqlite3.connect(str(db_path), isolation_level="DEFERRED")
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        imported = []

        if groups_db.exists():
            count = _import_groups_db(conn, groups_db)
            if count:
                imported.append(f"groups.db: {count} records")

        if users_db.exists():
            count = _import_users_db(conn, users_db)
            if count:
                imported.append(f"users.db: {count} records")

        if imported:
            conn.commit()
            summary = ", ".join(imported)
            print(f"Imported legacy data: {summary}")
            logger.info(f"Legacy import complete: {summary}")

    except Exception as e:
        conn.rollback()
        logger.warning(f"Legacy import failed: {e}")
        print(f"Warning: could not import legacy data: {e}")
    finally:
        conn.close()


def _import_groups_db(conn: sqlite3.Connection, groups_db: Path) -> int:
    """Attach groups.db and copy chat_groups, group_chats, group_tasks."""
    total = 0
    conn.execute(f"ATTACH DATABASE '{groups_db!s}' AS old_groups")
    try:
        old_tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM old_groups.sqlite_master WHERE type='table'"
            ).fetchall()
        }

        if "chat_groups" in old_tables:
            old_cols = {
                r[1] for r in conn.execute("PRAGMA old_groups.table_info(chat_groups)").fetchall()
            }
            new_cols = {"id", "name", "settings", "status", "created_at", "updated_at",
                        "analysis_started_at", "user_id"}
            cols = sorted(old_cols & new_cols)
            if cols:
                col_list = ", ".join(cols)
                n = conn.execute(
                    f"INSERT OR IGNORE INTO chat_groups ({col_list}) "
                    f"SELECT {col_list} FROM old_groups.chat_groups"
                ).rowcount
                total += n

        if "group_chats" in old_tables:
            old_cols = {
                r[1] for r in conn.execute("PRAGMA old_groups.table_info(group_chats)").fetchall()
            }
            new_cols = {"id", "group_id", "chat_ref", "chat_type", "status",
                        "assigned_account", "error", "subscribers", "tried_accounts",
                        "title", "moderation", "messages_per_hour",
                        "unique_authors_per_hour", "captcha", "partial_data",
                        "metrics_version"}
            cols = sorted(old_cols & new_cols)
            if cols:
                col_list = ", ".join(cols)
                n = conn.execute(
                    f"INSERT OR IGNORE INTO group_chats ({col_list}) "
                    f"SELECT {col_list} FROM old_groups.group_chats"
                ).rowcount
                total += n

        if "group_tasks" in old_tables:
            old_cols = {
                r[1] for r in conn.execute("PRAGMA old_groups.table_info(group_tasks)").fetchall()
            }
            new_cols = {"id", "group_id", "requested_metrics", "time_window",
                        "created_at", "status"}
            cols = sorted(old_cols & new_cols)
            if cols:
                col_list = ", ".join(cols)
                n = conn.execute(
                    f"INSERT OR IGNORE INTO group_tasks ({col_list}) "
                    f"SELECT {col_list} FROM old_groups.group_tasks"
                ).rowcount
                total += n

    finally:
        conn.commit()
        conn.execute("DETACH DATABASE old_groups")

    return total


def _import_users_db(conn: sqlite3.Connection, users_db: Path) -> int:
    """Attach users.db and copy users table."""
    conn.execute(f"ATTACH DATABASE '{users_db!s}' AS old_users")
    try:
        old_tables = {
            r[0]
            for r in conn.execute(
                "SELECT name FROM old_users.sqlite_master WHERE type='table'"
            ).fetchall()
        }
        if "users" not in old_tables:
            return 0

        old_cols = {
            r[1] for r in conn.execute("PRAGMA old_users.table_info(users)").fetchall()
        }
        new_cols = {"id", "username", "password_hash", "is_admin", "created_at"}
        cols = sorted(old_cols & new_cols)
        if not cols:
            return 0

        col_list = ", ".join(cols)
        n = conn.execute(
            f"INSERT OR IGNORE INTO users ({col_list}) "
            f"SELECT {col_list} FROM old_users.users"
        ).rowcount
        return n

    finally:
        conn.commit()
        conn.execute("DETACH DATABASE old_users")

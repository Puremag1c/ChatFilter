"""User storage module for authentication and user management."""

from __future__ import annotations

import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path

import bcrypt

from chatfilter.storage.database import SQLiteDatabase


class UserDatabase(SQLiteDatabase):
    """SQLite database for user management and authentication."""

    def _initialize_schema(self) -> None:
        with self._connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    is_admin INTEGER NOT NULL DEFAULT 0,
                    created_at TIMESTAMP NOT NULL
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_users_username
                ON users (username)
            """)

    def create_user(
        self,
        username: str,
        password: str,
        is_admin: bool = False,
        user_id: str | None = None,
    ) -> str:
        """Create a new user. Returns the user id."""
        uid = user_id or str(uuid.uuid4())
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        created_at = self._datetime_to_str(datetime.now(UTC))
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO users (id, username, password_hash, is_admin, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (uid, username, password_hash, 1 if is_admin else 0, created_at),
            )
        return uid

    def get_user_by_username(self, username: str) -> dict | None:
        """Return user dict or None if not found."""
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM users WHERE username = ?", (username,)
            )
            row = cursor.fetchone()
        return self._row_to_dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> dict | None:
        """Return user dict or None if not found."""
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            )
            row = cursor.fetchone()
        return self._row_to_dict(row) if row else None

    def list_users(self) -> list[dict]:
        """Return all users ordered by created_at."""
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM users ORDER BY created_at ASC"
            )
            rows = cursor.fetchall()
        return [self._row_to_dict(row) for row in rows]

    def delete_user(self, user_id: str) -> bool:
        """Delete user by id. Returns True if deleted."""
        with self._connection() as conn:
            cursor = conn.execute(
                "DELETE FROM users WHERE id = ?", (user_id,)
            )
            return cursor.rowcount > 0

    def update_password(self, user_id: str, new_password: str) -> bool:
        """Update password for a user. Returns True if updated."""
        password_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        with self._connection() as conn:
            cursor = conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (password_hash, user_id),
            )
            return cursor.rowcount > 0

    def verify_password(self, username: str, password: str) -> bool:
        """Return True if username exists and password matches."""
        user = self.get_user_by_username(username)
        if not user:
            return False
        return bcrypt.checkpw(password.encode(), user["password_hash"].encode())

    def upsert_user(
        self,
        username: str,
        password: str,
        is_admin: bool = False,
    ) -> str:
        """Create or update user. Returns user id."""
        existing = self.get_user_by_username(username)
        if existing:
            self.update_password(existing["id"], password)
            return existing["id"]
        return self.create_user(username, password, is_admin=is_admin)

    @staticmethod
    def _row_to_dict(row: object) -> dict:
        return {
            "id": row["id"],
            "username": row["username"],
            "password_hash": row["password_hash"],
            "is_admin": bool(row["is_admin"]),
            "created_at": row["created_at"],
        }


def get_user_db(data_dir: Path) -> UserDatabase:
    """Return a UserDatabase instance for the given data directory."""
    return UserDatabase(data_dir / "users.db")


def delete_user_files(user_id: str, sessions_dir: Path, config_dir: Path) -> None:
    """Remove session directory and proxy file for the given user.

    Safe to call even if files/directories do not exist.
    """
    session_path = sessions_dir / user_id
    if session_path.exists():
        shutil.rmtree(session_path, ignore_errors=True)

    proxy_file = config_dir / f"proxies_{user_id}.json"
    proxy_file.unlink(missing_ok=True)

"""User storage module for authentication and user management."""

from __future__ import annotations

import shutil
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import bcrypt
from sqlalchemy.exc import IntegrityError as SAIntegrityError

from chatfilter.storage.sqlite import SQLiteDatabase


class UserAlreadyExistsError(Exception):
    """Raised when attempting to create a user with a duplicate username or email."""


class UserDatabase(SQLiteDatabase):
    """Database for user management and authentication.

    Tables are managed by Alembic — run ``chatfilter migrate`` before first use.
    """

    def _initialize_schema(self) -> None:
        """No-op. Schema is managed by Alembic."""

    def create_user(
        self,
        username: str,
        password: str,
        is_admin: bool = False,
        user_id: str | None = None,
        email: str | None = None,
    ) -> str:
        """Create a new user. Returns the user id."""
        uid = user_id or str(uuid.uuid4())
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        created_at = self._datetime_to_str(datetime.now(UTC))
        try:
            with self._connection() as conn:
                conn.execute(
                    """
                    INSERT INTO users (id, username, password_hash, is_admin, created_at, email)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (uid, username, password_hash, 1 if is_admin else 0, created_at, email),
                )
        except SAIntegrityError as exc:
            raise UserAlreadyExistsError(
                f"User with username '{username}' or email '{email}' already exists"
            ) from exc
        return uid

    def get_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Return user dict or None if not found."""
        with self._connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE email = ?", (email,))
            row = cursor.fetchone()
        return self._row_to_dict(row) if row else None

    def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Return user dict or None if not found."""
        with self._connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
        return self._row_to_dict(row) if row else None

    def get_user_by_id(self, user_id: str) -> dict[str, Any] | None:
        """Return user dict or None if not found."""
        with self._connection() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
        return self._row_to_dict(row) if row else None

    def list_users(
        self,
        page: int = 1,
        page_size: int = 50,
        query: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Return paginated users ordered by created_at.

        Args:
            page: 1-based page number.
            page_size: number of rows per page.
            query: optional search string matched against username OR email
                (case-insensitive, including Cyrillic).

        Returns:
            Tuple of (list of user dicts, total_count).
        """
        offset = (max(1, page) - 1) * page_size
        with self._connection() as conn:
            if query:
                pattern = f"%{query.lower()}%"
                count_row = conn.execute(
                    """
                    SELECT COUNT(*) FROM users
                    WHERE LOWER(username) LIKE LOWER(?) OR LOWER(email) LIKE LOWER(?)
                    """,
                    (pattern, pattern),
                ).fetchone()
                if count_row is not None:
                    total_count: int = count_row[0]
                else:
                    total_count = 0
                rows = conn.execute(
                    """
                    SELECT * FROM users
                    WHERE LOWER(username) LIKE LOWER(?) OR LOWER(email) LIKE LOWER(?)
                    ORDER BY created_at ASC
                    LIMIT ? OFFSET ?
                    """,
                    (pattern, pattern, page_size, offset),
                ).fetchall()
            else:
                count_row = conn.execute("SELECT COUNT(*) FROM users").fetchone()
                total_count = count_row[0] if count_row is not None else 0
                rows = conn.execute(
                    "SELECT * FROM users ORDER BY created_at ASC LIMIT ? OFFSET ?",
                    (page_size, offset),
                ).fetchall()
        return [self._row_to_dict(row) for row in rows], total_count

    def delete_user(self, user_id: str) -> bool:
        """Delete user by id. Returns True if deleted."""
        with self._connection() as conn:
            cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
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

    def set_admin(self, user_id: str, is_admin: bool) -> bool:
        """Toggle admin status for a user. Returns True if updated."""
        with self._connection() as conn:
            cursor = conn.execute(
                "UPDATE users SET is_admin = ? WHERE id = ?",
                (1 if is_admin else 0, user_id),
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
            return str(existing["id"])
        return self.create_user(username, password, is_admin=is_admin)

    def get_balance(self, user_id: str) -> float:
        """Return current AI balance for user in USD. Returns 0.0 if user not found."""
        with self._connection() as conn:
            cursor = conn.execute("SELECT ai_balance_usd FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
        return float(row["ai_balance_usd"]) if row else 0.0

    def update_balance(self, user_id: str, new_balance: float) -> None:
        """Set AI balance for user."""
        with self._connection() as conn:
            conn.execute(
                "UPDATE users SET ai_balance_usd = ? WHERE id = ?",
                (new_balance, user_id),
            )

    def atomic_topup(self, user_id: str, amount_usd: float, description: str) -> float:
        """Atomically add amount_usd to balance and record a topup transaction.

        Uses a single SQL increment to prevent lost updates under concurrent topups.

        Returns new balance.
        """
        created_at = self._datetime_to_str(datetime.now(UTC))
        with self._connection() as conn:
            conn.execute(
                "UPDATE users SET ai_balance_usd = ai_balance_usd + ? WHERE id = ?",
                (amount_usd, user_id),
            )
            row = conn.execute(
                "SELECT ai_balance_usd FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            assert row is not None
            new_balance = float(row["ai_balance_usd"])
            conn.execute(
                """
                INSERT INTO ai_transactions
                    (user_id, type, amount_usd, balance_after, model,
                     tokens_in, tokens_out, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    "topup",
                    amount_usd,
                    new_balance,
                    None,
                    None,
                    None,
                    description,
                    created_at,
                ),
            )
            return new_balance

    def atomic_check_and_deduct(
        self,
        user_id: str,
        min_balance: float = 0.0,
        initial_deduct: float = 0.0,
    ) -> bool:
        """Atomically check balance > min_balance and deduct initial_deduct.

        Executes as a single UPDATE so concurrent requests are serialized at the DB
        level — unlike a separate SELECT then UPDATE, this prevents TOCTOU races.

        Returns True if the check passed (balance was > min_balance), False if the
        user had zero or insufficient balance.
        """
        with self._connection() as conn:
            cursor = conn.execute(
                "UPDATE users SET ai_balance_usd = ai_balance_usd - ? WHERE id = ? AND ai_balance_usd > ?",
                (initial_deduct, user_id, min_balance),
            )
            return cursor.rowcount > 0

    def force_charge(
        self,
        user_id: str,
        cost_usd: float,
        tx_type: str,
        model: str | None,
        tokens_in: int | None,
        tokens_out: int | None,
        description: str | None,
    ) -> float:
        """Deduct cost_usd from balance WITHOUT checking balance >= 0.

        Always succeeds — balance can go negative.
        Records a transaction with the given tx_type.

        Returns new balance.
        """
        created_at = self._datetime_to_str(datetime.now(UTC))
        with self._connection() as conn:
            conn.execute(
                "UPDATE users SET ai_balance_usd = ai_balance_usd - ? WHERE id = ?",
                (cost_usd, user_id),
            )
            row = conn.execute(
                "SELECT ai_balance_usd FROM users WHERE id = ?", (user_id,)
            ).fetchone()
            assert row is not None
            new_balance = float(row["ai_balance_usd"])

            conn.execute(
                """
                INSERT INTO ai_transactions
                    (user_id, type, amount_usd, balance_after, model,
                     tokens_in, tokens_out, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    tx_type,
                    -cost_usd,
                    new_balance,
                    model,
                    tokens_in,
                    tokens_out,
                    description,
                    created_at,
                ),
            )
            return new_balance

    def atomic_charge(
        self,
        user_id: str,
        cost_usd: float,
        model: str | None,
        tokens_in: int | None,
        tokens_out: int | None,
        description: str | None,
    ) -> float:
        """Atomically check balance, deduct cost, and record transaction.

        All three operations execute within a single DB transaction so concurrent
        requests cannot both pass the balance > 0 check before either deducts.

        Returns new balance.
        Raises ValueError("insufficient:<balance>") if balance <= 0.
        """
        created_at = self._datetime_to_str(datetime.now(UTC))
        with self._connection() as conn:
            # Atomic deduct: WHERE clause prevents deduction when balance < cost,
            # ensuring balance never goes below 0 even under concurrent requests.
            cursor = conn.execute(
                "UPDATE users SET ai_balance_usd = ai_balance_usd - ? WHERE id = ? AND ai_balance_usd >= ?",
                (cost_usd, user_id, cost_usd),
            )
            if cursor.rowcount == 0:
                bal_cursor = conn.execute(
                    "SELECT ai_balance_usd FROM users WHERE id = ?", (user_id,)
                )
                row = bal_cursor.fetchone()
                balance = float(row["ai_balance_usd"]) if row else 0.0
                raise ValueError(f"insufficient:{balance:.6f}")

            bal_cursor = conn.execute("SELECT ai_balance_usd FROM users WHERE id = ?", (user_id,))
            row = bal_cursor.fetchone()
            assert row is not None  # user must exist — we just updated their balance above
            new_balance = float(row["ai_balance_usd"])

            conn.execute(
                """
                INSERT INTO ai_transactions
                    (user_id, type, amount_usd, balance_after, model,
                     tokens_in, tokens_out, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    "charge",
                    -cost_usd,
                    new_balance,
                    model,
                    tokens_in,
                    tokens_out,
                    description,
                    created_at,
                ),
            )
            return new_balance

    def add_transaction(
        self,
        user_id: str,
        transaction_type: str,
        amount_usd: float,
        balance_after: float,
        model: str | None = None,
        tokens_in: int | None = None,
        tokens_out: int | None = None,
        description: str | None = None,
    ) -> None:
        """Insert a transaction record."""
        created_at = self._datetime_to_str(datetime.now(UTC))
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO ai_transactions
                    (user_id, type, amount_usd, balance_after, model,
                     tokens_in, tokens_out, description, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    transaction_type,
                    amount_usd,
                    balance_after,
                    model,
                    tokens_in,
                    tokens_out,
                    description,
                    created_at,
                ),
            )

    def get_transactions(self, user_id: str, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent transactions for user ordered by created_at DESC."""
        with self._connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, user_id, type, amount_usd, balance_after,
                       model, tokens_in, tokens_out, description, created_at
                FROM ai_transactions
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (user_id, limit),
            )
            rows = cursor.fetchall()
        return [self._transaction_row_to_dict(row) for row in rows]

    @staticmethod
    def _transaction_row_to_dict(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "type": row["type"],
            "amount_usd": row["amount_usd"],
            "balance_after": row["balance_after"],
            "model": row["model"],
            "tokens_in": row["tokens_in"],
            "tokens_out": row["tokens_out"],
            "description": row["description"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _row_to_dict(row: Any) -> dict[str, Any]:
        return {
            "id": row["id"],
            "username": row["username"],
            "password_hash": row["password_hash"],
            "is_admin": bool(row["is_admin"]),
            "created_at": row["created_at"],
            "ai_balance_usd": float(row["ai_balance_usd"])
            if row["ai_balance_usd"] is not None
            else 0.0,
            "email": row["email"] if row["email"] is not None else None,
        }


def get_user_db(url_or_path: str | Path) -> UserDatabase:
    """Return a UserDatabase instance.

    Args:
        url_or_path: Database URL string (sqlite:///... or postgresql://...)
            or a Path to data directory (legacy, uses <dir>/users.db).
    """
    if isinstance(url_or_path, Path) or "://" not in str(url_or_path):
        return UserDatabase(Path(url_or_path) / "users.db")
    return UserDatabase(url_or_path)


def delete_user_files(user_id: str, sessions_dir: Path, config_dir: Path) -> None:
    """Remove session directory and proxy file for the given user.

    Safe to call even if files/directories do not exist.
    """
    session_path = sessions_dir / user_id
    if session_path.exists():
        shutil.rmtree(session_path, ignore_errors=True)

    proxy_file = config_dir / f"proxies_{user_id}.json"
    proxy_file.unlink(missing_ok=True)

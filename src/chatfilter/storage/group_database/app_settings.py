"""AppSettings CRUD operations for GroupDatabase."""

from __future__ import annotations

from datetime import UTC, datetime

from ._base import DatabaseMixinBase

_MAX_CHATS_DEFAULT = 300
_FRESHNESS_DAYS_DEFAULT = 7


class AppSettingsMixin(DatabaseMixinBase):
    """Mixin providing CRUD operations for app_settings table."""

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        """Get a setting value by key."""
        with self._connection() as conn:
            cursor = conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
            row = cursor.fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Upsert a setting value."""
        now = datetime.now(UTC).isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO app_settings (key, value, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, value, now),
            )

    def get_all_settings(self) -> dict[str, str]:
        """Get all settings as a dict."""
        with self._connection() as conn:
            cursor = conn.execute("SELECT key, value FROM app_settings")
            rows = cursor.fetchall()
        return {row["key"]: row["value"] for row in rows}

    def get_max_chats_per_account(self) -> int:
        """Get max_chats_per_account setting (default 300)."""
        val = self.get_setting("max_chats_per_account")
        return int(val) if val is not None else _MAX_CHATS_DEFAULT

    def get_analysis_freshness_days(self) -> int:
        """Get analysis_freshness_days setting (default 7)."""
        val = self.get_setting("analysis_freshness_days")
        return int(val) if val is not None else _FRESHNESS_DAYS_DEFAULT

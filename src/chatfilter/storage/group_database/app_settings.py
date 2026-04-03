"""AppSettings CRUD operations for GroupDatabase."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

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

    # --- Cost multiplier ---

    def get_cost_multiplier(self) -> float:
        """Get global cost multiplier (default 1.0)."""
        val = self.get_setting("cost_multiplier")
        return float(val) if val is not None else 1.0

    def set_cost_multiplier(self, value: float) -> None:
        """Set global cost multiplier."""
        self.set_setting("cost_multiplier", str(value))

    # --- Platform settings CRUD ---

    def get_platform_setting(self, platform_id: str) -> dict[str, Any] | None:
        """Get platform settings by ID. Returns None if not found."""
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT id, api_key, cost_per_request_usd, enabled, extra_config"
                " FROM platform_settings WHERE id = ?",
                (platform_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "api_key": row["api_key"],
            "cost_per_request_usd": row["cost_per_request_usd"],
            "enabled": bool(row["enabled"]),
            "extra_config": json.loads(row["extra_config"]) if row["extra_config"] else {},
        }

    def save_platform_setting(
        self,
        platform_id: str,
        api_key: str | None = None,
        cost: float = 0.0,
        enabled: bool = True,
    ) -> None:
        """Upsert platform settings."""
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO platform_settings (id, api_key, cost_per_request_usd, enabled)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    api_key = excluded.api_key,
                    cost_per_request_usd = excluded.cost_per_request_usd,
                    enabled = excluded.enabled
                """,
                (platform_id, api_key, cost, int(enabled)),
            )

    def get_all_platform_settings(self) -> list[dict[str, Any]]:
        """Get all platform settings."""
        with self._connection() as conn:
            cursor = conn.execute(
                "SELECT id, api_key, cost_per_request_usd, enabled, extra_config"
                " FROM platform_settings"
            )
            rows = cursor.fetchall()
        return [
            {
                "id": row["id"],
                "api_key": row["api_key"],
                "cost_per_request_usd": row["cost_per_request_usd"],
                "enabled": bool(row["enabled"]),
                "extra_config": json.loads(row["extra_config"]) if row["extra_config"] else {},
            }
            for row in rows
        ]

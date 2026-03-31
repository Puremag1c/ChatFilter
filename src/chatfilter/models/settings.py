"""Application settings helper with typed constants."""

from __future__ import annotations

MAX_CHATS_PER_ACCOUNT: int = 300
ANALYSIS_FRESHNESS_DAYS: int = 7


class AppSettings:
    """Helper for managing application settings as key-value pairs.

    Provides typed accessors and constants for commonly used settings.
    The backing storage (dict) is injected or managed by the database layer.

    Usage:
        settings = AppSettings()
        settings.set_setting("max_chats", "500")
        val = settings.get_setting("max_chats", "300")
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}

    def get_setting(self, key: str, default: str | None = None) -> str | None:
        """Get a setting value by key.

        Args:
            key: Setting key.
            default: Default value if key not found.

        Returns:
            Setting value or default.
        """
        return self._store.get(key, default)

    def set_setting(self, key: str, value: str) -> None:
        """Set a setting value.

        Args:
            key: Setting key.
            value: Setting value (string).
        """
        self._store[key] = value

    @property
    def max_chats_per_account(self) -> int:
        """Maximum chats per account (default: MAX_CHATS_PER_ACCOUNT)."""
        val = self.get_setting("max_chats_per_account")
        if val is not None:
            return int(val)
        return MAX_CHATS_PER_ACCOUNT

    @property
    def analysis_freshness_days(self) -> int:
        """Days after which catalog data is considered stale (default: ANALYSIS_FRESHNESS_DAYS)."""
        val = self.get_setting("analysis_freshness_days")
        if val is not None:
            return int(val)
        return ANALYSIS_FRESHNESS_DAYS

"""Platform registry for managing scraper platforms."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .base import BasePlatform

if TYPE_CHECKING:
    from chatfilter.storage.group_database.app_settings import AppSettingsMixin

logger = logging.getLogger(__name__)


class PlatformRegistry:
    """Registry for all available scraper platforms."""

    def __init__(self) -> None:
        self._platforms: dict[str, BasePlatform] = {}

    def register(self, platform: BasePlatform) -> None:
        """Register a platform instance."""
        self._platforms[platform.id] = platform
        logger.debug("Registered platform: %s", platform.id)

    def get(self, platform_id: str) -> BasePlatform:
        """Get a platform by ID.

        Raises:
            KeyError: If platform is not registered.
        """
        return self._platforms[platform_id]

    def get_all(self) -> list[BasePlatform]:
        """Get all registered platforms."""
        return list(self._platforms.values())

    def get_available(self, db: AppSettingsMixin) -> list[BasePlatform]:
        """Get platforms that are enabled and configured in database settings.

        A platform is available if:
        - It has a row in platform_settings with enabled=True (or no row exists for
          platforms that don't need an API key)
        - If needs_api_key=True, the api_key is set and non-empty
        """
        available = []
        all_settings = {s["id"]: s for s in db.get_all_platform_settings()}

        for platform in self._platforms.values():
            settings = all_settings.get(platform.id)

            if settings is not None:
                # Has explicit settings row — respect enabled flag
                if not settings["enabled"]:
                    continue
                if platform.needs_api_key and not settings.get("api_key"):
                    continue
            else:
                # No settings row — only include if no API key required
                if platform.needs_api_key:
                    continue

            available.append(platform)

        return available


# Global registry instance
registry = PlatformRegistry()

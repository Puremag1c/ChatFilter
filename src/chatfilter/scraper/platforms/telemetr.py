"""Telemetr.io API platform — Telegram channel search via api.telemetr.io.

Requires an API key configured in admin panel (x-api-key header).
Searches both channels and groups via two separate requests.
API docs: https://api.telemetr.io/docs/intro/overview
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)

_API_URL = "https://api.telemetr.io/v1/channels/search"
_TIMEOUT = 30


class TelemetrPlatform(BasePlatform):
    """Search Telegram channels and groups via Telemetr.io API."""

    id = "telemetr"
    name = "Telemetr"
    url = "https://telemetr.io"
    method = "api"
    needs_api_key = True
    cost_tier = "medium"

    async def is_available(self) -> bool:
        """Return True only when API key is configured in DB."""
        if not self._db:
            return False
        settings = self._db.get_platform_setting(self.id)
        return bool(settings and settings.get("api_key"))

    async def search(self, query: str) -> PlatformSearchResult:
        api_key = self._get_api_key()
        if not api_key:
            logger.warning("telemetr: API key not configured, skipping search")
            return PlatformSearchResult()

        headers = {"x-api-key": api_key}
        all_refs: list[str] = []

        # Search both channels and groups
        for peer_type in ("Channel", "Group"):
            params: dict[str, str | int] = {
                "term": query,
                "peer_type": peer_type,
                "search_in_about": "true",
                "limit": 20,
            }
            try:
                async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                    resp = await client.get(
                        _API_URL, params=params, headers=headers,
                    )
                    resp.raise_for_status()
                    data = resp.json()
            except Exception:
                logger.warning(
                    "telemetr: request failed for query=%r peer_type=%s", query, peer_type,
                )
                continue

            all_refs.extend(_parse_refs(data))

        return PlatformSearchResult(refs=all_refs)

    def _get_api_key(self) -> str | None:
        if not self._db:
            return None
        settings = self._db.get_platform_setting(self.id)
        if not settings:
            return None
        return settings.get("api_key") or None


def _parse_refs(data: Any) -> list[str]:
    """Extract Telegram channel/group refs from Telemetr.io API response."""
    if not isinstance(data, list):
        # API may wrap in {"items": [...]} or return list directly
        data = data.get("items", []) if isinstance(data, dict) else []

    refs: list[str] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        username = item.get("username") or item.get("link")
        if username:
            refs.append(f"@{username.lstrip('@')}")
    return refs

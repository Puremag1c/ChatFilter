"""TGStat API platform — structured JSON search, no AI parsing needed."""

from __future__ import annotations

import logging
import re

import httpx

from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)

_API_URL = "https://api.tgstat.ru/channels/search"


class TgstatPlatform(BasePlatform):
    """Search Telegram channels via TGStat API."""

    id = "tgstat"
    name = "TGStat"
    url = "https://tgstat.ru"
    method = "api"
    needs_api_key = True
    cost_tier = "medium"

    async def is_available(self) -> bool:
        """Available only when API key is configured in platform_settings."""
        key = self._get_api_key()
        return key is not None

    async def search(self, query: str) -> PlatformSearchResult:  # type: ignore[override]
        api_key = self._get_api_key()
        if not api_key:
            logger.warning("tgstat: API key not configured")
            return PlatformSearchResult()

        params = {
            "token": api_key,
            "q": query,
            "peer_type": "all",
            "limit": 50,
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(_API_URL, params=params)
                resp.raise_for_status()
        except httpx.HTTPError:
            logger.warning("tgstat: request failed for query=%r", query)
            return PlatformSearchResult()

        try:
            data = resp.json()
        except ValueError:
            logger.warning("tgstat: invalid JSON response")
            return PlatformSearchResult()

        items = data.get("response", {}).get("items", [])
        refs: list[str] = []
        for item in items:
            ref = _extract_ref(item)
            if ref:
                refs.append(ref)

        return PlatformSearchResult(refs=refs, ai_cost=0)

    def _get_api_key(self) -> str | None:
        """Read API key from platform_settings via database."""
        if self._db is None:
            return None
        settings = self._db.get_platform_setting(self.id)
        if settings is None:
            return None
        key = settings.get("api_key")
        return key if key else None


def _extract_ref(item: dict) -> str | None:
    """Extract a Telegram channel reference from a TGStat API item."""
    username = item.get("username")
    if username:
        return f"@{username.lstrip('@')}"

    link = item.get("link", "")
    m = re.search(r"t\.me/([A-Za-z0-9_]+)", link)
    if m:
        return f"@{m.group(1)}"

    return None

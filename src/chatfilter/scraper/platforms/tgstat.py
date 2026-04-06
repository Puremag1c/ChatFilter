"""TGStat API platform — Telegram channel search via api.tgstat.ru."""

from __future__ import annotations

import logging

import httpx

from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)

_API_URL = "https://api.tgstat.ru/channels/search"
_TIMEOUT = 30


class TgstatPlatform(BasePlatform):
    """Search Telegram channels via TGStat API."""

    id = "tgstat"
    name = "TGStat"
    url = "https://tgstat.ru"
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
            logger.warning("tgstat: API key not configured, skipping search")
            return PlatformSearchResult()

        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                resp = await client.get(
                    _API_URL,
                    params={"token": api_key, "q": query, "limit": 20},
                )
                resp.raise_for_status()
                data = resp.json()
        except Exception:
            logger.warning("tgstat: request failed for query=%r", query)
            return PlatformSearchResult()

        refs = _parse_refs(data)
        return PlatformSearchResult(refs=refs)

    def _get_api_key(self) -> str | None:
        if not self._db:
            return None
        settings = self._db.get_platform_setting(self.id)
        if not settings:
            return None
        return settings.get("api_key") or None


def _parse_refs(data: dict) -> list[str]:
    """Extract Telegram channel refs from TGStat API response."""
    if data.get("status") != "ok":
        return []

    response = data.get("response", {})
    items = response.get("items", []) if isinstance(response, dict) else []

    refs: list[str] = []
    for item in items:
        username = item.get("username") or item.get("link")
        if username:
            ref = f"@{username.lstrip('@')}"
            refs.append(ref)

    return refs

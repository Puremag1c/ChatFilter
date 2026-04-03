"""TGStat platform — REST API search for Telegram channels."""

from __future__ import annotations

import logging
import re

import httpx

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)

_USERNAME_RE = re.compile(r"@?([\w]{5,})")


class TGStatPlatform(BasePlatform):
    """Search Telegram channels via TGStat REST API."""

    id = "tgstat"
    name = "TGStat"
    url = "https://api.tgstat.ru"
    method = "api"
    needs_api_key = True
    cost_tier = "medium"

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    async def is_available(self) -> bool:
        return bool(self._api_key)

    async def search(self, query: str) -> list[str]:
        """Search TGStat for channels matching query.

        Returns list of chat_ref strings like '@username'.
        """
        params = {
            "token": self._api_key,
            "q": query,
            "limit": 20,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.get(
                    f"{self.url}/channels/search",
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError as exc:
                logger.warning("TGStat request failed: %s", exc)
                return []

        results: list[str] = []
        items = data.get("response", {}).get("items", [])
        for item in items:
            username = item.get("username") or item.get("link") or ""
            username = username.lstrip("@").strip()
            if username:
                results.append(f"@{username}")

        return results

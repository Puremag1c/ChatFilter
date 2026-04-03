"""Telegago platform — Google Custom Search Engine for Telegram channels."""

from __future__ import annotations

import logging
import re

import httpx

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)

_TME_RE = re.compile(r"(?:https?://)?t\.me/([\w]{5,})")


class TelegagoPlatform(BasePlatform):
    """Search Telegram channels via Google Custom Search Engine (Telegago CSE)."""

    id = "telegago"
    name = "Telegago"
    url = "https://www.googleapis.com/customsearch/v1"
    method = "api"
    needs_api_key = True
    cost_tier = "medium"

    def __init__(self, api_key: str, cx: str) -> None:
        """
        Args:
            api_key: Google API key with Custom Search enabled.
            cx: Custom Search Engine ID (cx parameter).
        """
        self._api_key = api_key
        self._cx = cx

    async def is_available(self) -> bool:
        return bool(self._api_key and self._cx)

    async def search(self, query: str) -> list[str]:
        """Search via Google CSE and extract t.me links.

        Returns list of chat_ref strings like 't.me/username'.
        """
        params = {
            "key": self._api_key,
            "cx": self._cx,
            "q": query,
            "num": 10,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.get(self.url, params=params)
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError as exc:
                logger.warning("Telegago request failed: %s", exc)
                return []

        results: list[str] = []
        seen: set[str] = set()

        for item in data.get("items", []):
            # Check link, displayLink and snippet for t.me references
            sources = [
                item.get("link", ""),
                item.get("displayLink", ""),
                item.get("snippet", ""),
            ]
            for source in sources:
                for match in _TME_RE.finditer(source):
                    username = match.group(1)
                    ref = f"t.me/{username}"
                    if ref not in seen:
                        seen.add(ref)
                        results.append(ref)

        return results

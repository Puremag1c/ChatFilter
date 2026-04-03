"""Google Search platform — find Telegram channels via site:t.me search."""

from __future__ import annotations

import asyncio
import logging
import re

import httpx

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)

_TME_RE = re.compile(r"(?:https?://)?t\.me/([\w]{5,})")

# Rate limit: 1 request per 2 seconds to avoid being blocked
_RATE_LIMIT_DELAY = 2.0


class GoogleSearchPlatform(BasePlatform):
    """Search Telegram channels via Google search (site:t.me).

    Uses direct httpx requests with strict rate limiting.
    Optional SerpAPI key for higher reliability.
    """

    id = "google_search"
    name = "Google Search"
    url = "https://www.google.com/search"
    method = "http"
    needs_api_key = False
    cost_tier = "medium"

    def __init__(self, serpapi_key: str | None = None) -> None:
        """
        Args:
            serpapi_key: Optional SerpAPI key for structured results.
                         If provided, uses SerpAPI instead of direct Google.
        """
        self._serpapi_key = serpapi_key

    async def is_available(self) -> bool:
        return True

    async def search(self, query: str) -> list[str]:
        """Search Google for 'site:t.me QUERY' and extract channel refs.

        Returns list of chat_ref strings like 't.me/username'.
        """
        if self._serpapi_key:
            return await self._search_serpapi(query)
        return await self._search_direct(query)

    async def _search_serpapi(self, query: str) -> list[str]:
        """Search via SerpAPI for structured Google results."""
        params = {
            "api_key": self._serpapi_key,
            "engine": "google",
            "q": f"site:t.me {query}",
            "num": 10,
        }
        async with httpx.AsyncClient(timeout=15) as client:
            try:
                resp = await client.get(
                    "https://serpapi.com/search",
                    params=params,
                )
                resp.raise_for_status()
                data = resp.json()
            except httpx.HTTPError as exc:
                logger.warning("SerpAPI request failed: %s", exc)
                return []

        results: list[str] = []
        seen: set[str] = set()

        for item in data.get("organic_results", []):
            link = item.get("link", "")
            for match in _TME_RE.finditer(link):
                username = match.group(1)
                ref = f"t.me/{username}"
                if ref not in seen:
                    seen.add(ref)
                    results.append(ref)

        return results

    async def _search_direct(self, query: str) -> list[str]:
        """Search Google directly with rate limiting."""
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (compatible; ChatFilter/1.0; "
                "+https://github.com/chatfilter)"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }
        params = {
            "q": f"site:t.me {query}",
            "num": 10,
            "hl": "en",
        }

        await asyncio.sleep(_RATE_LIMIT_DELAY)

        async with httpx.AsyncClient(
            timeout=15,
            headers=headers,
            follow_redirects=True,
        ) as client:
            try:
                resp = await client.get(self.url, params=params)
                resp.raise_for_status()
                html = resp.text
            except httpx.HTTPError as exc:
                logger.warning("Google direct search failed: %s", exc)
                return []

        results: list[str] = []
        seen: set[str] = set()

        for match in _TME_RE.finditer(html):
            username = match.group(1)
            # Skip Google's own navigation paths
            if username.lower() in {"search", "maps", "images", "accounts"}:
                continue
            ref = f"t.me/{username}"
            if ref not in seen:
                seen.add(ref)
                results.append(ref)

        return results

"""Google Search HTTP platform (stub)."""

from __future__ import annotations

import logging

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)


class GoogleSearchPlatform(BasePlatform):
    """Search Telegram channels via Google Search."""

    id = "google_search"
    name = "Google Search"
    url = "https://google.com"
    method = "http"
    needs_api_key = False
    cost_tier = "medium"
    is_implemented = False

    async def search(self, query: str) -> list[str]:
        logger.warning("google_search: HTTP scraping not yet implemented")
        return []

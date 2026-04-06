"""Combot.org HTTP scraping platform."""

from __future__ import annotations

import logging
from urllib.parse import urlencode

import httpx

from chatfilter.ai.html_parser import extract_telegram_links
from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)


class CombotPlatform(BasePlatform):
    """Search Telegram groups via combot.org."""

    id = "combot"
    name = "Combot"
    url = "https://combot.org"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> PlatformSearchResult:
        search_url = "https://combot.org/chats?" + urlencode({"q": query})
        headers = {
            "User-Agent": ("Mozilla/5.0 (compatible; ChatFilter/1.0; +https://chatfilter.app)")
        }
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get(search_url, headers=headers)
                resp.raise_for_status()
        except Exception:
            logger.warning("combot: request failed for query=%r", query)
            return PlatformSearchResult(refs=[], ai_cost=0.0)

        # Use AI parser to extract Telegram links
        if self._ai_service is None:
            logger.warning("combot: AI service not configured")
            return PlatformSearchResult(refs=[], ai_cost=0.0)

        refs, ai_response = await extract_telegram_links(
            resp.text, self.name, self._ai_service, user_id=None
        )

        return PlatformSearchResult(
            refs=refs,
            ai_cost=ai_response.cost_usd,
            ai_model=ai_response.model,
            ai_tokens_in=ai_response.tokens_in,
            ai_tokens_out=ai_response.tokens_out,
        )

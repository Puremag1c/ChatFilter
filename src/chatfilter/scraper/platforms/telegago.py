"""Telegago: Google search restricted to t.me (site:t.me).

Uses Playwright headless browser to render Google's JS-heavy results page.
AI parsing extracts t.me links from the rendered HTML.
No API key required.
"""

from __future__ import annotations

import logging
from urllib.parse import quote_plus

from chatfilter.ai.html_parser import extract_telegram_links
from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)

_GOOGLE_SEARCH_URL = "https://www.google.com/search?q=site%3At.me+{query}&num=20&hl=en"


class TelegagoPlatform(BasePlatform):
    """Search Telegram channels via Google (site:t.me query)."""

    id = "telegago"
    name = "Telegago"
    url = "https://www.google.com"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> PlatformSearchResult:
        url = _GOOGLE_SEARCH_URL.format(query=quote_plus(query))

        try:
            from chatfilter.scraper.browser import get_page

            async with get_page() as page:
                await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                # Wait for results to render (Google loads them via JS)
                await page.wait_for_timeout(2000)
                html = await page.content()
        except Exception:
            logger.warning("telegago: browser request failed for query=%r", query, exc_info=True)
            return PlatformSearchResult()

        if self._ai_service is None:
            logger.warning("telegago: AI service not configured, cannot parse results")
            return PlatformSearchResult()

        refs, ai_response = await extract_telegram_links(
            html=html,
            platform_name=self.name,
            ai_service=self._ai_service,
            search_query=query,
        )

        return PlatformSearchResult(
            refs=refs,
            ai_cost=ai_response.cost_usd,
            ai_model=ai_response.model or None,
            ai_tokens_in=ai_response.tokens_in,
            ai_tokens_out=ai_response.tokens_out,
        )

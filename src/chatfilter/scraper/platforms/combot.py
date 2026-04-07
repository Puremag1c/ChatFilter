"""Combot.org HTTP scraping platform.

Uses Playwright headless browser to bypass Cloudflare challenge.
AI parsing extracts Telegram links from rendered HTML.
"""

from __future__ import annotations

import logging
from urllib.parse import urlencode

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
        search_url = "https://combot.org/telegram/top/chats?" + urlencode({"q": query})

        try:
            from chatfilter.scraper.browser import get_page

            async with get_page() as page:
                await page.goto(search_url, wait_until="domcontentloaded", timeout=30_000)
                # Wait for Cloudflare challenge + page render
                await page.wait_for_timeout(5000)
                html = await page.content()
        except Exception:
            logger.warning("combot: browser request failed for query=%r", query)
            return PlatformSearchResult(refs=[], ai_cost=0.0)

        if self._ai_service is None:
            logger.warning("combot: AI service not configured")
            return PlatformSearchResult(refs=[], ai_cost=0.0)

        refs, ai_response = await extract_telegram_links(
            html, self.name, self._ai_service, user_id=None
        )

        return PlatformSearchResult(
            refs=refs,
            ai_cost=ai_response.cost_usd,
            ai_model=ai_response.model,
            ai_tokens_in=ai_response.tokens_in,
            ai_tokens_out=ai_response.tokens_out,
        )

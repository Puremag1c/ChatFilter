"""Telegago: Google search restricted to t.me (site:t.me).

Uses curl_cffi to bypass Google's TLS fingerprint checks.
AI parsing extracts t.me links from Google's HTML results.
No API key required.
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial
from urllib.parse import quote_plus

from curl_cffi import requests as cf_requests

from chatfilter.ai.html_parser import extract_telegram_links
from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)

_GOOGLE_SEARCH_URL = "https://www.google.com/search?q=site%3At.me+{query}&num=20"

_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


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
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                partial(
                    cf_requests.get,
                    url,
                    impersonate="chrome",
                    headers=_HEADERS,
                    timeout=30,
                ),
            )
            resp.raise_for_status()  # type: ignore[no-untyped-call]
        except Exception:
            logger.warning("telegago: request failed for query=%r", query)
            return PlatformSearchResult()

        if self._ai_service is None:
            logger.warning("telegago: AI service not configured, cannot parse results")
            return PlatformSearchResult()

        refs, ai_response = await extract_telegram_links(
            html=resp.text,
            platform_name=self.name,
            ai_service=self._ai_service,
        )

        return PlatformSearchResult(
            refs=refs,
            ai_cost=ai_response.cost_usd,
            ai_model=ai_response.model or None,
            ai_tokens_in=ai_response.tokens_in,
            ai_tokens_out=ai_response.tokens_out,
        )

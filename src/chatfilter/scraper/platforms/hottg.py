"""Hottg.com HTTP scraping platform.

Uses curl_cffi to bypass bot detection (plain httpx times out).
"""

from __future__ import annotations

import asyncio
import logging
from functools import partial
from urllib.parse import urlencode

from curl_cffi import requests as cf_requests

from chatfilter.ai.html_parser import extract_telegram_links
from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)


class HottgPlatform(BasePlatform):
    """Search Telegram channels via hottg.com."""

    id = "hottg"
    name = "Hottg"
    url = "https://hottg.com"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> PlatformSearchResult:
        search_url = "https://hottg.com/search?" + urlencode({"q": query})
        try:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                partial(
                    cf_requests.get,
                    search_url,
                    impersonate="chrome",
                    timeout=30,
                ),
            )
            resp.raise_for_status()  # type: ignore[no-untyped-call]
        except Exception:
            logger.warning("hottg: request failed for query=%r", query)
            return PlatformSearchResult()

        if self._ai_service is None:
            logger.warning("hottg: AI service not configured, cannot parse results")
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

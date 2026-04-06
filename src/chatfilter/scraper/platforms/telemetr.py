"""Telemetr.io HTTP scraping platform.

Uses curl_cffi to bypass Cloudflare's TLS fingerprint challenge.
Extracts Telegram links using AI-powered HTML parser.
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


class TelemetrPlatform(BasePlatform):
    """Search Telegram channels via telemetr.io."""

    id = "telemetr"
    name = "Telemetr"
    url = "https://telemetr.io"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> PlatformSearchResult:
        search_url = "https://telemetr.io/en/channels?" + urlencode({"channel": query, "page": 1})
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
            logger.warning("telemetr: request failed for query=%r", query)
            return PlatformSearchResult(refs=[])

        if not self._ai_service:
            logger.warning("telemetr: AI service not configured, skipping extraction")
            return PlatformSearchResult(refs=[])

        # Use AI parser to extract Telegram links
        refs, ai_response = await extract_telegram_links(
            resp.text,
            platform_name=self.name,
            ai_service=self._ai_service,
        )

        return PlatformSearchResult(
            refs=refs,
            ai_cost=ai_response.cost_usd,
            ai_model=ai_response.model,
            ai_tokens_in=ai_response.tokens_in,
            ai_tokens_out=ai_response.tokens_out,
        )

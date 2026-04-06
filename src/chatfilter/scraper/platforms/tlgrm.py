"""Tlgrm.ru HTTP scraping platform."""

from __future__ import annotations

import logging
from urllib.parse import quote

import httpx

from chatfilter.ai.html_parser import extract_telegram_links
from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)


class TlgrmPlatform(BasePlatform):
    """Search Telegram channels via tlgrm.ru (Russian catalog)."""

    id = "tlgrm"
    name = "Tlgrm"
    url = "https://tlgrm.ru"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> PlatformSearchResult:
        search_url = "https://tlgrm.ru/channels/search/" + quote(query, safe="")
        headers = {
            "User-Agent": ("Mozilla/5.0 (compatible; ChatFilter/1.0; +https://chatfilter.app)")
        }
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get(search_url, headers=headers)
                resp.raise_for_status()
        except Exception:
            logger.warning("tlgrm: request failed for query=%r", query)
            return PlatformSearchResult()

        if self._ai_service is None:
            logger.warning("tlgrm: AI service not configured, cannot parse results")
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

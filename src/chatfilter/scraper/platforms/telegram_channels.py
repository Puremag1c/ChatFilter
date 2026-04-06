"""TelegramChannels.me HTTP scraping platform."""

from __future__ import annotations

import logging

import httpx

from chatfilter.ai.html_parser import extract_telegram_links
from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)


class TelegramChannelsPlatform(BasePlatform):
    """Search Telegram channels via telegramchannels.me."""

    id = "telegram_channels"
    name = "TelegramChannels"
    url = "https://telegramchannels.me"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> PlatformSearchResult:
        search_url = f"https://telegramchannels.me/channels?search={query}"
        headers = {
            "User-Agent": ("Mozilla/5.0 (compatible; ChatFilter/1.0; +https://chatfilter.app)")
        }
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get(search_url, headers=headers)
                resp.raise_for_status()
        except Exception:
            logger.warning("telegram_channels: request failed for query=%r", query)
            return PlatformSearchResult(refs=[])

        if not self._ai_service:
            logger.warning("telegram_channels: AI service not configured, skipping extraction")
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

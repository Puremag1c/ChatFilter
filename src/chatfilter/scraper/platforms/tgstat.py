"""TGStat API platform (stub — requires API key)."""

from __future__ import annotations

import logging

from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)


class TgstatPlatform(BasePlatform):
    """Search Telegram channels via TGStat API."""

    id = "tgstat"
    name = "TGStat"
    url = "https://tgstat.ru"
    method = "api"
    needs_api_key = True
    cost_tier = "medium"

    async def search(self, query: str) -> PlatformSearchResult:
        logger.warning("tgstat: API key not configured")
        return PlatformSearchResult()

"""Telegago Google CSE platform (stub — requires API key)."""

from __future__ import annotations

import logging

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)


class TelegagoPlatform(BasePlatform):
    """Search Telegram channels via Telegago (Google Custom Search Engine)."""

    id = "telegago"
    name = "Telegago"
    url = "https://cse.google.com"
    method = "api"
    needs_api_key = True
    cost_tier = "medium"

    async def search(self, query: str) -> list[str]:
        logger.warning("telegago: API key not configured")
        return []

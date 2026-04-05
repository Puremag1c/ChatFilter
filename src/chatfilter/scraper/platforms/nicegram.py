"""Nicegram Hub Playwright platform (stub)."""

from __future__ import annotations

import logging

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)


class NicegramPlatform(BasePlatform):
    """Search Telegram channels via Nicegram Hub (SPA)."""

    id = "nicegram"
    name = "Nicegram Hub"
    url = "https://nicegram.app/hub"
    method = "playwright"
    needs_api_key = False
    cost_tier = "medium"
    is_implemented = False

    async def search(self, query: str) -> list[str]:
        logger.warning("nicegram: Playwright scraping not yet implemented")
        return []

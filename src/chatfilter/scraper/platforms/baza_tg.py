"""Baza-TG API platform (stub — requires paid API key)."""

from __future__ import annotations

import logging

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)


class BazaTgPlatform(BasePlatform):
    """Search Telegram channels via Baza-TG API."""

    id = "baza_tg"
    name = "Baza-TG"
    url = "https://baza-tg.online"
    method = "api"
    needs_api_key = True
    cost_tier = "expensive"

    async def search(self, query: str) -> list[str]:
        logger.warning("baza_tg: API key not configured")
        return []

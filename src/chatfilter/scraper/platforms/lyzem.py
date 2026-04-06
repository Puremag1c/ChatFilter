"""Lyzem.com HTTP scraping platform."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlencode

import httpx
from bs4 import BeautifulSoup

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)

TGREF_RE = re.compile(r"(?:https?://)?t\.me/([A-Za-z0-9_]+)")


class LyzemPlatform(BasePlatform):
    """Search Telegram channels via lyzem.com."""

    id = "lyzem"
    name = "Lyzem"
    url = "https://lyzem.com"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> list[str]:
        search_url = "https://lyzem.com/search?" + urlencode({"q": query, "lang": "all"})
        headers = {
            "User-Agent": ("Mozilla/5.0 (compatible; ChatFilter/1.0; +https://chatfilter.app)")
        }
        try:
            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                resp = await client.get(search_url, headers=headers)
                resp.raise_for_status()
        except Exception:
            logger.warning("lyzem: request failed for query=%r", query)
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        refs: set[str] = set()

        for tag in soup.find_all("a", href=True):
            m = TGREF_RE.search(str(tag["href"]))
            if m:
                refs.add(f"@{m.group(1)}")

        for text_node in soup.find_all(string=TGREF_RE):
            for m in TGREF_RE.finditer(str(text_node)):
                refs.add(f"@{m.group(1)}")

        return list(refs)

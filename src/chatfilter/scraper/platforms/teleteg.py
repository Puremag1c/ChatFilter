"""Teleteg.com HTTP scraping platform.

Uses curl_cffi for browser-like TLS fingerprint.
Correct search URL: /search-results/?query=...
"""

from __future__ import annotations

import asyncio
import logging
import re
from functools import partial

from bs4 import BeautifulSoup
from curl_cffi import requests as cf_requests

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)

TGREF_RE = re.compile(r"(?:https?://)?t\.me/([A-Za-z0-9_]+)")


class TeletegPlatform(BasePlatform):
    """Search Telegram channels via teleteg.com."""

    id = "teleteg"
    name = "Teleteg"
    url = "https://teleteg.com"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> list[str]:
        search_url = f"https://teleteg.com/search-results/?query={query}"
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
            logger.warning("teleteg: request failed for query=%r", query)
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

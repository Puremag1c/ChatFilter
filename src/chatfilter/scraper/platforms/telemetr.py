"""Telemetr.io HTTP scraping platform.

Uses curl_cffi to bypass Cloudflare's TLS fingerprint challenge.
Extracts channel usernames from telemetr's internal /en/channels/ID-name links.
"""

from __future__ import annotations

import asyncio
import logging
import re
from functools import partial
from urllib.parse import urlencode

from bs4 import BeautifulSoup
from curl_cffi import requests as cf_requests

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)

# Matches telemetr internal channel links: /en/channels/1234567-username
_CHANNEL_RE = re.compile(r"/en/channels/\d+-([A-Za-z0-9_]+)")

# Also match t.me links in page text
_TGREF_RE = re.compile(r"(?:https?://)?t\.me/([A-Za-z0-9_]+)")

# Exclude known non-channel usernames (telemetr's own bots/pages)
_EXCLUDED = frozenset(
    {
        "telemetrio_news",
        "telemetrio_api_bot",
        "telemetr_io_bot",
        "telemetrio",
        "telemetrioalertbot",
    }
)


class TelemetrPlatform(BasePlatform):
    """Search Telegram channels via telemetr.io."""

    id = "telemetr"
    name = "Telemetr"
    url = "https://telemetr.io"
    method = "http"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> list[str]:
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
            return []

        soup = BeautifulSoup(resp.text, "html.parser")
        refs: set[str] = set()

        # Extract from telemetr internal channel links
        for tag in soup.find_all("a", href=True):
            m = _CHANNEL_RE.search(str(tag["href"]))
            if m:
                username = m.group(1).lower()
                if username not in _EXCLUDED:
                    refs.add(f"@{username}")

        # Also extract any t.me links found in page
        for tag in soup.find_all("a", href=True):
            m = _TGREF_RE.search(str(tag["href"]))
            if m:
                username = m.group(1).lower()
                if username not in _EXCLUDED:
                    refs.add(f"@{username}")

        return list(refs)

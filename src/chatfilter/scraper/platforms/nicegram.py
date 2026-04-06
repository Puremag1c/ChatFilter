"""Nicegram Hub HTTP scraping platform.

Uses curl_cffi to bypass TLS fingerprinting (returns 403 without it).
Searches both channels and groups, with cursor-based pagination (up to 2 pages each).
AI parsing extracts Telegram refs from HTML responses.
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

_BASE_URL = "https://nicegram.app/hub/search"
_SEARCH_TYPES = ("channels", "groups")


class NicegramPlatform(BasePlatform):
    """Search Telegram channels and groups via Nicegram Hub."""

    id = "nicegram"
    name = "Nicegram Hub"
    url = "https://nicegram.app/hub"
    method = "http"
    needs_api_key = False
    cost_tier = "medium"

    async def search(self, query: str) -> PlatformSearchResult:  # type: ignore[override]
        refs: set[str] = set()
        total_cost = 0.0
        total_tokens_in = 0
        total_tokens_out = 0
        ai_model: str | None = None

        for search_type in _SEARCH_TYPES:
            cursor: str | None = None
            for _page in range(2):
                params: dict[str, str] = {"q": query, "searchType": search_type}
                if cursor:
                    params["cursor"] = cursor

                url = _BASE_URL + "?" + urlencode(params)
                html, next_cursor = await self._fetch_page(url)
                if html is None:
                    break

                if self._ai_service:
                    page_refs, ai_resp = await extract_telegram_links(
                        html, self.name, self._ai_service
                    )
                    refs.update(page_refs)
                    total_cost += ai_resp.cost_usd
                    total_tokens_in += ai_resp.tokens_in
                    total_tokens_out += ai_resp.tokens_out
                    if ai_resp.model:
                        ai_model = ai_resp.model
                else:
                    logger.warning("nicegram: no AI service configured, skipping page")

                if not next_cursor:
                    break
                cursor = next_cursor

        return PlatformSearchResult(
            refs=list(refs),
            ai_cost=total_cost,
            ai_model=ai_model,
            ai_tokens_in=total_tokens_in,
            ai_tokens_out=total_tokens_out,
        )

    async def _fetch_page(self, url: str) -> tuple[str | None, str | None]:
        """Fetch a page and return (html, next_cursor). Returns (None, None) on error."""
        try:
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                partial(
                    cf_requests.get,
                    url,
                    impersonate="chrome",
                    timeout=30,
                ),
            )
            resp.raise_for_status()  # type: ignore[no-untyped-call]
        except Exception:
            logger.warning("nicegram: request failed for url=%r", url)
            return None, None

        # Try to extract next cursor from JSON response or HTML meta
        next_cursor = _extract_cursor(resp.text)
        return resp.text, next_cursor


def _extract_cursor(text: str) -> str | None:
    """Try to extract pagination cursor from response text (JSON or embedded data)."""
    import json
    import re

    # Try to find JSON with cursor field
    cursor_re = re.compile(r'"cursor"\s*:\s*"([^"]+)"')
    m = cursor_re.search(text)
    if m:
        return m.group(1)

    # Try parsing as JSON directly
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data.get("cursor") or data.get("nextCursor") or data.get("next_cursor")
    except (json.JSONDecodeError, ValueError):
        pass

    return None

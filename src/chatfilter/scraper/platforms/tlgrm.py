"""Tlgrm.ru channel search via Typesense API.

Tlgrm.ru renders search results client-side via a public Typesense instance.
We call the same API directly — no HTML scraping or AI parsing needed.
The API key is fetched dynamically from tlgrm.ru and cached in memory.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)

_TYPESENSE_HOST = "https://typesense.tlgrm.ru"
_TYPESENSE_COLLECTION = "channels"

# Cached API key (fetched from tlgrm.ru page source on first use).
_cached_api_key: str | None = None


async def _fetch_api_key() -> str | None:
    """Fetch the current Typesense API key from tlgrm.ru page source."""
    global _cached_api_key  # noqa: PLW0603
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get("https://tlgrm.ru")
            resp.raise_for_status()
            match = re.search(r'"typesense_api_key"\s*:\s*"([^"]+)"', resp.text)
            if match:
                _cached_api_key = match.group(1)
                logger.info("tlgrm: fetched fresh Typesense API key")
                return _cached_api_key
            logger.warning("tlgrm: could not find typesense_api_key in page source")
    except Exception:
        logger.warning("tlgrm: failed to fetch API key from tlgrm.ru", exc_info=True)
    return None


async def _get_api_key(*, force_refresh: bool = False) -> str | None:
    """Return cached API key, fetching from tlgrm.ru if needed."""
    global _cached_api_key  # noqa: PLW0603
    if _cached_api_key is not None and not force_refresh:
        return _cached_api_key
    return await _fetch_api_key()


class TlgrmPlatform(BasePlatform):
    """Search Telegram channels via tlgrm.ru (Typesense API)."""

    id = "tlgrm"
    name = "Tlgrm"
    url = "https://tlgrm.ru"
    method = "api"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> PlatformSearchResult:
        api_key = await _get_api_key()
        if not api_key:
            logger.warning("tlgrm: no API key available, skipping search")
            return PlatformSearchResult()

        result = await self._do_search(query, api_key)
        if result is not None:
            return result

        # 401 → key probably rotated, refresh and retry once
        logger.info("tlgrm: refreshing API key after 401")
        api_key = await _get_api_key(force_refresh=True)
        if not api_key:
            return PlatformSearchResult()

        result = await self._do_search(query, api_key)
        return result if result is not None else PlatformSearchResult()

    async def _do_search(self, query: str, api_key: str) -> PlatformSearchResult | None:
        """Execute search. Returns None on 401 (key expired), result otherwise."""
        url = f"{_TYPESENSE_HOST}/collections/{_TYPESENSE_COLLECTION}/documents/search"
        params: dict[str, str] = {
            "q": query.lower().strip(),
            "query_by": "tokenized_name,tags,link",
            "query_by_weights": "120,30,10",
            "sort_by": "_eval(official:true):desc,subscribers:desc,_text_match:desc",
            "filter_by": "lang:[na,ru]",
            "per_page": "20",
            "page": "1",
            "highlight_fields": "_",
            "min_len_1typo": "5",
            "min_len_2typo": "8",
        }
        headers = {"X-Typesense-Api-Key": api_key}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, params=params, headers=headers)
                if resp.status_code == 401:
                    return None
                resp.raise_for_status()
                data = resp.json()
        except Exception:
            logger.warning("tlgrm: typesense search failed for query=%r", query, exc_info=True)
            return PlatformSearchResult()

        refs = _parse_hits(data)
        return PlatformSearchResult(refs=refs)


def _parse_hits(data: dict[str, Any]) -> list[str]:
    """Extract @username refs from Typesense search response."""
    hits = data.get("hits", [])
    refs: list[str] = []
    for hit in hits:
        doc = hit.get("document", hit)
        link = doc.get("link")
        if link:
            refs.append(f"@{link.lstrip('@')}")
    return refs

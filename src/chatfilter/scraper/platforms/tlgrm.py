"""Tlgrm.ru channel search via Typesense API.

Tlgrm.ru renders search results client-side via a public Typesense instance.
We call the same API directly — no HTML scraping or AI parsing needed.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from chatfilter.scraper.base import BasePlatform, PlatformSearchResult

logger = logging.getLogger(__name__)

# Typesense endpoint and public read-only key (embedded in tlgrm.ru page source).
_TYPESENSE_HOST = "https://typesense.tlgrm.ru"
_TYPESENSE_COLLECTION = "channels"
# Key is scoped to read-only search with excluded fields (tags, embedding).
_TYPESENSE_API_KEY = (
    "S21Iay9yTjM0QnVUNkJ2STREZHhoZ3liVFJhdW9UaGc4UXAxRUthNS9DRT0"
    "9TzI5MHsiZXhjbHVkZV9maWVsZHMiOiJ0YWdzLGVtYmVkZGluZyJ9"
)


class TlgrmPlatform(BasePlatform):
    """Search Telegram channels via tlgrm.ru (Typesense API)."""

    id = "tlgrm"
    name = "Tlgrm"
    url = "https://tlgrm.ru"
    method = "api"
    needs_api_key = False
    cost_tier = "cheap"

    async def search(self, query: str) -> PlatformSearchResult:
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
        headers = {"X-Typesense-Api-Key": _TYPESENSE_API_KEY}

        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, params=params, headers=headers)
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

"""Baza-TG platform — API with Playwright fallback."""

from __future__ import annotations

import logging
import re
from typing import Any

import httpx

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)

_TG_LINK_RE = re.compile(r"(?:https?://)?t\.me/([a-zA-Z_][a-zA-Z0-9_]{3,})")


class BazaTGPlatform(BasePlatform):
    """Baza-TG (baza-tg.online) — API-first with Playwright fallback."""

    id = "baza_tg"
    name = "Baza-TG"
    url = "https://baza-tg.online"
    method = "api"
    needs_api_key = True
    cost_tier = "expensive"

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key

    async def is_available(self) -> bool:
        return bool(self._api_key)

    async def search(self, query: str) -> list[str]:
        """Try API first, fall back to Playwright if API fails."""
        if self._api_key:
            try:
                return await self._search_api(query)
            except Exception:
                logger.warning("Baza-TG API failed, falling back to Playwright")

        return await self._search_playwright(query)

    async def _search_api(self, query: str) -> list[str]:
        """Search via Baza-TG HTTP API."""
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.url}/api/search",
                params={"q": query},
                headers={"Authorization": f"Bearer {self._api_key}"},
            )
            resp.raise_for_status()
            data: Any = resp.json()

        return self._extract_refs(data)

    async def _search_playwright(self, query: str) -> list[str]:
        """Fallback: search via headless browser."""
        from playwright.async_api import async_playwright

        results: list[str] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.goto(self.url, wait_until="domcontentloaded", timeout=30_000)

                # Try to find search form
                search_input = page.locator(
                    "input[type='search'], input[type='text'], input[placeholder*='earch']"
                ).first
                await search_input.wait_for(state="visible", timeout=15_000)
                await search_input.fill(query)
                await search_input.press("Enter")

                await page.wait_for_timeout(3000)

                # Extract Telegram links from results
                links = await page.locator("a[href*='t.me/']").all()
                seen: set[str] = set()
                for link in links:
                    href = await link.get_attribute("href")
                    if href:
                        match = _TG_LINK_RE.search(href)
                        if match:
                            username = match.group(1).lower()
                            if username not in seen:
                                seen.add(username)
                                results.append(f"@{username}")

                logger.info(
                    "Baza-TG Playwright search for %r returned %d results",
                    query,
                    len(results),
                )
            except Exception:
                logger.exception("Baza-TG Playwright search failed for query %r", query)
            finally:
                await browser.close()

        return results

    @staticmethod
    def _extract_refs(data: Any) -> list[str]:
        """Extract channel refs from API JSON response.

        Handles common response shapes:
        - {"results": [{"username": "..."}, ...]}
        - {"results": [{"url": "t.me/..."}, ...]}
        - {"channels": ["@...", ...]}
        """
        refs: list[str] = []
        seen: set[str] = set()

        items: list[Any] = []
        if isinstance(data, dict):
            items = data.get("results", data.get("channels", []))
        elif isinstance(data, list):
            items = data

        for item in items:
            username: str | None = None
            if isinstance(item, str):
                # Could be "@channel" or "t.me/channel"
                if item.startswith("@"):
                    username = item[1:].lower()
                else:
                    match = _TG_LINK_RE.search(item)
                    if match:
                        username = match.group(1).lower()
            elif isinstance(item, dict):
                raw = item.get("username") or item.get("url") or item.get("link", "")
                if raw.startswith("@"):
                    username = raw[1:].lower()
                else:
                    match = _TG_LINK_RE.search(raw)
                    if match:
                        username = match.group(1).lower()

            if username and username not in seen:
                seen.add(username)
                refs.append(f"@{username}")

        return refs

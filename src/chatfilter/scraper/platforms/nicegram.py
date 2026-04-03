"""Nicegram Hub platform — SPA requiring Playwright browser automation."""

from __future__ import annotations

import logging
import re

from chatfilter.scraper.base import BasePlatform

logger = logging.getLogger(__name__)

# Regex to extract Telegram channel refs from links
_TG_LINK_RE = re.compile(r"(?:https?://)?t\.me/([a-zA-Z_][a-zA-Z0-9_]{3,})")


class NicegramHubPlatform(BasePlatform):
    """Nicegram Hub (nicegram.app/hub) — SPA search via Playwright."""

    id = "nicegram_hub"
    name = "Nicegram Hub"
    url = "https://nicegram.app/hub"
    method = "playwright"
    needs_api_key = False
    cost_tier = "medium"

    async def search(self, query: str) -> list[str]:
        """Launch headless browser, search hub, extract channel links."""
        from playwright.async_api import async_playwright

        results: list[str] = []

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                page = await browser.new_page()
                await page.goto(self.url, wait_until="domcontentloaded", timeout=30_000)

                # Wait for the search input to appear (SPA hydration)
                search_input = page.locator(
                    "input[type='search'], input[type='text'], input[placeholder*='earch']"
                ).first
                await search_input.wait_for(state="visible", timeout=15_000)
                await search_input.fill(query)
                await search_input.press("Enter")

                # Wait for results to load
                await page.wait_for_timeout(3000)

                # Extract all links that look like Telegram channel references
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

                logger.info("Nicegram Hub search for %r returned %d results", query, len(results))
            except Exception:
                logger.exception("Nicegram Hub search failed for query %r", query)
            finally:
                await browser.close()

        return results

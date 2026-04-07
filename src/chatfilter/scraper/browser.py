"""Shared headless browser (Playwright) for platforms that need JS rendering.

Usage::

    async with get_page() as page:
        await page.goto("https://example.com")
        html = await page.content()

The browser instance is created lazily and reused across calls.
Call ``shutdown()`` during app teardown to close it.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

logger = logging.getLogger(__name__)

_browser: Any = None
_playwright: Any = None
_lock = asyncio.Lock()


async def _ensure_browser() -> Any:
    """Lazily start Playwright and launch a headless Chromium browser."""
    global _browser, _playwright  # noqa: PLW0603
    if _browser is not None:
        return _browser

    async with _lock:
        # Double-check after acquiring lock
        if _browser is not None:
            return _browser

        from playwright.async_api import async_playwright

        _playwright = await async_playwright().start()
        _browser = await _playwright.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
            ],
        )
        logger.info("Playwright browser started")
        return _browser


@asynccontextmanager
async def get_page() -> AsyncIterator[Any]:
    """Yield a new browser page, close it on exit."""
    browser = await _ensure_browser()
    context = await browser.new_context(
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        locale="en-US",
    )
    page = await context.new_page()
    try:
        yield page
    finally:
        await page.close()
        await context.close()


async def shutdown() -> None:
    """Close the shared browser. Call during app teardown."""
    global _browser, _playwright  # noqa: PLW0603
    if _browser:
        await _browser.close()
        _browser = None
    if _playwright:
        await _playwright.stop()
        _playwright = None
        logger.info("Playwright browser stopped")

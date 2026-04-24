"""Async helper for reading the remaining balance on an OpenRouter API key.

Used by ``MonitorService.balances()``. Single endpoint, single method,
5-minute in-memory TTL cache so the dashboard's 30s polling doesn't
hammer OpenRouter.

Graceful fallback: network errors and 401 return ``None`` so the
dashboard can show "—" instead of crashing.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CREDITS_URL = "https://openrouter.ai/api/v1/credits"
TIMEOUT = 10.0
CACHE_TTL = 300.0
# /credits responds with a handful of bytes; a generous 100 KB cap still
# stops us from buffering a runaway / MitM'd response into memory.
MAX_RESPONSE_BYTES = 100_000


@dataclass
class _Cached:
    value: dict[str, Any] | None
    fetched_at: float


_cache: dict[str, _Cached] = {}


async def fetch_credits(api_key: str) -> dict[str, Any] | None:
    """Return ``{"remaining": float, "total_used": float}`` or ``None``.

    OpenRouter's response shape is ``{"data": {"total_credits": N,
    "total_usage": M}}`` — we compute remaining as the difference.
    """
    if not api_key:
        return None

    cached = _cache.get(api_key)
    if cached and (time.time() - cached.fetched_at) < CACHE_TTL:
        return cached.value

    headers = {"Authorization": f"Bearer {api_key}"}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            resp = await client.get(CREDITS_URL, headers=headers)
    except httpx.HTTPError as e:
        logger.warning("openrouter: fetch_credits failed: %s", e)
        return None

    if resp.status_code == 401:
        logger.warning("openrouter: 401 — invalid key")
        _cache[api_key] = _Cached(None, time.time())
        return None
    if resp.status_code >= 400:
        logger.warning("openrouter: %d on /credits: %s", resp.status_code, resp.text[:200])
        return None

    if len(resp.content) > MAX_RESPONSE_BYTES:
        logger.warning("openrouter: response too large (%d bytes) — dropping", len(resp.content))
        return None
    try:
        payload = resp.json()
    except ValueError:
        logger.warning("openrouter: non-JSON response")
        return None

    data = payload.get("data", payload) if isinstance(payload, dict) else {}
    total_credits = float(data.get("total_credits", 0.0) or 0.0)
    total_usage = float(data.get("total_usage", 0.0) or 0.0)
    result = {
        "remaining": max(0.0, total_credits - total_usage),
        "total_used": total_usage,
    }
    _cache[api_key] = _Cached(result, time.time())
    return result


def clear_cache() -> None:
    _cache.clear()

"""Thin async wrapper around the ProxyLine REST API.

Documentation: https://dev.proxyline.net/api/
Base URL: https://panel.proxyline.net/api/
Auth: ``API-KEY`` HTTP header.
Rate limit: 50 requests per minute.

We deliberately do NOT pull the ``proxyline-api`` PyPI package — it
sits behind a Cloudflare challenge in the browser and brings a
heavier transitive footprint than we need. Everything here is a
hundred lines of httpx.

Admin-pool only: the Monitor service / syncer / UI buttons that
call this client live under ``/admin/*`` mounts with the
``require_admin`` dep. Power-users never see this code path.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

import httpx

logger = logging.getLogger(__name__)

BASE_URL = "https://panel.proxyline.net/api"
DEFAULT_TIMEOUT = 15.0
# Cap on response body we're willing to parse. ProxyLine's list endpoints
# return a few KB per proxy; a 1 MB ceiling fits tens of thousands of
# rows with plenty of slack, and shields us from buffering a runaway
# (or MitM'd) response into memory inside the event loop.
MAX_RESPONSE_BYTES = 1_000_000


class ProxylineError(Exception):
    """Any failed ProxyLine API call (network, 4xx, 5xx, malformed)."""


@dataclass
class _CachedValue:
    value: Any
    fetched_at: float

    def is_fresh(self, ttl: float) -> bool:
        return (time.time() - self.fetched_at) < ttl


class ProxylineClient:
    """Async ProxyLine client — one instance per process.

    The client is deliberately stateless across calls besides an
    in-memory TTL cache. TTLs:
      - balance: 5 min (admin doesn't need sub-minute accuracy)
      - proxies: 10 min (we re-sync explicitly after renew/purchase)
      - countries: 24h (they almost never change)
    """

    BALANCE_TTL = 300.0
    PROXIES_TTL = 600.0
    COUNTRIES_TTL = 86400.0

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._cache: dict[str, _CachedValue] = {}
        # Serialise writes that invalidate the cache.
        self._cache_lock = asyncio.Lock()

    # ---- low-level --------------------------------------------------

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        data: dict[str, Any] | None = None,
    ) -> Any:
        url = f"{self._base_url}/{path.lstrip('/')}"
        headers = {"API-KEY": self._api_key, "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.request(method, url, params=params, data=data, headers=headers)
        except httpx.HTTPError as e:
            raise ProxylineError(f"ProxyLine {method} {path}: {e}") from e

        if resp.status_code == 401:
            raise ProxylineError("ProxyLine: invalid API key (401)")
        if resp.status_code >= 400:
            body = resp.text[:400]
            raise ProxylineError(f"ProxyLine {resp.status_code} on {path}: {body}")

        if len(resp.content) > MAX_RESPONSE_BYTES:
            raise ProxylineError(
                f"ProxyLine {path}: response too large ({len(resp.content)} bytes)"
            )
        try:
            return resp.json()
        except ValueError as e:
            raise ProxylineError(f"ProxyLine: non-JSON response from {path}") from e

    # ---- balance ----------------------------------------------------

    async def get_balance(self) -> dict[str, float]:
        """Return ``{"main": float, "affiliate": float}``.

        ProxyLine's ``/balance/`` returns the raw numbers; we don't
        assume currency (docs call it USD for dedicated proxies).
        """
        cached = self._cache.get("balance")
        if cached and cached.is_fresh(self.BALANCE_TTL):
            return cached.value  # type: ignore[no-any-return]

        data = await self._request("GET", "/balance/")
        parsed = {
            "main": float(data.get("balance", 0.0) or 0.0),
            "affiliate": float(data.get("affiliate_balance", 0.0) or 0.0),
        }
        async with self._cache_lock:
            self._cache["balance"] = _CachedValue(parsed, time.time())
        return parsed

    # ---- proxies ----------------------------------------------------

    async def list_proxies(self, status: str = "active") -> list[dict[str, Any]]:
        """Return list of active proxies with expiry dates."""
        key = f"proxies:{status}"
        cached = self._cache.get(key)
        if cached and cached.is_fresh(self.PROXIES_TTL):
            return cached.value  # type: ignore[no-any-return]

        data = await self._request("GET", "/proxies/", params={"status": status})
        items_raw = data.get("results", data) if isinstance(data, dict) else data
        items: list[dict[str, Any]] = items_raw if isinstance(items_raw, list) else []
        async with self._cache_lock:
            self._cache[key] = _CachedValue(items, time.time())
        return items

    async def list_countries(self) -> list[dict[str, Any]]:
        cached = self._cache.get("countries")
        if cached and cached.is_fresh(self.COUNTRIES_TTL):
            return cached.value  # type: ignore[no-any-return]

        data = await self._request("GET", "/countries/")
        items_raw = data if isinstance(data, list) else data.get("results", [])
        items: list[dict[str, Any]] = items_raw if isinstance(items_raw, list) else []
        async with self._cache_lock:
            self._cache["countries"] = _CachedValue(items, time.time())
        return items

    async def preview_order(
        self,
        country: str,
        quantity: int,
        period: int,
        *,
        type_: str = "dedicated",
        ip_version: int = 4,
    ) -> dict[str, Any]:
        """Calculate cost without placing the order."""
        result = await self._request(
            "POST",
            "/new-order-amount/",
            data={
                "country": country,
                "quantity": quantity,
                "period": period,
                "type": type_,
                "ip_version": ip_version,
            },
        )
        return result if isinstance(result, dict) else {}

    async def create_order(
        self,
        country: str,
        quantity: int,
        period: int,
        *,
        type_: str = "dedicated",
        ip_version: int = 4,
    ) -> dict[str, Any]:
        """Place a new order. Cache gets invalidated (balance/proxies stale)."""
        result = await self._request(
            "POST",
            "/new-order/",
            data={
                "country": country,
                "quantity": quantity,
                "period": period,
                "type": type_,
                "ip_version": ip_version,
            },
        )
        await self._invalidate(("balance", "proxies:active"))
        return result  # type: ignore[no-any-return]

    async def renew(self, proxy_ids: list[int], period: int) -> dict[str, Any]:
        """Extend existing proxies (stored as ``proxyline_id`` locally)."""
        # ProxyLine expects repeated ``proxies`` params; httpx handles lists.
        result = await self._request(
            "POST",
            "/renew/",
            data={"proxies": proxy_ids, "period": period},
        )
        await self._invalidate(("balance", "proxies:active"))
        return result  # type: ignore[no-any-return]

    # ---- cache maintenance ------------------------------------------

    async def _invalidate(self, keys: tuple[str, ...]) -> None:
        async with self._cache_lock:
            for k in keys:
                self._cache.pop(k, None)


# ---------------------------------------------------------------------------
# Module-level instance — constructed lazily with the API key from
# app_settings. Reset when the admin changes the key.
#
# Access is guarded by ``threading.Lock`` (not ``asyncio.Lock``) because
# callers live in **both** sync and async contexts: the hourly syncer
# awaits this singleton, while the FastAPI form handler for the admin
# settings page calls it synchronously after saving. Using a threading
# lock keeps a single coherent story for both. Contention is negligible
# (rotation is rare, reads are fast pointer dereferences).
# ---------------------------------------------------------------------------

_client: ProxylineClient | None = None
_client_key_fingerprint: str | None = None
_client_lock = threading.Lock()


def get_proxyline_client(api_key: str | None) -> ProxylineClient | None:
    """Return a cached client bound to ``api_key``. ``None`` when no
    key is configured — callers should treat this as "integration
    disabled"."""
    global _client, _client_key_fingerprint
    with _client_lock:
        if not api_key:
            _client = None
            _client_key_fingerprint = None
            return None
        # Rebuild when the admin rotates the key.
        if _client is None or _client_key_fingerprint != api_key:
            _client = ProxylineClient(api_key)
            _client_key_fingerprint = api_key
        return _client

"""ProxylineClient — thin REST wrapper tests.

Covers: auth header, endpoint shapes, TTL cache, graceful errors,
cache invalidation after writes. All network traffic is faked via
``httpx.MockTransport`` so no live calls leave the test.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest

from chatfilter.service.proxyline_client import (
    BASE_URL,
    ProxylineClient,
    ProxylineError,
    get_proxyline_client,
)


def _make_client(handler, *, api_key: str = "tst-key", timeout: float = 5.0) -> ProxylineClient:
    """Build a client whose requests are routed through a MockTransport.

    Monkeypatches ``httpx.AsyncClient`` to use the mock transport so the
    client's internal ``async with httpx.AsyncClient(...)`` pattern
    transparently hits our handler.
    """
    transport = httpx.MockTransport(handler)
    client = ProxylineClient(api_key, timeout=timeout)

    # Wrap AsyncClient so every instantiation gets our transport.
    original = httpx.AsyncClient

    class _Wrapped(original):  # type: ignore[misc,valid-type]
        def __init__(self, *a: Any, **kw: Any) -> None:
            kw["transport"] = transport
            super().__init__(*a, **kw)

    httpx.AsyncClient = _Wrapped  # type: ignore[misc]

    # Restore on first garbage/test teardown via finalizer pattern isn't
    # available here; rely on fixture teardown in tests below to restore.
    client._restore_async_client = lambda: setattr(httpx, "AsyncClient", original)  # type: ignore[attr-defined]
    return client


@pytest.fixture
def mock_httpx(monkeypatch):
    """Yield a registrar that lets each test set its own handler."""
    original = httpx.AsyncClient
    state: dict[str, Any] = {"handler": None, "calls": []}

    def handler(request: httpx.Request) -> httpx.Response:
        state["calls"].append(request)
        fn = state["handler"]
        assert fn is not None, "test forgot to set handler"
        return fn(request)

    transport = httpx.MockTransport(handler)

    class _Wrapped(original):  # type: ignore[misc,valid-type]
        def __init__(self, *a: Any, **kw: Any) -> None:
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _Wrapped)

    def set_handler(fn):
        state["handler"] = fn

    yield state, set_handler


# ---------------------------------------------------------------------------
# Auth + request shape
# ---------------------------------------------------------------------------


class TestRequestShape:
    @pytest.mark.asyncio
    async def test_sends_api_key_header(self, mock_httpx) -> None:
        state, set_handler = mock_httpx

        def _h(req: httpx.Request) -> httpx.Response:
            assert req.headers.get("API-KEY") == "tst-key"
            return httpx.Response(200, json={"balance": 0, "affiliate_balance": 0})

        set_handler(_h)
        c = ProxylineClient("tst-key")
        await c.get_balance()
        assert len(state["calls"]) == 1

    @pytest.mark.asyncio
    async def test_uses_panel_base_url(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, json={"balance": 0}))
        c = ProxylineClient("k")
        await c.get_balance()
        assert str(state["calls"][0].url).startswith(BASE_URL)


# ---------------------------------------------------------------------------
# Balance
# ---------------------------------------------------------------------------


class TestBalance:
    @pytest.mark.asyncio
    async def test_parses_main_and_affiliate(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(
            lambda r: httpx.Response(200, json={"balance": "42.5", "affiliate_balance": 3.0})
        )
        c = ProxylineClient("k")
        b = await c.get_balance()
        assert b == {"main": 42.5, "affiliate": 3.0}

    @pytest.mark.asyncio
    async def test_defaults_when_fields_missing(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, json={}))
        c = ProxylineClient("k")
        b = await c.get_balance()
        assert b == {"main": 0.0, "affiliate": 0.0}

    @pytest.mark.asyncio
    async def test_401_raises_proxyline_error(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(401, json={"error": "nope"}))
        c = ProxylineClient("bad")
        with pytest.raises(ProxylineError, match="invalid API key"):
            await c.get_balance()

    @pytest.mark.asyncio
    async def test_cache_hit_skips_network(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, json={"balance": 1.0, "affiliate_balance": 0.0}))
        c = ProxylineClient("k")
        await c.get_balance()
        await c.get_balance()
        assert len(state["calls"]) == 1, "second call must hit cache"

    @pytest.mark.asyncio
    async def test_cache_expires_after_ttl(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, json={"balance": 1.0}))
        c = ProxylineClient("k")
        await c.get_balance()
        # Age the cache beyond TTL.
        c._cache["balance"].fetched_at = time.time() - (c.BALANCE_TTL + 1)
        await c.get_balance()
        assert len(state["calls"]) == 2


# ---------------------------------------------------------------------------
# List endpoints
# ---------------------------------------------------------------------------


class TestListProxies:
    @pytest.mark.asyncio
    async def test_returns_list_from_results_envelope(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(
            lambda r: httpx.Response(
                200,
                json={"results": [{"id": 1, "ip": "1.1.1.1"}]},
            )
        )
        c = ProxylineClient("k")
        items = await c.list_proxies()
        assert items == [{"id": 1, "ip": "1.1.1.1"}]

    @pytest.mark.asyncio
    async def test_returns_list_when_api_returns_bare_list(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, json=[{"id": 5}]))
        c = ProxylineClient("k")
        items = await c.list_proxies()
        assert items == [{"id": 5}]

    @pytest.mark.asyncio
    async def test_cache_keyed_by_status(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, json={"results": []}))
        c = ProxylineClient("k")
        await c.list_proxies(status="active")
        await c.list_proxies(status="expired")
        # Different status → different cache key → two network calls.
        assert len(state["calls"]) == 2


class TestListCountries:
    @pytest.mark.asyncio
    async def test_accepts_bare_list(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, json=[{"code": "US"}]))
        c = ProxylineClient("k")
        assert await c.list_countries() == [{"code": "US"}]

    @pytest.mark.asyncio
    async def test_accepts_results_envelope(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, json={"results": [{"code": "DE"}]}))
        c = ProxylineClient("k")
        assert await c.list_countries() == [{"code": "DE"}]


# ---------------------------------------------------------------------------
# Write endpoints + cache invalidation
# ---------------------------------------------------------------------------


class TestWrites:
    @pytest.mark.asyncio
    async def test_renew_invalidates_balance_and_proxies_cache(self, mock_httpx) -> None:
        state, set_handler = mock_httpx

        def _h(req: httpx.Request) -> httpx.Response:
            path = req.url.path
            if path.endswith("/balance/"):
                return httpx.Response(200, json={"balance": 10.0})
            if path.endswith("/proxies/"):
                return httpx.Response(200, json={"results": [{"id": 1}]})
            if path.endswith("/renew/"):
                return httpx.Response(200, json={"order_id": 77})
            return httpx.Response(404)

        set_handler(_h)
        c = ProxylineClient("k")
        # Warm caches.
        await c.get_balance()
        await c.list_proxies()
        assert "balance" in c._cache
        assert "proxies:active" in c._cache

        await c.renew([1, 2], period=30)

        # Cache cleared — next reads hit network again.
        assert "balance" not in c._cache
        assert "proxies:active" not in c._cache

    @pytest.mark.asyncio
    async def test_create_order_also_invalidates(self, mock_httpx) -> None:
        _, set_handler = mock_httpx

        def _h(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/balance/"):
                return httpx.Response(200, json={"balance": 5.0})
            return httpx.Response(200, json={"order_id": 1})

        set_handler(_h)
        c = ProxylineClient("k")
        await c.get_balance()
        assert "balance" in c._cache
        await c.create_order("US", 1, 30)
        assert "balance" not in c._cache

    @pytest.mark.asyncio
    async def test_preview_order_does_not_invalidate(self, mock_httpx) -> None:
        _, set_handler = mock_httpx

        def _h(req: httpx.Request) -> httpx.Response:
            if req.url.path.endswith("/balance/"):
                return httpx.Response(200, json={"balance": 5.0})
            return httpx.Response(200, json={"amount": "3.50", "currency": "USD"})

        set_handler(_h)
        c = ProxylineClient("k")
        await c.get_balance()
        await c.preview_order("US", 1, 30)
        assert "balance" in c._cache, "preview is read-only, must not invalidate"


# ---------------------------------------------------------------------------
# Error shapes
# ---------------------------------------------------------------------------


class TestErrors:
    @pytest.mark.asyncio
    async def test_network_error_wraps_into_proxyline_error(self, monkeypatch: Any) -> None:
        original = httpx.AsyncClient

        def _boom(*a: Any, **kw: Any):
            raise httpx.ConnectError("nope")

        class _Wrapped(original):  # type: ignore[misc,valid-type]
            async def request(self, *a: Any, **kw: Any):  # type: ignore[override]
                _boom()

        monkeypatch.setattr(httpx, "AsyncClient", _Wrapped)
        c = ProxylineClient("k")
        with pytest.raises(ProxylineError):
            await c.get_balance()

    @pytest.mark.asyncio
    async def test_non_json_body_raises(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, content=b"<html>nope</html>"))
        c = ProxylineClient("k")
        with pytest.raises(ProxylineError, match="non-JSON"):
            await c.get_balance()

    @pytest.mark.asyncio
    async def test_5xx_raises_with_status(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(503, content=b"upstream down"))
        c = ProxylineClient("k")
        with pytest.raises(ProxylineError, match="503"):
            await c.get_balance()

    @pytest.mark.asyncio
    async def test_oversized_response_rejected(self, mock_httpx) -> None:
        """A hostile / buggy upstream returning megabytes must not be
        buffered into memory by our client."""
        from chatfilter.service.proxyline_client import MAX_RESPONSE_BYTES

        _, set_handler = mock_httpx
        big_body = b'{"padding":"' + b"x" * (MAX_RESPONSE_BYTES + 10) + b'"}'
        set_handler(lambda r: httpx.Response(200, content=big_body))
        c = ProxylineClient("k")
        with pytest.raises(ProxylineError, match="too large"):
            await c.get_balance()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------


class TestSingleton:
    def test_none_when_no_key(self) -> None:
        assert get_proxyline_client(None) is None
        assert get_proxyline_client("") is None

    def test_reuses_instance_for_same_key(self) -> None:
        a = get_proxyline_client("same")
        b = get_proxyline_client("same")
        assert a is b

    def test_rebuilds_on_key_rotation(self) -> None:
        a = get_proxyline_client("first")
        b = get_proxyline_client("second")
        assert a is not b

    def test_none_clears_cached_instance(self) -> None:
        get_proxyline_client("x")
        assert get_proxyline_client(None) is None
        # Next non-empty call builds a fresh instance.
        fresh = get_proxyline_client("x")
        assert fresh is not None

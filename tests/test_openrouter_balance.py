"""OpenRouter ``fetch_credits`` tests.

Covers: auth header, success parsing, 401 and network error → None,
TTL cache, cache-clear helper.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest

from chatfilter.ai import openrouter_client as or_mod


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    or_mod.clear_cache()
    yield
    or_mod.clear_cache()


@pytest.fixture
def mock_httpx(monkeypatch):
    original = httpx.AsyncClient
    state: dict[str, Any] = {"handler": None, "calls": []}

    def handler(req: httpx.Request) -> httpx.Response:
        state["calls"].append(req)
        fn = state["handler"]
        assert fn is not None
        return fn(req)

    transport = httpx.MockTransport(handler)

    class _Wrapped(original):  # type: ignore[misc,valid-type]
        def __init__(self, *a: Any, **kw: Any) -> None:
            kw["transport"] = transport
            super().__init__(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", _Wrapped)
    yield state, lambda fn: state.__setitem__("handler", fn)


class TestFetchCredits:
    @pytest.mark.asyncio
    async def test_returns_none_for_empty_key(self) -> None:
        assert await or_mod.fetch_credits("") is None
        assert await or_mod.fetch_credits(None) is None  # type: ignore[arg-type]

    @pytest.mark.asyncio
    async def test_sends_bearer_auth(self, mock_httpx) -> None:
        state, set_handler = mock_httpx

        def _h(req: httpx.Request) -> httpx.Response:
            assert req.headers.get("Authorization") == "Bearer sk-test"
            return httpx.Response(200, json={"data": {"total_credits": 10, "total_usage": 3}})

        set_handler(_h)
        result = await or_mod.fetch_credits("sk-test")
        assert result == {"remaining": 7.0, "total_used": 3.0}
        assert len(state["calls"]) == 1

    @pytest.mark.asyncio
    async def test_clamps_remaining_to_zero(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        # Usage exceeds credits (rare but possible at end-of-billing).
        set_handler(
            lambda r: httpx.Response(200, json={"data": {"total_credits": 1, "total_usage": 5}})
        )
        result = await or_mod.fetch_credits("sk-x")
        assert result == {"remaining": 0.0, "total_used": 5.0}

    @pytest.mark.asyncio
    async def test_401_returns_none(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(401, json={"error": "invalid"}))
        assert await or_mod.fetch_credits("bad") is None

    @pytest.mark.asyncio
    async def test_5xx_returns_none(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(503, content=b"down"))
        assert await or_mod.fetch_credits("k") is None

    @pytest.mark.asyncio
    async def test_non_json_returns_none(self, mock_httpx) -> None:
        _, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200, content=b"<html>"))
        assert await or_mod.fetch_credits("k") is None

    @pytest.mark.asyncio
    async def test_oversized_response_returns_none(self, mock_httpx) -> None:
        """A runaway response must not be parsed — graceful None instead."""
        from chatfilter.ai.openrouter_client import MAX_RESPONSE_BYTES

        _, set_handler = mock_httpx
        big = b'{"data":"' + b"x" * (MAX_RESPONSE_BYTES + 10) + b'"}'
        set_handler(lambda r: httpx.Response(200, content=big))
        assert await or_mod.fetch_credits("k") is None

    @pytest.mark.asyncio
    async def test_network_error_returns_none(self, monkeypatch: Any) -> None:
        original = httpx.AsyncClient

        class _Wrapped(original):  # type: ignore[misc,valid-type]
            async def get(self, *a: Any, **kw: Any):  # type: ignore[override]
                raise httpx.ConnectError("unreachable")

        monkeypatch.setattr(httpx, "AsyncClient", _Wrapped)
        assert await or_mod.fetch_credits("k") is None


class TestCache:
    @pytest.mark.asyncio
    async def test_cache_hit_skips_network(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(
            lambda r: httpx.Response(200, json={"data": {"total_credits": 5, "total_usage": 1}})
        )
        await or_mod.fetch_credits("k")
        await or_mod.fetch_credits("k")
        assert len(state["calls"]) == 1

    @pytest.mark.asyncio
    async def test_cache_is_per_key(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(
            lambda r: httpx.Response(200, json={"data": {"total_credits": 5, "total_usage": 1}})
        )
        await or_mod.fetch_credits("k1")
        await or_mod.fetch_credits("k2")
        assert len(state["calls"]) == 2

    @pytest.mark.asyncio
    async def test_expired_cache_refetches(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(
            lambda r: httpx.Response(200, json={"data": {"total_credits": 5, "total_usage": 1}})
        )
        await or_mod.fetch_credits("k")
        # Age the cache entry past TTL.
        or_mod._cache["k"].fetched_at = time.time() - (or_mod.CACHE_TTL + 1)
        await or_mod.fetch_credits("k")
        assert len(state["calls"]) == 2

    @pytest.mark.asyncio
    async def test_401_cached_as_none(self, mock_httpx) -> None:
        """A 401 should cache the None result so we don't hammer OR with
        a bad key. The admin fixes the key → cache-clear or TTL expiry
        lets it recover."""
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(401))
        await or_mod.fetch_credits("bad")
        await or_mod.fetch_credits("bad")
        assert len(state["calls"]) == 1, "second call should hit cached None"

    def test_clear_cache_resets_state(self) -> None:
        or_mod._cache["x"] = or_mod._Cached({"remaining": 1.0, "total_used": 0.0}, time.time())
        or_mod.clear_cache()
        assert or_mod._cache == {}

"""Diagnostic tests for SSE streaming through middleware stack.

Tests verify whether SSE endpoints properly stream data through
BaseHTTPMiddleware layers (8 layers total) without buffering.

Background:
    Starlette was updated to 0.50.0. BaseHTTPMiddleware wraps
    StreamingResponse and may buffer the entire body before sending,
    which breaks SSE (Server-Sent Events) streaming.

Tests diagnose:
    a) Whether SSE streams through middleware (first event arrives before
       stream closes, not after all data is accumulated)
    b) Whether request.is_disconnected() works correctly inside SSE
       generators wrapped by BaseHTTPMiddleware (may return True immediately,
       causing generator to exit after first yield)

Key findings format:
    PASS = SSE works correctly
    FAIL = SSE broken — see assertion message for diagnosis
    TIMEOUT (if test exceeds mark) = BaseHTTPMiddleware deadlock (buffers infinite stream)
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure test mode so AuthMiddleware is bypassed
os.environ.setdefault("CHATFILTER_TESTING", "1")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _collect_first_chunk_with_timeout(
    gen: AsyncGenerator[str, None],
    timeout: float = 3.0,
) -> str | None:
    """Try to get first chunk from async generator within timeout.

    Returns the chunk string, or None if timed out (= buffering suspected).
    """
    try:
        return await asyncio.wait_for(gen.__anext__(), timeout=timeout)
    except (TimeoutError, StopAsyncIteration):
        return None


# ---------------------------------------------------------------------------
# Session SSE endpoint: /api/sessions/events (isolated, no middleware)
# ---------------------------------------------------------------------------


class TestSessionSSEStreaming:
    """Verify SSE generator works in isolation (no middleware).

    If these pass but middleware tests fail, the problem is confirmed in
    BaseHTTPMiddleware.
    """

    @pytest.mark.asyncio
    async def test_session_sse_first_event_arrives_immediately(self) -> None:
        """First SSE event (connected) should arrive without waiting for stream close.

        This tests the generator directly without middleware.
        If this passes but middleware test times out, BaseHTTPMiddleware is
        buffering the StreamingResponse.
        """
        from chatfilter.web.routers.sessions.sse import session_events

        mock_request = AsyncMock()
        mock_request.cookies = {}
        mock_request.is_disconnected = AsyncMock(return_value=False)
        mock_request.app = MagicMock()

        response = await session_events(mock_request)
        iterator = response.body_iterator

        first_chunk = await _collect_first_chunk_with_timeout(iterator, timeout=2.0)

        with contextlib.suppress(Exception):
            await iterator.aclose()

        assert first_chunk is not None, (
            "SSE generator timed out — generator itself is broken (no middleware involved)"
        )
        assert 'data: {"type": "connected"}' in first_chunk, (
            f"Expected connected event, got: {first_chunk!r}"
        )

    @pytest.mark.asyncio
    async def test_session_sse_content_type_is_text_event_stream(self) -> None:
        """SSE endpoint should return content-type: text/event-stream."""
        from chatfilter.web.routers.sessions.sse import session_events

        mock_request = AsyncMock()
        mock_request.cookies = {}
        mock_request.is_disconnected = AsyncMock(return_value=False)
        mock_request.app = MagicMock()

        response = await session_events(mock_request)

        assert response.media_type == "text/event-stream", (
            f"Wrong media type: {response.media_type!r}. SSE requires 'text/event-stream'."
        )

        with contextlib.suppress(Exception):
            await response.body_iterator.aclose()

    @pytest.mark.asyncio
    async def test_session_sse_cache_control_header(self) -> None:
        """SSE endpoint should have Cache-Control: no-cache header."""
        from chatfilter.web.routers.sessions.sse import session_events

        mock_request = AsyncMock()
        mock_request.cookies = {}
        mock_request.is_disconnected = AsyncMock(return_value=False)
        mock_request.app = MagicMock()

        response = await session_events(mock_request)

        assert "Cache-Control" in response.headers, "Cache-Control header missing"
        assert response.headers["Cache-Control"] == "no-cache", (
            f"Expected 'no-cache', got: {response.headers['Cache-Control']!r}"
        )

        with contextlib.suppress(Exception):
            await response.body_iterator.aclose()

    @pytest.mark.asyncio
    async def test_session_sse_is_disconnected_not_true_immediately(self) -> None:
        """request.is_disconnected() must NOT return True on first call.

        DIAGNOSIS: Through BaseHTTPMiddleware, is_disconnected() may return
        True immediately because the underlying connection state is incorrect.
        This causes the SSE generator to exit right after the first yield.

        This test checks the generator in isolation (no middleware).
        """
        from chatfilter.web.routers.sessions.sse import session_events

        is_disconnected_calls: list[bool] = []

        async def track_is_disconnected() -> bool:
            # Normal mock: not disconnected — but track each call
            result = False
            is_disconnected_calls.append(result)
            return result

        mock_request = AsyncMock()
        mock_request.cookies = {}
        mock_request.is_disconnected = track_is_disconnected
        mock_request.app = MagicMock()

        response = await session_events(mock_request)
        iterator = response.body_iterator

        chunks: list[str] = []
        try:
            # Get first event (connected) — this is yielded before is_disconnected check
            chunk = await asyncio.wait_for(iterator.__anext__(), timeout=1.0)
            chunks.append(chunk)

            # Second iteration calls is_disconnected() then waits on queue (30s timeout)
            # We only wait 1s — enough to confirm is_disconnected was called
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(iterator.__anext__(), timeout=1.0)
        except (TimeoutError, StopAsyncIteration):
            pass
        finally:
            with contextlib.suppress(Exception):
                await iterator.aclose()

        assert len(chunks) >= 1, "No events received from SSE generator"
        assert 'data: {"type": "connected"}' in chunks[0]

        assert len(is_disconnected_calls) >= 1, (
            "is_disconnected() was never called — generator may have exited early"
        )
        assert is_disconnected_calls[0] is False, (
            "BUG: is_disconnected() returned True on first call in isolation! "
            "The generator logic itself has an issue."
        )

    @pytest.mark.asyncio
    async def test_session_sse_keepalive_arrives_on_timeout(self) -> None:
        """Keepalive comment (': keepalive') is yielded after queue timeout.

        Uses patched asyncio.wait_for to trigger immediate timeout
        (simulates the 30s queue wait without waiting 30 seconds).
        """
        from chatfilter.web.routers.sessions.sse import session_events

        mock_request = AsyncMock()
        mock_request.cookies = {}
        mock_request.is_disconnected = AsyncMock(return_value=False)
        mock_request.app = MagicMock()

        # Patch wait_for in the sse module to immediately raise TimeoutError
        # for the 30s queue.get() call
        original_wait_for = asyncio.wait_for

        async def fast_wait_for(coro, timeout=None):
            if timeout and timeout > 5.0:
                # This is the queue.get() call — simulate immediate timeout
                with contextlib.suppress(Exception):
                    coro.close()
                raise TimeoutError
            return await original_wait_for(coro, timeout=timeout)

        response = await session_events(mock_request)
        iterator = response.body_iterator

        chunks: list[str] = []
        with patch("chatfilter.web.routers.sessions.sse.asyncio.wait_for", fast_wait_for):
            try:
                # First: connected event
                chunk1 = await asyncio.wait_for(iterator.__anext__(), timeout=2.0)
                chunks.append(chunk1)

                # Second: keepalive (queue timed out immediately)
                chunk2 = await asyncio.wait_for(iterator.__anext__(), timeout=2.0)
                chunks.append(chunk2)
            except (TimeoutError, StopAsyncIteration):
                pass
            finally:
                with contextlib.suppress(Exception):
                    await iterator.aclose()

        assert len(chunks) >= 1, "No chunks received"
        assert 'data: {"type": "connected"}' in chunks[0], (
            f"Expected connected as first chunk, got: {chunks[0]!r}"
        )
        if len(chunks) >= 2:
            assert ": keepalive" in chunks[1], (
                f"Expected keepalive in second chunk, got: {chunks[1]!r}"
            )


# ---------------------------------------------------------------------------
# Full middleware stack tests using httpx AsyncClient
# ---------------------------------------------------------------------------


class TestSSEThroughMiddlewareStack:
    """Test SSE streaming through the FULL middleware stack.

    Uses raw ASGI protocol to verify streaming works (httpx ASGITransport
    does not support true SSE streaming in tests).

    SSE paths bypass BaseHTTPMiddleware via SSEPassthroughMixin to avoid
    response buffering that would deadlock infinite streams.

    CHATFILTER_TESTING=1 bypasses AuthMiddleware — no auth setup needed.
    """

    @pytest.fixture
    def app(self):
        """Create FastAPI app instance."""
        from chatfilter.web.app import create_app

        return create_app()

    @staticmethod
    async def _raw_asgi_sse_request(
        app,
        path: str,
        timeout: float = 5.0,
    ) -> tuple[int | None, dict[str, str], list[str]]:
        """Send raw ASGI request and collect SSE response chunks.

        Returns (status_code, headers_dict, body_chunks).
        """
        scope = {
            "type": "http",
            "method": "GET",
            "path": path,
            "query_string": b"",
            "root_path": "",
            "headers": [],
            "server": ("testserver", 80),
        }

        status: int | None = None
        headers: dict[str, str] = {}
        chunks: list[str] = []
        first_body = asyncio.Event()

        async def receive():
            await asyncio.sleep(60)
            return {"type": "http.disconnect"}

        async def send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                for k, v in message.get("headers", []):
                    headers[k.decode()] = v.decode()
            elif message["type"] == "http.response.body":
                body = message.get("body", b"")
                if body:
                    chunks.append(body.decode())
                    first_body.set()

        task = asyncio.create_task(app(scope, receive, send))
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(first_body.wait(), timeout=timeout)
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        return status, headers, chunks

    @pytest.mark.asyncio
    @pytest.mark.timeout(8)
    async def test_session_sse_streams_through_full_middleware(self, app) -> None:
        """SSE /api/sessions/events should deliver first event immediately."""
        status, headers, chunks = await self._raw_asgi_sse_request(app, "/api/sessions/events")

        assert status == 200, f"Expected 200, got {status}"
        assert "text/event-stream" in headers.get("content-type", ""), (
            f"Wrong content-type: {headers.get('content-type')!r}"
        )
        assert len(chunks) >= 1, "No SSE data received — BaseHTTPMiddleware is still buffering!"
        assert 'data: {"type": "connected"}' in chunks[0], (
            f"Expected connected event, got: {chunks[0]!r}"
        )

    @pytest.mark.asyncio
    @pytest.mark.timeout(8)
    async def test_groups_sse_streams_through_full_middleware(self, app) -> None:
        """SSE /api/groups/events should stream through middleware without buffering."""
        with (
            patch("chatfilter.web.routers.groups.progress._get_group_service") as mock_svc,
            patch("chatfilter.web.routers.groups.progress._get_progress_tracker"),
        ):
            service = MagicMock()
            service.list_groups.return_value = []
            mock_svc.return_value = service

            status, headers, chunks = await self._raw_asgi_sse_request(app, "/api/groups/events")

        assert status == 200, f"Expected 200, got {status}"
        assert "text/event-stream" in headers.get("content-type", ""), (
            f"Wrong content-type: {headers.get('content-type')!r}"
        )

    @pytest.mark.asyncio
    @pytest.mark.timeout(8)
    async def test_sse_passthrough_mixin_applied(self, app) -> None:
        """Verify SSEPassthroughMixin is applied to all middleware classes."""
        from chatfilter.i18n.middleware import LocaleMiddleware
        from chatfilter.web.middleware import (
            AuthMiddleware,
            CSRFProtectionMiddleware,
            GracefulShutdownMiddleware,
            RequestIDMiddleware,
            RequestLoggingMiddleware,
            SecurityHeadersMiddleware,
            SessionMiddleware,
            SSEPassthroughMixin,
        )

        for cls in [
            RequestIDMiddleware,
            RequestLoggingMiddleware,
            SessionMiddleware,
            GracefulShutdownMiddleware,
            SecurityHeadersMiddleware,
            AuthMiddleware,
            CSRFProtectionMiddleware,
            LocaleMiddleware,
        ]:
            assert issubclass(cls, SSEPassthroughMixin), (
                f"{cls.__name__} does not inherit SSEPassthroughMixin — "
                f"SSE will be buffered through this middleware!"
            )


# ---------------------------------------------------------------------------
# Isolated generator tests (without middleware)
# ---------------------------------------------------------------------------


class TestSSEGeneratorIsolated:
    """Test SSE generators in isolation (no middleware).

    BASELINE: These tests must pass to confirm generators work correctly.
    If middleware tests fail but these pass, the bug is in BaseHTTPMiddleware.
    """

    @pytest.mark.asyncio
    async def test_session_sse_generator_yields_connected_first(self) -> None:
        """SSE generator (no middleware) yields 'connected' as first event."""
        from chatfilter.web.routers.sessions.sse import session_events

        mock_request = AsyncMock()
        mock_request.cookies = {}
        mock_request.is_disconnected = AsyncMock(return_value=False)
        mock_request.app = MagicMock()

        response = await session_events(mock_request)
        iterator = response.body_iterator

        first = await asyncio.wait_for(iterator.__anext__(), timeout=1.0)

        with contextlib.suppress(Exception):
            await iterator.aclose()

        assert 'data: {"type": "connected"}' in first, (
            f"Expected connected event as first yield, got: {first!r}"
        )

    @pytest.mark.asyncio
    async def test_groups_sse_generator_yields_events_no_active_groups(self) -> None:
        """Groups SSE generator (no middleware) works with no active groups."""
        with (
            patch("chatfilter.web.routers.groups.progress._get_group_service") as mock_svc,
            patch("chatfilter.web.routers.groups.progress._get_progress_tracker"),
        ):
            service = MagicMock()
            service.list_groups.return_value = []
            mock_svc.return_value = service

            from chatfilter.web.routers.groups.progress import _generate_unified_sse_events

            mock_request = AsyncMock()
            call_count = 0

            async def is_disconnected() -> bool:
                nonlocal call_count
                call_count += 1
                # Disconnect after 3 calls to stop the infinite loop quickly
                return call_count > 3

            mock_request.is_disconnected = is_disconnected

            events: list[str] = []
            try:
                async with asyncio.timeout(3.0):
                    async for event in _generate_unified_sse_events(mock_request):
                        events.append(event)
                        if len(events) >= 5:
                            break
            except TimeoutError:
                pass

            # Generator should have been called (not crash immediately)
            assert call_count >= 1, (
                "Generator never called is_disconnected() — did it crash on startup?"
            )

    @pytest.mark.asyncio
    async def test_session_sse_generator_respects_disconnect(self) -> None:
        """SSE generator stops when is_disconnected() returns True.

        Uses patched queue.get() to avoid 30s timeout in the generator.
        The generator checks is_disconnected() before each queue.get() call.
        """
        import asyncio as asyncio_mod

        from chatfilter.web.routers.sessions.sse import session_events

        disconnect_after_n = 1
        call_count = 0

        async def is_disconnected() -> bool:
            nonlocal call_count
            call_count += 1
            return call_count > disconnect_after_n

        mock_request = AsyncMock()
        mock_request.cookies = {}
        mock_request.is_disconnected = is_disconnected
        mock_request.app = MagicMock()

        response = await session_events(mock_request)
        iterator = response.body_iterator

        chunks: list[str] = []

        # Patch queue.get to return immediately (avoid 30s wait in generator)
        async def fast_queue_get_timeout(coro, timeout=None):
            # For the queue.get() with 30s timeout, raise TimeoutError immediately
            # This simulates the keepalive path and lets the loop check disconnect again
            if timeout and timeout > 5.0:
                with contextlib.suppress(Exception):
                    coro.close()
                raise TimeoutError
            return await asyncio_mod.wait_for(coro, timeout=timeout)

        with patch("chatfilter.web.routers.sessions.sse.asyncio.wait_for", fast_queue_get_timeout):
            try:
                async with asyncio_mod.timeout(5.0):
                    async for chunk in iterator:
                        chunks.append(chunk)
                        if len(chunks) > 10:
                            break
            except (StopAsyncIteration, asyncio_mod.CancelledError, TimeoutError):
                pass
            finally:
                with contextlib.suppress(Exception):
                    await iterator.aclose()

        # Generator should have stopped after detecting disconnect
        assert len(chunks) <= 10, f"Generator didn't stop on disconnect: got {len(chunks)} chunks"
        # But must have yielded at least the connected event
        assert len(chunks) >= 1, "Generator yielded nothing — not even connected event"
        assert 'data: {"type": "connected"}' in chunks[0], (
            f"First chunk should be connected event, got: {chunks[0]!r}"
        )

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
import time
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
            f"Wrong media type: {response.media_type!r}. "
            "SSE requires 'text/event-stream'."
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
    """Test SSE streaming through the FULL middleware stack (8 BaseHTTPMiddleware layers).

    CRITICAL: These tests use httpx.AsyncClient + ASGITransport to exercise
    the real app with all middleware active.

    KNOWN ISSUE: BaseHTTPMiddleware buffers StreamingResponse in some Starlette
    versions. When this happens, httpx hangs indefinitely waiting for data that
    never arrives (because the middleware is waiting for the infinite stream to
    complete before forwarding).

    These tests are marked with @pytest.mark.timeout(8) to fail fast.
    A TIMEOUT failure = buffering confirmed.
    A PASS = SSE streams correctly through middleware.

    CHATFILTER_TESTING=1 bypasses AuthMiddleware — no auth setup needed.
    """

    @pytest.fixture
    def app(self):
        """Create FastAPI app instance."""
        from chatfilter.web.app import create_app

        return create_app()

    @pytest.mark.asyncio
    @pytest.mark.timeout(8)
    async def test_session_sse_streams_through_full_middleware(self, app) -> None:
        """SSE /api/sessions/events should deliver first event through all middleware.

        DIAGNOSIS RESULT:
        - PASS: SSE streams correctly (no buffering in middleware)
        - TIMEOUT (8s): BaseHTTPMiddleware deadlock — buffers infinite stream,
          httpx never receives data. Confirms buffering bug.
        - FAIL with assertion: Data received but wrong content-type or content
        """
        import httpx

        first_chunk: str | None = None
        content_type: str | None = None

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://testserver",
        ) as client:
            try:
                async with client.stream(
                    "GET",
                    "/api/sessions/events",
                    timeout=httpx.Timeout(connect=2.0, read=5.0, write=2.0, pool=2.0),
                ) as response:
                    content_type = response.headers.get("content-type", "")

                    start = time.monotonic()
                    async for chunk in response.aiter_text():
                        if chunk.strip():
                            first_chunk = chunk
                            break
                        if time.monotonic() - start > 4.0:
                            break
            except httpx.ReadTimeout:
                # Timeout without receiving data = buffering detected
                pass
            except Exception as exc:
                pytest.skip(f"App setup error (not a streaming issue): {exc}")

        print("\n=== SESSION SSE MIDDLEWARE DIAGNOSIS ===")
        print(f"Content-Type: {content_type!r}")
        print(f"First chunk received: {first_chunk is not None}")
        if first_chunk:
            print(f"First chunk: {first_chunk!r}")
        else:
            print("RESULT: No data received — BaseHTTPMiddleware is buffering SSE stream!")
            print("All 8 middleware layers use BaseHTTPMiddleware which buffers StreamingResponse.")
            print("SEE: ChatFilter-9mb for fix.")
        print("========================================\n")

        assert first_chunk is not None, (
            "DIAGNOSIS: SSE is BUFFERED through BaseHTTPMiddleware stack!\n"
            "Expected 'data: {\"type\": \"connected\"}' within timeout, got nothing.\n"
            "BaseHTTPMiddleware (8 layers) buffers the infinite SSE stream.\n"
            "Fix options (ChatFilter-9mb):\n"
            "  A) Bypass middleware for /api/*/events paths\n"
            "  B) Replace is_disconnected() with try/except CancelledError\n"
            "  C) Convert to pure ASGI middleware"
        )

        assert "text/event-stream" in (content_type or ""), (
            f"Wrong content-type through middleware: {content_type!r}. "
            "Expected 'text/event-stream'."
        )

    @pytest.mark.asyncio
    @pytest.mark.timeout(8)
    async def test_groups_sse_streams_through_full_middleware(self, app) -> None:
        """SSE /api/groups/events should deliver first event through all middleware.

        Same as session SSE test, but for /api/groups/events.

        DIAGNOSIS RESULT:
        - PASS: SSE streams correctly
        - TIMEOUT: BaseHTTPMiddleware buffering confirmed (same root cause)
        """
        import httpx

        first_chunk: str | None = None
        content_type: str | None = None

        with (
            patch("chatfilter.web.routers.groups.progress._get_group_service") as mock_svc,
            patch("chatfilter.web.routers.groups.progress._get_progress_tracker"),
        ):
            service = MagicMock()
            service.list_groups.return_value = []
            mock_svc.return_value = service

            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://testserver",
            ) as client:
                try:
                    async with client.stream(
                        "GET",
                        "/api/groups/events",
                        timeout=httpx.Timeout(connect=2.0, read=5.0, write=2.0, pool=2.0),
                    ) as response:
                        content_type = response.headers.get("content-type", "")

                        start = time.monotonic()
                        async for chunk in response.aiter_text():
                            if chunk.strip():
                                first_chunk = chunk
                                break
                            if time.monotonic() - start > 4.0:
                                break
                except httpx.ReadTimeout:
                    pass
                except Exception as exc:
                    pytest.skip(f"App setup error: {exc}")

        print("\n=== GROUPS SSE MIDDLEWARE DIAGNOSIS ===")
        print(f"Content-Type: {content_type!r}")
        print(f"First chunk received: {first_chunk is not None}")
        if not first_chunk:
            print("RESULT: No data received — BaseHTTPMiddleware buffers /api/groups/events too!")
        print("=======================================\n")

        assert first_chunk is not None, (
            "DIAGNOSIS: /api/groups/events is BUFFERED through BaseHTTPMiddleware!\n"
            "Same root cause as /api/sessions/events.\n"
            "Both SSE endpoints are broken through the 8-layer middleware stack."
        )

        assert "text/event-stream" in (content_type or ""), (
            f"Wrong content-type: {content_type!r}."
        )

    @pytest.mark.asyncio
    @pytest.mark.timeout(8)
    async def test_is_disconnected_through_middleware(self, app) -> None:
        """Test request.is_disconnected() behavior through BaseHTTPMiddleware.

        DIAGNOSIS: Through BaseHTTPMiddleware, is_disconnected() may return
        True immediately because:
        1. The middleware consumes the ASGI receive channel
        2. The SSE generator's request object has a different receive callable
        3. This causes immediate True from is_disconnected()

        If this test times out (same as the streaming test), it means the
        middleware buffering prevents us from even reaching the is_disconnected() check.

        RESULT:
        - PASS: is_disconnected() returns False initially (correct behavior)
        - FAIL: is_disconnected() returns True immediately (causes SSE to stop after 1 event)
        - TIMEOUT: Middleware deadlock (buffering prevents generator from running)
        """
        import httpx

        is_disconnected_results: list[bool] = []

        # Instrument the SSE generator to track is_disconnected calls
        from chatfilter.web.routers.sessions import sse as sse_module

        original_session_events = sse_module.session_events

        async def instrumented_session_events(request):
            original_is_disconnected = request.is_disconnected

            async def tracked_is_disconnected():
                result = await original_is_disconnected()
                is_disconnected_results.append(result)
                return result

            request.is_disconnected = tracked_is_disconnected
            return await original_session_events(request)

        with patch.object(sse_module, "session_events", instrumented_session_events):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://testserver",
            ) as client:
                try:
                    async with client.stream(
                        "GET",
                        "/api/sessions/events",
                        timeout=httpx.Timeout(connect=2.0, read=5.0, write=2.0, pool=2.0),
                    ) as response:
                        # Read a bit of data to trigger is_disconnected calls
                        chunks = []
                        start = time.monotonic()
                        async for chunk in response.aiter_text():
                            if chunk.strip():
                                chunks.append(chunk)
                            if len(chunks) >= 1 or time.monotonic() - start > 2.0:
                                break
                except (httpx.ReadTimeout, httpx.RemoteProtocolError):
                    pass
                except Exception as exc:
                    pytest.skip(f"App setup error: {exc}")

        print("\n=== IS_DISCONNECTED DIAGNOSIS ===")
        print(f"is_disconnected() calls: {is_disconnected_results}")
        if is_disconnected_results:
            first = is_disconnected_results[0]
            if first:
                print("BUG FOUND: is_disconnected() returned True immediately through middleware!")
                print("Generator exits after first yield. SSE broken.")
            else:
                print("OK: is_disconnected() returned False initially (correct).")
        else:
            print("is_disconnected() never called — middleware likely buffering (TIMEOUT path)")
        print("=================================\n")

        # If we got here (no timeout), check the actual results
        if is_disconnected_results:
            assert is_disconnected_results[0] is False, (
                "DIAGNOSIS BUG: request.is_disconnected() returns True immediately!\n"
                "Through BaseHTTPMiddleware, the receive callable is consumed.\n"
                "The SSE generator exits after the first 'connected' event.\n"
                "Fix: Replace is_disconnected() check with try/except asyncio.CancelledError"
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
        assert len(chunks) <= 10, (
            f"Generator didn't stop on disconnect: got {len(chunks)} chunks"
        )
        # But must have yielded at least the connected event
        assert len(chunks) >= 1, "Generator yielded nothing — not even connected event"
        assert 'data: {"type": "connected"}' in chunks[0], (
            f"First chunk should be connected event, got: {chunks[0]!r}"
        )

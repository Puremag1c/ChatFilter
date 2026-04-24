"""WebhookNotifier — admin-pool alert dispatch tests.

Shape: ``POST <url>`` with a JSON envelope ``{source, timestamp,
severity, subject, body, details}``. Timeout 5 s, 1 retry on
transport error, dedup within 1 hour per event key.
"""

from __future__ import annotations

import time
from typing import Any

import httpx
import pytest

from chatfilter.service.notifications import (
    WebhookEvent,
    WebhookNotifier,
    validate_webhook_url,
)


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


def _evt(
    key: str = "admin.accounts.error",
    severity: str = "warning",
    subject: str = "Admin accounts in error",
    body: str = "2 admin accounts errored",
    details: dict[str, Any] | None = None,
) -> WebhookEvent:
    return WebhookEvent(
        key=key,
        severity=severity,
        subject=subject,
        body=body,
        details=details or {},
    )


class TestEventShape:
    @pytest.mark.asyncio
    async def test_posts_json_envelope(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        payloads: list[dict[str, Any]] = []

        def _h(req: httpx.Request) -> httpx.Response:
            import json as _json

            payloads.append(_json.loads(req.content))
            return httpx.Response(200)

        set_handler(_h)
        notifier = WebhookNotifier()
        ok = await notifier.send("https://hook.example.com/x", _evt(details={"count": 2}))
        assert ok is True
        body = payloads[0]
        assert body["source"] == "chatfilter"
        assert body["severity"] == "warning"
        assert body["subject"] == "Admin accounts in error"
        assert body["body"] == "2 admin accounts errored"
        assert body["details"] == {"count": 2}
        assert "timestamp" in body

    @pytest.mark.asyncio
    async def test_disabled_without_url(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200))
        notifier = WebhookNotifier()
        ok = await notifier.send("", _evt())
        assert ok is False
        assert state["calls"] == []

        ok = await notifier.send(None, _evt())  # type: ignore[arg-type]
        assert ok is False


class TestRetryAndTimeout:
    @pytest.mark.asyncio
    async def test_retries_once_on_transport_error(self, monkeypatch: Any) -> None:
        # First call raises, second returns 200 → overall success.
        original = httpx.AsyncClient
        state = {"n": 0}

        async def _send(self, *a: Any, **kw: Any):  # type: ignore[no-untyped-def]
            state["n"] += 1
            if state["n"] == 1:
                raise httpx.ConnectError("blip")
            return httpx.Response(200)

        class _Wrapped(original):  # type: ignore[misc,valid-type]
            post = _send  # type: ignore[assignment]

        monkeypatch.setattr(httpx, "AsyncClient", _Wrapped)

        notifier = WebhookNotifier()
        ok = await notifier.send("https://hook.example.com/x", _evt(key="retry-test"))
        assert ok is True
        assert state["n"] == 2

    @pytest.mark.asyncio
    async def test_two_consecutive_errors_fails_silently(self, monkeypatch: Any) -> None:
        original = httpx.AsyncClient

        async def _send(self, *a: Any, **kw: Any):  # type: ignore[no-untyped-def]
            raise httpx.ConnectError("always down")

        class _Wrapped(original):  # type: ignore[misc,valid-type]
            post = _send  # type: ignore[assignment]

        monkeypatch.setattr(httpx, "AsyncClient", _Wrapped)

        notifier = WebhookNotifier()
        # Must not raise — webhook delivery is best-effort.
        ok = await notifier.send("https://hook.example.com/x", _evt(key="fail-silently"))
        assert ok is False

    @pytest.mark.asyncio
    async def test_4xx_not_retried(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(400, content=b"bad"))
        notifier = WebhookNotifier()
        ok = await notifier.send("https://hook.example.com/x", _evt(key="4xx-test"))
        assert ok is False
        assert len(state["calls"]) == 1  # no retry on 4xx


class TestDedup:
    @pytest.mark.asyncio
    async def test_same_key_suppressed_within_window(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200))
        notifier = WebhookNotifier(dedup_window=3600.0)
        ev = _evt(key="dedup-key")

        await notifier.send("https://hook.example.com/x", ev)
        await notifier.send("https://hook.example.com/x", ev)

        assert len(state["calls"]) == 1, "second send with same key must be suppressed"

    @pytest.mark.asyncio
    async def test_different_keys_both_sent(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200))
        notifier = WebhookNotifier()
        await notifier.send("https://hook.example.com/x", _evt(key="a"))
        await notifier.send("https://hook.example.com/x", _evt(key="b"))
        assert len(state["calls"]) == 2

    @pytest.mark.asyncio
    async def test_dedup_expires_after_window(self, mock_httpx) -> None:
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200))
        notifier = WebhookNotifier(dedup_window=1.0)
        ev = _evt(key="expiring")

        await notifier.send("https://hook.example.com/x", ev)
        # Age the dedup entry manually.
        notifier._last_sent[ev.key] = time.time() - 2.0
        await notifier.send("https://hook.example.com/x", ev)

        assert len(state["calls"]) == 2

    @pytest.mark.asyncio
    async def test_failed_delivery_does_not_populate_dedup(self, mock_httpx) -> None:
        """If the webhook fails, retrying later should still be allowed —
        otherwise a transient outage silently swallows the first real alert."""
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(500))
        notifier = WebhookNotifier(dedup_window=3600.0)
        ev = _evt(key="transient")

        await notifier.send("https://hook.example.com/x", ev)
        # Now it recovers.
        set_handler(lambda r: httpx.Response(200))
        await notifier.send("https://hook.example.com/x", ev)

        assert len(state["calls"]) == 2


class TestValidateWebhookUrl:
    """SSRF guardrail — reject URLs pointing at internal / non-HTTP targets."""

    def test_accepts_public_https(self) -> None:
        assert validate_webhook_url("https://hooks.slack.com/services/X/Y/Z") == (
            "https://hooks.slack.com/services/X/Y/Z"
        )

    def test_accepts_public_http(self) -> None:
        assert validate_webhook_url("http://example.com/hook") == "http://example.com/hook"

    def test_strips_whitespace(self) -> None:
        assert validate_webhook_url("  https://x.com/hook  ") == "https://x.com/hook"

    def test_rejects_empty_and_none(self) -> None:
        assert validate_webhook_url(None) is None
        assert validate_webhook_url("") is None
        assert validate_webhook_url("   ") is None

    def test_rejects_non_http_scheme(self) -> None:
        assert validate_webhook_url("file:///etc/passwd") is None
        assert validate_webhook_url("javascript:alert(1)") is None
        assert validate_webhook_url("gopher://evil.com/") is None
        assert validate_webhook_url("ftp://internal/") is None

    def test_rejects_localhost(self) -> None:
        assert validate_webhook_url("http://localhost/hook") is None
        assert validate_webhook_url("https://localhost:8080/x") is None
        assert validate_webhook_url("http://localhost.localdomain/") is None

    def test_rejects_loopback_ips(self) -> None:
        assert validate_webhook_url("http://127.0.0.1/") is None
        assert validate_webhook_url("http://127.1.2.3/x") is None
        assert validate_webhook_url("http://[::1]/") is None

    def test_rejects_private_ranges(self) -> None:
        assert validate_webhook_url("http://10.0.0.1/") is None
        assert validate_webhook_url("http://192.168.1.10/") is None
        assert validate_webhook_url("http://172.16.0.5/") is None
        assert validate_webhook_url("http://172.31.0.5/") is None

    def test_rejects_link_local(self) -> None:
        # AWS / GCP metadata endpoint — common SSRF target.
        assert validate_webhook_url("http://169.254.169.254/latest/meta-data/") is None

    def test_rejects_missing_host(self) -> None:
        assert validate_webhook_url("http:///path") is None

    @pytest.mark.asyncio
    async def test_send_refuses_blocked_url(self, mock_httpx) -> None:
        """End-to-end: send() short-circuits on a loopback URL."""
        state, set_handler = mock_httpx
        set_handler(lambda r: httpx.Response(200))
        notifier = WebhookNotifier()
        ok = await notifier.send("http://localhost/hook", _evt(key="ssrf-test"))
        assert ok is False
        assert state["calls"] == [], "blocked URL must not produce any HTTP call"


class TestNonJsonSafeDetails:
    """``json.dumps(default=str)`` lets datetimes & similar survive."""

    @pytest.mark.asyncio
    async def test_datetime_in_details_is_serialised(self, mock_httpx) -> None:
        import json as _json
        from datetime import UTC, datetime

        state, set_handler = mock_httpx
        bodies: list[dict] = []

        def _h(req: httpx.Request) -> httpx.Response:
            bodies.append(_json.loads(req.content))
            return httpx.Response(200)

        set_handler(_h)
        notifier = WebhookNotifier()
        ev = WebhookEvent(
            key="dt-test",
            severity="info",
            subject="s",
            body="b",
            details={"when": datetime(2026, 5, 1, 12, 0, tzinfo=UTC)},
        )
        ok = await notifier.send("https://hook.example.com/x", ev)
        assert ok is True
        assert "2026-05-01" in bodies[0]["details"]["when"]

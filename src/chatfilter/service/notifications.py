"""Webhook notifications for admin-pool alerts.

Delivery model: best-effort POST of a JSON envelope to a single admin-
configured URL. The URL might point at Discord, Slack, n8n, Zapier, a
custom bot — our code stays agnostic. Scope is strictly admin pool:
user-pool events never reach this notifier.

Envelope (stable contract for downstream integrations)::

    {
      "source": "chatfilter",
      "timestamp": "2026-04-23T12:34:56+00:00",
      "severity": "info" | "warning" | "error",
      "subject": "...",
      "body": "...",
      "details": { ... arbitrary JSON-safe context ... }
    }

Durability guarantees we *don't* offer: no persistent queue, no
guaranteed delivery, no ordering. If the webhook is down we log and
move on. Dashboard and DB are the source of truth; notifications are
a convenience.

This module is deliberately free of imports from ``monitor``. The
periodic loop that evaluates the dashboard snapshot against thresholds
lives in ``alerts_loop.py`` so the dependency goes one way only:
``monitor -> notifications`` (dispatch), ``alerts_loop -> monitor``
(read) — no cycle.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 5.0
DEFAULT_DEDUP_WINDOW = 3600.0  # 1 hour
MAX_RESPONSE_LOG_BYTES = 200

# Non-standard ports are almost always a sign of someone trying to
# reach an internal service (Redis 6379, Postgres 5432, Elastic 9200,
# etc.) via a public DNS name. Webhook providers live on standard
# HTTPS. Keep the list tiny on purpose.
_ALLOWED_WEBHOOK_PORTS = frozenset({80, 443, 8080, 8443})


@dataclass(frozen=True)
class WebhookEvent:
    """A single alert to dispatch.

    ``key`` is the dedup identifier — events with the same key are
    collapsed inside the dedup window. Use stable, human-readable keys
    like ``"admin.accounts.error"``, ``"admin.proxy.expiring:<id>"``.
    """

    key: str
    severity: str  # "info" | "warning" | "error"
    subject: str
    body: str
    details: dict[str, Any] = field(default_factory=dict)


def validate_webhook_url(url: str | None) -> str | None:
    """Return ``url`` stripped if safe to POST to, else ``None``.

    Admins can type arbitrary strings into the settings form. Without a
    guard, a malicious or careless URL turns our webhook sender into an
    internal-network probe (SSRF). We accept only:

      - scheme ``https://`` or ``http://``
      - non-empty host
      - host that is NOT a loopback / link-local / private IP literal

    We do *not* resolve DNS — a public hostname might still resolve to
    a private IP (DNS rebinding). That's a broader problem; the cheap
    checks above cover the common blunders (``localhost``, ``127.x``,
    ``169.254.x``, ``10.x``, ``192.168.x``, etc.). If higher assurance
    is needed, wire a proxy or egress allowlist in front of this.
    """
    if not url:
        return None
    stripped = url.strip()
    if not stripped:
        return None

    parsed = urlparse(stripped)
    if parsed.scheme not in ("https", "http"):
        return None
    if not parsed.hostname:
        return None

    host = parsed.hostname
    # Block IP literals in private / loopback / link-local ranges.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved):
        return None
    # Block the most common hostname forms for loopback.
    if host.lower() in ("localhost", "localhost.localdomain"):
        return None

    # Port must be a standard web port — anything else is a strong hint
    # that someone is aiming a public DNS name at an internal service.
    # urllib gives us the port only when the URL actually carries one;
    # None means default-for-scheme which is always 80/443, so safe.
    try:
        port = parsed.port
    except ValueError:
        return None
    if port is not None and port not in _ALLOWED_WEBHOOK_PORTS:
        return None

    return stripped


class WebhookNotifier:
    """Posts ``WebhookEvent``s to a user-configured URL.

    Stateless across process restarts (dedup is in-memory). That's
    intentional — restarting the process is a legit reason for a
    previously-suppressed alert to fire again, since the operator may
    have missed it.
    """

    def __init__(
        self,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        dedup_window: float = DEFAULT_DEDUP_WINDOW,
    ) -> None:
        self._timeout = timeout
        self._dedup_window = dedup_window
        self._last_sent: dict[str, float] = {}

    async def send(self, url: str | None, event: WebhookEvent) -> bool:
        """Deliver ``event`` to ``url``. Returns True iff POST reached a 2xx.

        Suppresses when: url is empty/unsafe, or the same event key was
        delivered successfully less than ``dedup_window`` ago. Failures
        don't populate the dedup map — transient outage shouldn't eat
        the first successful retry.
        """
        safe_url = validate_webhook_url(url)
        if safe_url is None:
            return False

        now = time.time()
        last = self._last_sent.get(event.key)
        if last is not None and (now - last) < self._dedup_window:
            return False

        payload = {
            "source": "chatfilter",
            "timestamp": datetime.now(UTC).isoformat(),
            "severity": event.severity,
            "subject": event.subject,
            "body": event.body,
            "details": event.details,
        }

        try:
            # ``default=str`` lets datetimes, enums, paths etc. serialise
            # without the caller having to pre-convert every detail.
            body = json.dumps(payload, default=str).encode("utf-8")
        except (TypeError, ValueError):
            logger.warning("webhook: event %s has non-JSON-safe details", event.key)
            return False

        outcome = await self._post_once(safe_url, body)
        if outcome == "transport_error":
            outcome = await self._post_once(safe_url, body)

        ok = outcome == "ok"
        if ok:
            self._last_sent[event.key] = time.time()
        return ok

    async def _post_once(self, url: str, body: bytes) -> str:
        """One HTTP attempt. Returns ``"ok"``, ``"http_error"``, or
        ``"transport_error"``. Only ``transport_error`` is worth a retry —
        if the server replied with 4xx/5xx, hammering it again won't help."""
        headers = {"Content-Type": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(url, content=body, headers=headers)
        except httpx.HTTPError as e:
            logger.warning("webhook post failed: %s", e)
            return "transport_error"
        if 200 <= resp.status_code < 300:
            return "ok"
        logger.warning(
            "webhook returned %d: %s", resp.status_code, resp.text[:MAX_RESPONSE_LOG_BYTES]
        )
        return "http_error"


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_notifier: WebhookNotifier | None = None


def get_webhook_notifier() -> WebhookNotifier:
    global _notifier
    if _notifier is None:
        _notifier = WebhookNotifier()
    return _notifier


def reset_webhook_notifier_for_tests() -> None:
    global _notifier
    _notifier = None

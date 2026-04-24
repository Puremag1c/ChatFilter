"""Aggregators for the admin Monitor dashboard.

Scope is **strictly admin pool** — every counter, every balance, every
list returned here reflects only the shared admin accounts and
``proxies_admin.json``. Personal pools of power-users (``sessions/user_<id>/``,
``proxies_user_*.json``) do not participate in monitoring at all; each
power-user is responsible for their own resources.

The MVP (PR 1) returns only counts and placeholders for balances.
PR 3 wires in ProxyLine + OpenRouter balance fetchers.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State groups used for the dashboard. Keep in sync with SessionState names
# that the listing layer returns (see web/routers/sessions/listing.py).
# ---------------------------------------------------------------------------

ACCOUNT_STATES_ORDER = (
    "connected",
    "disconnected",
    "connecting",
    "error",
    "banned",
    # Overlay bucket: accounts currently rate-limited by Telegram.
    # Named without underscore so the SessionManager's 8-state model
    # guard (tests/test_8_state_model.py) doesn't mistake this for a
    # proper session state — it's purely a dashboard aggregation.
    "floodwait",
    "needs_code",
    "needs_2fa",
    "needs_confirmation",
    "needs_config",
)


class MonitorService:
    """Collects a snapshot of admin-pool health for the dashboard.

    Takes no session-manager / settings arguments at construction —
    everything is looked up lazily on each call so tests can monkeypatch
    freely and we don't pin stale state between polls.
    """

    def accounts_summary(self) -> dict[str, Any]:
        """Counts of admin-pool accounts grouped by their current state.

        Relies on ``list_stored_sessions(user_id="admin")`` which already
        filters to the shared admin pool by reading ``.account_info.json``
        owner field. On top of that, overlays FloodWait state so
        accounts waiting out a ban show up as ``flood_wait`` regardless
        of their connect state.

        Returns a dict with:
          - ``total``: int
          - one key per state in ``ACCOUNT_STATES_ORDER`` → int count
          - ``items``: full list of session items (for the UI to drill
            into without re-fetching)
        """
        from chatfilter.telegram.flood_tracker import get_flood_tracker
        from chatfilter.web.routers.sessions.listing import list_stored_sessions

        try:
            sessions = list_stored_sessions(user_id="admin")
        except Exception:
            logger.exception("monitor: failed to list admin sessions")
            sessions = []

        blocked = get_flood_tracker().get_blocked_accounts()

        counts: dict[str, int] = dict.fromkeys(ACCOUNT_STATES_ORDER, 0)
        items: list[dict[str, Any]] = []
        for sess in sessions:
            # FloodWait trumps everything else for display purposes —
            # an account that's technically CONNECTED but FloodWaited
            # is useless for analyses and deserves its own bucket.
            if sess.session_id in blocked:
                effective_state = "floodwait"
            else:
                effective_state = sess.state or "disconnected"

            counts[effective_state] = counts.get(effective_state, 0) + 1
            items.append(
                {
                    "session_id": sess.session_id,
                    "state": effective_state,
                    "raw_state": sess.state,
                    "error_message": sess.error_message,
                    "flood_wait_until": blocked.get(sess.session_id),
                }
            )

        return {"total": len(sessions), **counts, "items": items}

    def proxies_summary(self) -> dict[str, Any]:
        """Counts of admin-pool proxies grouped by ProxyStatus.

        Reads ``load_proxy_pool("admin")`` directly — user pools are
        not scanned.
        """
        from chatfilter.config_proxy import ProxyStatus
        from chatfilter.storage.proxy_pool import load_proxy_pool

        try:
            proxies = load_proxy_pool("admin")
        except Exception:
            logger.exception("monitor: failed to load admin proxy pool")
            proxies = []

        counts = {
            "working": 0,
            "no_ping": 0,
            "untested": 0,
        }
        for p in proxies:
            if p.status == ProxyStatus.WORKING:
                counts["working"] += 1
            elif p.status == ProxyStatus.NO_PING:
                counts["no_ping"] += 1
            else:
                counts["untested"] += 1

        return {"total": len(proxies), **counts}

    async def balances(self) -> dict[str, Any]:
        """Fetch ProxyLine + OpenRouter balances concurrently.

        Both fetchers are cached (5 min for OpenRouter, 5 min for
        ProxyLine balance) so running this on every 30s poll doesn't
        hit the external APIs. Missing API key or network error →
        ``None`` in the corresponding slot — the UI renders "—".
        """
        import asyncio as _asyncio
        import time as _time

        result: dict[str, Any] = {
            "openrouter": {"remaining": None, "last_checked": None},
            "proxyline": {"main": None, "affiliate": None, "last_checked": None},
        }

        or_key = self._get_setting("openrouter_api_key")
        pl_key = self._get_setting("proxyline_api_key")

        async def _or() -> dict[str, Any] | None:
            if not or_key:
                return None
            from chatfilter.ai.openrouter_client import fetch_credits

            return await fetch_credits(or_key)

        async def _pl() -> dict[str, float] | None:
            if not pl_key:
                return None
            from chatfilter.service.proxyline_client import ProxylineError, get_proxyline_client

            client = get_proxyline_client(pl_key)
            if client is None:
                return None
            try:
                return await client.get_balance()
            except ProxylineError as e:
                logger.warning("monitor: proxyline balance failed: %s", e)
                return None

        or_res, pl_res = await _asyncio.gather(_or(), _pl(), return_exceptions=True)
        now_ts = _time.time()

        if isinstance(or_res, dict):
            result["openrouter"] = {
                "remaining": or_res.get("remaining"),
                "last_checked": now_ts,
            }
        if isinstance(pl_res, dict):
            result["proxyline"] = {
                "main": pl_res.get("main"),
                "affiliate": pl_res.get("affiliate"),
                "last_checked": now_ts,
            }

        # If the admin configured both keys but both fetchers came back
        # empty, the dashboard will show "—/—" with no signal that the
        # monitoring itself is broken. Log a warning so operators see it
        # in the container output even when the webhook is silent.
        if or_key and pl_key and not isinstance(or_res, dict) and not isinstance(pl_res, dict):
            logger.warning(
                "monitor: both balance fetchers returned nothing — "
                "dashboard will render placeholders"
            )

        return result

    def proxies_expiring_soon(self, days: int = 7) -> list[dict[str, Any]]:
        """Admin-pool proxies with ``expires_at`` within the next N days.

        Reads the cached ``expires_at`` that ``ProxylineSyncer`` keeps
        in the admin pool JSON — no live ProxyLine call here. Ordered
        by expiry ascending (soonest first).
        """
        from datetime import UTC, datetime, timedelta

        from chatfilter.storage.proxy_pool import load_proxy_pool

        try:
            proxies = load_proxy_pool("admin")
        except Exception:
            logger.exception("monitor: load admin pool for expiring check failed")
            return []

        now = datetime.now(UTC)
        cutoff = now + timedelta(days=days)
        upcoming = []
        for p in proxies:
            if p.expires_at is None:
                continue
            exp = p.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            if exp <= cutoff:
                upcoming.append(
                    {
                        "id": p.id,
                        "name": p.name,
                        "host": p.host,
                        "port": p.port,
                        "proxyline_id": p.proxyline_id,
                        "expires_at": exp.isoformat(),
                        "days_left": max(0, (exp - now).days),
                    }
                )
        upcoming.sort(key=lambda e: str(e["expires_at"]))
        return upcoming

    @staticmethod
    def _get_setting(key: str) -> str | None:
        """Best-effort read of a key from app_settings.

        Returns ``None`` on any error so the dashboard never crashes
        because the DB is momentarily unavailable.
        """
        try:
            from chatfilter.config import get_settings
            from chatfilter.storage.group_database import GroupDatabase

            settings = get_settings()
            db = GroupDatabase(settings.effective_database_url)
            raw = db.get_setting(key)
            return str(raw).strip() if raw else None
        except Exception:
            return None

    async def gather(self) -> dict[str, Any]:
        """Single call for the dashboard partial.

        Bundles the sync-safe aggregators with the async balance fetch.
        """
        return {
            "accounts": self.accounts_summary(),
            "proxies": self.proxies_summary(),
            "expiring_soon": self.proxies_expiring_soon(),
            "balances": await self.balances(),
        }

    # ------------------------------------------------------------------
    # Webhook alert dispatch
    # ------------------------------------------------------------------

    async def check_and_notify(
        self, snapshot: dict[str, Any], *, notifier: Any = None
    ) -> list[str]:
        """Inspect a dashboard snapshot and send any triggered webhooks.

        Reads the webhook URL and thresholds from ``app_settings``. If
        no URL is configured, nothing is sent. Returns the list of event
        keys that were dispatched — useful for tests and for the Monitor
        background loop to log activity.

        Dispatch is best-effort: WebhookNotifier handles retries, dedup,
        and silent failure. We never raise.

        Events are collected first and posted concurrently via
        ``asyncio.gather`` so a long-running webhook endpoint doesn't
        turn a 10-event tick into a 10×5s serial wait.
        """
        import asyncio as _asyncio

        from chatfilter.service.notifications import (
            WebhookEvent,
            get_webhook_notifier,
        )

        if notifier is None:
            notifier = get_webhook_notifier()

        url = self._get_setting("webhook_url")
        if not url:
            return []

        accounts = snapshot.get("accounts", {}) or {}
        proxies = snapshot.get("proxies", {}) or {}
        expiring = snapshot.get("expiring_soon", []) or []
        balances = snapshot.get("balances", {}) or {}

        events: list[WebhookEvent] = []

        # ---- admin accounts stuck in error -----------------------------
        error_count = int(accounts.get("error", 0) or 0)
        threshold_err = _to_int(self._get_setting("webhook_threshold_accounts_error"), default=1)
        if error_count >= threshold_err and error_count > 0:
            events.append(
                WebhookEvent(
                    key="admin.accounts.error",
                    severity="warning",
                    subject="Admin accounts in error state",
                    body=f"{error_count} admin account(s) are currently in ERROR.",
                    details={"count": error_count, "threshold": threshold_err},
                )
            )

        # ---- proxy expiring within 1 day -------------------------------
        for p in expiring:
            # Don't use ``value or default`` — days_left == 0 is the most
            # urgent case and is falsy.
            raw = p.get("days_left")
            days_left = int(raw) if raw is not None else 999
            if days_left > 1:
                continue
            severity = "error" if days_left == 0 else "warning"
            events.append(
                WebhookEvent(
                    key=f"admin.proxy.expiring:{p.get('id', 'unknown')}",
                    severity=severity,
                    subject=f"Proxy {p.get('name', '?')} expires in {days_left} day(s)",
                    body=f"Proxy {p.get('host', '?')}:{p.get('port', '?')} expires at {p.get('expires_at')}.",
                    details={
                        "proxy_id": p.get("id"),
                        "proxyline_id": p.get("proxyline_id"),
                        "days_left": days_left,
                    },
                )
            )

        # ---- OpenRouter balance ---------------------------------------
        or_rem = (balances.get("openrouter") or {}).get("remaining")
        if or_rem is not None:
            or_threshold = _to_float(self._get_setting("webhook_threshold_openrouter"), default=5.0)
            if or_rem < or_threshold:
                events.append(
                    WebhookEvent(
                        key="admin.balance.openrouter",
                        severity="error",
                        subject="OpenRouter balance is low",
                        body=f"OpenRouter remaining: ${or_rem:.2f} (threshold ${or_threshold:.2f}).",
                        details={"remaining": or_rem, "threshold": or_threshold},
                    )
                )

        # ---- ProxyLine balance ----------------------------------------
        pl_main = (balances.get("proxyline") or {}).get("main")
        if pl_main is not None:
            pl_threshold = _to_float(self._get_setting("webhook_threshold_proxyline"), default=10.0)
            if pl_main < pl_threshold:
                events.append(
                    WebhookEvent(
                        key="admin.balance.proxyline",
                        severity="warning",
                        subject="ProxyLine balance is low",
                        body=f"ProxyLine main balance: ${pl_main:.2f} (threshold ${pl_threshold:.2f}).",
                        details={"main": pl_main, "threshold": pl_threshold},
                    )
                )

        _ = proxies  # currently only counts consumed by balance/expiring

        if not events:
            return []

        # Fan out concurrently. Exceptions from any one send don't kill
        # the others — ``return_exceptions=True`` surfaces them as values
        # we then inspect. A ``send`` returning ``False`` means the
        # notifier chose to suppress (dedup / bad URL / delivery failed).
        outcomes = await _asyncio.gather(
            *(notifier.send(url, e) for e in events), return_exceptions=True
        )
        dispatched: list[str] = []
        for evt, outcome in zip(events, outcomes, strict=True):
            if outcome is True:
                dispatched.append(evt.key)
            elif isinstance(outcome, Exception):
                logger.warning("monitor: webhook for %s raised: %s", evt.key, outcome)
        return dispatched


def _to_int(value: Any, *, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


def _to_float(value: Any, *, default: float) -> float:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError, AttributeError):
        return default


# Module-level singleton — MonitorService has no per-request state, so
# one instance is fine. Creating a fresh instance each call is also
# harmless; this keeps the import ergonomic.
_monitor: MonitorService | None = None


def get_monitor_service() -> MonitorService:
    global _monitor
    if _monitor is None:
        _monitor = MonitorService()
    return _monitor

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
    "flood_wait",
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
                effective_state = "flood_wait"
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

    def balances(self) -> dict[str, Any]:
        """External balances for the Monitor dashboard.

        PR 1 placeholder — returns ``None`` everywhere. PR 3 wires in
        ProxyLine (``main``, ``affiliate``) and OpenRouter (``remaining``).
        """
        return {
            "openrouter": {"remaining": None, "last_checked": None},
            "proxyline": {"main": None, "affiliate": None, "last_checked": None},
        }

    def gather(self) -> dict[str, Any]:
        """Single call for the dashboard partial."""
        return {
            "accounts": self.accounts_summary(),
            "proxies": self.proxies_summary(),
            "balances": self.balances(),
        }


# Module-level singleton — MonitorService has no per-request state, so
# one instance is fine. Creating a fresh instance each call is also
# harmless; this keeps the import ergonomic.
_monitor: MonitorService | None = None


def get_monitor_service() -> MonitorService:
    global _monitor
    if _monitor is None:
        _monitor = MonitorService()
    return _monitor

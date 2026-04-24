"""MonitorService → WebhookNotifier integration tests.

Business rules covered:
  - Enough admin accounts in ``error`` → severity=warning.
  - Proxy expiring in 0–1 days → severity=warning.
  - OpenRouter balance below threshold → severity=error.
  - ProxyLine balance below threshold → severity=warning.

We don't verify HTTP delivery here (that's in ``test_webhook_notifier``),
only that MonitorService's trigger logic asks the notifier to send the
right events with the right severities.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest


@pytest.fixture
def svc_with_notifier(tmp_path: Path, monkeypatch: Any):
    from chatfilter.config import get_settings
    from chatfilter.service.monitor import MonitorService
    from chatfilter.service.notifications import WebhookNotifier

    settings = get_settings()
    settings.sessions_dir.mkdir(parents=True, exist_ok=True)
    settings.config_dir.mkdir(parents=True, exist_ok=True)

    svc = MonitorService()
    notifier = WebhookNotifier(dedup_window=3600.0)
    notifier.send = AsyncMock(return_value=True)  # type: ignore[method-assign]
    return svc, notifier, settings


def _seed_app_settings(webhook_url: str, **thresholds: str) -> None:
    """Write webhook_url + thresholds into app_settings so the trigger
    logic can read them."""
    from chatfilter.config import get_settings
    from chatfilter.storage.group_database import GroupDatabase

    settings = get_settings()
    db = GroupDatabase(settings.effective_database_url)
    db.set_setting("webhook_url", webhook_url)
    for k, v in thresholds.items():
        db.set_setting(k, v)


class TestAccountsErrorTrigger:
    @pytest.mark.asyncio
    async def test_accounts_error_over_threshold_warns(self, svc_with_notifier) -> None:
        svc, notifier, _ = svc_with_notifier
        _seed_app_settings(
            "https://hook.example.com/x",
            webhook_threshold_accounts_error="2",
        )
        snapshot = {
            "accounts": {"total": 5, "error": 3, "banned": 0, "floodwait": 0},
            "proxies": {"total": 0},
            "balances": {
                "openrouter": {"remaining": 100.0},
                "proxyline": {"main": 50.0, "affiliate": 0.0},
            },
            "expiring_soon": [],
        }
        await svc.check_and_notify(snapshot, notifier=notifier)

        calls = notifier.send.await_args_list
        events = [c.args[1] for c in calls]
        assert any(e.key == "admin.accounts.error" for e in events)
        evt = next(e for e in events if e.key == "admin.accounts.error")
        assert evt.severity == "warning"
        assert evt.details.get("count") == 3

    @pytest.mark.asyncio
    async def test_accounts_error_below_threshold_no_event(self, svc_with_notifier) -> None:
        svc, notifier, _ = svc_with_notifier
        _seed_app_settings(
            "https://hook.example.com/x",
            webhook_threshold_accounts_error="5",
        )
        snapshot = {
            "accounts": {"total": 5, "error": 3, "banned": 0, "floodwait": 0},
            "proxies": {"total": 0},
            "balances": {
                "openrouter": {"remaining": 100.0},
                "proxyline": {"main": 50.0, "affiliate": 0.0},
            },
            "expiring_soon": [],
        }
        await svc.check_and_notify(snapshot, notifier=notifier)

        events = [c.args[1] for c in notifier.send.await_args_list]
        assert not any(e.key == "admin.accounts.error" for e in events)


class TestProxyExpiringTrigger:
    @pytest.mark.asyncio
    async def test_expiring_in_one_day_warns(self, svc_with_notifier) -> None:
        svc, notifier, _ = svc_with_notifier
        _seed_app_settings("https://hook.example.com/x")
        snapshot = {
            "accounts": {"total": 0, "error": 0},
            "proxies": {"total": 1},
            "balances": {
                "openrouter": {"remaining": 100.0},
                "proxyline": {"main": 50.0, "affiliate": 0.0},
            },
            "expiring_soon": [
                {
                    "id": "abc",
                    "name": "p1",
                    "host": "1.1.1.1",
                    "port": 1080,
                    "proxyline_id": 7,
                    "expires_at": (datetime.now(UTC) + timedelta(hours=12)).isoformat(),
                    "days_left": 0,
                },
            ],
        }
        await svc.check_and_notify(snapshot, notifier=notifier)

        events = [c.args[1] for c in notifier.send.await_args_list]
        urgent = [e for e in events if e.key.startswith("admin.proxy.expiring")]
        assert urgent, "should have fired an expiring alert"
        assert all(e.severity in ("warning", "error") for e in urgent)

    @pytest.mark.asyncio
    async def test_expiring_in_six_days_no_event(self, svc_with_notifier) -> None:
        """The dashboard banner shows anything ≤7 days, but we only *notify*
        for the urgent ones (≤1 day)."""
        svc, notifier, _ = svc_with_notifier
        _seed_app_settings("https://hook.example.com/x")
        snapshot = {
            "accounts": {"total": 0, "error": 0},
            "proxies": {"total": 1},
            "balances": {
                "openrouter": {"remaining": 100.0},
                "proxyline": {"main": 50.0, "affiliate": 0.0},
            },
            "expiring_soon": [
                {
                    "id": "abc",
                    "name": "p1",
                    "host": "1.1.1.1",
                    "port": 1080,
                    "proxyline_id": 7,
                    "expires_at": (datetime.now(UTC) + timedelta(days=6)).isoformat(),
                    "days_left": 6,
                },
            ],
        }
        await svc.check_and_notify(snapshot, notifier=notifier)

        events = [c.args[1] for c in notifier.send.await_args_list]
        assert not any(e.key.startswith("admin.proxy.expiring") for e in events)


class TestBalanceTriggers:
    @pytest.mark.asyncio
    async def test_openrouter_low_balance_is_error(self, svc_with_notifier) -> None:
        svc, notifier, _ = svc_with_notifier
        _seed_app_settings(
            "https://hook.example.com/x",
            webhook_threshold_openrouter="5.00",
        )
        snapshot = {
            "accounts": {"total": 0, "error": 0},
            "proxies": {"total": 0},
            "balances": {
                "openrouter": {"remaining": 2.5},
                "proxyline": {"main": 50.0, "affiliate": 0.0},
            },
            "expiring_soon": [],
        }
        await svc.check_and_notify(snapshot, notifier=notifier)

        events = [c.args[1] for c in notifier.send.await_args_list]
        or_events = [e for e in events if e.key == "admin.balance.openrouter"]
        assert or_events and or_events[0].severity == "error"

    @pytest.mark.asyncio
    async def test_proxyline_low_balance_is_warning(self, svc_with_notifier) -> None:
        svc, notifier, _ = svc_with_notifier
        _seed_app_settings(
            "https://hook.example.com/x",
            webhook_threshold_proxyline="10.00",
        )
        snapshot = {
            "accounts": {"total": 0, "error": 0},
            "proxies": {"total": 0},
            "balances": {
                "openrouter": {"remaining": 100.0},
                "proxyline": {"main": 3.5, "affiliate": 0.0},
            },
            "expiring_soon": [],
        }
        await svc.check_and_notify(snapshot, notifier=notifier)

        events = [c.args[1] for c in notifier.send.await_args_list]
        pl_events = [e for e in events if e.key == "admin.balance.proxyline"]
        assert pl_events and pl_events[0].severity == "warning"

    @pytest.mark.asyncio
    async def test_balance_none_does_not_trigger(self, svc_with_notifier) -> None:
        """If we can't read the balance (no key) — don't scream."""
        svc, notifier, _ = svc_with_notifier
        _seed_app_settings("https://hook.example.com/x")
        snapshot = {
            "accounts": {"total": 0, "error": 0},
            "proxies": {"total": 0},
            "balances": {
                "openrouter": {"remaining": None},
                "proxyline": {"main": None, "affiliate": None},
            },
            "expiring_soon": [],
        }
        await svc.check_and_notify(snapshot, notifier=notifier)

        events = [c.args[1] for c in notifier.send.await_args_list]
        assert not any(
            e.key in ("admin.balance.openrouter", "admin.balance.proxyline") for e in events
        )


class TestConcurrentDispatch:
    @pytest.mark.asyncio
    async def test_multiple_events_dispatched_concurrently(self, svc_with_notifier) -> None:
        """A tick with many events must fan out the ``send`` calls via
        ``asyncio.gather`` — otherwise a slow webhook endpoint would turn
        10 events × 5s into a 50-second tick."""
        import asyncio
        import time

        svc, notifier, _ = svc_with_notifier
        _seed_app_settings(
            "https://hook.example.com/x",
            webhook_threshold_accounts_error="1",
            webhook_threshold_openrouter="999.00",
            webhook_threshold_proxyline="999.00",
        )

        # Replace the AsyncMock with one that actually awaits — if the
        # caller fans out we'll observe wall-clock ≈ one slot, not N slots.
        SLEEP = 0.2
        call_count = {"n": 0}

        async def slow_send(_url, _evt):
            call_count["n"] += 1
            await asyncio.sleep(SLEEP)
            return True

        notifier.send.side_effect = slow_send

        snapshot = {
            "accounts": {"total": 10, "error": 5},
            "proxies": {"total": 0},
            "balances": {
                "openrouter": {"remaining": 1.0},
                "proxyline": {"main": 1.0, "affiliate": 0.0},
            },
            "expiring_soon": [],
        }

        t0 = time.monotonic()
        dispatched = await svc.check_and_notify(snapshot, notifier=notifier)
        elapsed = time.monotonic() - t0

        assert call_count["n"] == 3, "expected 3 triggers (accounts, OR, PL)"
        assert len(dispatched) == 3
        # Serial dispatch would take ≥ 3×SLEEP; concurrent should finish
        # in ~1 slot plus asyncio overhead. Leave generous headroom.
        assert elapsed < (SLEEP * 3) - 0.05, (
            f"dispatch looks serial: took {elapsed:.3f}s for 3 events at {SLEEP}s each"
        )


class TestWebhookDisabled:
    @pytest.mark.asyncio
    async def test_no_url_no_calls(self, svc_with_notifier) -> None:
        svc, notifier, _ = svc_with_notifier
        _seed_app_settings("")  # empty URL → disabled
        snapshot = {
            "accounts": {"total": 5, "error": 5},
            "proxies": {"total": 0},
            "balances": {
                "openrouter": {"remaining": 0.01},
                "proxyline": {"main": 0.01, "affiliate": 0.0},
            },
            "expiring_soon": [],
        }
        await svc.check_and_notify(snapshot, notifier=notifier)

        assert notifier.send.await_count == 0, "no URL configured → no dispatch"

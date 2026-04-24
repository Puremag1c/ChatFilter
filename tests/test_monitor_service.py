"""MonitorService — admin-pool dashboard aggregators.

Scope is admin-pool only: user-owned sessions and proxy pools must
not leak into the counters. Covered by ``test_user_pool_is_ignored_*``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def monitor(tmp_path: Path, monkeypatch: Any):
    """Fresh MonitorService against an isolated sessions/config tree.

    The autouse ``_isolate_data_dir`` fixture in the root conftest
    already points get_settings() at a per-test tmp dir — we just seed
    it.
    """
    from chatfilter.config import get_settings
    from chatfilter.service.monitor import MonitorService

    settings = get_settings()
    settings.sessions_dir.mkdir(parents=True, exist_ok=True)
    settings.config_dir.mkdir(parents=True, exist_ok=True)
    return MonitorService(), settings


def _seed_session(sessions_root: Path, scope: str, name: str, owner: str) -> None:
    d = sessions_root / scope / name
    d.mkdir(parents=True, exist_ok=True)
    (d / ".account_info.json").write_text(json.dumps({"user_id": 1, "owner": owner, "phone": "+1"}))
    (d / "config.json").write_text(json.dumps({"proxy_id": None}))


def _seed_proxy_pool(config_dir: Path, scope: str, entries: list[dict]) -> None:
    import uuid

    normalized = []
    for e in entries:
        normalized.append(
            {
                "id": e.get("id", str(uuid.uuid4())),
                "name": e.get("name", "p"),
                "type": "socks5",
                "host": "1.2.3.4",
                "port": 1080,
                "username": "",
                "password": "",
                "status": e["status"],
                "last_ping_at": None,
                "last_success_at": None,
                "consecutive_failures": 0,
            }
        )
    (config_dir / f"proxies_{scope}.json").write_text(json.dumps(normalized))


class TestAccountsSummary:
    def test_counts_admin_sessions_by_state(self, monitor) -> None:
        svc, settings = monitor
        _seed_session(settings.sessions_dir, "admin", "A", owner="admin")
        _seed_session(settings.sessions_dir, "admin", "B", owner="admin")

        summary = svc.accounts_summary()

        assert summary["total"] == 2
        # Both sessions have no session.session file, so they end up in
        # ``disconnected`` via the listing's config_status fallback.
        assert summary["disconnected"] == 2
        assert summary["connected"] == 0

    def test_flood_wait_trumps_state(self, monitor) -> None:
        """An account in FloodWait should land in the flood_wait bucket
        regardless of what the listing layer thinks its state is."""
        from chatfilter.telegram.flood_tracker import get_flood_tracker

        svc, settings = monitor
        _seed_session(settings.sessions_dir, "admin", "Blocked", owner="admin")
        get_flood_tracker().record_flood_wait("Blocked", 600)

        summary = svc.accounts_summary()

        assert summary["floodwait"] == 1
        assert summary["disconnected"] == 0
        get_flood_tracker().clear_account("Blocked")

    def test_user_pool_is_ignored(self, monitor) -> None:
        """Power-user sessions must not leak into the admin counter."""
        svc, settings = monitor
        _seed_session(settings.sessions_dir, "admin", "AdminOne", owner="admin")
        _seed_session(settings.sessions_dir, "user_42", "Mine", owner="user:42")

        summary = svc.accounts_summary()

        assert summary["total"] == 1
        session_ids = [item["session_id"] for item in summary["items"]]
        assert session_ids == ["AdminOne"]


class TestProxiesSummary:
    def test_counts_by_status(self, monitor) -> None:
        svc, settings = monitor
        _seed_proxy_pool(
            settings.config_dir,
            "admin",
            [
                {"status": "working"},
                {"status": "working"},
                {"status": "no_ping"},
                {"status": "untested"},
            ],
        )

        summary = svc.proxies_summary()

        assert summary["total"] == 4
        assert summary["working"] == 2
        assert summary["no_ping"] == 1
        assert summary["untested"] == 1

    def test_user_pool_is_ignored(self, monitor) -> None:
        svc, settings = monitor
        _seed_proxy_pool(settings.config_dir, "admin", [{"status": "working"}])
        _seed_proxy_pool(
            settings.config_dir, "user_42", [{"status": "no_ping"}, {"status": "working"}]
        )

        summary = svc.proxies_summary()

        assert summary["total"] == 1
        assert summary["working"] == 1
        assert summary["no_ping"] == 0

    def test_empty_pool(self, monitor) -> None:
        svc, _ = monitor
        summary = svc.proxies_summary()
        assert summary == {"total": 0, "working": 0, "no_ping": 0, "untested": 0}


class TestBalancesPlaceholder:
    @pytest.mark.asyncio
    async def test_returns_none_when_keys_missing(self, monitor) -> None:
        """Without API keys configured balances stay None — UI shows "—"."""
        svc, _ = monitor
        b = await svc.balances()
        assert b["openrouter"]["remaining"] is None
        assert b["proxyline"]["main"] is None
        assert b["proxyline"]["affiliate"] is None


class TestGather:
    @pytest.mark.asyncio
    async def test_single_call_bundles_all(self, monitor) -> None:
        svc, settings = monitor
        _seed_session(settings.sessions_dir, "admin", "A", owner="admin")
        _seed_proxy_pool(settings.config_dir, "admin", [{"status": "working"}])

        bundle = await svc.gather()

        assert bundle["accounts"]["total"] == 1
        assert bundle["proxies"]["total"] == 1
        assert "balances" in bundle
        assert "expiring_soon" in bundle

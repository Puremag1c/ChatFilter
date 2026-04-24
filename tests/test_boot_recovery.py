"""Boot Recovery — after-restart revival of "working" sessions and proxies.

Scope: admin pool + all user pools. The core promise is "whatever was
connected before the restart comes back by itself" — with one explicit
opt-out via the ``autoconnect=False`` flag written by the Disconnect
endpoint.

These tests drive the module through simulated session trees and a
fake ``SessionManager``. No real Telegram I/O.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from chatfilter.config_proxy import ProxyStatus, ProxyType
from chatfilter.models.proxy import ProxyEntry
from chatfilter.service.boot_recovery import (
    BootRecoveryHolder,
    BootRecoverySnapshot,
    get_boot_recovery_holder,
    run_boot_recovery,
    set_boot_recovery_holder,
)
from chatfilter.storage.proxy_pool import save_proxy_pool

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _seed_session(
    sessions_root: Path,
    scope: str,
    name: str,
    *,
    owner: str = "admin",
    proxy_id: str | None = None,
    autoconnect: bool = True,
    has_session_file: bool = True,
) -> Path:
    """Write the files the listing layer + loader expect."""
    d = sessions_root / scope / name
    d.mkdir(parents=True, exist_ok=True)
    (d / ".account_info.json").write_text(json.dumps({"user_id": 1, "owner": owner, "phone": "+1"}))
    cfg: dict[str, Any] = {"autoconnect": autoconnect}
    if proxy_id is not None:
        cfg["proxy_id"] = proxy_id
    (d / "config.json").write_text(json.dumps(cfg))
    if has_session_file:
        (d / "session.session").write_bytes(b"")
    return d


def _make_proxy(label: str, status: ProxyStatus = ProxyStatus.WORKING) -> ProxyEntry:
    return ProxyEntry(
        id=str(uuid.uuid4()),
        name=f"proxy-{label}",
        type=ProxyType.SOCKS5,
        host="1.2.3.4",
        port=1080,
        username="",
        password="",
        status=status,
    )


class _FakeSessionManager:
    """Minimal surface used by boot_recovery: register + connect."""

    def __init__(self) -> None:
        self._factories: dict[str, Any] = {}
        self.register = MagicMock(side_effect=self._register)
        self.connect = AsyncMock()

    def _register(self, session_id: str, factory: Any) -> None:
        self._factories[session_id] = factory


@pytest.fixture
def settings_tmp():
    """The autouse ``_isolate_data_dir`` in conftest already gives us a
    per-test data dir — we just materialise it and hand the paths back."""
    from chatfilter.config import get_settings

    s = get_settings()
    s.sessions_dir.mkdir(parents=True, exist_ok=True)
    s.config_dir.mkdir(parents=True, exist_ok=True)
    return s


@pytest.fixture
def sm() -> _FakeSessionManager:
    return _FakeSessionManager()


@pytest.fixture
def holder() -> BootRecoveryHolder:
    h = BootRecoveryHolder()
    set_boot_recovery_holder(h)
    yield h
    set_boot_recovery_holder(None)


@pytest.fixture(autouse=True)
def _patch_proxy_health(monkeypatch):
    """Replace ``check_all_proxies`` with a no-op that leaves the pool
    files as-is. Individual tests seed the pool with the status they
    want to simulate (WORKING / NO_PING), and we trust that value.

    Real ping-over-Telegram obviously can't run in unit tests.
    """

    async def _noop():
        return {}

    monkeypatch.setattr("chatfilter.service.boot_recovery.check_all_proxies", _noop)


# ---------------------------------------------------------------------------
# run_boot_recovery — core behaviour
# ---------------------------------------------------------------------------


class TestRunBootRecovery:
    @pytest.mark.asyncio
    async def test_session_with_autoconnect_false_is_skipped(
        self, settings_tmp, sm, holder
    ) -> None:
        _seed_session(settings_tmp.sessions_dir, "admin", "S1", autoconnect=False)

        await run_boot_recovery(sm, holder)

        snap = holder.snapshot()
        assert snap.sessions_skipped_autoconnect_false == 1
        assert snap.sessions_connected == 0
        sm.connect.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_session_with_live_proxy_is_reconnected(
        self, settings_tmp, sm, holder, monkeypatch
    ) -> None:
        proxy = _make_proxy("p-alive", ProxyStatus.WORKING)
        save_proxy_pool([proxy], "admin")
        _seed_session(settings_tmp.sessions_dir, "admin", "Live", proxy_id=proxy.id)

        # Stub the loader so boot_recovery doesn't try to read encrypted creds.
        loader = MagicMock(_proxy_id=proxy.id)
        monkeypatch.setattr(
            "chatfilter.service.boot_recovery.TelegramClientLoader",
            lambda _path: loader,
        )

        await run_boot_recovery(sm, holder)

        loader.validate.assert_called_once()
        sm.register.assert_called_once_with("Live", loader)
        sm.connect.assert_awaited_once_with("Live")
        assert holder.snapshot().sessions_connected == 1

    @pytest.mark.asyncio
    async def test_session_with_dead_proxy_is_skipped(
        self, settings_tmp, sm, holder, monkeypatch
    ) -> None:
        proxy = _make_proxy("p-dead", ProxyStatus.NO_PING)
        save_proxy_pool([proxy], "admin")
        _seed_session(settings_tmp.sessions_dir, "admin", "Dead", proxy_id=proxy.id)

        monkeypatch.setattr(
            "chatfilter.service.boot_recovery.TelegramClientLoader",
            lambda _path: MagicMock(_proxy_id=proxy.id),
        )

        await run_boot_recovery(sm, holder)

        sm.connect.assert_not_awaited()
        snap = holder.snapshot()
        assert snap.sessions_skipped_dead_proxy == 1
        assert snap.sessions_connected == 0

    @pytest.mark.asyncio
    async def test_session_without_proxy_is_reconnected(
        self, settings_tmp, sm, holder, monkeypatch
    ) -> None:
        _seed_session(settings_tmp.sessions_dir, "admin", "NoProxy", proxy_id=None)
        loader = MagicMock(_proxy_id=None)
        monkeypatch.setattr(
            "chatfilter.service.boot_recovery.TelegramClientLoader",
            lambda _path: loader,
        )

        await run_boot_recovery(sm, holder)

        sm.connect.assert_awaited_once_with("NoProxy")
        assert holder.snapshot().sessions_connected == 1

    @pytest.mark.asyncio
    async def test_session_without_session_file_is_skipped(self, settings_tmp, sm, holder) -> None:
        _seed_session(settings_tmp.sessions_dir, "admin", "NoAuth", has_session_file=False)
        await run_boot_recovery(sm, holder)
        sm.connect.assert_not_awaited()
        assert holder.snapshot().sessions_skipped_human_needed == 1

    @pytest.mark.asyncio
    async def test_user_pool_sessions_are_processed(
        self, settings_tmp, sm, holder, monkeypatch
    ) -> None:
        """Boot recovery scans all pools, not just admin."""
        # Admin session + user_42 session.
        _seed_session(settings_tmp.sessions_dir, "admin", "A", owner="admin")
        _seed_session(settings_tmp.sessions_dir, "user_42", "B", owner="user:42")
        monkeypatch.setattr(
            "chatfilter.service.boot_recovery.TelegramClientLoader",
            lambda _path: MagicMock(_proxy_id=None),
        )

        await run_boot_recovery(sm, holder)

        # Both sessions attempted.
        connected_ids = {c.args[0] for c in sm.connect.await_args_list}
        assert connected_ids == {"A", "B"}

    @pytest.mark.asyncio
    async def test_connect_raising_does_not_kill_recovery(
        self, settings_tmp, sm, holder, monkeypatch
    ) -> None:
        """One failed connect() must not stop the rest."""
        _seed_session(settings_tmp.sessions_dir, "admin", "Good", proxy_id=None)
        _seed_session(settings_tmp.sessions_dir, "admin", "Bad", proxy_id=None)

        monkeypatch.setattr(
            "chatfilter.service.boot_recovery.TelegramClientLoader",
            lambda _path: MagicMock(_proxy_id=None),
        )

        async def _connect(sid: str):
            if sid == "Bad":
                raise RuntimeError("boom")

        sm.connect.side_effect = _connect

        await run_boot_recovery(sm, holder)

        snap = holder.snapshot()
        assert snap.sessions_connected == 1
        assert snap.sessions_failed == 1

    @pytest.mark.asyncio
    async def test_phase_transitions_to_done(self, settings_tmp, sm, holder) -> None:
        # No sessions, no proxies — fastest possible pass.
        await run_boot_recovery(sm, holder)
        snap = holder.snapshot()
        assert snap.phase == "done"
        assert snap.in_progress is False
        assert snap.finished_at is not None

    @pytest.mark.asyncio
    async def test_failsafe_timeout_force_done(self, settings_tmp, sm, holder, monkeypatch) -> None:
        """If the internal Phase B hangs, the failsafe timeout kicks in,
        phase flips to ``done`` and the holder never leaves ``in_progress=False``."""
        _seed_session(settings_tmp.sessions_dir, "admin", "Hang", proxy_id=None)
        monkeypatch.setattr(
            "chatfilter.service.boot_recovery.TelegramClientLoader",
            lambda _path: MagicMock(_proxy_id=None),
        )

        async def _hang(_sid: str):
            await asyncio.sleep(60)  # way beyond our test failsafe

        sm.connect.side_effect = _hang

        # Tight failsafe — test should finish in ~1 s, not 60 s.
        await run_boot_recovery(sm, holder, failsafe_seconds=0.5)

        snap = holder.snapshot()
        assert snap.in_progress is False
        assert snap.phase in ("done", "failed")


# ---------------------------------------------------------------------------
# Holder snapshot semantics
# ---------------------------------------------------------------------------


class TestHolder:
    def test_initial_snapshot_is_in_progress(self) -> None:
        h = BootRecoveryHolder()
        snap = h.snapshot()
        assert snap.in_progress is True
        assert snap.phase == "pinging_proxies"
        assert snap.sessions_total == 0

    def test_update_produces_new_immutable_snapshot(self) -> None:
        h = BootRecoveryHolder()
        h.update(sessions_total=5, sessions_connected=2)
        snap = h.snapshot()
        assert snap.sessions_total == 5
        assert snap.sessions_connected == 2
        # ETA derived automatically from remaining × ~5 s.
        assert snap.eta_seconds is not None and snap.eta_seconds > 0

    def test_mark_done_clears_in_progress(self) -> None:
        h = BootRecoveryHolder()
        h.mark_done()
        snap = h.snapshot()
        assert snap.in_progress is False
        assert snap.phase == "done"
        assert snap.finished_at is not None

    def test_singleton_set_get(self) -> None:
        h = BootRecoveryHolder()
        set_boot_recovery_holder(h)
        try:
            assert get_boot_recovery_holder() is h
        finally:
            set_boot_recovery_holder(None)

    def test_snapshot_is_frozen(self) -> None:
        h = BootRecoveryHolder()
        snap = h.snapshot()
        with pytest.raises((AttributeError, TypeError)):
            # ``frozen=True`` dataclass — attribute assignment is blocked.
            snap.sessions_total = 999  # type: ignore[misc]

    def test_snapshot_roundtrips_via_replace(self) -> None:
        """Used by the endpoint to serialise with ``asdict``."""
        s = BootRecoverySnapshot(
            in_progress=True,
            phase="connecting_accounts",
            started_at=datetime.now(UTC),
            finished_at=None,
            proxies_total=1,
            proxies_pinged=1,
            proxies_alive=1,
            sessions_total=2,
            sessions_connected=1,
            sessions_skipped_autoconnect_false=0,
            sessions_skipped_dead_proxy=0,
            sessions_skipped_human_needed=0,
            sessions_failed=0,
            eta_seconds=5,
        )
        s2 = replace(s, sessions_connected=2)
        assert s2.sessions_connected == 2
        assert s.sessions_connected == 1  # original untouched


class TestBootStatusEndpoint:
    """``/admin/api/boot-status`` — polled by the banner JS."""

    @pytest.mark.asyncio
    async def test_rejects_anonymous(self, monkeypatch) -> None:
        from chatfilter.web.routers.boot import boot_status

        # No user_id in session → 401.
        monkeypatch.setattr("chatfilter.web.routers.boot.get_session", lambda _req: {})
        fake_request = MagicMock()
        resp = await boot_status(fake_request)
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_returns_done_when_no_holder(self, monkeypatch) -> None:
        from chatfilter.web.routers.boot import boot_status

        set_boot_recovery_holder(None)
        monkeypatch.setattr(
            "chatfilter.web.routers.boot.get_session",
            lambda _req: {"user_id": 1},
        )
        resp = await boot_status(MagicMock())
        assert resp.status_code == 200
        body = json.loads(resp.body)
        assert body == {"in_progress": False, "phase": "done"}

    @pytest.mark.asyncio
    async def test_returns_snapshot_for_logged_in_user(self, monkeypatch) -> None:
        from chatfilter.web.routers.boot import boot_status

        h = BootRecoveryHolder()
        h.update(sessions_total=3, sessions_connected=1)
        set_boot_recovery_holder(h)
        try:
            monkeypatch.setattr(
                "chatfilter.web.routers.boot.get_session",
                lambda _req: {"user_id": 42},
            )
            resp = await boot_status(MagicMock())
            assert resp.status_code == 200
            body = json.loads(resp.body)
            assert body["in_progress"] is True
            assert body["sessions_total"] == 3
            assert body["sessions_connected"] == 1
            # ISO date round-trip for JSON.
            assert "T" in body["started_at"]
            assert body["finished_at"] is None
        finally:
            set_boot_recovery_holder(None)

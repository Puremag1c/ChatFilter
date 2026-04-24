"""ProxylineSyncer — admin-pool expiry refresher tests.

Scope tests are load-bearing: user-pool proxies must NEVER be touched
by the syncer, regardless of what the remote API returns.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from chatfilter.models.proxy import ProxyEntry, ProxyStatus, ProxyType
from chatfilter.service.proxyline_syncer import ProxylineSyncer, _parse_expires
from chatfilter.storage.proxy_pool import load_proxy_pool, save_proxy_pool


def _make_entry(
    name: str,
    *,
    proxyline_id: int | None = None,
    expires_at: datetime | None = None,
) -> ProxyEntry:
    return ProxyEntry(
        name=name,
        type=ProxyType.SOCKS5,
        host="1.2.3.4",
        port=1080,
        username="",
        password="",
        status=ProxyStatus.WORKING,
        proxyline_id=proxyline_id,
        expires_at=expires_at,
    )


@pytest.fixture
def seeded_pools(tmp_path: Path, monkeypatch: Any):
    """Fresh per-test admin and user pools, plus settings already isolated."""
    from chatfilter.config import get_settings

    settings = get_settings()
    settings.config_dir.mkdir(parents=True, exist_ok=True)
    return settings


class TestParseExpires:
    def test_iso_string(self) -> None:
        parsed = _parse_expires("2026-05-01T12:00:00+00:00")
        assert parsed is not None
        assert parsed.year == 2026 and parsed.month == 5

    def test_iso_with_z(self) -> None:
        parsed = _parse_expires("2026-05-01T12:00:00Z")
        assert parsed is not None
        assert parsed.tzinfo is not None

    def test_none_input(self) -> None:
        assert _parse_expires(None) is None

    def test_garbage_string_returns_none(self) -> None:
        assert _parse_expires("not-a-date") is None

    def test_datetime_passthrough(self) -> None:
        now = datetime.now(UTC)
        assert _parse_expires(now) is now


class TestRunOnce:
    @pytest.mark.asyncio
    async def test_no_api_key_noop(self, seeded_pools) -> None:
        with patch(
            "chatfilter.service.proxyline_syncer._get_proxyline_api_key",
            return_value=None,
        ):
            syncer = ProxylineSyncer()
            stats = await syncer.run_once()
        assert stats["skipped_no_key"] == 1
        assert stats["synced"] == 0

    @pytest.mark.asyncio
    async def test_updates_expires_at_for_admin_proxy(self, seeded_pools) -> None:
        new_expiry = datetime.now(UTC) + timedelta(days=30)
        save_proxy_pool([_make_entry("p1", proxyline_id=111)], "admin")

        mock_client = AsyncMock()
        mock_client.list_proxies = AsyncMock(
            return_value=[{"id": 111, "expires_at": new_expiry.isoformat()}]
        )

        with (
            patch(
                "chatfilter.service.proxyline_syncer._get_proxyline_api_key",
                return_value="key",
            ),
            patch(
                "chatfilter.service.proxyline_client.get_proxyline_client",
                return_value=mock_client,
            ),
        ):
            stats = await ProxylineSyncer().run_once()

        assert stats["synced"] == 1
        refreshed = load_proxy_pool("admin")
        assert refreshed[0].expires_at is not None
        # Normalise both sides to same precision for compare.
        assert refreshed[0].expires_at.isoformat() == new_expiry.isoformat()

    @pytest.mark.asyncio
    async def test_unchanged_counted_not_rewritten(self, seeded_pools) -> None:
        expiry = datetime.now(UTC) + timedelta(days=15)
        save_proxy_pool([_make_entry("p1", proxyline_id=2, expires_at=expiry)], "admin")

        mock_client = AsyncMock()
        mock_client.list_proxies = AsyncMock(
            return_value=[{"id": 2, "expires_at": expiry.isoformat()}]
        )

        with (
            patch(
                "chatfilter.service.proxyline_syncer._get_proxyline_api_key",
                return_value="key",
            ),
            patch(
                "chatfilter.service.proxyline_client.get_proxyline_client",
                return_value=mock_client,
            ),
        ):
            stats = await ProxylineSyncer().run_once()

        assert stats["unchanged"] == 1
        assert stats["synced"] == 0

    @pytest.mark.asyncio
    async def test_missing_remote_counted(self, seeded_pools) -> None:
        save_proxy_pool([_make_entry("p1", proxyline_id=404)], "admin")

        mock_client = AsyncMock()
        mock_client.list_proxies = AsyncMock(return_value=[])

        with (
            patch(
                "chatfilter.service.proxyline_syncer._get_proxyline_api_key",
                return_value="key",
            ),
            patch(
                "chatfilter.service.proxyline_client.get_proxyline_client",
                return_value=mock_client,
            ),
        ):
            stats = await ProxylineSyncer().run_once()

        assert stats["missing_remote"] == 1

    @pytest.mark.asyncio
    async def test_user_pool_never_touched(self, seeded_pools) -> None:
        """Power-user proxies with a proxyline_id (even if they somehow
        got one) must be ignored. The syncer only loads the admin pool."""
        new_expiry = datetime.now(UTC) + timedelta(days=30)
        # Seed both pools.
        save_proxy_pool([_make_entry("admin1", proxyline_id=1)], "admin")
        save_proxy_pool([_make_entry("user1", proxyline_id=9999)], "user_42")

        mock_client = AsyncMock()
        # Return expiry for BOTH ids — syncer should only apply admin's.
        mock_client.list_proxies = AsyncMock(
            return_value=[
                {"id": 1, "expires_at": new_expiry.isoformat()},
                {"id": 9999, "expires_at": new_expiry.isoformat()},
            ]
        )

        with (
            patch(
                "chatfilter.service.proxyline_syncer._get_proxyline_api_key",
                return_value="key",
            ),
            patch(
                "chatfilter.service.proxyline_client.get_proxyline_client",
                return_value=mock_client,
            ),
        ):
            await ProxylineSyncer().run_once()

        admin_pool = load_proxy_pool("admin")
        user_pool = load_proxy_pool("user_42")
        assert admin_pool[0].expires_at is not None, "admin expiry updated"
        assert user_pool[0].expires_at is None, "user-pool must stay untouched"

    @pytest.mark.asyncio
    async def test_ignores_entries_without_proxyline_id(self, seeded_pools) -> None:
        save_proxy_pool(
            [
                _make_entry("linked", proxyline_id=1),
                _make_entry("manual", proxyline_id=None),
            ],
            "admin",
        )

        new_expiry = datetime.now(UTC) + timedelta(days=30)
        mock_client = AsyncMock()
        mock_client.list_proxies = AsyncMock(
            return_value=[{"id": 1, "expires_at": new_expiry.isoformat()}]
        )

        with (
            patch(
                "chatfilter.service.proxyline_syncer._get_proxyline_api_key",
                return_value="key",
            ),
            patch(
                "chatfilter.service.proxyline_client.get_proxyline_client",
                return_value=mock_client,
            ),
        ):
            stats = await ProxylineSyncer().run_once()

        assert stats["synced"] == 1
        pool = load_proxy_pool("admin")
        manual = next(p for p in pool if p.name == "manual")
        assert manual.expires_at is None

    @pytest.mark.asyncio
    async def test_list_proxies_failure_is_caught(self, seeded_pools) -> None:
        from chatfilter.service.proxyline_client import ProxylineError

        save_proxy_pool([_make_entry("p1", proxyline_id=1)], "admin")

        mock_client = AsyncMock()
        mock_client.list_proxies = AsyncMock(side_effect=ProxylineError("down"))

        with (
            patch(
                "chatfilter.service.proxyline_syncer._get_proxyline_api_key",
                return_value="key",
            ),
            patch(
                "chatfilter.service.proxyline_client.get_proxyline_client",
                return_value=mock_client,
            ),
        ):
            stats = await ProxylineSyncer().run_once()

        # Graceful: no exception, nothing synced, pool intact.
        assert stats["synced"] == 0
        assert load_proxy_pool("admin")[0].expires_at is None


class TestLifecycle:
    @pytest.mark.asyncio
    async def test_start_creates_loop_task(self) -> None:
        syncer = ProxylineSyncer(interval=3600.0)
        await syncer.start()
        try:
            assert syncer._loop_task is not None
            assert not syncer._loop_task.done()
        finally:
            await syncer.stop(timeout=1.0)

    @pytest.mark.asyncio
    async def test_stop_cancels_loop(self) -> None:
        syncer = ProxylineSyncer(interval=3600.0)
        await syncer.start()
        await syncer.stop(timeout=1.0)
        assert syncer._loop_task is None

    @pytest.mark.asyncio
    async def test_double_start_is_idempotent(self) -> None:
        syncer = ProxylineSyncer(interval=3600.0)
        await syncer.start()
        first_task = syncer._loop_task
        await syncer.start()
        assert syncer._loop_task is first_task
        await syncer.stop(timeout=1.0)

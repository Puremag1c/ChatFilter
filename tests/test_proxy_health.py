"""Tests for proxy health monitoring service.

Tests cover:
- check_proxy_health: TCP connection check
- update_proxy_health: status update logic
- check_single_proxy: single proxy check
- check_all_proxies: batch proxy check
- retest_proxy: reset and retest
- ProxyHealthMonitor: background monitoring
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.config import ProxyStatus, ProxyType
from chatfilter.models.proxy import ProxyEntry
from chatfilter.service.proxy_health import (
    MAX_CONSECUTIVE_FAILURES,
    ProxyHealthMonitor,
    check_all_proxies,
    check_proxy_health,
    check_single_proxy,
    get_proxy_health_monitor,
    retest_proxy,
    update_proxy_health,
)


@pytest.fixture
def sample_proxy() -> ProxyEntry:
    """Create a sample proxy for testing."""
    return ProxyEntry(
        name="Test Proxy",
        type=ProxyType.SOCKS5,
        host="127.0.0.1",
        port=1080,
    )  # ID is auto-generated as valid UUID


class TestCheckProxyHealth:
    """Tests for check_proxy_health function."""

    @pytest.mark.asyncio
    async def test_success(self, sample_proxy: ProxyEntry) -> None:
        """Should return True for successful connection."""
        with patch("asyncio.open_connection") as mock_open:
            mock_reader = MagicMock()
            mock_writer = MagicMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            mock_open.return_value = (mock_reader, mock_writer)

            result = await check_proxy_health(sample_proxy)

            assert result is True
            mock_writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_timeout(self, sample_proxy: ProxyEntry) -> None:
        """Should return False on timeout."""
        with patch("asyncio.open_connection", side_effect=TimeoutError()):
            result = await check_proxy_health(sample_proxy)

            assert result is False

    @pytest.mark.asyncio
    async def test_connection_error(self, sample_proxy: ProxyEntry) -> None:
        """Should return False on connection error."""
        with patch("asyncio.open_connection", side_effect=OSError("Connection refused")):
            result = await check_proxy_health(sample_proxy)

            assert result is False


class TestUpdateProxyHealth:
    """Tests for update_proxy_health function."""

    @pytest.mark.asyncio
    async def test_success_updates_status(self, sample_proxy: ProxyEntry) -> None:
        """Should update status to WORKING on success."""
        with patch("chatfilter.service.proxy_health.update_proxy") as mock_update:
            result = await update_proxy_health(sample_proxy, success=True)

            assert result.status == ProxyStatus.WORKING
            assert result.consecutive_failures == 0
            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_failure_increments_counter(self, sample_proxy: ProxyEntry) -> None:
        """Should increment failure counter on failure."""
        with patch("chatfilter.service.proxy_health.update_proxy") as mock_update:
            result = await update_proxy_health(sample_proxy, success=False)

            assert result.consecutive_failures == 1
            mock_update.assert_called_once()

    @pytest.mark.asyncio
    async def test_auto_disable_after_failures(self) -> None:
        """Should auto-disable after MAX_CONSECUTIVE_FAILURES."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
            consecutive_failures=MAX_CONSECUTIVE_FAILURES - 1,
        )

        with patch("chatfilter.service.proxy_health.update_proxy"):
            result = await update_proxy_health(proxy, success=False)

            assert result.status == ProxyStatus.NO_PING


class TestCheckSingleProxy:
    """Tests for check_single_proxy function."""

    @pytest.mark.asyncio
    async def test_combines_health_and_update(self, sample_proxy: ProxyEntry) -> None:
        """Should check health and update status."""
        with patch("chatfilter.service.proxy_health.check_proxy_health") as mock_check:
            mock_check.return_value = True

            with patch("chatfilter.service.proxy_health.update_proxy_health") as mock_update:
                expected_result = sample_proxy.with_health_update(success=True)
                mock_update.return_value = expected_result

                await check_single_proxy(sample_proxy)

                mock_check.assert_called_once_with(sample_proxy)
                mock_update.assert_called_once_with(sample_proxy, True)


class TestCheckAllProxies:
    """Tests for check_all_proxies function."""

    @pytest.mark.asyncio
    async def test_checks_all_proxies(self) -> None:
        """Should check all proxies in pool."""
        proxies = [
            ProxyEntry(name="Proxy1", type=ProxyType.SOCKS5, host="1.1.1.1", port=1080),
            ProxyEntry(name="Proxy2", type=ProxyType.HTTP, host="2.2.2.2", port=8080),
        ]

        with patch("chatfilter.service.proxy_health.load_proxy_pool") as mock_load:
            mock_load.return_value = proxies

            with patch("chatfilter.service.proxy_health.check_single_proxy") as mock_check:
                mock_check.side_effect = [
                    proxies[0].with_health_update(success=True),
                    proxies[1].with_health_update(success=False),
                ]

                result = await check_all_proxies()

                assert len(result) == 2
                assert mock_check.call_count == 2

    @pytest.mark.asyncio
    async def test_empty_pool(self) -> None:
        """Should handle empty proxy pool."""
        with patch("chatfilter.service.proxy_health.load_proxy_pool") as mock_load:
            mock_load.return_value = []

            result = await check_all_proxies()

            assert result == {}


class TestRetestProxy:
    """Tests for retest_proxy function."""

    @pytest.mark.asyncio
    async def test_resets_and_retests(self, sample_proxy: ProxyEntry) -> None:
        """Should reset status and perform health check."""
        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get:
            mock_get.return_value = sample_proxy

            with (
                patch("chatfilter.service.proxy_health.update_proxy"),
                patch("chatfilter.service.proxy_health.check_single_proxy") as mock_check,
            ):
                expected = sample_proxy.with_health_update(success=True)
                mock_check.return_value = expected

                result = await retest_proxy(sample_proxy.id)

                assert result is not None
                mock_check.assert_called_once()

    @pytest.mark.asyncio
    async def test_proxy_not_found(self) -> None:
        """Should return None if proxy not found."""
        from chatfilter.storage.errors import StorageNotFoundError

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get:
            mock_get.side_effect = StorageNotFoundError("Not found")

            result = await retest_proxy("nonexistent-id")

            assert result is None


class TestProxyHealthMonitor:
    """Tests for ProxyHealthMonitor class."""

    def test_initialization(self) -> None:
        """Should initialize with default interval."""
        monitor = ProxyHealthMonitor()

        assert monitor.interval == 300.0
        assert monitor._running is False
        assert monitor._task is None

    def test_custom_interval(self) -> None:
        """Should accept custom interval."""
        monitor = ProxyHealthMonitor(interval_seconds=60.0)

        assert monitor.interval == 60.0

    def test_start(self) -> None:
        """Should start background task."""
        monitor = ProxyHealthMonitor()

        with patch("asyncio.create_task") as mock_create:
            mock_task = MagicMock()
            mock_create.return_value = mock_task

            monitor.start()

            assert monitor._running is True
            mock_create.assert_called_once()

    def test_start_already_running(self) -> None:
        """Should not start if already running."""
        monitor = ProxyHealthMonitor()
        monitor._running = True

        with patch("asyncio.create_task") as mock_create:
            monitor.start()

            mock_create.assert_not_called()

    @pytest.mark.asyncio
    async def test_stop(self) -> None:
        """Should stop background task."""
        monitor = ProxyHealthMonitor()

        # Start the monitor
        with patch.object(monitor, "_run_loop", new_callable=AsyncMock):
            monitor.start()

            # Give the task time to be created
            await asyncio.sleep(0.01)

            # Stop should work without error
            await monitor.stop()

            assert monitor._running is False


class TestGetProxyHealthMonitor:
    """Tests for get_proxy_health_monitor singleton."""

    def test_returns_monitor(self) -> None:
        """Should return ProxyHealthMonitor instance."""
        import chatfilter.service.proxy_health as phm

        phm._health_monitor = None

        monitor = get_proxy_health_monitor()

        assert isinstance(monitor, ProxyHealthMonitor)

    def test_singleton(self) -> None:
        """Should return same instance."""
        import chatfilter.service.proxy_health as phm

        phm._health_monitor = None

        monitor1 = get_proxy_health_monitor()
        monitor2 = get_proxy_health_monitor()

        assert monitor1 is monitor2

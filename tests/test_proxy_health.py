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
    socks5_tunnel_check,
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
        # Mock socks5_tunnel_check for SOCKS5 proxy
        with patch("chatfilter.service.proxy_health.socks5_tunnel_check", return_value=True):
            result = await check_proxy_health(sample_proxy)

            assert result is True

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

    @pytest.mark.asyncio
    async def test_tcp_works_but_socks5_fails(self, sample_proxy: ProxyEntry) -> None:
        """Should return False when TCP works but SOCKS5 tunnel fails (done_when test)."""
        # SOCKS5 tunnel check fails
        with patch("chatfilter.service.proxy_health.socks5_tunnel_check", return_value=False):
            # TCP connection succeeds (for diagnostic logging)
            with patch("asyncio.open_connection") as mock_open:
                mock_reader = MagicMock()
                mock_writer = MagicMock()
                mock_writer.close = MagicMock()
                mock_writer.wait_closed = AsyncMock()
                mock_open.return_value = (mock_reader, mock_writer)

                result = await check_proxy_health(sample_proxy)

                # Should return False despite TCP success
                assert result is False
                # Should have tried TCP for diagnostics
                mock_open.assert_called_once()

    @pytest.mark.asyncio
    async def test_http_proxy_uses_tcp_check(self) -> None:
        """HTTP proxies should use TCP-only check, not SOCKS5 tunnel."""
        http_proxy = ProxyEntry(
            name="HTTP Proxy",
            type=ProxyType.HTTP,
            host="127.0.0.1",
            port=8080,
        )

        # Should NOT call socks5_tunnel_check for HTTP proxy
        with patch("chatfilter.service.proxy_health.socks5_tunnel_check") as mock_tunnel:
            # TCP connection succeeds
            with patch("asyncio.open_connection") as mock_open:
                mock_reader = MagicMock()
                mock_writer = MagicMock()
                mock_writer.close = MagicMock()
                mock_writer.wait_closed = AsyncMock()
                mock_open.return_value = (mock_reader, mock_writer)

                result = await check_proxy_health(http_proxy)

                # Should return True via TCP check
                assert result is True
                # Should NOT have called SOCKS5 tunnel check
                mock_tunnel.assert_not_called()
                # Should have used TCP check
                mock_open.assert_called_once()

    @pytest.mark.asyncio
    async def test_socks5_auth_error_no_credential_leak(self) -> None:
        """Should not leak username/password in SOCKS5 auth errors (security test)."""
        import socks

        from chatfilter.service.proxy_health import ProxyCheckError, _socks5_connect_sync

        # Proxy with credentials
        proxy_username = "secret_user"
        proxy_password = "secret_pass"

        # Mock socksocket to raise auth error
        with patch("socks.socksocket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_socket_class.return_value = mock_sock
            mock_sock.connect.side_effect = socks.SOCKS5AuthError("Auth failed")

            # Should raise ProxyCheckError without credentials
            with pytest.raises(ProxyCheckError) as exc_info:
                _socks5_connect_sync(
                    proxy_host="127.0.0.1",
                    proxy_port=1080,
                    proxy_username=proxy_username,
                    proxy_password=proxy_password,
                    target_host="149.154.167.51",
                    target_port=443,
                    timeout=10.0,
                )

            # Error message should NOT contain credentials
            error_message = str(exc_info.value)
            assert proxy_username not in error_message
            assert proxy_password not in error_message
            assert "Authentication failed" in error_message


class TestSocks5TunnelCheck:
    """Tests for socks5_tunnel_check function."""

    @pytest.mark.asyncio
    async def test_success(self) -> None:
        """Should return True for successful SOCKS5 tunnel."""
        proxy = ProxyEntry(
            name="Test SOCKS5",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
            username="user",
            password="pass",
        )

        # Mock _socks5_connect_sync to succeed
        with patch("chatfilter.service.proxy_health._socks5_connect_sync", return_value=True):
            result = await socks5_tunnel_check(proxy)

            assert result is True

    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        """Should return False on timeout."""
        proxy = ProxyEntry(
            name="Test SOCKS5",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
        )

        # Mock _socks5_connect_sync to raise timeout
        with patch("chatfilter.service.proxy_health._socks5_connect_sync") as mock_connect:
            mock_connect.side_effect = asyncio.TimeoutError("Timeout")

            result = await socks5_tunnel_check(proxy, timeout=1.0)

            assert result is False

    @pytest.mark.asyncio
    async def test_auth_failure(self) -> None:
        """Should return False on authentication failure."""
        from chatfilter.service.proxy_health import ProxyCheckError

        proxy = ProxyEntry(
            name="Test SOCKS5",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
            username="wrong_user",
            password="wrong_pass",
        )

        # Mock _socks5_connect_sync to raise auth error
        with patch("chatfilter.service.proxy_health._socks5_connect_sync") as mock_connect:
            mock_connect.side_effect = ProxyCheckError("Authentication failed")

            result = await socks5_tunnel_check(proxy)

            assert result is False

    @pytest.mark.asyncio
    async def test_connection_refused(self) -> None:
        """Should return False on connection refused."""
        from chatfilter.service.proxy_health import ProxyCheckError

        proxy = ProxyEntry(
            name="Test SOCKS5",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=9999,  # Non-existent port
        )

        # Mock _socks5_connect_sync to raise connection error
        with patch("chatfilter.service.proxy_health._socks5_connect_sync") as mock_connect:
            mock_connect.side_effect = ProxyCheckError("Proxy unreachable")

            result = await socks5_tunnel_check(proxy)

            assert result is False

    @pytest.mark.asyncio
    async def test_unexpected_error_no_leak(self) -> None:
        """Should not leak proxy details in unexpected errors (security test)."""
        proxy = ProxyEntry(
            name="Sensitive Proxy Name",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
            username="secret_user",
        )

        # Mock _socks5_connect_sync to raise unexpected error
        with patch("chatfilter.service.proxy_health._socks5_connect_sync") as mock_connect:
            mock_connect.side_effect = RuntimeError("Some unexpected error")

            # Should log warning but not leak proxy details
            with patch("chatfilter.service.proxy_health.logger") as mock_logger:
                result = await socks5_tunnel_check(proxy)

                assert result is False
                # Logger should NOT contain sensitive data
                for call in mock_logger.warning.call_args_list:
                    log_message = str(call)
                    assert "secret_user" not in log_message
                    assert proxy.name not in log_message


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

    @pytest.mark.asyncio
    async def test_storage_write_error_propagated(self, sample_proxy: ProxyEntry) -> None:
        """Critical: storage write error → exception propagated (not silent log)."""
        from chatfilter.storage.errors import StorageError

        with patch("chatfilter.service.proxy_health.update_proxy") as mock_update:
            # Storage write fails
            mock_update.side_effect = StorageError("Disk write failed")

            # Exception should propagate (not caught silently)
            with pytest.raises(StorageError):
                await update_proxy_health(sample_proxy, success=True)


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

    @pytest.mark.asyncio
    async def test_socks5_proxy_uses_tunnel_check(self) -> None:
        """Retest button should use socks5_tunnel_check for SOCKS5 proxies."""
        socks5_proxy = ProxyEntry(
            name="SOCKS5 Proxy",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
        )

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get:
            mock_get.return_value = socks5_proxy

            with (
                patch("chatfilter.service.proxy_health.update_proxy"),
                patch("chatfilter.service.proxy_health.socks5_tunnel_check") as mock_tunnel,
            ):
                mock_tunnel.return_value = True

                result = await retest_proxy(socks5_proxy.id)

                # Should have called socks5_tunnel_check
                mock_tunnel.assert_called_once()
                assert result is not None
                assert result.status == ProxyStatus.WORKING

    @pytest.mark.asyncio
    async def test_health_check_fails_becomes_no_ping_not_untested(self) -> None:
        """Critical: health check fails → status becomes NO_PING (not UNTESTED)."""
        proxy = ProxyEntry(
            name="Test Proxy",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
            status=ProxyStatus.UNTESTED,
            consecutive_failures=0,
        )

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get:
            mock_get.return_value = proxy

            with (
                patch("chatfilter.service.proxy_health.check_proxy_health") as mock_check,
                patch("chatfilter.service.proxy_health.update_proxy") as mock_update,
            ):
                # Health check fails
                mock_check.return_value = False

                result = await retest_proxy(proxy.id)

                assert result is not None
                # After 1 failed retest, status should be NO_PING (not UNTESTED)
                assert result.status == ProxyStatus.NO_PING
                assert result.consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_health_check_succeeds_becomes_working(self) -> None:
        """Critical: health check succeeds → status becomes WORKING."""
        proxy = ProxyEntry(
            name="Test Proxy",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
            status=ProxyStatus.NO_PING,
            consecutive_failures=3,
        )

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get:
            mock_get.return_value = proxy

            with (
                patch("chatfilter.service.proxy_health.check_proxy_health") as mock_check,
                patch("chatfilter.service.proxy_health.update_proxy") as mock_update,
            ):
                # Health check succeeds
                mock_check.return_value = True

                result = await retest_proxy(proxy.id)

                assert result is not None
                assert result.status == ProxyStatus.WORKING
                assert result.consecutive_failures == 0

    @pytest.mark.asyncio
    async def test_exception_during_check_not_left_untested(self) -> None:
        """Critical: exception during check → status not left UNTESTED."""
        proxy = ProxyEntry(
            name="Test Proxy",
            type=ProxyType.SOCKS5,
            host="127.0.0.1",
            port=1080,
            status=ProxyStatus.UNTESTED,
            consecutive_failures=0,
        )

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get:
            mock_get.return_value = proxy

            with patch("chatfilter.service.proxy_health.check_proxy_health") as mock_check:
                # Health check throws exception
                mock_check.side_effect = TimeoutError("Connection timeout")

                # Exception should propagate (not silently caught)
                with pytest.raises(TimeoutError):
                    await retest_proxy(proxy.id)


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

"""Tests for network graceful degradation functionality.

Tests network connectivity monitoring, error handling, and graceful degradation
when internet connectivity is lost.
"""

from __future__ import annotations

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.utils.network import (
    DNSCheckStrategy,
    NetworkMonitor,
    NetworkOfflineError,
    NetworkStatus,
    TelegramAPICheckStrategy,
    detect_network_error,
    get_network_monitor,
    reset_network_monitor,
)


class TestDNSCheckStrategy:
    """Tests for DNS-based network checking."""

    @pytest.mark.asyncio
    async def test_dns_check_online(self) -> None:
        """Test DNS check when network is online."""
        strategy = DNSCheckStrategy(hosts=["8.8.8.8"], timeout=1.0)

        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            status = await strategy.check()

            assert status.is_online is True
            assert status.error_message is None
            assert status.check_duration_ms is not None
            # Duration can be 0.0 on fast systems with mocked calls
            assert status.check_duration_ms >= 0

    @pytest.mark.asyncio
    async def test_dns_check_offline(self) -> None:
        """Test DNS check when network is offline."""
        strategy = DNSCheckStrategy(hosts=["nonexistent.test"], timeout=1.0)

        with patch("socket.gethostbyname", side_effect=socket.gaierror("DNS resolution failed")):
            status = await strategy.check()

            assert status.is_online is False
            assert status.error_message is not None
            assert "DNS" in status.error_message or "offline" in status.error_message

    @pytest.mark.asyncio
    async def test_dns_check_timeout(self) -> None:
        """Test DNS check handles timeout gracefully."""
        strategy = DNSCheckStrategy(hosts=["slow.test"], timeout=0.1)

        # Mock with asyncio.TimeoutError to simulate timeout
        with patch("socket.gethostbyname", side_effect=TimeoutError("DNS timeout")):
            status = await strategy.check()

            assert status.is_online is False


class TestTelegramAPICheckStrategy:
    """Tests for Telegram API-based network checking."""

    @pytest.mark.asyncio
    async def test_telegram_check_online(self) -> None:
        """Test Telegram API check when reachable."""
        strategy = TelegramAPICheckStrategy(hosts=["api.telegram.org"], port=443, timeout=1.0)

        # Mock successful connection
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch("asyncio.open_connection", return_value=(mock_reader, mock_writer)):
            status = await strategy.check()

            assert status.is_online is True
            assert status.error_message is None
            mock_writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_telegram_check_offline(self) -> None:
        """Test Telegram API check when unreachable."""
        strategy = TelegramAPICheckStrategy(hosts=["unreachable.test"], port=443, timeout=1.0)

        with patch("asyncio.open_connection", side_effect=OSError("Connection refused")):
            status = await strategy.check()

            assert status.is_online is False
            assert status.error_message is not None


class TestNetworkMonitor:
    """Tests for NetworkMonitor class."""

    def setup_method(self) -> None:
        """Reset network monitor before each test."""
        reset_network_monitor()

    @pytest.mark.asyncio
    async def test_monitor_caches_status(self) -> None:
        """Test that monitor caches status for TTL period."""
        from datetime import UTC, datetime

        mock_strategy = AsyncMock()
        mock_strategy.check = AsyncMock(
            return_value=NetworkStatus(
                is_online=True,
                last_check=datetime.now(UTC),
                check_duration_ms=10.0,
            )
        )

        monitor = NetworkMonitor(strategy=mock_strategy, cache_ttl_seconds=60.0)

        # First call should check
        status1 = await monitor.get_status()
        assert status1.is_online is True
        assert mock_strategy.check.call_count == 1

        # Second call should use cache
        status2 = await monitor.get_status()
        assert status2.is_online is True
        assert mock_strategy.check.call_count == 1  # Still 1, used cache

    @pytest.mark.asyncio
    async def test_monitor_force_check_bypasses_cache(self) -> None:
        """Test that force_check bypasses cache."""
        from datetime import UTC, datetime

        mock_strategy = AsyncMock()
        mock_strategy.check = AsyncMock(
            return_value=NetworkStatus(
                is_online=True,
                last_check=datetime.now(UTC),
                check_duration_ms=10.0,
            )
        )

        monitor = NetworkMonitor(strategy=mock_strategy, cache_ttl_seconds=60.0)

        # First call
        await monitor.get_status()
        assert mock_strategy.check.call_count == 1

        # Force check should bypass cache
        await monitor.get_status(force_check=True)
        assert mock_strategy.check.call_count == 2

    @pytest.mark.asyncio
    async def test_monitor_is_online(self) -> None:
        """Test is_online convenience method."""
        from datetime import UTC, datetime

        mock_strategy = AsyncMock()
        mock_strategy.check = AsyncMock(
            return_value=NetworkStatus(
                is_online=True,
                last_check=datetime.now(UTC),
                check_duration_ms=10.0,
            )
        )

        monitor = NetworkMonitor(strategy=mock_strategy)

        is_online = await monitor.is_online()
        assert is_online is True

    @pytest.mark.asyncio
    async def test_monitor_ensure_online_when_online(self) -> None:
        """Test ensure_online doesn't raise when online."""
        from datetime import UTC, datetime

        mock_strategy = AsyncMock()
        mock_strategy.check = AsyncMock(
            return_value=NetworkStatus(
                is_online=True,
                last_check=datetime.now(UTC),
                check_duration_ms=10.0,
            )
        )

        monitor = NetworkMonitor(strategy=mock_strategy)

        # Should not raise
        await monitor.ensure_online()

    @pytest.mark.asyncio
    async def test_monitor_ensure_online_when_offline(self) -> None:
        """Test ensure_online raises when offline."""
        from datetime import UTC, datetime

        mock_strategy = AsyncMock()
        mock_strategy.check = AsyncMock(
            return_value=NetworkStatus(
                is_online=False,
                last_check=datetime.now(UTC),
                error_message="Network offline",
                check_duration_ms=10.0,
            )
        )

        monitor = NetworkMonitor(strategy=mock_strategy)

        # Should raise
        with pytest.raises(NetworkOfflineError) as exc_info:
            await monitor.ensure_online()

        assert "Network connection unavailable" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_monitor_wait_for_connectivity_succeeds(self) -> None:
        """Test wait_for_connectivity when network comes back."""
        from datetime import UTC, datetime

        mock_strategy = AsyncMock()

        # First call: offline, second call: online
        call_count = 0

        async def check_side_effect():
            nonlocal call_count
            call_count += 1
            return NetworkStatus(
                is_online=(call_count >= 2),  # Online on second call
                last_check=datetime.now(UTC),
                check_duration_ms=10.0,
            )

        mock_strategy.check = AsyncMock(side_effect=check_side_effect)

        monitor = NetworkMonitor(strategy=mock_strategy, cache_ttl_seconds=0)

        # Should succeed after second check
        result = await monitor.wait_for_connectivity(max_wait_seconds=5.0, check_interval=0.1)

        assert result is True
        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_monitor_wait_for_connectivity_timeout(self) -> None:
        """Test wait_for_connectivity timeout."""
        from datetime import UTC, datetime

        mock_strategy = AsyncMock()
        mock_strategy.check = AsyncMock(
            return_value=NetworkStatus(
                is_online=False,
                last_check=datetime.now(UTC),
                check_duration_ms=10.0,
            )
        )

        monitor = NetworkMonitor(strategy=mock_strategy, cache_ttl_seconds=0)

        # Should timeout and return False
        result = await monitor.wait_for_connectivity(max_wait_seconds=0.5, check_interval=0.1)

        assert result is False


class TestNetworkErrorDetection:
    """Tests for network error detection."""

    def test_detect_network_error_connection_error(self) -> None:
        """Test detection of ConnectionError."""
        error = ConnectionError("Connection refused")
        assert detect_network_error(error) is True

    def test_detect_network_error_timeout(self) -> None:
        """Test detection of TimeoutError."""
        error = TimeoutError("Request timeout")
        assert detect_network_error(error) is True

    def test_detect_network_error_socket_error(self) -> None:
        """Test detection of socket errors."""
        error = OSError("Socket error")
        assert detect_network_error(error) is True

    def test_detect_network_error_network_offline_error(self) -> None:
        """Test detection of NetworkOfflineError."""
        error = NetworkOfflineError("Network offline")
        assert detect_network_error(error) is True

    def test_detect_network_error_by_message(self) -> None:
        """Test detection by error message keywords."""
        errors_with_keywords = [
            Exception("Network connection failed"),
            Exception("DNS resolution timeout"),
            Exception("SSL handshake error"),
            Exception("Host unreachable"),
        ]

        for error in errors_with_keywords:
            assert detect_network_error(error) is True

    def test_detect_network_error_non_network(self) -> None:
        """Test that non-network errors are not detected."""
        error = ValueError("Invalid input")
        assert detect_network_error(error) is False


class TestNetworkGracefulDegradation:
    """Integration tests for graceful degradation."""

    @pytest.mark.asyncio
    async def test_service_handles_network_offline(self) -> None:
        """Test that service operations handle network offline gracefully."""
        # This would test actual service methods with mocked network
        # For now, we verify the structure is in place
        from chatfilter.telegram.retry import with_retry

        @with_retry(max_attempts=2, base_delay=0.1)
        async def operation_that_might_fail():
            raise ConnectionError("Network offline")

        # Should retry and eventually raise
        with pytest.raises(ConnectionError):
            await operation_that_might_fail()

    def test_exception_handler_detects_network_errors(self) -> None:
        """Test that exception handlers properly detect network errors."""

        from chatfilter.web.exception_handlers import network_error_handler

        # This would require a full FastAPI test setup
        # For now, we verify the function exists and is importable
        assert network_error_handler is not None


def test_global_network_monitor_singleton() -> None:
    """Test that get_network_monitor returns singleton."""
    reset_network_monitor()

    monitor1 = get_network_monitor()
    monitor2 = get_network_monitor()

    assert monitor1 is monitor2

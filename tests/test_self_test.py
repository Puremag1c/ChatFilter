"""Tests for self_test module."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from chatfilter.self_test import SelfTest, TestResult, TestStatus


def test_test_status_enum():
    """Test TestStatus enum values."""
    assert TestStatus.PASS == "PASS"
    assert TestStatus.WARN == "WARN"
    assert TestStatus.FAIL == "FAIL"
    assert TestStatus.SKIP == "SKIP"


def test_test_result_dataclass():
    """Test TestResult dataclass."""
    result = TestResult(
        name="test_name",
        status=TestStatus.PASS,
        message="Test passed",
        details={"key": "value"},
        error=None,
    )

    assert result.name == "test_name"
    assert result.status == TestStatus.PASS
    assert result.message == "Test passed"
    assert result.details == {"key": "value"}
    assert result.error is None


def test_self_test_init():
    """Test SelfTest initialization."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    assert self_test.settings == mock_settings
    assert self_test.results == []


def test_add_result():
    """Test _add_result method."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    self_test._add_result(
        name="test",
        status=TestStatus.PASS,
        message="Test message",
        details={"detail": "value"},
        error=None,
    )

    assert len(self_test.results) == 1
    assert self_test.results[0].name == "test"
    assert self_test.results[0].status == TestStatus.PASS
    assert self_test.results[0].message == "Test message"


@pytest.mark.asyncio
async def test_network_connectivity_success():
    """Test successful network connectivity."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    # Mock successful connection
    mock_writer = AsyncMock()
    mock_writer.close = Mock()
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(AsyncMock(), mock_writer)):
        await self_test.test_network_connectivity()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.PASS
    assert "connectivity verified" in self_test.results[0].message


@pytest.mark.asyncio
async def test_network_connectivity_failure():
    """Test network connectivity failure."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    # Mock failed connections (timeout)
    with patch("asyncio.open_connection", side_effect=TimeoutError()):
        await self_test.test_network_connectivity()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.FAIL
    assert "Unable to establish" in self_test.results[0].message


@pytest.mark.asyncio
async def test_dns_resolution_success():
    """Test successful DNS resolution."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    # Mock successful DNS resolution
    mock_addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("5.6.7.8", 0)),
    ]

    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(return_value=mock_addresses)
        await self_test.test_dns_resolution()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.PASS
    assert "Successfully resolved" in self_test.results[0].message
    assert "telegram.org" in self_test.results[0].message


@pytest.mark.asyncio
async def test_dns_resolution_timeout():
    """Test DNS resolution timeout."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(side_effect=TimeoutError())
        await self_test.test_dns_resolution()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.FAIL
    assert "timed out" in self_test.results[0].message


@pytest.mark.asyncio
async def test_dns_resolution_gaierror():
    """Test DNS resolution with socket.gaierror."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(side_effect=socket.gaierror("DNS error"))
        await self_test.test_dns_resolution()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.FAIL
    assert "failed" in self_test.results[0].message


@pytest.mark.asyncio
async def test_dns_resolution_empty_result():
    """Test DNS resolution with empty result."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    with patch("asyncio.get_running_loop") as mock_loop:
        mock_loop.return_value.getaddrinfo = AsyncMock(return_value=[])
        await self_test.test_dns_resolution()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.FAIL
    assert "returned no results" in self_test.results[0].message


@pytest.mark.asyncio
async def test_telegram_connectivity_success():
    """Test successful Telegram connectivity."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    # Mock successful connection
    mock_writer = AsyncMock()
    mock_writer.close = Mock()
    mock_writer.wait_closed = AsyncMock()

    with patch("asyncio.open_connection", return_value=(AsyncMock(), mock_writer)):
        await self_test.test_telegram_connectivity()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.PASS
    assert "Successfully connected" in self_test.results[0].message


@pytest.mark.asyncio
async def test_telegram_connectivity_partial_success():
    """Test Telegram connectivity with some failures."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    # Mock first connection success, second timeout
    mock_writer = AsyncMock()
    mock_writer.close = Mock()
    mock_writer.wait_closed = AsyncMock()

    call_count = [0]

    async def mock_open_connection(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] == 1:
            return AsyncMock(), mock_writer
        raise TimeoutError()

    with patch("asyncio.open_connection", side_effect=mock_open_connection):
        await self_test.test_telegram_connectivity()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.PASS
    assert "Successfully connected" in self_test.results[0].message


@pytest.mark.asyncio
async def test_telegram_connectivity_failure():
    """Test Telegram connectivity failure."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    with patch("asyncio.open_connection", side_effect=TimeoutError()):
        await self_test.test_telegram_connectivity()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.FAIL
    assert "Unable to connect" in self_test.results[0].message


def test_write_permissions_success(isolated_tmp_dir: Path):
    """Test successful write permissions check."""
    mock_settings = MagicMock()
    mock_settings.data_dir = isolated_tmp_dir / "data"
    mock_settings.config_dir = isolated_tmp_dir / "config"
    mock_settings.sessions_dir = isolated_tmp_dir / "sessions"
    mock_settings.exports_dir = isolated_tmp_dir / "exports"

    self_test = SelfTest(mock_settings)
    self_test.test_write_permissions()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.PASS
    assert "Write permissions verified" in self_test.results[0].message


def test_write_permissions_mkdir_failure():
    """Test write permissions with directory creation failure."""
    mock_settings = MagicMock()
    mock_settings.data_dir = "/nonexistent/readonly/path"
    mock_settings.config_dir = "/nonexistent/readonly/path2"
    mock_settings.sessions_dir = "/nonexistent/readonly/path3"
    mock_settings.exports_dir = "/nonexistent/readonly/path4"

    self_test = SelfTest(mock_settings)

    with patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied")):
        self_test.test_write_permissions()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.FAIL
    assert "Write permission failures" in self_test.results[0].message


def test_port_availability_success():
    """Test port availability check when port is free."""
    mock_settings = MagicMock()
    mock_settings.host = "127.0.0.1"
    mock_settings.port = 0  # Use port 0 to get any available port

    self_test = SelfTest(mock_settings)
    self_test.test_port_availability()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.PASS
    assert "is available" in self_test.results[0].message


def test_port_availability_in_use():
    """Test port availability when port is already in use."""
    # Bind to a port to make it unavailable
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    _, port = sock.getsockname()

    mock_settings = MagicMock()
    mock_settings.host = "127.0.0.1"
    mock_settings.port = port

    self_test = SelfTest(mock_settings)
    self_test.test_port_availability()

    sock.close()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.FAIL
    assert (
        "already in use" in self_test.results[0].message
        or "Cannot bind" in self_test.results[0].message
    )


def test_configuration_success():
    """Test configuration validation success."""
    mock_settings = MagicMock()
    mock_settings.validate = Mock(return_value=[])
    mock_settings.data_dir = Path("/data")
    mock_settings.host = "localhost"
    mock_settings.port = 8000

    self_test = SelfTest(mock_settings)
    self_test.test_configuration()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.PASS
    assert "validation passed" in self_test.results[0].message


def test_configuration_failure():
    """Test configuration validation failure."""
    mock_settings = MagicMock()
    mock_settings.validate = Mock(return_value=["Error 1", "Error 2"])

    self_test = SelfTest(mock_settings)
    self_test.test_configuration()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.FAIL
    assert "validation failed" in self_test.results[0].message


def test_configuration_exception():
    """Test configuration validation with exception."""
    mock_settings = MagicMock()
    mock_settings.validate = Mock(side_effect=ValueError("Invalid config"))

    self_test = SelfTest(mock_settings)
    self_test.test_configuration()

    assert len(self_test.results) == 1
    assert self_test.results[0].status == TestStatus.FAIL
    assert "raised an exception" in self_test.results[0].message


@pytest.mark.asyncio
async def test_run_all_tests(isolated_tmp_dir: Path):
    """Test run_all_tests executes all tests."""
    mock_settings = MagicMock()
    mock_settings.data_dir = isolated_tmp_dir / "data"
    mock_settings.config_dir = isolated_tmp_dir / "config"
    mock_settings.sessions_dir = isolated_tmp_dir / "sessions"
    mock_settings.exports_dir = isolated_tmp_dir / "exports"
    mock_settings.host = "127.0.0.1"
    mock_settings.port = 0
    mock_settings.validate = Mock(return_value=[])

    self_test = SelfTest(mock_settings)

    # Mock network methods to avoid actual network calls
    self_test.test_network_connectivity = AsyncMock()
    self_test.test_dns_resolution = AsyncMock()
    self_test.test_telegram_connectivity = AsyncMock()

    results = await self_test.run_all_tests()

    # Verify all tests were called
    assert self_test.test_network_connectivity.called
    assert self_test.test_dns_resolution.called
    assert self_test.test_telegram_connectivity.called

    # Results should contain at least the sync tests (config, write, port)
    assert len(results) >= 3
    assert results == self_test.results


def test_has_failures():
    """Test has_failures method."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    # No failures initially
    assert not self_test.has_failures()

    # Add passing result
    self_test._add_result("test1", TestStatus.PASS, "Passed")
    assert not self_test.has_failures()

    # Add failing result
    self_test._add_result("test2", TestStatus.FAIL, "Failed")
    assert self_test.has_failures()


def test_has_warnings():
    """Test has_warnings method."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    # No warnings initially
    assert not self_test.has_warnings()

    # Add passing result
    self_test._add_result("test1", TestStatus.PASS, "Passed")
    assert not self_test.has_warnings()

    # Add warning result
    self_test._add_result("test2", TestStatus.WARN, "Warning")
    assert self_test.has_warnings()


def test_to_dict():
    """Test to_dict method."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    # Add various results
    self_test._add_result("test1", TestStatus.PASS, "Passed", details={"key": "value"})
    self_test._add_result("test2", TestStatus.FAIL, "Failed", error="Error message")
    self_test._add_result("test3", TestStatus.WARN, "Warning")
    self_test._add_result("test4", TestStatus.SKIP, "Skipped")

    result_dict = self_test.to_dict()

    # Check summary
    assert result_dict["summary"]["total"] == 4
    assert result_dict["summary"]["passed"] == 1
    assert result_dict["summary"]["failed"] == 1
    assert result_dict["summary"]["warned"] == 1
    assert result_dict["summary"]["skipped"] == 1
    assert result_dict["summary"]["has_failures"] is True
    assert result_dict["summary"]["has_warnings"] is True

    # Check tests list
    assert len(result_dict["tests"]) == 4
    assert result_dict["tests"][0]["name"] == "test1"
    assert result_dict["tests"][0]["status"] == "PASS"
    assert result_dict["tests"][1]["error"] == "Error message"


def test_format_table():
    """Test format_table method."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    # Add results
    self_test._add_result("test1", TestStatus.PASS, "Test passed", details={"key": "value"})
    self_test._add_result("test2", TestStatus.FAIL, "Test failed", error="Error message")

    output = self_test.format_table()

    # Check key sections are present
    assert "SELF-TEST DIAGNOSTICS" in output
    assert "Summary:" in output
    assert "Total:" in output
    assert "Passed:" in output
    assert "Failed:" in output
    assert "test1" in output
    assert "test2" in output
    assert "FAILED" in output  # Overall status


def test_format_table_all_passed():
    """Test format_table with all tests passing."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    self_test._add_result("test1", TestStatus.PASS, "Test passed")
    self_test._add_result("test2", TestStatus.PASS, "Another test passed")

    output = self_test.format_table()

    assert "ALL TESTS PASSED" in output
    assert "ready to start" in output


def test_format_table_with_warnings():
    """Test format_table with warnings but no failures."""
    mock_settings = MagicMock()
    self_test = SelfTest(mock_settings)

    self_test._add_result("test1", TestStatus.PASS, "Test passed")
    self_test._add_result("test2", TestStatus.WARN, "Test warning")

    output = self_test.format_table()

    assert "PASSED WITH WARNINGS" in output
    assert "should function" in output

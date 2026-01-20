"""Tests for port utilities."""

from __future__ import annotations

import socket

import pytest

from chatfilter.utils.ports import (
    PortInfo,
    find_available_port,
    format_port_conflict_message,
    get_port_info,
    is_port_available,
)


class TestPortAvailability:
    """Tests for port availability checking."""

    def test_port_is_available(self) -> None:
        """Test detecting available port."""
        # Find a port that should be available
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            port = s.getsockname()[1]
        # Socket is closed now, port should be available
        assert is_port_available("127.0.0.1", port)

    def test_port_is_not_available(self) -> None:
        """Test detecting occupied port."""
        # Bind to a port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.listen(1)

        try:
            assert not is_port_available("127.0.0.1", port)
        finally:
            sock.close()


class TestFindAvailablePort:
    """Tests for finding available ports."""

    def test_find_available_port_in_range(self) -> None:
        """Test finding an available port in a range."""
        port = find_available_port("127.0.0.1", 50000, 50100)
        assert port is not None
        assert 50000 <= port <= 50100
        assert is_port_available("127.0.0.1", port)

    def test_find_available_port_when_all_occupied(self) -> None:
        """Test finding port when all ports in range are occupied."""
        # This is hard to test reliably without binding hundreds of sockets
        # Instead, test with a very small range
        port = find_available_port("127.0.0.1", 60000, 60000)
        # Should return 60000 if available, or None if occupied
        assert port is None or port == 60000

    def test_find_available_port_default_range(self) -> None:
        """Test finding port with default range."""
        port = find_available_port()
        assert port is not None
        assert 8000 <= port <= 9000


class TestGetPortInfo:
    """Tests for getting port information."""

    def test_get_port_info_for_free_port(self) -> None:
        """Test getting info for a port that's not in use."""
        # Find a free port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            port = s.getsockname()[1]

        info = get_port_info(port)
        # Port is free, should return None
        assert info is None

    def test_get_port_info_for_occupied_port(self) -> None:
        """Test getting info for a port that's in use."""
        # Bind to a port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.listen(1)

        try:
            info = get_port_info(port)
            # Might return None if lsof/netstat not available or fails
            if info is not None:
                assert isinstance(info, PortInfo)
                assert info.port == port
                assert info.pid is not None
        finally:
            sock.close()


class TestFormatPortConflictMessage:
    """Tests for formatting port conflict messages."""

    def test_format_message_for_occupied_port(self) -> None:
        """Test formatting message for port conflict."""
        # Bind to a port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.listen(1)

        try:
            message = format_port_conflict_message("127.0.0.1", port)

            # Check message contains key information
            assert str(port) in message
            assert "already in use" in message.lower()
            assert "Fix:" in message
            assert "Hint:" in message

            # Should suggest alternative port
            alt_port = find_available_port("127.0.0.1", port + 1, port + 100)
            if alt_port:
                assert str(alt_port) in message

        finally:
            sock.close()

    def test_format_message_includes_process_info(self) -> None:
        """Test that message includes process info when available."""
        # Bind to a port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.listen(1)

        try:
            message = format_port_conflict_message("127.0.0.1", port)

            # If process info is available, it should be in the message
            port_info = get_port_info(port)
            if port_info and port_info.pid:
                assert "PID" in message
                assert str(port_info.pid) in message
        finally:
            sock.close()

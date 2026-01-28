"""Tests for Proxy pool models.

Tests cover:
- ProxyEntry: creation, validation, properties, methods
- Field validators: name, host, id, type, status
- Health update methods
- Telethon proxy conversion
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from chatfilter.config import ProxyStatus, ProxyType
from chatfilter.models.proxy import ProxyEntry


class TestProxyEntryCreation:
    """Tests for ProxyEntry creation."""

    def test_valid_proxy(self) -> None:
        """Should create valid proxy entry."""
        proxy = ProxyEntry(
            name="Test Proxy",
            type=ProxyType.SOCKS5,
            host="proxy.example.com",
            port=1080,
        )

        assert proxy.name == "Test Proxy"
        assert proxy.type == ProxyType.SOCKS5
        assert proxy.host == "proxy.example.com"
        assert proxy.port == 1080
        assert proxy.username == ""
        assert proxy.password == ""
        assert proxy.status == ProxyStatus.UNTESTED

    def test_auto_generated_id(self) -> None:
        """ID should be auto-generated UUID."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
        )

        # Should be valid UUID
        uuid.UUID(proxy.id)

    def test_with_auth(self) -> None:
        """Should accept authentication credentials."""
        proxy = ProxyEntry(
            name="Auth Proxy",
            type=ProxyType.HTTP,
            host="proxy.example.com",
            port=8080,
            username="user",
            password="pass",
        )

        assert proxy.username == "user"
        assert proxy.password == "pass"

    def test_frozen_model(self) -> None:
        """ProxyEntry should be immutable."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
        )

        with pytest.raises((ValidationError, AttributeError)):
            proxy.name = "Changed"  # type: ignore


class TestNameValidation:
    """Tests for name validation."""

    def test_valid_name(self) -> None:
        """Should accept valid name."""
        proxy = ProxyEntry(
            name="My Proxy Server",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
        )

        assert proxy.name == "My Proxy Server"

    def test_name_stripped(self) -> None:
        """Should strip whitespace from name."""
        proxy = ProxyEntry(
            name="  Proxy Name  ",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
        )

        assert proxy.name == "Proxy Name"

    def test_empty_name_rejected(self) -> None:
        """Should reject empty name."""
        with pytest.raises(ValidationError):
            ProxyEntry(
                name="",
                type=ProxyType.SOCKS5,
                host="localhost",
                port=1080,
            )

    def test_whitespace_only_name_rejected(self) -> None:
        """Should reject whitespace-only name."""
        with pytest.raises(ValidationError):
            ProxyEntry(
                name="   ",
                type=ProxyType.SOCKS5,
                host="localhost",
                port=1080,
            )


class TestHostValidation:
    """Tests for host validation."""

    def test_valid_hostname(self) -> None:
        """Should accept valid hostname."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="proxy.example.com",
            port=1080,
        )

        assert proxy.host == "proxy.example.com"

    def test_valid_ip(self) -> None:
        """Should accept IP address."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="192.168.1.1",
            port=1080,
        )

        assert proxy.host == "192.168.1.1"

    def test_host_lowercased(self) -> None:
        """Should lowercase host."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="PROXY.EXAMPLE.COM",
            port=1080,
        )

        assert proxy.host == "proxy.example.com"

    def test_host_with_spaces_rejected(self) -> None:
        """Should reject host with spaces."""
        with pytest.raises(ValidationError):
            ProxyEntry(
                name="Test",
                type=ProxyType.SOCKS5,
                host="proxy example.com",
                port=1080,
            )


class TestPortValidation:
    """Tests for port validation."""

    def test_valid_port(self) -> None:
        """Should accept valid port."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
        )

        assert proxy.port == 1080

    def test_port_min(self) -> None:
        """Should accept minimum port (1)."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1,
        )

        assert proxy.port == 1

    def test_port_max(self) -> None:
        """Should accept maximum port (65535)."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=65535,
        )

        assert proxy.port == 65535

    def test_port_zero_rejected(self) -> None:
        """Should reject port 0."""
        with pytest.raises(ValidationError):
            ProxyEntry(
                name="Test",
                type=ProxyType.SOCKS5,
                host="localhost",
                port=0,
            )

    def test_port_too_high_rejected(self) -> None:
        """Should reject port > 65535."""
        with pytest.raises(ValidationError):
            ProxyEntry(
                name="Test",
                type=ProxyType.SOCKS5,
                host="localhost",
                port=65536,
            )


class TestTypeCoercion:
    """Tests for proxy type coercion."""

    def test_enum_value(self) -> None:
        """Should accept ProxyType enum."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
        )

        assert proxy.type == ProxyType.SOCKS5

    def test_string_value(self) -> None:
        """Should coerce string to ProxyType."""
        proxy = ProxyEntry(
            name="Test",
            type="socks5",  # type: ignore
            host="localhost",
            port=1080,
        )

        assert proxy.type == ProxyType.SOCKS5

    def test_invalid_type_rejected(self) -> None:
        """Should reject invalid type string."""
        with pytest.raises(ValidationError):
            ProxyEntry(
                name="Test",
                type="invalid",  # type: ignore
                host="localhost",
                port=1080,
            )


class TestStatusCoercion:
    """Tests for proxy status coercion."""

    def test_enum_value(self) -> None:
        """Should accept ProxyStatus enum."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            status=ProxyStatus.WORKING,
        )

        assert proxy.status == ProxyStatus.WORKING

    def test_string_value(self) -> None:
        """Should coerce string to ProxyStatus."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            status="working",  # type: ignore
        )

        assert proxy.status == ProxyStatus.WORKING


class TestProperties:
    """Tests for ProxyEntry properties."""

    def test_has_auth_false(self) -> None:
        """Should return False when no auth."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
        )

        assert proxy.has_auth is False

    def test_has_auth_true(self) -> None:
        """Should return True when auth provided."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            username="user",
        )

        assert proxy.has_auth is True

    def test_is_available_untested(self) -> None:
        """Untested should be available."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            status=ProxyStatus.UNTESTED,
        )

        assert proxy.is_available is True

    def test_is_available_working(self) -> None:
        """Working should be available."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            status=ProxyStatus.WORKING,
        )

        assert proxy.is_available is True

    def test_is_available_no_ping(self) -> None:
        """No ping should not be available."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            status=ProxyStatus.NO_PING,
        )

        assert proxy.is_available is False


class TestWithHealthUpdate:
    """Tests for with_health_update method."""

    def test_success_sets_working(self) -> None:
        """Success should set status to WORKING."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
        )

        updated = proxy.with_health_update(success=True)

        assert updated.status == ProxyStatus.WORKING
        assert updated.consecutive_failures == 0
        assert updated.last_success_at is not None

    def test_failure_increments_counter(self) -> None:
        """Failure should increment counter."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            consecutive_failures=0,
        )

        updated = proxy.with_health_update(success=False)

        assert updated.consecutive_failures == 1

    def test_auto_disable_after_three_failures(self) -> None:
        """Should auto-disable after 3 failures."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            consecutive_failures=2,
        )

        updated = proxy.with_health_update(success=False)

        assert updated.consecutive_failures == 3
        assert updated.status == ProxyStatus.NO_PING

    def test_preserves_other_fields(self) -> None:
        """Should preserve other fields."""
        proxy = ProxyEntry(
            name="Test Proxy",
            type=ProxyType.HTTP,
            host="example.com",
            port=8080,
            username="user",
            password="pass",
        )

        updated = proxy.with_health_update(success=True)

        assert updated.name == "Test Proxy"
        assert updated.type == ProxyType.HTTP
        assert updated.host == "example.com"
        assert updated.port == 8080
        assert updated.username == "user"
        assert updated.password == "pass"


class TestWithStatusReset:
    """Tests for with_status_reset method."""

    def test_resets_status(self) -> None:
        """Should reset status to UNTESTED."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            status=ProxyStatus.NO_PING,
            consecutive_failures=5,
        )

        reset = proxy.with_status_reset()

        assert reset.status == ProxyStatus.UNTESTED
        assert reset.consecutive_failures == 0

    def test_preserves_timestamps(self) -> None:
        """Should preserve last_ping_at and last_success_at."""
        now = datetime.now(UTC)
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="localhost",
            port=1080,
            last_ping_at=now,
            last_success_at=now,
        )

        reset = proxy.with_status_reset()

        assert reset.last_ping_at == now
        assert reset.last_success_at == now


class TestToTelethonProxy:
    """Tests for to_telethon_proxy method."""

    def test_socks5_conversion(self) -> None:
        """Should convert SOCKS5 proxy."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="proxy.example.com",
            port=1080,
        )

        result = proxy.to_telethon_proxy()

        # (proxy_type, host, port, rdns, username, password)
        assert result[1] == "proxy.example.com"
        assert result[2] == 1080
        assert result[3] is True  # rdns
        assert result[4] is None  # no username
        assert result[5] is None  # no password

    def test_with_auth(self) -> None:
        """Should include auth credentials."""
        proxy = ProxyEntry(
            name="Test",
            type=ProxyType.SOCKS5,
            host="proxy.example.com",
            port=1080,
            username="user",
            password="pass",
        )

        result = proxy.to_telethon_proxy()

        assert result[4] == "user"
        assert result[5] == "pass"

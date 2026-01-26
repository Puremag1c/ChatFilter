"""Tests for proxy pool migration from legacy proxy.json."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chatfilter.storage.proxy_pool import (
    load_proxy_pool,
)


@pytest.fixture
def app_root(isolated_tmp_dir: Path) -> Path:
    """Create an isolated application root with config directory."""
    config_dir = isolated_tmp_dir / "data" / "config"
    config_dir.mkdir(parents=True)
    return isolated_tmp_dir


@pytest.fixture
def legacy_proxy_json(app_root: Path) -> Path:
    """Create a legacy proxy.json file."""
    config_dir = app_root / "data" / "config"
    proxy_file = config_dir / "proxy.json"
    proxy_file.write_text(
        json.dumps(
            {
                "enabled": True,
                "proxy_type": "socks5",
                "host": "192.168.1.100",
                "port": 9050,
                "username": "testuser",
                "password": "testpass",
            }
        )
    )
    return proxy_file


@contextmanager
def mock_proxy_pool_paths(app_root: Path) -> Iterator[None]:
    """Mock both get_application_path and get_settings for proxy_pool tests."""
    mock_settings = MagicMock()
    mock_settings.config_dir = app_root / "data" / "config"

    with (
        patch("chatfilter.storage.proxy_pool.get_application_path", return_value=app_root),
        patch("chatfilter.storage.proxy_pool.get_settings", return_value=mock_settings),
    ):
        yield


class TestLegacyProxyMigration:
    """Tests for legacy proxy.json migration."""

    def test_migration_creates_proxies_json(self, app_root: Path, legacy_proxy_json: Path) -> None:
        """Migration should create proxies.json from legacy proxy.json."""
        with mock_proxy_pool_paths(app_root):
            proxies = load_proxy_pool()

        assert len(proxies) == 1
        proxy = proxies[0]
        assert proxy.name == "Default"
        assert proxy.type.value == "socks5"
        assert proxy.host == "192.168.1.100"
        assert proxy.port == 9050
        assert proxy.username == "testuser"
        assert proxy.password == "testpass"

        # Verify file was created
        proxies_file = app_root / "data" / "config" / "proxies.json"
        assert proxies_file.exists()

    def test_migration_skipped_if_proxies_exists(
        self, app_root: Path, legacy_proxy_json: Path
    ) -> None:
        """Migration should not run if proxies.json already exists."""
        # Create existing proxies.json
        proxies_file = app_root / "data" / "config" / "proxies.json"
        proxies_file.write_text(json.dumps([]))

        with mock_proxy_pool_paths(app_root):
            proxies = load_proxy_pool()

        # Should be empty since we didn't put anything in proxies.json
        assert len(proxies) == 0

    def test_migration_skipped_if_no_legacy_file(self, app_root: Path) -> None:
        """Migration should not run if no legacy proxy.json exists."""
        with mock_proxy_pool_paths(app_root):
            proxies = load_proxy_pool()

        assert len(proxies) == 0

    def test_migration_handles_http_proxy_type(self, app_root: Path) -> None:
        """Migration should handle HTTP proxy type."""
        config_dir = app_root / "data" / "config"
        proxy_file = config_dir / "proxy.json"
        proxy_file.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "proxy_type": "http",
                    "host": "proxy.example.com",
                    "port": 8080,
                    "username": "",
                    "password": "",
                }
            )
        )

        with mock_proxy_pool_paths(app_root):
            proxies = load_proxy_pool()

        assert len(proxies) == 1
        assert proxies[0].type.value == "http"

    def test_migration_handles_unknown_proxy_type(self, app_root: Path) -> None:
        """Migration should default to socks5 for unknown proxy types."""
        config_dir = app_root / "data" / "config"
        proxy_file = config_dir / "proxy.json"
        proxy_file.write_text(
            json.dumps(
                {
                    "enabled": True,
                    "proxy_type": "unknown_type",
                    "host": "127.0.0.1",
                    "port": 1080,
                    "username": "",
                    "password": "",
                }
            )
        )

        with mock_proxy_pool_paths(app_root):
            proxies = load_proxy_pool()

        assert len(proxies) == 1
        assert proxies[0].type.value == "socks5"  # Default

    def test_migration_handles_invalid_json(self, app_root: Path) -> None:
        """Migration should handle invalid JSON gracefully."""
        config_dir = app_root / "data" / "config"
        proxy_file = config_dir / "proxy.json"
        proxy_file.write_text("not valid json")

        with mock_proxy_pool_paths(app_root):
            proxies = load_proxy_pool()

        # Should return empty list without crashing
        assert len(proxies) == 0

    def test_migration_handles_invalid_format(self, app_root: Path) -> None:
        """Migration should handle wrong JSON format (array instead of object)."""
        config_dir = app_root / "data" / "config"
        proxy_file = config_dir / "proxy.json"
        proxy_file.write_text(json.dumps([1, 2, 3]))

        with mock_proxy_pool_paths(app_root):
            proxies = load_proxy_pool()

        # Should return empty list without crashing
        assert len(proxies) == 0

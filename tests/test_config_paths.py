"""Tests for OS-specific path configuration."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from chatfilter.config import (
    _get_default_data_dir,
    get_user_cache_dir,
    get_user_config_dir,
    get_user_log_dir,
)


class TestPlatformPaths:
    """Tests for platform-specific directory paths."""

    def test_data_dir_returns_path(self) -> None:
        """Test that data dir returns a valid Path."""
        data_dir = _get_default_data_dir()
        assert isinstance(data_dir, Path)
        assert "ChatFilter" in str(data_dir)

    def test_config_dir_returns_path(self) -> None:
        """Test that config dir returns a valid Path."""
        config_dir = get_user_config_dir()
        assert isinstance(config_dir, Path)
        assert "ChatFilter" in str(config_dir)

    def test_cache_dir_returns_path(self) -> None:
        """Test that cache dir returns a valid Path."""
        cache_dir = get_user_cache_dir()
        assert isinstance(cache_dir, Path)
        assert "ChatFilter" in str(cache_dir)

    def test_log_dir_returns_path(self) -> None:
        """Test that log dir returns a valid Path."""
        log_dir = get_user_log_dir()
        assert isinstance(log_dir, Path)
        assert "ChatFilter" in str(log_dir)

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-specific test")
    def test_macos_paths(self) -> None:
        """Test macOS-specific paths."""
        data_dir = _get_default_data_dir()
        config_dir = get_user_config_dir()
        cache_dir = get_user_cache_dir()
        log_dir = get_user_log_dir()

        # macOS uses specific directories
        assert "Library/Application Support" in str(data_dir)
        assert "Library/Application Support" in str(config_dir)
        assert "Library/Caches" in str(cache_dir)
        assert "Library/Logs" in str(log_dir)

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_paths(self) -> None:
        """Test Windows-specific paths."""
        data_dir = _get_default_data_dir()
        config_dir = get_user_config_dir()
        cache_dir = get_user_cache_dir()
        log_dir = get_user_log_dir()

        # Windows uses AppData directories
        assert "AppData" in str(data_dir) or "Roaming" in str(data_dir)
        assert "AppData" in str(config_dir) or "Roaming" in str(config_dir)

    @pytest.mark.skipif(sys.platform != "linux", reason="Linux-specific test")
    def test_linux_paths(self) -> None:
        """Test Linux-specific paths."""
        data_dir = _get_default_data_dir()
        config_dir = get_user_config_dir()
        cache_dir = get_user_cache_dir()
        log_dir = get_user_log_dir()

        # Linux uses XDG base directory spec
        assert ".local/share" in str(data_dir) or "XDG_DATA_HOME" in str(data_dir)
        assert ".config" in str(config_dir) or "XDG_CONFIG_HOME" in str(config_dir)
        assert ".cache" in str(cache_dir) or "XDG_CACHE_HOME" in str(cache_dir)

    def test_paths_are_absolute(self) -> None:
        """Test that all paths are absolute."""
        data_dir = _get_default_data_dir()
        config_dir = get_user_config_dir()
        cache_dir = get_user_cache_dir()
        log_dir = get_user_log_dir()

        assert data_dir.is_absolute()
        assert config_dir.is_absolute()
        assert cache_dir.is_absolute()
        assert log_dir.is_absolute()

    def test_paths_contain_app_name(self) -> None:
        """Test that all paths contain application name."""
        data_dir = _get_default_data_dir()
        config_dir = get_user_config_dir()
        cache_dir = get_user_cache_dir()
        log_dir = get_user_log_dir()

        app_name = "ChatFilter"
        assert app_name in str(data_dir)
        assert app_name in str(config_dir)
        assert app_name in str(cache_dir)
        assert app_name in str(log_dir)

"""Tests for path utilities for PyInstaller compatibility.

Tests cover:
- get_base_path: base application path
- get_application_path: executable directory
- is_frozen: PyInstaller detection
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

from chatfilter.utils.paths import get_application_path, get_base_path, is_frozen


class TestGetBasePath:
    """Tests for get_base_path function."""

    def test_development_mode(self) -> None:
        """Should return package directory in development."""
        # Ensure not frozen
        with patch.object(sys, "frozen", False, create=True):
            result = get_base_path()

            assert isinstance(result, Path)
            # Should point to chatfilter package
            assert result.exists() or "chatfilter" in str(result)

    def test_frozen_mode(self) -> None:
        """Should return _MEIPASS/chatfilter in frozen mode."""
        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "_MEIPASS", "/tmp/pyinstaller_temp", create=True),
        ):
            result = get_base_path()

            assert isinstance(result, Path)
            assert str(result) == "/tmp/pyinstaller_temp/chatfilter"


class TestGetApplicationPath:
    """Tests for get_application_path function."""

    def test_development_mode(self) -> None:
        """Should return project root in development."""
        with patch.object(sys, "frozen", False, create=True):
            result = get_application_path()

            assert isinstance(result, Path)

    def test_frozen_mode(self) -> None:
        """Should return executable directory in frozen mode."""
        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "executable", "/usr/local/bin/chatfilter", create=True),
        ):
            result = get_application_path()

            assert isinstance(result, Path)
            assert str(result) == "/usr/local/bin"


class TestIsFrozen:
    """Tests for is_frozen function."""

    def test_not_frozen(self) -> None:
        """Should return False when not frozen."""
        with patch.object(sys, "frozen", False, create=True):
            result = is_frozen()

            assert result is False

    def test_frozen_without_meipass(self) -> None:
        """Should return False if frozen but no _MEIPASS."""
        with patch.object(sys, "frozen", True, create=True):
            # Remove _MEIPASS if exists
            if hasattr(sys, "_MEIPASS"):
                delattr(sys, "_MEIPASS")

            result = is_frozen()

            assert result is False

    def test_frozen_with_meipass(self) -> None:
        """Should return True if frozen with _MEIPASS."""
        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "_MEIPASS", "/tmp/meipass", create=True),
        ):
            result = is_frozen()

            assert result is True

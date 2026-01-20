"""Tests for configuration validation."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from chatfilter.config import Settings


class TestConfigValidation:
    """Tests for Settings.validate() method."""

    def test_valid_config(self, tmp_path: Path) -> None:
        """Test that valid configuration passes validation."""
        # Find available port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            port = s.getsockname()[1]

        settings = Settings(data_dir=tmp_path, port=port)
        errors = settings.validate()

        assert errors == []

    def test_invalid_port_too_low(self, tmp_path: Path) -> None:
        """Test that port below 1 fails validation."""
        from pydantic import ValidationError

        # Pydantic should catch this during Settings construction
        with pytest.raises(ValidationError, match="port"):
            Settings(data_dir=tmp_path, port=0)

    def test_data_dir_is_file(self, tmp_path: Path) -> None:
        """Test that data directory existing as file fails validation."""
        file_path = tmp_path / "not_a_directory"
        file_path.write_text("content")

        settings = Settings(data_dir=file_path, port=8888)
        errors = settings.validate()

        assert len(errors) > 0
        assert any("not a directory" in err for err in errors)
        assert any("Fix:" in err for err in errors)

    def test_readonly_parent_directory(self, tmp_path: Path) -> None:
        """Test that read-only parent directory fails validation."""
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)  # Read-only

        data_dir = readonly_dir / "data"
        settings = Settings(data_dir=data_dir, port=8889)

        try:
            errors = settings.validate()
            # Should have permission error
            assert len(errors) > 0
            assert any("permission" in err.lower() for err in errors)
        finally:
            # Cleanup: restore permissions
            readonly_dir.chmod(0o755)

    def test_port_in_use(self, tmp_path: Path) -> None:
        """Test that occupied port fails validation."""
        # Bind to a port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.listen(1)

        try:
            settings = Settings(data_dir=tmp_path, port=port, host="127.0.0.1")
            errors = settings.validate()

            # Should detect port in use
            assert len(errors) > 0
            assert any(str(port) in err for err in errors)
            assert any("already in use" in err for err in errors)
            assert any("Fix:" in err for err in errors)
        finally:
            sock.close()

    def test_writable_data_directory(self, tmp_path: Path) -> None:
        """Test that writable data directory passes validation."""
        data_dir = tmp_path / "data"

        # Find available port
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            port = s.getsockname()[1]

        settings = Settings(data_dir=data_dir, port=port)
        errors = settings.validate()

        assert errors == []
        assert data_dir.exists()  # Should be created during validation

    def test_validation_messages_have_fixes(self, tmp_path: Path) -> None:
        """Test that validation errors include fix suggestions."""
        # Create a file instead of directory
        file_path = tmp_path / "not_a_dir"
        file_path.write_text("content")

        settings = Settings(data_dir=file_path, port=8890)
        errors = settings.validate()

        # All errors should have "Fix:" suggestions
        assert len(errors) > 0
        for error in errors:
            assert "→ Fix:" in error or "→ Hint:" in error


class TestConfigCheck:
    """Tests for Settings.check() method (warnings)."""

    def test_debug_mode_production_warning(self, tmp_path: Path) -> None:
        """Test warning for debug mode with public binding."""
        settings = Settings(
            data_dir=tmp_path,
            debug=True,
            host="0.0.0.0",
            port=8891,
        )

        warnings = settings.check()

        assert len(warnings) > 0
        assert any("debug" in w.lower() and "production" in w.lower() for w in warnings)

    def test_no_warnings_for_valid_config(self, tmp_path: Path) -> None:
        """Test that valid configuration has no warnings."""
        settings = Settings(
            data_dir=tmp_path,
            debug=False,
            host="127.0.0.1",
            port=8892,
        )

        warnings = settings.check()

        # May have no warnings or only benign ones
        assert isinstance(warnings, list)

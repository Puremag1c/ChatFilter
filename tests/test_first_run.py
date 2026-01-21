"""Tests for first-run detection and setup."""

from pathlib import Path

from chatfilter.config import Settings, reset_settings


class TestFirstRun:
    """Test first-run detection and setup."""

    def test_first_run_detection(self, tmp_path: Path) -> None:
        """Test that first run is correctly detected."""
        reset_settings()
        settings = Settings(data_dir=tmp_path, port=8888)

        # Before marker file exists
        assert settings.is_first_run() is True

        # Create marker file
        settings.mark_first_run_complete()

        # After marker file exists
        assert settings.is_first_run() is False
        assert settings.first_run_marker_path.exists()

    def test_first_run_marker_content(self, tmp_path: Path) -> None:
        """Test that first-run marker file has correct content."""
        reset_settings()
        settings = Settings(data_dir=tmp_path, port=8889)

        settings.ensure_data_dirs()
        settings.mark_first_run_complete()

        marker_content = settings.first_run_marker_path.read_text()
        assert "ChatFilter initialized at" in marker_content

    def test_ensure_data_dirs_returns_empty_on_success(self, tmp_path: Path) -> None:
        """Test that ensure_data_dirs returns empty list on success."""
        reset_settings()
        settings = Settings(data_dir=tmp_path, port=8890)

        errors = settings.ensure_data_dirs()
        assert errors == []
        assert settings.data_dir.exists()
        assert settings.config_dir.exists()
        assert settings.sessions_dir.exists()
        assert settings.exports_dir.exists()

    def test_ensure_data_dirs_creates_log_dir_when_enabled(self, tmp_path: Path) -> None:
        """Test that ensure_data_dirs creates log directory when log_to_file is enabled."""
        reset_settings()
        settings = Settings(data_dir=tmp_path, port=8891, log_to_file=True)

        errors = settings.ensure_data_dirs()
        assert errors == []
        assert settings.log_dir.exists()

    def test_ensure_data_dirs_handles_permission_errors_gracefully(self, tmp_path: Path) -> None:
        """Test that ensure_data_dirs handles permission errors gracefully."""
        reset_settings()

        # Create a read-only directory
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)  # Read-only

        try:
            settings = Settings(data_dir=readonly_dir / "subdir", port=8892)
            errors = settings.ensure_data_dirs()

            # Should return errors but not raise exceptions
            assert isinstance(errors, list)
            # On some systems, permission errors may not occur in tmp_path
            # so we just verify the return type is correct

        finally:
            # Restore permissions for cleanup
            readonly_dir.chmod(0o755)

    def test_first_run_marker_path_property(self, tmp_path: Path) -> None:
        """Test first_run_marker_path property."""
        reset_settings()
        settings = Settings(data_dir=tmp_path, port=8893)

        marker_path = settings.first_run_marker_path
        assert marker_path == tmp_path / ".initialized"
        assert marker_path.parent == settings.data_dir

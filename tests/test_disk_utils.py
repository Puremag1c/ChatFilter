"""Tests for disk space utilities."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from chatfilter.utils.disk import (
    DiskSpaceError,
    ensure_space_available,
    format_bytes,
    get_available_space,
)


def test_get_available_space(tmp_path: Path) -> None:
    """Test getting available disk space."""
    # Should return a positive integer for existing path
    space = get_available_space(tmp_path)
    assert isinstance(space, int)
    assert space > 0


def test_get_available_space_nonexistent_file(tmp_path: Path) -> None:
    """Test getting available space for a file that doesn't exist yet."""
    nonexistent = tmp_path / "nonexistent.txt"
    # Should check parent directory
    space = get_available_space(nonexistent)
    assert isinstance(space, int)
    assert space > 0


def test_ensure_space_available_success(tmp_path: Path) -> None:
    """Test successful space check when enough space is available."""
    test_file = tmp_path / "test.txt"

    # Request a small amount of space (should succeed)
    ensure_space_available(test_file, 1024)  # 1 KB

    # Should not raise any exception


def test_ensure_space_available_insufficient_space(tmp_path: Path) -> None:
    """Test space check failure when insufficient space."""
    test_file = tmp_path / "test.txt"

    # Mock disk_usage to simulate low disk space
    from collections import namedtuple

    DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])

    with patch("shutil.disk_usage") as mock_usage:
        # Simulate only 50 MB free
        mock_usage.return_value = DiskUsage(
            total=1000 * 1024 * 1024,  # 1 GB
            used=950 * 1024 * 1024,  # 950 MB
            free=50 * 1024 * 1024,  # 50 MB
        )

        # Request 200 MB (should fail with buffer)
        with pytest.raises(DiskSpaceError) as exc_info:
            ensure_space_available(test_file, 200 * 1024 * 1024)

        # Check error details
        error = exc_info.value
        assert error.required > error.available
        assert error.path == test_file
        assert "Insufficient disk space" in str(error)
        # Required includes buffer (200 MB + 100 MB buffer = 300 MB)
        assert "300" in str(error) or "Required" in str(error)


def test_ensure_space_available_without_buffer(tmp_path: Path) -> None:
    """Test space check without safety buffer."""
    test_file = tmp_path / "test.txt"

    # Mock disk_usage to simulate exact amount of space
    from collections import namedtuple

    DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])

    with patch("shutil.disk_usage") as mock_usage:
        # Simulate exactly 150 MB free
        mock_usage.return_value = DiskUsage(
            total=1000 * 1024 * 1024,
            used=850 * 1024 * 1024,
            free=150 * 1024 * 1024,
        )

        # Request 150 MB without buffer (should succeed)
        ensure_space_available(test_file, 150 * 1024 * 1024, include_buffer=False)

        # Request 150 MB with buffer (should fail)
        with pytest.raises(DiskSpaceError):
            ensure_space_available(test_file, 150 * 1024 * 1024, include_buffer=True)


def test_format_bytes() -> None:
    """Test human-readable byte formatting."""
    assert format_bytes(0) == "0.0 B"
    assert format_bytes(1023) == "1023.0 B"
    assert format_bytes(1024) == "1.0 KB"
    assert format_bytes(1536) == "1.5 KB"
    assert format_bytes(1024 * 1024) == "1.0 MB"
    assert format_bytes(1024 * 1024 * 1024) == "1.0 GB"
    assert format_bytes(1024 * 1024 * 1024 * 1024) == "1.0 TB"


def test_disk_space_error_message() -> None:
    """Test DiskSpaceError message formatting."""
    error = DiskSpaceError(
        required=200 * 1024 * 1024,  # 200 MB
        available=50 * 1024 * 1024,  # 50 MB
        path=Path("/tmp/test.txt"),
    )

    msg = str(error)
    assert "Insufficient disk space" in msg
    assert "200" in msg  # Required MB
    assert "50" in msg  # Available MB
    assert "/tmp/test.txt" in msg


def test_ensure_space_available_with_real_write(tmp_path: Path) -> None:
    """Integration test: check space and write file."""
    test_file = tmp_path / "integration.txt"
    content = "Hello, World!" * 1000
    content_bytes = content.encode("utf-8")

    # Check space is available
    ensure_space_available(test_file, len(content_bytes))

    # Write the file
    test_file.write_text(content)

    # Verify file was written correctly
    assert test_file.exists()
    assert test_file.read_text() == content


def test_ensure_space_available_csv_scenario(tmp_path: Path) -> None:
    """Test disk space check in CSV export scenario."""
    csv_file = tmp_path / "results.csv"

    # Simulate large CSV content (1 MB)
    csv_content = "chat_id,title,type\n" * 10000
    csv_bytes = csv_content.encode("utf-8")

    # Check space
    ensure_space_available(csv_file, len(csv_bytes))

    # Write CSV
    csv_file.write_text(csv_content)

    assert csv_file.exists()
    assert csv_file.stat().st_size > 0


def test_ensure_space_available_session_scenario(tmp_path: Path) -> None:
    """Test disk space check in session upload scenario."""
    session_file = tmp_path / "session.session"

    # Simulate session file (typically a few KB)
    session_content = b"SQLite format 3\x00" + b"\x00" * (5 * 1024)  # 5 KB

    # Check space
    ensure_space_available(session_file, len(session_content))

    # Write session
    session_file.write_bytes(session_content)

    assert session_file.exists()
    assert session_file.stat().st_size == len(session_content)


def test_get_available_space_error_handling() -> None:
    """Test error handling when unable to get disk space."""
    # Mock shutil.disk_usage to raise an exception
    with patch("shutil.disk_usage") as mock_usage:
        mock_usage.side_effect = OSError("Permission denied")

        with pytest.raises(OSError) as exc_info:
            get_available_space(Path("/tmp/test"))

        assert "Unable to check disk space" in str(exc_info.value)

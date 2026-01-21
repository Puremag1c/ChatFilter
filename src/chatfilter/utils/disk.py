"""Disk space utilities for safe file operations.

Provides utilities for checking available disk space before file writes
to prevent "No space left on device" errors with graceful error handling.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

# Minimum free space buffer (in bytes) to reserve for system operations
# Keep at least 100 MB free to prevent system issues
MIN_FREE_SPACE_BUFFER = 100 * 1024 * 1024  # 100 MB


class DiskSpaceError(OSError):
    """Raised when there is insufficient disk space for an operation."""

    def __init__(self, required: int, available: int, path: Path) -> None:
        """Initialize disk space error with detailed information.

        Args:
            required: Required space in bytes
            available: Available space in bytes
            path: Path where the operation was attempted
        """
        self.required = required
        self.available = available
        self.path = path

        # Format human-readable sizes
        required_mb = required / (1024 * 1024)
        available_mb = available / (1024 * 1024)

        super().__init__(
            f"Insufficient disk space at {path}. "
            f"Required: {required_mb:.1f} MB, "
            f"Available: {available_mb:.1f} MB. "
            f"Please free up disk space and try again."
        )


def get_available_space(path: Path) -> int:
    """Get available disk space for a given path.

    Args:
        path: Path to check (file or directory)

    Returns:
        Available space in bytes

    Raises:
        OSError: If unable to determine disk space
    """
    try:
        # Use parent directory if path is a file that doesn't exist yet
        check_path = path if path.exists() else path.parent

        # Get disk usage statistics
        stat = shutil.disk_usage(check_path)
        return stat.free
    except Exception as e:
        logger.error(f"Failed to get disk space for {path}: {e}")
        raise OSError(f"Unable to check disk space: {e}") from e


def ensure_space_available(
    path: Path,
    required_bytes: int,
    *,
    include_buffer: bool = True,
) -> None:
    """Ensure sufficient disk space is available before a write operation.

    Checks available disk space and raises DiskSpaceError if insufficient.
    This should be called before any file write operation to prevent
    OSError "No space left on device" with better error messages.

    Args:
        path: Path where the file will be written
        required_bytes: Number of bytes that will be written
        include_buffer: Whether to include MIN_FREE_SPACE_BUFFER in check
            (default: True). Set to False only for small writes where
            the buffer is not needed.

    Raises:
        DiskSpaceError: If insufficient disk space is available
        OSError: If unable to check disk space

    Example:
        ```python
        from pathlib import Path
        from chatfilter.utils.disk import ensure_space_available

        content = "Large CSV data..."
        output_path = Path("results.csv")

        # Check space before writing
        ensure_space_available(output_path, len(content.encode()))

        # Safe to write now
        output_path.write_text(content)
        ```
    """
    # Get available space
    available = get_available_space(path)

    # Calculate total required space (content + buffer)
    total_required = required_bytes
    if include_buffer:
        total_required += MIN_FREE_SPACE_BUFFER

    # Check if enough space is available
    if available < total_required:
        logger.warning(
            f"Insufficient disk space: required={total_required}, "
            f"available={available}, path={path}"
        )
        raise DiskSpaceError(total_required, available, path)

    logger.debug(
        f"Disk space check passed: required={total_required}, available={available}, path={path}"
    )


def format_bytes(num_bytes: int) -> str:
    """Format bytes as human-readable string.

    Args:
        num_bytes: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB", "500 KB")
    """
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

"""File-based storage implementation with atomic writes."""

from __future__ import annotations

import atexit
import contextlib
import logging
import os
import shutil
import tempfile
from pathlib import Path

from chatfilter.storage.base import Storage
from chatfilter.storage.errors import (
    StorageError,
    StorageNotFoundError,
    StoragePermissionError,
)

logger = logging.getLogger(__name__)


# Global registry for temporary files cleanup on abnormal exit
# Note: Using set instead of WeakSet because Path objects don't support weak references
_temp_files_registry: set[Path] = set()


def _cleanup_temp_files() -> None:
    """Clean up any remaining temporary files on exit.

    This handler is called via atexit to ensure temp files are removed
    even if the process crashes or exits abnormally.
    """
    for temp_path in list(_temp_files_registry):
        try:
            if temp_path.exists():
                temp_path.unlink()
                logger.debug(f"Cleaned up temp file on exit: {temp_path}")
        except (OSError, Exception) as e:
            # Log but don't raise - we're in cleanup
            logger.warning(f"Failed to cleanup temp file {temp_path}: {e}")


# Register cleanup handler
atexit.register(_cleanup_temp_files)


def cleanup_orphaned_temp_files(directory: Path, pattern: str = ".*.tmp") -> int:
    """Clean up orphaned temporary files from previous crashes.

    Searches for and removes temporary files matching the pattern.
    This should be called at application startup to clean up any
    temp files left over from abnormal exits.

    Args:
        directory: Directory to search for temp files
        pattern: Glob pattern for temp files (default: ".*.tmp")

    Returns:
        Number of files cleaned up
    """
    if not directory.exists() or not directory.is_dir():
        return 0

    cleaned_count = 0
    try:
        for temp_file in directory.rglob(pattern):
            if temp_file.is_file():
                try:
                    temp_file.unlink()
                    logger.info(f"Cleaned up orphaned temp file: {temp_file}")
                    cleaned_count += 1
                except OSError as e:
                    logger.warning(f"Failed to clean up temp file {temp_file}: {e}")
    except OSError as e:
        logger.warning(f"Error scanning directory {directory} for temp files: {e}")

    return cleaned_count


class FileStorage(Storage):
    """File system storage with atomic write operations.

    Features:
    - Atomic writes (write to temp file + rename)
    - Centralized error handling with custom exceptions
    - Safe directory operations
    - Extensible via StorageDecorator

    Example:
        ```python
        storage = FileStorage()

        # Atomic write
        storage.save(path, content)

        # Read
        data = storage.load(path)

        # Delete
        storage.delete(path)
        ```
    """

    def save(self, path: Path, content: bytes | str) -> None:
        """Save content with atomic write.

        Writes to a temporary file first, then atomically renames it
        to the target path. This ensures the file is never in a
        partially written state.

        Args:
            path: Destination path
            content: Content to save

        Raises:
            StoragePermissionError: If write permission denied
            StorageError: If operation fails
        """
        # Convert string to bytes if needed
        content_bytes = content.encode("utf-8") if isinstance(content, str) else content

        # Ensure parent directory exists
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            raise StoragePermissionError(
                f"Cannot create directory {path.parent}: permission denied"
            ) from e
        except OSError as e:
            raise StorageError(f"Failed to create directory {path.parent}: {e}") from e

        # Write to temporary file in same directory (for atomic rename)
        tmp_path = None
        try:
            # Use same directory as target for atomic rename on same filesystem
            temp_dir = path.parent
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=temp_dir,
                delete=False,
                prefix=f".{path.name}.",
                suffix=".tmp",
            ) as tmp_file:
                tmp_path = Path(tmp_file.name)
                # Register for cleanup on abnormal exit
                _temp_files_registry.add(tmp_path)

                tmp_file.write(content_bytes)
                tmp_file.flush()
                # Ensure data is written to disk
                os.fsync(tmp_file.fileno())

            # Atomic rename
            tmp_path.replace(path)
            # Remove from registry after successful rename
            _temp_files_registry.discard(tmp_path)
            logger.debug(f"Saved {len(content_bytes)} bytes to {path}")

        except PermissionError as e:
            raise StoragePermissionError(f"Cannot write to {path}: permission denied") from e
        except OSError as e:
            raise StorageError(f"Failed to write {path}: {e}") from e
        finally:
            # Clean up temp file if it still exists (i.e., rename didn't happen)
            if tmp_path is not None:
                _temp_files_registry.discard(tmp_path)
                if tmp_path.exists():
                    with contextlib.suppress(OSError):
                        tmp_path.unlink()

    def load(self, path: Path) -> bytes:
        """Load content from file.

        Args:
            path: Source path

        Returns:
            File content as bytes

        Raises:
            StorageNotFoundError: If file doesn't exist
            StoragePermissionError: If read permission denied
            StorageError: If operation fails
        """
        try:
            content = path.read_bytes()
            logger.debug(f"Loaded {len(content)} bytes from {path}")
            return content
        except FileNotFoundError as e:
            raise StorageNotFoundError(f"File not found: {path}") from e
        except PermissionError as e:
            raise StoragePermissionError(f"Cannot read {path}: permission denied") from e
        except OSError as e:
            raise StorageError(f"Failed to read {path}: {e}") from e

    def delete(self, path: Path) -> None:
        """Delete file or directory.

        Safely handles both files and directories. For directories,
        removes all contents recursively.

        Args:
            path: Path to delete

        Raises:
            StorageNotFoundError: If path doesn't exist
            StoragePermissionError: If delete permission denied
            StorageError: If operation fails
        """
        if not path.exists():
            raise StorageNotFoundError(f"Path not found: {path}")

        try:
            if path.is_dir():
                shutil.rmtree(path)
                logger.debug(f"Deleted directory {path}")
            else:
                path.unlink()
                logger.debug(f"Deleted file {path}")
        except PermissionError as e:
            raise StoragePermissionError(f"Cannot delete {path}: permission denied") from e
        except OSError as e:
            raise StorageError(f"Failed to delete {path}: {e}") from e

    def exists(self, path: Path) -> bool:
        """Check if path exists.

        Args:
            path: Path to check

        Returns:
            True if path exists
        """
        return path.exists()

    def list_files(self, directory: Path, pattern: str = "*") -> list[Path]:
        """List files in directory matching pattern.

        Args:
            directory: Directory to list
            pattern: Glob pattern (default: all files)

        Returns:
            List of matching file paths (sorted)

        Raises:
            StorageNotFoundError: If directory doesn't exist
            StoragePermissionError: If list permission denied
            StorageError: If operation fails
        """
        if not directory.exists():
            raise StorageNotFoundError(f"Directory not found: {directory}")

        if not directory.is_dir():
            raise StorageError(f"Not a directory: {directory}")

        try:
            files = sorted(directory.glob(pattern))
            logger.debug(f"Found {len(files)} files in {directory} matching {pattern}")
            return files
        except PermissionError as e:
            raise StoragePermissionError(f"Cannot list {directory}: permission denied") from e
        except OSError as e:
            raise StorageError(f"Failed to list {directory}: {e}") from e

    def ensure_dir(self, path: Path) -> None:
        """Ensure directory exists (create if needed).

        Args:
            path: Directory path

        Raises:
            StoragePermissionError: If create permission denied
            StorageError: If operation fails
        """
        try:
            path.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured directory exists: {path}")
        except PermissionError as e:
            raise StoragePermissionError(
                f"Cannot create directory {path}: permission denied"
            ) from e
        except OSError as e:
            raise StorageError(f"Failed to create directory {path}: {e}") from e

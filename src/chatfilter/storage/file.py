"""File-based storage implementation with atomic writes."""

from __future__ import annotations

import logging
import shutil
import tempfile
from pathlib import Path

from chatfilter.storage.base import Storage
from chatfilter.storage.errors import (
    StorageCorruptedError,
    StorageError,
    StorageNotFoundError,
    StoragePermissionError,
)

logger = logging.getLogger(__name__)


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
        if isinstance(content, str):
            content_bytes = content.encode("utf-8")
        else:
            content_bytes = content

        # Ensure parent directory exists
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            raise StoragePermissionError(
                f"Cannot create directory {path.parent}: permission denied"
            ) from e
        except OSError as e:
            raise StorageError(
                f"Failed to create directory {path.parent}: {e}"
            ) from e

        # Write to temporary file in same directory (for atomic rename)
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
                tmp_file.write(content_bytes)
                tmp_file.flush()
                # Ensure data is written to disk
                tmp_file.file.fileno()
                import os
                os.fsync(tmp_file.fileno())

            # Atomic rename
            tmp_path.replace(path)
            logger.debug(f"Saved {len(content_bytes)} bytes to {path}")

        except PermissionError as e:
            # Clean up temp file
            if "tmp_path" in locals():
                tmp_path.unlink(missing_ok=True)
            raise StoragePermissionError(
                f"Cannot write to {path}: permission denied"
            ) from e
        except OSError as e:
            # Clean up temp file
            if "tmp_path" in locals():
                tmp_path.unlink(missing_ok=True)
            raise StorageError(f"Failed to write {path}: {e}") from e

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
            raise StoragePermissionError(
                f"Cannot read {path}: permission denied"
            ) from e
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
            raise StoragePermissionError(
                f"Cannot delete {path}: permission denied"
            ) from e
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
            raise StoragePermissionError(
                f"Cannot list {directory}: permission denied"
            ) from e
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

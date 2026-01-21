"""Base storage interface for file operations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path


class Storage(ABC):
    """Abstract base class for storage operations.

    Provides a unified interface for save/load/delete operations
    with centralized error handling and extensibility for features
    like encryption, compression, etc.
    """

    @abstractmethod
    def save(self, path: Path, content: bytes | str) -> None:
        """Save content to path.

        Args:
            path: Destination path
            content: Content to save (bytes or string)

        Raises:
            StoragePermissionError: If write permission denied
            StorageError: If operation fails
        """

    @abstractmethod
    def load(self, path: Path) -> bytes:
        """Load content from path.

        Args:
            path: Source path

        Returns:
            File content as bytes

        Raises:
            StorageNotFoundError: If file doesn't exist
            StoragePermissionError: If read permission denied
            StorageError: If operation fails
        """

    @abstractmethod
    def delete(self, path: Path) -> None:
        """Delete file or directory at path.

        Args:
            path: Path to delete

        Raises:
            StorageNotFoundError: If path doesn't exist
            StoragePermissionError: If delete permission denied
            StorageError: If operation fails
        """

    @abstractmethod
    def exists(self, path: Path) -> bool:
        """Check if path exists.

        Args:
            path: Path to check

        Returns:
            True if path exists
        """

    @abstractmethod
    def list_files(self, directory: Path, pattern: str = "*") -> list[Path]:
        """List files in directory matching pattern.

        Args:
            directory: Directory to list
            pattern: Glob pattern (default: all files)

        Returns:
            List of matching file paths

        Raises:
            StorageNotFoundError: If directory doesn't exist
            StoragePermissionError: If list permission denied
            StorageError: If operation fails
        """

    @abstractmethod
    def ensure_dir(self, path: Path) -> None:
        """Ensure directory exists (create if needed).

        Args:
            path: Directory path

        Raises:
            StoragePermissionError: If create permission denied
            StorageError: If operation fails
        """


class StorageDecorator(Storage):
    """Base class for storage decorators (encryption, compression, etc).

    Allows adding functionality to any Storage implementation via
    the decorator pattern.

    Example:
        ```python
        storage = FileStorage()
        encrypted = EncryptedStorage(storage, key)
        encrypted.save(path, data)  # Automatically encrypted
        ```
    """

    def __init__(self, wrapped: Storage) -> None:
        """Initialize decorator.

        Args:
            wrapped: Storage instance to wrap
        """
        self._wrapped = wrapped

    def save(self, path: Path, content: bytes | str) -> None:
        """Delegate to wrapped storage."""
        self._wrapped.save(path, content)

    def load(self, path: Path) -> bytes:
        """Delegate to wrapped storage."""
        return self._wrapped.load(path)

    def delete(self, path: Path) -> None:
        """Delegate to wrapped storage."""
        self._wrapped.delete(path)

    def exists(self, path: Path) -> bool:
        """Delegate to wrapped storage."""
        return self._wrapped.exists(path)

    def list_files(self, directory: Path, pattern: str = "*") -> list[Path]:
        """Delegate to wrapped storage."""
        return self._wrapped.list_files(directory, pattern)

    def ensure_dir(self, path: Path) -> None:
        """Delegate to wrapped storage."""
        self._wrapped.ensure_dir(path)

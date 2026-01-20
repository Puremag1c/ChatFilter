"""Storage layer exceptions."""

from __future__ import annotations


class StorageError(Exception):
    """Base exception for storage operations."""


class StorageNotFoundError(StorageError):
    """Raised when a file or resource is not found."""


class StoragePermissionError(StorageError):
    """Raised when operation fails due to insufficient permissions."""


class StorageValidationError(StorageError):
    """Raised when content validation fails."""


class StorageCorruptedError(StorageError):
    """Raised when stored data is corrupted or invalid."""

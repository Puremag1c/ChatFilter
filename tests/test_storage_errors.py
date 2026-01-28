"""Tests for storage layer exceptions.

Tests cover:
- StorageError: base exception
- StorageNotFoundError: file not found
- StoragePermissionError: permission denied
- StorageValidationError: validation failed
- StorageCorruptedError: corrupted data
"""

from __future__ import annotations

import pytest

from chatfilter.storage.errors import (
    StorageCorruptedError,
    StorageError,
    StorageNotFoundError,
    StoragePermissionError,
    StorageValidationError,
)


class TestStorageError:
    """Tests for StorageError base exception."""

    def test_is_exception(self) -> None:
        """StorageError should be an Exception."""
        assert issubclass(StorageError, Exception)

    def test_can_be_raised(self) -> None:
        """Should be raisable with message."""
        with pytest.raises(StorageError) as exc_info:
            raise StorageError("Test error")

        assert str(exc_info.value) == "Test error"

    def test_can_be_caught_as_exception(self) -> None:
        """Should be catchable as Exception."""
        try:
            raise StorageError("test")
        except Exception as e:
            assert isinstance(e, StorageError)


class TestStorageNotFoundError:
    """Tests for StorageNotFoundError."""

    def test_inherits_from_storage_error(self) -> None:
        """Should inherit from StorageError."""
        assert issubclass(StorageNotFoundError, StorageError)

    def test_can_be_raised(self) -> None:
        """Should be raisable with message."""
        with pytest.raises(StorageNotFoundError) as exc_info:
            raise StorageNotFoundError("File not found: test.txt")

        assert "File not found" in str(exc_info.value)

    def test_can_be_caught_as_storage_error(self) -> None:
        """Should be catchable as StorageError."""
        try:
            raise StorageNotFoundError("test")
        except StorageError as e:
            assert isinstance(e, StorageNotFoundError)


class TestStoragePermissionError:
    """Tests for StoragePermissionError."""

    def test_inherits_from_storage_error(self) -> None:
        """Should inherit from StorageError."""
        assert issubclass(StoragePermissionError, StorageError)

    def test_can_be_raised(self) -> None:
        """Should be raisable with message."""
        with pytest.raises(StoragePermissionError) as exc_info:
            raise StoragePermissionError("Permission denied")

        assert "Permission denied" in str(exc_info.value)


class TestStorageValidationError:
    """Tests for StorageValidationError."""

    def test_inherits_from_storage_error(self) -> None:
        """Should inherit from StorageError."""
        assert issubclass(StorageValidationError, StorageError)

    def test_can_be_raised(self) -> None:
        """Should be raisable with message."""
        with pytest.raises(StorageValidationError) as exc_info:
            raise StorageValidationError("Invalid data format")

        assert "Invalid data" in str(exc_info.value)


class TestStorageCorruptedError:
    """Tests for StorageCorruptedError."""

    def test_inherits_from_storage_error(self) -> None:
        """Should inherit from StorageError."""
        assert issubclass(StorageCorruptedError, StorageError)

    def test_can_be_raised(self) -> None:
        """Should be raisable with message."""
        with pytest.raises(StorageCorruptedError) as exc_info:
            raise StorageCorruptedError("Data corrupted")

        assert "corrupted" in str(exc_info.value)


class TestExceptionHierarchy:
    """Tests for exception hierarchy."""

    def test_all_inherit_from_storage_error(self) -> None:
        """All storage exceptions should inherit from StorageError."""
        exceptions = [
            StorageNotFoundError,
            StoragePermissionError,
            StorageValidationError,
            StorageCorruptedError,
        ]

        for exc_class in exceptions:
            assert issubclass(exc_class, StorageError)

    def test_catch_all_with_storage_error(self) -> None:
        """Should be able to catch all exceptions with StorageError."""
        exceptions_to_test = [
            StorageNotFoundError("not found"),
            StoragePermissionError("no permission"),
            StorageValidationError("invalid"),
            StorageCorruptedError("corrupted"),
        ]

        for exc in exceptions_to_test:
            try:
                raise exc
            except StorageError:
                pass  # Should catch all
            else:
                pytest.fail(f"{type(exc).__name__} was not caught by StorageError")

"""Helper functions for common storage operations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chatfilter.storage.errors import StorageCorruptedError, StorageValidationError
from chatfilter.storage.file import FileStorage

# Default storage instance
_default_storage = FileStorage()


def save_json(
    path: Path,
    data: Any,
    *,
    indent: int = 2,
    storage: FileStorage | None = None,
) -> None:
    """Save data as JSON with atomic write.

    Args:
        path: Destination path
        data: Data to serialize
        indent: JSON indentation (default: 2)
        storage: Storage instance (default: FileStorage)

    Raises:
        StorageValidationError: If data cannot be serialized
        StoragePermissionError: If write permission denied
        StorageError: If operation fails

    Example:
        ```python
        save_json(path, {"key": "value"})
        ```
    """
    storage = storage or _default_storage

    try:
        content = json.dumps(data, indent=indent, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        raise StorageValidationError(f"Cannot serialize to JSON: {e}") from e

    storage.save(path, content)


def load_json(path: Path, *, storage: FileStorage | None = None) -> Any:
    """Load JSON data from file.

    Args:
        path: Source path
        storage: Storage instance (default: FileStorage)

    Returns:
        Deserialized data

    Raises:
        StorageNotFoundError: If file doesn't exist
        StorageCorruptedError: If JSON is invalid
        StoragePermissionError: If read permission denied
        StorageError: If operation fails

    Example:
        ```python
        data = load_json(path)
        ```
    """
    storage = storage or _default_storage

    content = storage.load(path)

    try:
        return json.loads(content.decode("utf-8"))
    except json.JSONDecodeError as e:
        raise StorageCorruptedError(f"Invalid JSON in {path}: {e}") from e
    except UnicodeDecodeError as e:
        raise StorageCorruptedError(f"Invalid UTF-8 encoding in {path}: {e}") from e

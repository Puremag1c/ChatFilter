"""Storage layer for file operations.

Provides unified interface for save/load/delete with:
- Atomic writes for consistency
- Centralized error handling
- Decorator pattern for encryption/compression
- JSON and binary helpers

Example:
    ```python
    from chatfilter.storage import FileStorage, save_json, load_json

    # Use storage directly
    storage = FileStorage()
    storage.save(path, content)

    # Use JSON helpers
    save_json(path, {"key": "value"})
    data = load_json(path)
    ```
"""

from __future__ import annotations

from chatfilter.storage.base import Storage, StorageDecorator
from chatfilter.storage.encrypted import (
    EncryptedStorage,
    StorageDecryptionError,
    derive_key_from_machine_id,
)
from chatfilter.storage.errors import (
    StorageCorruptedError,
    StorageError,
    StorageNotFoundError,
    StoragePermissionError,
    StorageValidationError,
)
from chatfilter.storage.file import FileStorage
from chatfilter.storage.helpers import load_json, save_json

__all__ = [
    # Base classes
    "Storage",
    "StorageDecorator",
    # Implementations
    "FileStorage",
    "EncryptedStorage",
    # Helpers
    "save_json",
    "load_json",
    "derive_key_from_machine_id",
    # Exceptions
    "StorageError",
    "StorageNotFoundError",
    "StoragePermissionError",
    "StorageValidationError",
    "StorageCorruptedError",
    "StorageDecryptionError",
]

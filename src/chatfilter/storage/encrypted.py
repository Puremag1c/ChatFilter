"""Encrypted storage decorator with Fernet symmetric encryption."""

from __future__ import annotations

import hashlib
import logging
import struct
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from cryptography.fernet import Fernet, InvalidToken

from chatfilter.storage.base import Storage, StorageDecorator
from chatfilter.storage.errors import (
    StorageCorruptedError,
    StorageError,
)

if TYPE_CHECKING:
    from chatfilter.security.key_manager import KeyManager

logger = logging.getLogger(__name__)

# File format: MAGIC (4 bytes) + VERSION (2 bytes) + KEY_ID (2 bytes) + encrypted data
MAGIC = b"CFES"  # ChatFilter Encrypted Storage
FORMAT_VERSION = 1
HEADER_SIZE = 8  # 4 (magic) + 2 (version) + 2 (key_id)


class StorageDecryptionError(StorageError):
    """Raised when decryption fails (wrong key, corrupted data)."""


def _derive_fernet_key(machine_id: int, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from machine ID.

    Args:
        machine_id: Machine identifier (from uuid.getnode() or machine-id)
        salt: Salt bytes for key derivation

    Returns:
        Base64-encoded Fernet key
    """
    from base64 import urlsafe_b64encode

    # Combine machine ID and salt
    key_material = f"{machine_id}".encode() + salt

    # Derive 32-byte key using SHA-256
    key_hash = hashlib.sha256(key_material).digest()

    # Fernet expects base64-encoded key
    return urlsafe_b64encode(key_hash)


def derive_key_from_machine_id() -> bytes:
    """Derive encryption key from machine-specific identifier.

    Uses the machine's UUID (from /etc/machine-id on Linux, registry on Windows,
    or hardware UUID on macOS) combined with a constant salt to generate a
    deterministic encryption key for this machine.

    Returns:
        Base64-encoded Fernet key (32 bytes)

    Note:
        This provides basic at-rest encryption. The key is tied to the machine,
        so moving encrypted files to another machine will require re-encryption.
        For stronger security, consider deriving from user password.
    """
    # Get machine UUID (stable across reboots)
    machine_id = uuid.getnode()  # MAC address as fallback

    # Try to get real machine ID (more stable than MAC)
    try:
        # Linux: /etc/machine-id
        machine_id_file = Path("/etc/machine-id")
        if machine_id_file.exists():
            machine_id_bytes = machine_id_file.read_text().strip()
            machine_id = int(machine_id_bytes, 16)
    except (OSError, ValueError):
        pass

    # Derive key
    salt = b"chatfilter-storage-encryption-v1"
    return _derive_fernet_key(machine_id, salt)


class EncryptedStorage(StorageDecorator):
    """Storage decorator that encrypts content with Fernet symmetric encryption.

    Features:
    - Transparent encryption/decryption
    - Secure key management via OS keychain (recommended)
    - Machine-specific key derivation (fallback)
    - Support for custom encryption keys
    - File format versioning for key rotation
    - Corruption detection

    File Format:
        [MAGIC:4][VERSION:2][KEY_ID:2][encrypted_data:*]

    Example:
        ```python
        from chatfilter.storage import FileStorage, EncryptedStorage
        from chatfilter.security.key_manager import KeyManager

        # Recommended: Use KeyManager with OS keychain
        base_storage = FileStorage()
        key_manager = KeyManager.create()  # Auto-selects best backend
        storage = EncryptedStorage(base_storage, key_manager=key_manager)

        # Save encrypted
        storage.save(path, "sensitive data")

        # Load decrypted
        data = storage.load(path)

        # Alternative: Use machine-derived key (backward compatible)
        storage = EncryptedStorage(base_storage)

        # Use custom key
        custom_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=custom_key)
        ```
    """

    # Key rotation support: map key_id to key
    _KEY_REGISTRY: ClassVar[dict[int, bytes]] = {}

    def __init__(
        self,
        wrapped: Storage,
        *,
        encryption_key: bytes | None = None,
        key_id: int = 0,
        key_manager: KeyManager | None = None,
    ) -> None:
        """Initialize encrypted storage.

        Args:
            wrapped: Storage instance to wrap
            encryption_key: Encryption key (base64-encoded Fernet key).
                If None and no key_manager provided, derives key from machine ID.
                Takes precedence over key_manager if both provided.
            key_id: Key identifier for rotation support (0-65535)
            key_manager: KeyManager instance for secure key storage.
                If provided, uses KeyManager to retrieve keys instead of
                machine-derived keys.

        Note:
            Using key_manager is recommended for production deployments as it
            provides secure key storage via OS keychain or password-derived keys.
        """
        super().__init__(wrapped)

        self._key_manager = key_manager
        self._key_id = key_id

        # Priority: explicit encryption_key > key_manager > machine-derived
        if encryption_key is None:
            if key_manager is not None:
                encryption_key = key_manager.get_or_create_key(key_id)
                logger.debug(f"Using key from KeyManager (key_id={key_id})")
            else:
                encryption_key = derive_key_from_machine_id()
                logger.debug("Using machine-derived encryption key")

        self._key = encryption_key
        self._fernet = Fernet(encryption_key)

        # Register key for decryption
        self._KEY_REGISTRY[key_id] = encryption_key

    @classmethod
    def register_key(cls, key_id: int, key: bytes) -> None:
        """Register a key for decryption (supports key rotation).

        Args:
            key_id: Key identifier
            key: Base64-encoded Fernet key
        """
        cls._KEY_REGISTRY[key_id] = key
        logger.info(f"Registered encryption key {key_id}")

    def save(self, path: Path, content: bytes | str) -> None:
        """Save encrypted content.

        Args:
            path: Destination path
            content: Content to encrypt and save

        Raises:
            StoragePermissionError: If write permission denied
            StorageError: If operation fails
        """
        # Convert string to bytes if needed
        plaintext = content.encode("utf-8") if isinstance(content, str) else content

        # Encrypt
        try:
            encrypted = self._fernet.encrypt(plaintext)
        except Exception as e:
            raise StorageError(f"Encryption failed: {e}") from e

        # Build file format: MAGIC + VERSION + KEY_ID + encrypted_data
        header = struct.pack("!4sHH", MAGIC, FORMAT_VERSION, self._key_id)
        encrypted_content = header + encrypted

        # Delegate to wrapped storage
        self._wrapped.save(path, encrypted_content)
        logger.debug(f"Saved encrypted file: {path} (key_id={self._key_id})")

    def load(self, path: Path) -> bytes:
        """Load and decrypt content.

        Args:
            path: Source path

        Returns:
            Decrypted content as bytes

        Raises:
            StorageNotFoundError: If file doesn't exist
            StorageDecryptionError: If decryption fails (wrong key, corrupted)
            StorageCorruptedError: If file format is invalid
            StoragePermissionError: If read permission denied
            StorageError: If operation fails
        """
        # Load encrypted content
        encrypted_content = self._wrapped.load(path)

        # Verify minimum size
        if len(encrypted_content) < HEADER_SIZE:
            raise StorageCorruptedError(
                f"File too small to be encrypted: {path} ({len(encrypted_content)} bytes)"
            )

        # Parse header
        try:
            magic, version, key_id = struct.unpack(
                "!4sHH", encrypted_content[:HEADER_SIZE]
            )
        except struct.error as e:
            raise StorageCorruptedError(f"Invalid file header: {e}") from e

        # Verify magic
        if magic != MAGIC:
            raise StorageCorruptedError(
                f"Invalid file format (expected {MAGIC!r}, got {magic!r})"
            )

        # Check version
        if version != FORMAT_VERSION:
            raise StorageCorruptedError(
                f"Unsupported format version {version} (expected {FORMAT_VERSION})"
            )

        # Get encryption key for this key_id
        # Try KeyManager first, then fall back to registry
        decryption_key = None

        if self._key_manager is not None:
            decryption_key = self._key_manager.get_key(key_id)

        if decryption_key is None:
            if key_id not in self._KEY_REGISTRY:
                raise StorageDecryptionError(
                    f"Unknown key_id {key_id}. Key may have been rotated or file "
                    "was encrypted with a different key."
                )
            decryption_key = self._KEY_REGISTRY[key_id]

        fernet = Fernet(decryption_key)

        # Decrypt
        encrypted_data = encrypted_content[HEADER_SIZE:]
        try:
            plaintext = fernet.decrypt(encrypted_data)
        except InvalidToken as e:
            raise StorageDecryptionError(
                f"Decryption failed for {path}. File may be corrupted or "
                "encrypted with a different key."
            ) from e
        except Exception as e:
            raise StorageError(f"Decryption error: {e}") from e

        logger.debug(f"Loaded and decrypted file: {path} (key_id={key_id})")
        return plaintext

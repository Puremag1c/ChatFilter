"""Secure key management for encryption at rest.

This module provides secure storage and retrieval of encryption keys using:
1. OS keychain (preferred) - macOS Keychain, Windows Credential Locker, Linux Secret Service
2. Password-derived keys (fallback) - PBKDF2-based key derivation
3. Environment variables (for containers/CI)

The key management system ensures:
- Keys persist across application restarts
- Keys are stored securely in OS-provided secure storage
- Keys can be rotated without losing access to old data
- Multiple key backends can coexist for different deployment scenarios
"""

import hashlib
import os
from abc import ABC, abstractmethod
from base64 import urlsafe_b64encode
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from chatfilter.storage.errors import StorageError

try:
    import keyring
    import keyring.errors

    HAS_KEYRING = True
except ImportError:
    HAS_KEYRING = False


class KeyManagerError(StorageError):
    """Base exception for key management errors."""


class KeyNotFoundError(KeyManagerError):
    """Raised when encryption key cannot be found or accessed."""


class KeyBackend(ABC):
    """Abstract base class for key storage backends."""

    @abstractmethod
    def get_key(self, key_id: int) -> bytes | None:
        """Retrieve encryption key by ID.

        Args:
            key_id: Numeric key identifier (0-65535)

        Returns:
            32-byte Fernet-compatible key, or None if not found
        """

    @abstractmethod
    def set_key(self, key_id: int, key: bytes) -> None:
        """Store encryption key.

        Args:
            key_id: Numeric key identifier (0-65535)
            key: 32-byte Fernet-compatible key
        """

    @abstractmethod
    def delete_key(self, key_id: int) -> None:
        """Delete encryption key.

        Args:
            key_id: Numeric key identifier to delete
        """


class KeyringBackend(KeyBackend):
    """OS keychain-based key storage (preferred).

    Uses platform-specific secure storage:
    - macOS: Keychain
    - Windows: Credential Locker
    - Linux: Secret Service (gnome-keyring/libsecret)
    """

    SERVICE_NAME = "chatfilter-encryption"

    def __init__(self) -> None:
        if not HAS_KEYRING:
            raise KeyManagerError("keyring library not available")

    def _key_name(self, key_id: int) -> str:
        """Generate keyring entry name for key ID."""
        return f"encryption-key-{key_id}"

    def get_key(self, key_id: int) -> bytes | None:
        """Retrieve key from OS keychain."""
        try:
            key_str = keyring.get_password(self.SERVICE_NAME, self._key_name(key_id))
            if key_str is None:
                return None
            # Fernet keys are already base64-encoded, return as bytes
            return key_str.encode("ascii")
        except keyring.errors.KeyringError as e:
            raise KeyManagerError(f"Failed to retrieve key from keyring: {e}") from e

    def set_key(self, key_id: int, key: bytes) -> None:
        """Store key in OS keychain."""
        try:
            # Fernet keys are already base64-encoded, store as string
            if isinstance(key, bytes):
                key = key.decode("ascii")
            keyring.set_password(self.SERVICE_NAME, self._key_name(key_id), key)
        except keyring.errors.KeyringError as e:
            raise KeyManagerError(f"Failed to store key in keyring: {e}") from e

    def delete_key(self, key_id: int) -> None:
        """Delete key from OS keychain."""
        try:
            keyring.delete_password(self.SERVICE_NAME, self._key_name(key_id))
        except keyring.errors.PasswordDeleteError:
            pass  # Key doesn't exist, that's fine
        except keyring.errors.KeyringError as e:
            raise KeyManagerError(f"Failed to delete key from keyring: {e}") from e


class PasswordBackend(KeyBackend):
    """Password-derived key storage.

    Uses PBKDF2 to derive encryption keys from user-provided passwords.
    The password must be provided via environment variable or at runtime.
    """

    ENV_VAR_PREFIX = "CHATFILTER_ENCRYPTION_PASSWORD"
    PBKDF2_ITERATIONS = 600_000  # OWASP recommended minimum for 2023+
    SALT_PREFIX = b"chatfilter-key-derivation-v1"

    def __init__(self, password: str | None = None) -> None:
        """Initialize password backend.

        Args:
            password: Master password for key derivation. If None, will try
                     to read from CHATFILTER_ENCRYPTION_PASSWORD env var.
        """
        self._password = password or os.environ.get(self.ENV_VAR_PREFIX)
        if not self._password:
            raise KeyManagerError(
                f"Password required. Set {self.ENV_VAR_PREFIX} environment variable "
                "or provide password parameter"
            )

    def _derive_key(self, key_id: int) -> bytes:
        """Derive Fernet key from password and key ID."""
        # Use key_id as part of salt for key separation
        salt = self.SALT_PREFIX + key_id.to_bytes(2, "big")

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.PBKDF2_ITERATIONS,
        )
        key = kdf.derive(self._password.encode())
        return urlsafe_b64encode(key)

    def get_key(self, key_id: int) -> bytes | None:
        """Derive key from password."""
        return self._derive_key(key_id)

    def set_key(self, key_id: int, key: bytes) -> None:
        """No-op: keys are derived, not stored."""
        # Password-derived keys don't need storage
        # Just verify the key matches what we'd derive
        derived = self._derive_key(key_id)
        if key != derived:
            raise KeyManagerError("Provided key does not match password-derived key")

    def delete_key(self, key_id: int) -> None:
        """No-op: keys are derived, not stored."""
        pass


class EnvironmentBackend(KeyBackend):
    """Environment variable-based key storage.

    Keys are read from environment variables like:
    CHATFILTER_ENCRYPTION_KEY_0=<base64-encoded-key>
    CHATFILTER_ENCRYPTION_KEY_1=<base64-encoded-key>

    Useful for containerized deployments or CI environments.
    """

    ENV_VAR_PREFIX = "CHATFILTER_ENCRYPTION_KEY"

    def _env_var_name(self, key_id: int) -> str:
        """Generate environment variable name for key ID."""
        return f"{self.ENV_VAR_PREFIX}_{key_id}"

    def get_key(self, key_id: int) -> bytes | None:
        """Retrieve key from environment variable."""
        key_b64 = os.environ.get(self._env_var_name(key_id))
        if key_b64 is None:
            return None
        # Fernet keys are already base64-encoded, so we return them as-is
        # Just convert string to bytes if needed
        if isinstance(key_b64, str):
            return key_b64.encode("ascii")
        return key_b64

    def set_key(self, key_id: int, key: bytes) -> None:
        """Store key in environment (for current process only)."""
        # Fernet keys are already base64-encoded, store as-is
        if isinstance(key, bytes):
            key = key.decode("ascii")
        os.environ[self._env_var_name(key_id)] = key

    def delete_key(self, key_id: int) -> None:
        """Delete key from environment."""
        os.environ.pop(self._env_var_name(key_id), None)


class MachineKeyBackend(KeyBackend):
    """Machine-derived key storage (legacy compatibility).

    Derives keys from machine-specific identifiers. This provides
    encryption at rest but keys are machine-tied and deterministic.

    Use OS keychain or password-based backends for better security.
    """

    SALT = b"chatfilter-storage-encryption-v1"

    def _derive_key_from_machine_id(self) -> bytes:
        """Derive encryption key from machine-specific identifier."""
        import uuid

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

        # Derive key using SHA-256
        key_material = f"{machine_id}".encode() + self.SALT
        key_hash = hashlib.sha256(key_material).digest()
        return urlsafe_b64encode(key_hash)

    def get_key(self, key_id: int) -> bytes | None:
        """Derive key from machine ID (ignores key_id)."""
        return self._derive_key_from_machine_id()

    def set_key(self, key_id: int, key: bytes) -> None:
        """No-op: keys are derived, not stored."""
        pass

    def delete_key(self, key_id: int) -> None:
        """No-op: keys are derived, not stored."""
        pass


class KeyManager:
    """Centralized encryption key management.

    Provides secure key storage with multiple backend options:
    1. OS keychain (preferred)
    2. Password-derived keys
    3. Environment variables
    4. Machine-derived keys (legacy)

    Example usage:
        # Using OS keychain (recommended)
        km = KeyManager.create()
        key = km.get_or_create_key(0)

        # Using password-derived keys
        km = KeyManager.create(backend_type="password", password="secret")
        key = km.get_or_create_key(0)

        # Using environment variables
        os.environ["CHATFILTER_ENCRYPTION_KEY_0"] = base64_key
        km = KeyManager.create(backend_type="environment")
        key = km.get_key(0)
    """

    def __init__(self, backend: KeyBackend) -> None:
        """Initialize key manager with specific backend.

        Args:
            backend: Key storage backend implementation
        """
        self._backend = backend

    @classmethod
    def create(
        cls,
        backend_type: str = "auto",
        password: str | None = None,
    ) -> "KeyManager":
        """Create key manager with specified backend.

        Args:
            backend_type: Backend type - "auto", "keyring", "password",
                         "environment", or "machine"
            password: Password for password-derived keys (if backend_type="password")

        Returns:
            Configured KeyManager instance

        Raises:
            KeyManagerError: If backend cannot be initialized
        """
        if backend_type == "auto":
            # Try backends in order of preference
            # Note: We prefer explicit configuration (env vars, password) over system defaults (keyring, machine)

            # Try environment variables first (explicit configuration)
            if any(k.startswith("CHATFILTER_ENCRYPTION_KEY_") for k in os.environ):
                backend = EnvironmentBackend()
                return cls(backend)

            # Try password from environment (explicit configuration)
            if os.environ.get("CHATFILTER_ENCRYPTION_PASSWORD"):
                try:
                    backend = PasswordBackend()
                    return cls(backend)
                except KeyManagerError:
                    pass

            # Try OS keyring (secure system storage)
            if HAS_KEYRING:
                try:
                    backend = KeyringBackend()
                    return cls(backend)
                except KeyManagerError:
                    pass

            # Fall back to machine-derived (legacy)
            backend = MachineKeyBackend()
            return cls(backend)

        elif backend_type == "keyring":
            backend = KeyringBackend()
        elif backend_type == "password":
            backend = PasswordBackend(password)
        elif backend_type == "environment":
            backend = EnvironmentBackend()
        elif backend_type == "machine":
            backend = MachineKeyBackend()
        else:
            raise KeyManagerError(f"Unknown backend type: {backend_type}")

        return cls(backend)

    def get_key(self, key_id: int = 0) -> bytes | None:
        """Retrieve encryption key by ID.

        Args:
            key_id: Numeric key identifier (0-65535)

        Returns:
            32-byte Fernet-compatible key, or None if not found
        """
        return self._backend.get_key(key_id)

    def get_or_create_key(self, key_id: int = 0) -> bytes:
        """Get existing key or generate new one.

        Args:
            key_id: Numeric key identifier (0-65535)

        Returns:
            32-byte Fernet-compatible key

        Raises:
            KeyNotFoundError: If key cannot be retrieved or created
        """
        key = self.get_key(key_id)
        if key is not None:
            return key

        # Generate new key
        key = Fernet.generate_key()

        try:
            self._backend.set_key(key_id, key)
        except Exception as e:
            raise KeyNotFoundError(f"Failed to store new key: {e}") from e

        return key

    def set_key(self, key_id: int, key: bytes) -> None:
        """Store encryption key.

        Args:
            key_id: Numeric key identifier (0-65535)
            key: 32-byte Fernet-compatible key
        """
        if len(key) != 44:  # Base64-encoded 32-byte key
            raise KeyManagerError(f"Invalid key length: {len(key)} (expected 44 bytes)")

        self._backend.set_key(key_id, key)

    def delete_key(self, key_id: int) -> None:
        """Delete encryption key.

        Args:
            key_id: Numeric key identifier to delete
        """
        self._backend.delete_key(key_id)

    def rotate_key(self, old_key_id: int, new_key_id: int) -> bytes:
        """Rotate to a new encryption key.

        Args:
            old_key_id: Current key ID
            new_key_id: New key ID

        Returns:
            New encryption key

        Note:
            Old key is NOT deleted to allow decryption of existing files.
            Call delete_key(old_key_id) manually after re-encrypting all files.
        """
        # Verify old key exists
        old_key = self.get_key(old_key_id)
        if old_key is None:
            raise KeyNotFoundError(f"Old key {old_key_id} not found")

        # Generate and store new key
        new_key = Fernet.generate_key()
        self._backend.set_key(new_key_id, new_key)

        return new_key

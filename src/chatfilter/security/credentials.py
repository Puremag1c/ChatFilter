"""Secure storage for Telegram API credentials.

Implements layered security with multiple storage backends:
1. OS Keyring (preferred) - Uses system's native credential storage
2. Encrypted file (fallback) - For headless/unsupported systems
3. Environment variables (optional) - For containerized deployments

Security features:
- Never stores credentials in plaintext
- Redacts sensitive data in logs
- Secure deletion of plaintext files during migration
- Support for multiple sessions with isolated credentials
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.fernet import Fernet

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Service name for keyring storage
KEYRING_SERVICE = "ChatFilter"

# Environment variable names
ENV_API_ID_PREFIX = "CHATFILTER_API_ID"
ENV_API_HASH_PREFIX = "CHATFILTER_API_HASH"


class CredentialStorageError(Exception):
    """Base exception for credential storage errors."""


class CredentialNotFoundError(CredentialStorageError):
    """Raised when credentials are not found in any storage backend."""


class CredentialStorageBackend:
    """Base class for credential storage backends."""

    def store_credentials(self, session_id: str, api_id: int, api_hash: str) -> None:
        """Store API credentials securely.

        Args:
            session_id: Unique session identifier
            api_id: Telegram API ID
            api_hash: Telegram API hash

        Raises:
            CredentialStorageError: If storage fails
        """
        raise NotImplementedError

    def retrieve_credentials(self, session_id: str) -> tuple[int, str]:
        """Retrieve API credentials.

        Args:
            session_id: Unique session identifier

        Returns:
            Tuple of (api_id, api_hash)

        Raises:
            CredentialNotFoundError: If credentials not found
            CredentialStorageError: If retrieval fails
        """
        raise NotImplementedError

    def delete_credentials(self, session_id: str) -> None:
        """Delete stored credentials.

        Args:
            session_id: Unique session identifier

        Raises:
            CredentialStorageError: If deletion fails
        """
        raise NotImplementedError

    def is_available(self) -> bool:
        """Check if this backend is available on the current system.

        Returns:
            True if backend can be used
        """
        raise NotImplementedError


class KeyringBackend(CredentialStorageBackend):
    """OS keyring backend using native system credential storage.

    Uses:
    - macOS: Keychain
    - Windows: Credential Locker
    - Linux: Secret Service (libsecret/gnome-keyring)
    """

    def __init__(self) -> None:
        """Initialize keyring backend."""
        try:
            import keyring

            self._keyring = keyring
        except ImportError:
            self._keyring = None

    def is_available(self) -> bool:
        """Check if keyring is available."""
        if self._keyring is None:
            return False

        try:
            # Test if keyring backend is functional
            # Some systems have keyring installed but no usable backend
            backend = self._keyring.get_keyring()
            # Fail backend is used when no real backend is available
            return backend.priority >= 1  # type: ignore[union-attr]
        except Exception:
            return False

    def store_credentials(self, session_id: str, api_id: int, api_hash: str) -> None:
        """Store credentials in OS keyring."""
        if not self.is_available():
            raise CredentialStorageError("Keyring backend not available")

        try:
            # Store api_id as string (keyring stores strings)
            self._keyring.set_password(
                KEYRING_SERVICE,
                f"{session_id}:api_id",
                str(api_id),
            )
            self._keyring.set_password(
                KEYRING_SERVICE,
                f"{session_id}:api_hash",
                api_hash,
            )
            logger.info(f"Stored credentials in OS keyring for session: {session_id}")
        except Exception as e:
            raise CredentialStorageError(f"Failed to store in keyring: {e}") from e

    def retrieve_credentials(self, session_id: str) -> tuple[int, str]:
        """Retrieve credentials from OS keyring."""
        if not self.is_available():
            raise CredentialStorageError("Keyring backend not available")

        try:
            api_id_str = self._keyring.get_password(
                KEYRING_SERVICE,
                f"{session_id}:api_id",
            )
            api_hash = self._keyring.get_password(
                KEYRING_SERVICE,
                f"{session_id}:api_hash",
            )

            if api_id_str is None or api_hash is None:
                raise CredentialNotFoundError(
                    f"Credentials not found in keyring for session: {session_id}"
                )

            try:
                api_id = int(api_id_str)
            except ValueError as e:
                raise CredentialStorageError(f"Invalid api_id in keyring: {api_id_str}") from e

            return api_id, api_hash

        except CredentialNotFoundError:
            raise
        except CredentialStorageError:
            raise
        except Exception as e:
            raise CredentialStorageError(f"Failed to retrieve from keyring: {e}") from e

    def delete_credentials(self, session_id: str) -> None:
        """Delete credentials from OS keyring."""
        if not self.is_available():
            raise CredentialStorageError("Keyring backend not available")

        try:
            self._keyring.delete_password(KEYRING_SERVICE, f"{session_id}:api_id")
            self._keyring.delete_password(KEYRING_SERVICE, f"{session_id}:api_hash")
            logger.info(f"Deleted credentials from keyring for session: {session_id}")
        except Exception as e:
            # Don't fail if already deleted
            logger.debug(f"Error deleting from keyring (may not exist): {e}")


class EncryptedFileBackend(CredentialStorageBackend):
    """Encrypted file backend for systems without keyring support.

    Stores credentials in an encrypted file using Fernet (symmetric encryption).
    The encryption key is derived from a machine-specific master key.
    """

    def __init__(self, storage_dir: Path) -> None:
        """Initialize encrypted file backend.

        Args:
            storage_dir: Directory to store encrypted credentials file
        """
        self._storage_dir = storage_dir
        self._credentials_file = storage_dir / ".credentials.enc"
        self._key_file = storage_dir / ".master.key"

    def is_available(self) -> bool:
        """Encrypted file backend is always available."""
        return True

    def _get_or_create_key(self) -> bytes:
        """Get or create master encryption key.

        Returns:
            Encryption key bytes
        """
        # Ensure storage directory exists with restrictive permissions
        self._storage_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        if self._key_file.exists():
            return self._key_file.read_bytes()

        # Generate new key
        key = Fernet.generate_key()

        # Check disk space before writing (key is 44 bytes)
        from chatfilter.utils.disk import ensure_space_available

        ensure_space_available(self._key_file, len(key))

        # Write with restrictive permissions
        self._key_file.write_bytes(key)
        self._key_file.chmod(0o600)

        logger.info("Generated new master encryption key")
        return key

    def _get_fernet(self) -> Fernet:
        """Get Fernet instance with master key.

        Returns:
            Fernet cipher instance
        """
        key = self._get_or_create_key()
        return Fernet(key)

    def _load_credentials_file(self) -> dict[str, dict[str, str]]:
        """Load and decrypt credentials file.

        Returns:
            Dictionary mapping session_id to credentials dict
        """
        if not self._credentials_file.exists():
            return {}

        try:
            encrypted_data = self._credentials_file.read_bytes()
            fernet = self._get_fernet()
            decrypted_data = fernet.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode("utf-8"))
        except Exception as e:
            logger.error(f"Failed to decrypt credentials file: {e}")
            # Return empty dict if file is corrupted
            return {}

    def _save_credentials_file(self, credentials: dict[str, dict[str, str]]) -> None:
        """Encrypt and save credentials file.

        Args:
            credentials: Dictionary mapping session_id to credentials dict

        Raises:
            CredentialStorageError: If unable to save credentials
        """
        try:
            fernet = self._get_fernet()
            json_data = json.dumps(credentials).encode("utf-8")
            encrypted_data = fernet.encrypt(json_data)

            # Check disk space before writing
            from chatfilter.utils.disk import ensure_space_available

            ensure_space_available(self._credentials_file, len(encrypted_data))

            # Write with restrictive permissions
            self._credentials_file.write_bytes(encrypted_data)
            self._credentials_file.chmod(0o600)
        except Exception as e:
            raise CredentialStorageError(f"Failed to save encrypted credentials: {e}") from e

    def store_credentials(self, session_id: str, api_id: int, api_hash: str) -> None:
        """Store credentials in encrypted file."""
        credentials = self._load_credentials_file()
        credentials[session_id] = {
            "api_id": str(api_id),
            "api_hash": api_hash,
        }
        self._save_credentials_file(credentials)
        logger.info(f"Stored credentials in encrypted file for session: {session_id}")

    def retrieve_credentials(self, session_id: str) -> tuple[int, str]:
        """Retrieve credentials from encrypted file."""
        credentials = self._load_credentials_file()

        if session_id not in credentials:
            raise CredentialNotFoundError(
                f"Credentials not found in encrypted file for session: {session_id}"
            )

        session_creds = credentials[session_id]
        try:
            api_id = int(session_creds["api_id"])
            api_hash = session_creds["api_hash"]
            return api_id, api_hash
        except (KeyError, ValueError) as e:
            raise CredentialStorageError(
                f"Invalid credentials format for session: {session_id}"
            ) from e

    def delete_credentials(self, session_id: str) -> None:
        """Delete credentials from encrypted file."""
        credentials = self._load_credentials_file()

        if session_id in credentials:
            del credentials[session_id]
            self._save_credentials_file(credentials)
            logger.info(f"Deleted credentials from encrypted file for session: {session_id}")


class EnvironmentBackend(CredentialStorageBackend):
    """Environment variable backend for containerized deployments.

    Reads credentials from environment variables:
    - CHATFILTER_API_ID_{SESSION_ID}
    - CHATFILTER_API_HASH_{SESSION_ID}

    This backend is read-only and cannot store credentials.
    """

    def is_available(self) -> bool:
        """Environment backend is always available (read-only)."""
        return True

    def store_credentials(self, session_id: str, api_id: int, api_hash: str) -> None:
        """Environment backend is read-only."""
        raise CredentialStorageError("Cannot store credentials in environment backend (read-only)")

    def retrieve_credentials(self, session_id: str) -> tuple[int, str]:
        """Retrieve credentials from environment variables."""
        # Normalize session_id for env var (replace hyphens with underscores, uppercase)
        env_suffix = session_id.replace("-", "_").upper()

        api_id_env = f"{ENV_API_ID_PREFIX}_{env_suffix}"
        api_hash_env = f"{ENV_API_HASH_PREFIX}_{env_suffix}"

        api_id_str = os.getenv(api_id_env)
        api_hash = os.getenv(api_hash_env)

        if api_id_str is None or api_hash is None:
            raise CredentialNotFoundError(
                f"Credentials not found in environment for session: {session_id}"
            )

        try:
            api_id = int(api_id_str)
        except ValueError as e:
            raise CredentialStorageError(f"Invalid api_id in environment: {api_id_str}") from e

        return api_id, api_hash

    def delete_credentials(self, session_id: str) -> None:
        """Environment backend is read-only."""
        raise CredentialStorageError(
            "Cannot delete credentials from environment backend (read-only)"
        )


class SecureCredentialManager:
    """Manager for secure credential storage with multiple backends.

    Attempts to use backends in order of preference:
    1. Environment variables (read-only, for containers)
    2. OS Keyring (preferred for desktop)
    3. Encrypted file (fallback)

    For storage operations, uses:
    1. OS Keyring (if available)
    2. Encrypted file (fallback)
    """

    def __init__(self, storage_dir: Path) -> None:
        """Initialize credential manager.

        Args:
            storage_dir: Directory for encrypted file backend
        """
        self._env_backend = EnvironmentBackend()
        self._keyring_backend = KeyringBackend()
        self._file_backend = EncryptedFileBackend(storage_dir)

        # Determine preferred storage backend
        if self._keyring_backend.is_available():
            self._storage_backend = self._keyring_backend
            logger.info("Using OS keyring for credential storage")
        else:
            self._storage_backend = self._file_backend
            logger.warning(
                "OS keyring not available, using encrypted file backend. "
                "For better security, ensure keyring is properly configured."
            )

    def store_credentials(self, session_id: str, api_id: int, api_hash: str) -> None:
        """Store API credentials securely.

        Args:
            session_id: Unique session identifier
            api_id: Telegram API ID
            api_hash: Telegram API hash

        Raises:
            CredentialStorageError: If storage fails
        """
        self._storage_backend.store_credentials(session_id, api_id, api_hash)

    def retrieve_credentials(self, session_id: str) -> tuple[int, str]:
        """Retrieve API credentials.

        Attempts backends in order: environment, keyring, encrypted file.

        Args:
            session_id: Unique session identifier

        Returns:
            Tuple of (api_id, api_hash)

        Raises:
            CredentialNotFoundError: If credentials not found in any backend
        """
        # Try environment first (for containers)
        try:
            return self._env_backend.retrieve_credentials(session_id)
        except CredentialNotFoundError:
            pass

        # Try keyring if available
        if self._keyring_backend.is_available():
            try:
                return self._keyring_backend.retrieve_credentials(session_id)
            except CredentialNotFoundError:
                pass

        # Fall back to encrypted file
        try:
            return self._file_backend.retrieve_credentials(session_id)
        except CredentialNotFoundError:
            pass

        # No backend has the credentials
        raise CredentialNotFoundError(
            f"Credentials not found for session: {session_id}. "
            f"Please ensure credentials are properly stored."
        )

    def delete_credentials(self, session_id: str) -> None:
        """Delete stored credentials from all backends.

        Args:
            session_id: Unique session identifier
        """
        # Try deleting from both keyring and file
        # (credentials might be in both during migration)

        if self._keyring_backend.is_available():
            try:
                self._keyring_backend.delete_credentials(session_id)
            except Exception as e:
                logger.debug(f"Error deleting from keyring: {e}")

        try:
            self._file_backend.delete_credentials(session_id)
        except Exception as e:
            logger.debug(f"Error deleting from encrypted file: {e}")

    def has_credentials(self, session_id: str) -> bool:
        """Check if credentials exist for a session.

        Args:
            session_id: Unique session identifier

        Returns:
            True if credentials exist in any backend
        """
        try:
            self.retrieve_credentials(session_id)
            return True
        except CredentialNotFoundError:
            return False

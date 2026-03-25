"""Secure storage for Telegram session configuration (proxy).

Implements layered security with multiple storage backends:
1. Encrypted file (default) - Credentials encrypted with machine-specific key
2. Environment variables (optional) - For containerized deployments

Security features:
- Never stores credentials in plaintext
- Redacts sensitive data in logs
- Secure deletion of plaintext files during migration
- Support for multiple sessions with isolated credentials

NOTE: OS Keyring is NOT used because it causes repeated password prompts
on macOS (Apple Keychain dialog appearing multiple times per operation).

NOTE: api_id/api_hash are global settings (CHATFILTER_API_ID/API_HASH env vars)
and are NOT stored per-session. Only proxy_id is stored per-session.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING, cast

from cryptography.fernet import Fernet

from chatfilter.storage.helpers import atomic_write

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Environment variable names
ENV_PROXY_ID_PREFIX = "CHATFILTER_PROXY_ID"


class CredentialStorageError(Exception):
    """Base exception for credential storage errors."""


class CredentialNotFoundError(CredentialStorageError):
    """Raised when credentials are not found in any storage backend."""


class CredentialStorageBackend:
    """Base class for credential storage backends."""

    def store_session_config(
        self,
        session_id: str,
        proxy_id: str | None,
    ) -> None:
        """Store session configuration (proxy_id) securely.

        Args:
            session_id: Unique session identifier
            proxy_id: Optional proxy identifier

        Raises:
            CredentialStorageError: If storage fails
        """
        raise NotImplementedError

    def retrieve_session_config(self, session_id: str) -> str | None:
        """Retrieve session configuration (proxy_id).

        Args:
            session_id: Unique session identifier

        Returns:
            proxy_id or None if not configured

        Raises:
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


class EncryptedFileBackend(CredentialStorageBackend):
    """Encrypted file backend for systems without keyring support.

    Stores session config in an encrypted file using Fernet (symmetric encryption).
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

        # Atomic write to prevent corruption on crash
        atomic_write(self._key_file, key)
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
            return cast(dict[str, dict[str, str]], json.loads(decrypted_data.decode("utf-8")))
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

            # Atomic write to prevent corruption on crash
            atomic_write(self._credentials_file, encrypted_data)
            self._credentials_file.chmod(0o600)
        except Exception as e:
            raise CredentialStorageError(f"Failed to save encrypted credentials: {e}") from e

    def store_session_config(
        self,
        session_id: str,
        proxy_id: str | None,
    ) -> None:
        """Store session config (proxy_id) in encrypted file."""
        credentials = self._load_credentials_file()
        session_data = credentials.get(session_id, {})

        # Update or remove proxy_id
        if proxy_id is not None:
            session_data["proxy_id"] = proxy_id
        else:
            session_data.pop("proxy_id", None)

        credentials[session_id] = session_data
        self._save_credentials_file(credentials)
        logger.info(f"Stored session config in encrypted file for session: {session_id}")

    def retrieve_session_config(self, session_id: str) -> str | None:
        """Retrieve session config (proxy_id) from encrypted file."""
        credentials = self._load_credentials_file()
        session_data = credentials.get(session_id, {})
        return session_data.get("proxy_id")

    def delete_credentials(self, session_id: str) -> None:
        """Delete credentials from encrypted file."""
        credentials = self._load_credentials_file()

        if session_id in credentials:
            del credentials[session_id]
            self._save_credentials_file(credentials)
            logger.info(f"Deleted credentials from encrypted file for session: {session_id}")

    def migrate_strip_api_credentials(self) -> int:
        """Strip api_id and api_hash from all sessions in the encrypted file.

        Reads the old format (api_id + api_hash + proxy_id) and rewrites each
        session keeping only proxy_id and 2fa_password. This is a one-time
        migration helper called during startup before the schema change takes
        full effect.

        Returns:
            Number of sessions that were migrated (had api_id/api_hash removed)
        """
        credentials = self._load_credentials_file()
        migrated = 0

        for session_id, cred_data in credentials.items():
            if "api_id" in cred_data or "api_hash" in cred_data:
                # Keep only proxy_id and 2fa_password
                new_cred: dict[str, str] = {}
                if "proxy_id" in cred_data:
                    new_cred["proxy_id"] = cred_data["proxy_id"]
                if "2fa_password" in cred_data:
                    new_cred["2fa_password"] = cred_data["2fa_password"]
                credentials[session_id] = new_cred
                migrated += 1
                logger.info(
                    f"Stripped api_id/api_hash from credentials for session: {session_id}"
                )

        if migrated > 0:
            self._save_credentials_file(credentials)
            logger.info(f"Credential migration complete: {migrated} session(s) updated")

        return migrated


class EnvironmentBackend(CredentialStorageBackend):
    """Environment variable backend for containerized deployments.

    Reads proxy_id from environment variables:
    - CHATFILTER_PROXY_ID_{SESSION_ID} (optional)

    This backend is read-only and cannot store credentials.
    """

    def is_available(self) -> bool:
        """Environment backend is always available (read-only)."""
        return True

    def store_session_config(
        self,
        session_id: str,
        proxy_id: str | None,
    ) -> None:
        """Environment backend is read-only."""
        raise CredentialStorageError("Cannot store credentials in environment backend (read-only)")

    def retrieve_session_config(self, session_id: str) -> str | None:
        """Retrieve proxy_id from environment variables."""
        # Normalize session_id for env var (replace hyphens with underscores, uppercase)
        env_suffix = session_id.replace("-", "_").upper()
        proxy_id_env = f"{ENV_PROXY_ID_PREFIX}_{env_suffix}"
        return os.getenv(proxy_id_env)

    def delete_credentials(self, session_id: str) -> None:
        """Environment backend is read-only."""
        raise CredentialStorageError(
            "Cannot delete credentials from environment backend (read-only)"
        )


class SecureCredentialManager:
    """Manager for secure credential storage with multiple backends.

    Stores only proxy_id per session. api_id/api_hash are global settings
    loaded from CHATFILTER_API_ID/CHATFILTER_API_HASH environment variables.

    Backends in order of preference for retrieval:
    1. Environment variables (read-only, for containers)
    2. Encrypted file (default)

    NOTE: OS Keyring is NOT used because it causes repeated password prompts
    on macOS (Apple Keychain dialog appearing multiple times per operation).
    """

    _storage_backend: CredentialStorageBackend

    def __init__(self, storage_dir: Path) -> None:
        """Initialize credential manager.

        Args:
            storage_dir: Directory for encrypted file backend
        """
        self._env_backend = EnvironmentBackend()
        self._file_backend = EncryptedFileBackend(storage_dir)

        # Use encrypted file backend (no keychain prompts)
        self._storage_backend = self._file_backend
        logger.debug("Using encrypted file backend for credential storage")

    def store_session_config(
        self,
        session_id: str,
        proxy_id: str | None,
    ) -> None:
        """Store session configuration (proxy_id) securely.

        Args:
            session_id: Unique session identifier
            proxy_id: Optional proxy identifier

        Raises:
            CredentialStorageError: If storage fails
        """
        self._storage_backend.store_session_config(session_id, proxy_id)

    def retrieve_session_config(self, session_id: str) -> str | None:
        """Retrieve session configuration (proxy_id).

        Attempts backends in order: environment, encrypted file.

        Args:
            session_id: Unique session identifier

        Returns:
            proxy_id or None if not configured
        """
        # Try environment first (for containers)
        proxy_id = self._env_backend.retrieve_session_config(session_id)
        if proxy_id is not None:
            return proxy_id

        # Fall back to encrypted file
        return self._file_backend.retrieve_session_config(session_id)

    def delete_credentials(self, session_id: str) -> None:
        """Delete stored credentials.

        Args:
            session_id: Unique session identifier
        """
        try:
            self._file_backend.delete_credentials(session_id)
        except Exception as e:
            logger.debug(f"Error deleting from encrypted file: {e}")

    def has_credentials(self, session_id: str) -> bool:
        """Check if proxy_id is configured for a session.

        Args:
            session_id: Unique session identifier

        Returns:
            True if proxy_id exists in any backend
        """
        return self.retrieve_session_config(session_id) is not None

    def store_2fa(self, session_id: str, password: str) -> None:
        """Store encrypted 2FA password.

        Args:
            session_id: Unique session identifier
            password: 2FA password to encrypt and store

        Raises:
            CredentialStorageError: If storage fails
        """
        credentials = self._file_backend._load_credentials_file()

        if session_id not in credentials:
            credentials[session_id] = {}

        credentials[session_id]["2fa_password"] = password
        self._file_backend._save_credentials_file(credentials)
        logger.info(f"Stored encrypted 2FA password for session: {session_id}")

    def retrieve_2fa(self, session_id: str) -> str | None:
        """Retrieve decrypted 2FA password.

        Args:
            session_id: Unique session identifier

        Returns:
            Decrypted 2FA password or None if not found
        """
        credentials = self._file_backend._load_credentials_file()

        if session_id not in credentials:
            return None

        return credentials[session_id].get("2fa_password")

    def delete_2fa(self, session_id: str) -> None:
        """Delete stored 2FA password.

        Args:
            session_id: Unique session identifier
        """
        credentials = self._file_backend._load_credentials_file()

        if session_id in credentials and "2fa_password" in credentials[session_id]:
            del credentials[session_id]["2fa_password"]
            self._file_backend._save_credentials_file(credentials)
            logger.info(f"Deleted encrypted 2FA password for session: {session_id}")

    def migrate_strip_api_credentials(self) -> int:
        """Strip api_id and api_hash from the encrypted credentials file.

        One-time migration helper: reads the old format that stored api_id and
        api_hash in .credentials.enc, removes those fields, and rewrites the
        file keeping only proxy_id and 2fa_password per session.

        Returns:
            Number of sessions that had api_id/api_hash removed
        """
        return self._file_backend.migrate_strip_api_credentials()

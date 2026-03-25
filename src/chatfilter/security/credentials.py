"""Secure storage for session configuration (proxy, 2FA).

Implements layered security with multiple storage backends:
1. Encrypted file (default) - Data encrypted with machine-specific key
2. Environment variables (optional) - For containerized deployments

Security features:
- Never stores credentials in plaintext
- Redacts sensitive data in logs
- Secure deletion of plaintext files during migration
- Support for multiple sessions with isolated config

NOTE: api_id and api_hash are global (from Settings/ENV), not per-session.
NOTE: OS Keyring is NOT used because it causes repeated password prompts
on macOS (Apple Keychain dialog appearing multiple times per operation).
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
        proxy_id: str | None = None,
    ) -> None:
        """Store session configuration securely.

        Args:
            session_id: Unique session identifier
            proxy_id: Optional proxy identifier

        Raises:
            CredentialStorageError: If storage fails
        """
        raise NotImplementedError

    def retrieve_session_config(self, session_id: str) -> str | None:
        """Retrieve session configuration.

        Args:
            session_id: Unique session identifier

        Returns:
            proxy_id or None if not set

        Raises:
            CredentialNotFoundError: If session config not found
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
        self._storage_dir = storage_dir
        self._credentials_file = storage_dir / ".credentials.enc"
        self._key_file = storage_dir / ".master.key"

    def is_available(self) -> bool:
        return True

    def _get_or_create_key(self) -> bytes:
        self._storage_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        if self._key_file.exists():
            return self._key_file.read_bytes()

        key = Fernet.generate_key()

        from chatfilter.utils.disk import ensure_space_available

        ensure_space_available(self._key_file, len(key))

        atomic_write(self._key_file, key)
        self._key_file.chmod(0o600)

        logger.info("Generated new master encryption key")
        return key

    def _get_fernet(self) -> Fernet:
        key = self._get_or_create_key()
        return Fernet(key)

    def _load_credentials_file(self) -> dict[str, dict[str, str]]:
        if not self._credentials_file.exists():
            return {}

        try:
            encrypted_data = self._credentials_file.read_bytes()
            fernet = self._get_fernet()
            decrypted_data = fernet.decrypt(encrypted_data)
            return cast(dict[str, dict[str, str]], json.loads(decrypted_data.decode("utf-8")))
        except Exception as e:
            logger.error(f"Failed to decrypt credentials file: {e}")
            return {}

    def _save_credentials_file(self, credentials: dict[str, dict[str, str]]) -> None:
        try:
            fernet = self._get_fernet()
            json_data = json.dumps(credentials).encode("utf-8")
            encrypted_data = fernet.encrypt(json_data)

            from chatfilter.utils.disk import ensure_space_available

            ensure_space_available(self._credentials_file, len(encrypted_data))

            atomic_write(self._credentials_file, encrypted_data)
            self._credentials_file.chmod(0o600)
        except Exception as e:
            raise CredentialStorageError(f"Failed to save encrypted credentials: {e}") from e

    def store_session_config(
        self,
        session_id: str,
        proxy_id: str | None = None,
    ) -> None:
        credentials = self._load_credentials_file()
        cred_data: dict[str, str] = {}
        if proxy_id is not None:
            cred_data["proxy_id"] = proxy_id
        credentials[session_id] = cred_data
        self._save_credentials_file(credentials)
        logger.info(f"Stored session config in encrypted file for session: {session_id}")

    def retrieve_session_config(self, session_id: str) -> str | None:
        credentials = self._load_credentials_file()

        if session_id not in credentials:
            raise CredentialNotFoundError(
                f"Session config not found in encrypted file for session: {session_id}"
            )

        session_creds = credentials[session_id]
        return session_creds.get("proxy_id")

    def delete_credentials(self, session_id: str) -> None:
        credentials = self._load_credentials_file()

        if session_id in credentials:
            del credentials[session_id]
            self._save_credentials_file(credentials)
            logger.info(f"Deleted credentials from encrypted file for session: {session_id}")

    def migrate_strip_api_credentials(self) -> int:
        """Strip api_id and api_hash from all sessions in the encrypted file.

        One-time migration helper called during startup.

        Returns:
            Number of sessions that were migrated (had api_id/api_hash removed)
        """
        credentials = self._load_credentials_file()
        migrated = 0

        for session_id, cred_data in credentials.items():
            if "api_id" in cred_data or "api_hash" in cred_data:
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

    Reads session config from environment variables:
    - CHATFILTER_PROXY_ID_{SESSION_ID} (optional)

    This backend is read-only and cannot store config.
    """

    def is_available(self) -> bool:
        return True

    def store_session_config(
        self,
        session_id: str,
        proxy_id: str | None = None,
    ) -> None:
        raise CredentialStorageError("Cannot store config in environment backend (read-only)")

    def retrieve_session_config(self, session_id: str) -> str | None:
        env_suffix = session_id.replace("-", "_").upper()
        proxy_id_env = f"{ENV_PROXY_ID_PREFIX}_{env_suffix}"
        proxy_id = os.getenv(proxy_id_env)
        return proxy_id

    def delete_credentials(self, session_id: str) -> None:
        raise CredentialStorageError(
            "Cannot delete credentials from environment backend (read-only)"
        )


class SecureCredentialManager:
    """Manager for secure credential storage with multiple backends.

    Stores per-session config (proxy_id, 2FA) — NOT api_id/api_hash
    which are now global via Settings/ENV.

    Attempts to use backends in order of preference:
    1. Environment variables (read-only, for containers)
    2. Encrypted file (default)
    """

    _storage_backend: CredentialStorageBackend

    def __init__(self, storage_dir: Path) -> None:
        self._env_backend = EnvironmentBackend()
        self._file_backend = EncryptedFileBackend(storage_dir)
        self._storage_backend = self._file_backend
        logger.debug("Using encrypted file backend for credential storage")

    def store_session_config(
        self,
        session_id: str,
        proxy_id: str | None = None,
    ) -> None:
        """Store session configuration securely.

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
            proxy_id or None if not set
        """
        # Try environment first (for containers)
        env_proxy = self._env_backend.retrieve_session_config(session_id)
        if env_proxy is not None:
            return env_proxy

        # Use encrypted file backend
        try:
            return self._file_backend.retrieve_session_config(session_id)
        except CredentialNotFoundError:
            return None

    def delete_credentials(self, session_id: str) -> None:
        """Delete stored credentials for a session."""
        try:
            self._file_backend.delete_credentials(session_id)
        except Exception as e:
            logger.debug(f"Error deleting from encrypted file: {e}")

    def has_credentials(self, session_id: str) -> bool:
        """Check if credentials exist for a session (proxy_id is stored)."""
        try:
            proxy_id = self.retrieve_session_config(session_id)
            return proxy_id is not None
        except CredentialNotFoundError:
            return False

    def store_2fa(self, session_id: str, password: str) -> None:
        """Store encrypted 2FA password."""
        credentials = self._file_backend._load_credentials_file()

        if session_id not in credentials:
            credentials[session_id] = {}

        credentials[session_id]["2fa_password"] = password
        self._file_backend._save_credentials_file(credentials)
        logger.info(f"Stored encrypted 2FA password for session: {session_id}")

    def retrieve_2fa(self, session_id: str) -> str | None:
        """Retrieve decrypted 2FA password."""
        credentials = self._file_backend._load_credentials_file()

        if session_id not in credentials:
            return None

        return credentials[session_id].get("2fa_password")

    def delete_2fa(self, session_id: str) -> None:
        """Delete stored 2FA password."""
        credentials = self._file_backend._load_credentials_file()

        if session_id in credentials and "2fa_password" in credentials[session_id]:
            del credentials[session_id]["2fa_password"]
            self._file_backend._save_credentials_file(credentials)
            logger.info(f"Deleted encrypted 2FA password for session: {session_id}")

    def migrate_strip_api_credentials(self) -> int:
        """Strip api_id and api_hash from the encrypted credentials file.

        One-time migration helper.

        Returns:
            Number of sessions that had api_id/api_hash removed
        """
        return self._file_backend.migrate_strip_api_credentials()

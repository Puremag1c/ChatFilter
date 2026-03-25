"""Tests for secure credential storage and management."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet

from chatfilter.security.credentials import (
    CredentialStorageBackend,
    CredentialStorageError,
    EncryptedFileBackend,
    EnvironmentBackend,
    SecureCredentialManager,
)


class TestCredentialStorageBackend:
    """Tests for base CredentialStorageBackend class."""

    def test_base_store_session_config_not_implemented(self):
        """Test that base class store_session_config raises NotImplementedError."""
        backend = CredentialStorageBackend()

        with pytest.raises(NotImplementedError):
            backend.store_session_config("test-session", None)

    def test_base_retrieve_session_config_not_implemented(self):
        """Test that base class retrieve_session_config raises NotImplementedError."""
        backend = CredentialStorageBackend()

        with pytest.raises(NotImplementedError):
            backend.retrieve_session_config("test-session")

    def test_base_delete_credentials_not_implemented(self):
        """Test that base class delete_credentials raises NotImplementedError."""
        backend = CredentialStorageBackend()

        with pytest.raises(NotImplementedError):
            backend.delete_credentials("test-session")

    def test_base_is_available_not_implemented(self):
        """Test that base class is_available raises NotImplementedError."""
        backend = CredentialStorageBackend()

        with pytest.raises(NotImplementedError):
            backend.is_available()


class TestEncryptedFileBackend:
    """Tests for encrypted file-based credential storage."""

    def test_init(self, tmp_path: Path):
        """Test initialization of encrypted file backend."""
        storage_dir = tmp_path / "storage"
        backend = EncryptedFileBackend(storage_dir)

        assert backend._storage_dir == storage_dir
        assert backend._credentials_file == storage_dir / ".credentials.enc"
        assert backend._key_file == storage_dir / ".master.key"

    def test_is_available_always_true(self, tmp_path: Path):
        """Test that encrypted file backend is always available."""
        backend = EncryptedFileBackend(tmp_path)
        assert backend.is_available() is True

    def test_get_or_create_key_creates_new_key(self, tmp_path: Path):
        """Test creating a new master encryption key."""
        backend = EncryptedFileBackend(tmp_path)

        key = backend._get_or_create_key()

        assert len(key) == 44  # Fernet key is 44 bytes
        assert backend._key_file.exists()
        # Unix file permissions not applicable on Windows
        if sys.platform != "win32":
            assert backend._key_file.stat().st_mode & 0o777 == 0o600

    def test_get_or_create_key_returns_existing_key(self, tmp_path: Path):
        """Test that existing key is returned if it exists."""
        backend = EncryptedFileBackend(tmp_path)

        # Create key first time
        key1 = backend._get_or_create_key()

        # Get key second time
        key2 = backend._get_or_create_key()

        assert key1 == key2

    def test_get_or_create_key_creates_storage_directory(self, tmp_path: Path):
        """Test that storage directory is created if it doesn't exist."""
        storage_dir = tmp_path / "nested" / "storage"
        backend = EncryptedFileBackend(storage_dir)

        backend._get_or_create_key()

        assert storage_dir.exists()
        # Unix file permissions not applicable on Windows
        if sys.platform != "win32":
            assert storage_dir.stat().st_mode & 0o777 == 0o700

    def test_get_fernet_returns_fernet_instance(self, tmp_path: Path):
        """Test that _get_fernet returns a valid Fernet instance."""
        backend = EncryptedFileBackend(tmp_path)

        fernet = backend._get_fernet()

        assert isinstance(fernet, Fernet)

    def test_store_session_config_success(self, tmp_path: Path):
        """Test successfully storing session config in encrypted file."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_session_config("test-session", "proxy-123")

        assert backend._credentials_file.exists()
        # Unix file permissions not applicable on Windows
        if sys.platform != "win32":
            assert backend._credentials_file.stat().st_mode & 0o777 == 0o600

    def test_store_and_retrieve_session_config(self, tmp_path: Path):
        """Test storing and retrieving session config."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_session_config("test-session", "proxy-123")
        proxy_id = backend.retrieve_session_config("test-session")

        assert proxy_id == "proxy-123"

    def test_store_session_config_no_proxy(self, tmp_path: Path):
        """Test storing session config without proxy_id."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_session_config("test-session", None)
        proxy_id = backend.retrieve_session_config("test-session")

        assert proxy_id is None

    def test_store_multiple_sessions(self, tmp_path: Path):
        """Test storing config for multiple sessions."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_session_config("session1", "proxy1")
        backend.store_session_config("session2", "proxy2")
        backend.store_session_config("session3", None)

        assert backend.retrieve_session_config("session1") == "proxy1"
        assert backend.retrieve_session_config("session2") == "proxy2"
        assert backend.retrieve_session_config("session3") is None

    def test_store_session_config_updates_existing_session(self, tmp_path: Path):
        """Test that storing updates existing session."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_session_config("test-session", "proxy1")
        backend.store_session_config("test-session", "proxy2")

        proxy_id = backend.retrieve_session_config("test-session")
        assert proxy_id == "proxy2"

    def test_retrieve_session_config_not_found(self, tmp_path: Path):
        """Test retrieving non-existent session returns None."""
        backend = EncryptedFileBackend(tmp_path)

        proxy_id = backend.retrieve_session_config("nonexistent-session")
        assert proxy_id is None

    def test_retrieve_session_config_empty_file(self, tmp_path: Path):
        """Test retrieving from empty credentials file returns None."""
        backend = EncryptedFileBackend(tmp_path)

        # Create empty encrypted file
        fernet = backend._get_fernet()
        encrypted_data = fernet.encrypt(b"{}")
        backend._credentials_file.write_bytes(encrypted_data)

        proxy_id = backend.retrieve_session_config("test-session")
        assert proxy_id is None

    def test_retrieve_session_config_corrupted_file(self, tmp_path: Path):
        """Test retrieving from corrupted file returns None."""
        backend = EncryptedFileBackend(tmp_path)

        # Write corrupted data
        backend._credentials_file.write_text("corrupted data")

        proxy_id = backend.retrieve_session_config("test-session")
        assert proxy_id is None

    def test_delete_credentials_success(self, tmp_path: Path):
        """Test successfully deleting credentials."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_session_config("test-session", "proxy-123")
        backend.delete_credentials("test-session")

        proxy_id = backend.retrieve_session_config("test-session")
        assert proxy_id is None

    def test_delete_credentials_keeps_other_sessions(self, tmp_path: Path):
        """Test that deleting one session doesn't affect others."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_session_config("session1", "proxy1")
        backend.store_session_config("session2", "proxy2")

        backend.delete_credentials("session1")

        assert backend.retrieve_session_config("session2") == "proxy2"
        assert backend.retrieve_session_config("session1") is None

    def test_delete_credentials_nonexistent_session(self, tmp_path: Path):
        """Test deleting non-existent session doesn't raise error."""
        backend = EncryptedFileBackend(tmp_path)

        # Should not raise
        backend.delete_credentials("nonexistent-session")

    def test_load_credentials_file_missing_file(self, tmp_path: Path):
        """Test loading non-existent credentials file returns empty dict."""
        backend = EncryptedFileBackend(tmp_path)

        credentials = backend._load_credentials_file()

        assert credentials == {}

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Unix file permissions not applicable on Windows",
    )
    def test_save_credentials_file_error_handling(self, tmp_path: Path):
        """Test error handling when saving credentials file fails."""
        backend = EncryptedFileBackend(tmp_path)

        # Make storage directory read-only to cause write error
        backend._storage_dir.mkdir(parents=True, exist_ok=True)
        backend._get_or_create_key()  # Create key first
        backend._storage_dir.chmod(0o500)

        try:
            with pytest.raises(
                CredentialStorageError, match="Failed to save encrypted credentials"
            ):
                backend.store_session_config("test-session", "proxy-123")
        finally:
            # Restore permissions for cleanup
            backend._storage_dir.chmod(0o700)

    def test_credentials_file_encrypted(self, tmp_path: Path):
        """Test that credentials file is actually encrypted."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_session_config("test-session", "super-secret-proxy-id")

        # Read raw file content
        raw_content = backend._credentials_file.read_bytes()

        # Should not contain plaintext proxy_id
        assert b"super-secret-proxy-id" not in raw_content

    def test_encryption_key_persistence(self, tmp_path: Path):
        """Test that encryption key is persisted and reused."""
        backend1 = EncryptedFileBackend(tmp_path)
        backend1.store_session_config("test-session", "proxy-123")

        # Create new backend instance pointing to same directory
        backend2 = EncryptedFileBackend(tmp_path)
        proxy_id = backend2.retrieve_session_config("test-session")

        assert proxy_id == "proxy-123"


class TestEnvironmentBackend:
    """Tests for environment variable-based credential storage."""

    def test_is_available_always_true(self):
        """Test that environment backend is always available."""
        backend = EnvironmentBackend()
        assert backend.is_available() is True

    def test_store_session_config_raises_error(self):
        """Test that storing session config is not supported."""
        backend = EnvironmentBackend()

        with pytest.raises(CredentialStorageError, match="read-only"):
            backend.store_session_config("test-session", "proxy-123")

    def test_delete_credentials_raises_error(self):
        """Test that deleting credentials is not supported."""
        backend = EnvironmentBackend()

        with pytest.raises(CredentialStorageError, match="read-only"):
            backend.delete_credentials("test-session")

    def test_retrieve_session_config_success(self):
        """Test successfully retrieving proxy_id from environment."""
        os.environ["CHATFILTER_PROXY_ID_TEST_SESSION"] = "proxy-123"

        try:
            backend = EnvironmentBackend()
            proxy_id = backend.retrieve_session_config("test-session")

            assert proxy_id == "proxy-123"
        finally:
            os.environ.pop("CHATFILTER_PROXY_ID_TEST_SESSION", None)

    def test_retrieve_session_config_with_hyphens_in_session_id(self):
        """Test session ID normalization with hyphens."""
        os.environ["CHATFILTER_PROXY_ID_MY_SESSION"] = "proxy-456"

        try:
            backend = EnvironmentBackend()
            proxy_id = backend.retrieve_session_config("my-session")

            assert proxy_id == "proxy-456"
        finally:
            os.environ.pop("CHATFILTER_PROXY_ID_MY_SESSION", None)

    def test_retrieve_session_config_with_lowercase_session_id(self):
        """Test session ID normalization with lowercase."""
        os.environ["CHATFILTER_PROXY_ID_MYSESSION"] = "proxy-789"

        try:
            backend = EnvironmentBackend()
            proxy_id = backend.retrieve_session_config("mysession")

            assert proxy_id == "proxy-789"
        finally:
            os.environ.pop("CHATFILTER_PROXY_ID_MYSESSION", None)

    def test_retrieve_session_config_not_found(self):
        """Test that retrieve_session_config returns None when env var not set."""
        backend = EnvironmentBackend()

        os.environ.pop("CHATFILTER_PROXY_ID_NONEXISTENT_SESSION", None)
        proxy_id = backend.retrieve_session_config("nonexistent-session")
        assert proxy_id is None


class TestSecureCredentialManager:
    """Tests for SecureCredentialManager."""

    def test_init_uses_file_backend(self, tmp_path: Path):
        """Test that file backend is used by default (no keychain prompts)."""
        manager = SecureCredentialManager(tmp_path)

        assert isinstance(manager._storage_backend, EncryptedFileBackend)

    def test_store_session_config_uses_storage_backend(self, tmp_path: Path):
        """Test that store_session_config delegates to storage backend."""
        manager = SecureCredentialManager(tmp_path)
        manager._storage_backend = MagicMock()

        manager.store_session_config("test-session", "proxy-123")

        manager._storage_backend.store_session_config.assert_called_once_with(
            "test-session", "proxy-123"
        )

    def test_retrieve_session_config_tries_environment_first(self, tmp_path: Path):
        """Test that environment backend is tried first."""
        os.environ["CHATFILTER_PROXY_ID_TEST_SESSION"] = "proxy-from-env"

        try:
            manager = SecureCredentialManager(tmp_path)
            manager._file_backend = MagicMock()

            proxy_id = manager.retrieve_session_config("test-session")

            assert proxy_id == "proxy-from-env"

            # File backend should not be called
            manager._file_backend.retrieve_session_config.assert_not_called()
        finally:
            os.environ.pop("CHATFILTER_PROXY_ID_TEST_SESSION", None)

    def test_retrieve_session_config_uses_file_backend(self, tmp_path: Path):
        """Test that file backend is used when env var not set."""
        manager = SecureCredentialManager(tmp_path)
        manager._file_backend.store_session_config("test-session", "proxy-123")

        # Mock env backend to return None
        manager._env_backend = MagicMock()
        manager._env_backend.retrieve_session_config.return_value = None

        proxy_id = manager.retrieve_session_config("test-session")

        assert proxy_id == "proxy-123"

    def test_retrieve_session_config_returns_none_when_not_found(self, tmp_path: Path):
        """Test that retrieve_session_config returns None when not found in any backend."""
        manager = SecureCredentialManager(tmp_path)

        proxy_id = manager.retrieve_session_config("nonexistent-session")
        assert proxy_id is None

    def test_delete_credentials_deletes_from_file_backend(self, tmp_path: Path):
        """Test that delete removes from file backend."""
        manager = SecureCredentialManager(tmp_path)
        manager._file_backend = MagicMock()

        manager.delete_credentials("test-session")

        manager._file_backend.delete_credentials.assert_called_once_with("test-session")

    def test_delete_credentials_handles_file_backend_errors_gracefully(self, tmp_path: Path):
        """Test that delete handles file backend errors without crashing."""
        manager = SecureCredentialManager(tmp_path)
        manager._file_backend = MagicMock()
        manager._file_backend.delete_credentials.side_effect = Exception("File error")

        # Should not raise
        manager.delete_credentials("test-session")

    def test_has_credentials_returns_true_when_proxy_id_found(self, tmp_path: Path):
        """Test has_credentials returns True when proxy_id exists."""
        manager = SecureCredentialManager(tmp_path)
        manager._file_backend.store_session_config("test-session", "proxy-123")

        assert manager.has_credentials("test-session") is True

    def test_has_credentials_returns_false_when_no_proxy_id(self, tmp_path: Path):
        """Test has_credentials returns False when no proxy_id configured."""
        manager = SecureCredentialManager(tmp_path)

        assert manager.has_credentials("nonexistent-session") is False

    def test_integration_store_and_retrieve(self, tmp_path: Path):
        """Test integration of storing and retrieving session config."""
        manager = SecureCredentialManager(tmp_path)

        manager.store_session_config("test-session", "proxy-123")
        proxy_id = manager.retrieve_session_config("test-session")

        assert proxy_id == "proxy-123"

    def test_integration_store_retrieve_delete(self, tmp_path: Path):
        """Test full lifecycle of session config."""
        manager = SecureCredentialManager(tmp_path)

        # Store
        manager.store_session_config("test-session", "proxy-123")
        assert manager.has_credentials("test-session") is True

        # Retrieve
        proxy_id = manager.retrieve_session_config("test-session")
        assert proxy_id == "proxy-123"

        # Delete
        manager.delete_credentials("test-session")
        assert manager.has_credentials("test-session") is False

    def test_integration_multiple_sessions(self, tmp_path: Path):
        """Test managing multiple sessions simultaneously."""
        manager = SecureCredentialManager(tmp_path)

        # Store multiple sessions
        manager.store_session_config("session1", "proxy1")
        manager.store_session_config("session2", "proxy2")
        manager.store_session_config("session3", "proxy3")

        # Verify all exist
        assert manager.has_credentials("session1") is True
        assert manager.has_credentials("session2") is True
        assert manager.has_credentials("session3") is True

        # Delete one
        manager.delete_credentials("session2")

        # Verify correct session was deleted
        assert manager.has_credentials("session1") is True
        assert manager.has_credentials("session2") is False
        assert manager.has_credentials("session3") is True


class TestSecurityProperties:
    """Tests for security-related properties of credential storage."""

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Unix file permissions not applicable on Windows",
    )
    def test_encrypted_file_backend_file_permissions(self, tmp_path: Path):
        """Test that encrypted files have restrictive permissions."""
        backend = EncryptedFileBackend(tmp_path)
        backend.store_session_config("test-session", "proxy-123")

        # Check credentials file permissions (should be 600)
        cred_perms = backend._credentials_file.stat().st_mode & 0o777
        assert cred_perms == 0o600

        # Check key file permissions (should be 600)
        key_perms = backend._key_file.stat().st_mode & 0o777
        assert key_perms == 0o600

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Unix file permissions not applicable on Windows",
    )
    def test_encrypted_file_backend_directory_permissions(self, tmp_path: Path):
        """Test that storage directory has restrictive permissions."""
        backend = EncryptedFileBackend(tmp_path)
        backend._get_or_create_key()

        # Check directory permissions (should be 700)
        dir_perms = backend._storage_dir.stat().st_mode & 0o777
        assert dir_perms == 0o700

    def test_proxy_id_not_in_plaintext(self, tmp_path: Path):
        """Test that proxy_id is not stored in plaintext."""
        backend = EncryptedFileBackend(tmp_path)
        secret_proxy = "super_secret_proxy_value"

        backend.store_session_config("test-session", secret_proxy)

        # Read raw file content
        raw_content = backend._credentials_file.read_text(errors="ignore")

        # Secret should not appear in plaintext
        assert secret_proxy not in raw_content

    def test_different_encryption_keys_produce_different_ciphertext(self, tmp_path: Path):
        """Test that same plaintext with different keys produces different ciphertext."""
        backend1 = EncryptedFileBackend(tmp_path / "backend1")
        backend2 = EncryptedFileBackend(tmp_path / "backend2")

        # Store same config in both backends
        backend1.store_session_config("test-session", "proxy-123")
        backend2.store_session_config("test-session", "proxy-123")

        # Ciphertext should be different (different keys)
        content1 = backend1._credentials_file.read_bytes()
        content2 = backend2._credentials_file.read_bytes()

        assert content1 != content2


class TestErrorScenarios:
    """Tests for error handling and edge cases."""

    def test_empty_session_id(self, tmp_path: Path):
        """Test behavior with empty session ID."""
        manager = SecureCredentialManager(tmp_path)

        manager.store_session_config("", "proxy-123")
        proxy_id = manager.retrieve_session_config("")

        assert proxy_id == "proxy-123"

    def test_special_characters_in_session_id(self, tmp_path: Path):
        """Test handling of special characters in session ID."""
        manager = SecureCredentialManager(tmp_path)

        session_ids = [
            "session-with-hyphens",
            "session_with_underscores",
            "session.with.dots",
            "session@with#special$chars",
            "session with spaces",
        ]

        for session_id in session_ids:
            manager.store_session_config(session_id, "proxy-123")
            proxy_id = manager.retrieve_session_config(session_id)
            assert proxy_id == "proxy-123"

    def test_very_long_session_id(self, tmp_path: Path):
        """Test handling of very long session ID."""
        manager = SecureCredentialManager(tmp_path)
        long_session_id = "x" * 1000

        manager.store_session_config(long_session_id, "proxy-123")
        proxy_id = manager.retrieve_session_config(long_session_id)

        assert proxy_id == "proxy-123"

    def test_unicode_in_session_id(self, tmp_path: Path):
        """Test handling of unicode characters in session ID."""
        manager = SecureCredentialManager(tmp_path)

        unicode_session_id = "session-日本語-中文-العربية"
        manager.store_session_config(unicode_session_id, "proxy-123")
        proxy_id = manager.retrieve_session_config(unicode_session_id)

        assert proxy_id == "proxy-123"

    def test_very_long_proxy_id(self, tmp_path: Path):
        """Test handling of very long proxy_id value."""
        manager = SecureCredentialManager(tmp_path)
        long_proxy = "p" * 10000

        manager.store_session_config("test-session", long_proxy)
        proxy_id = manager.retrieve_session_config("test-session")

        assert proxy_id == long_proxy

    def test_none_proxy_id(self, tmp_path: Path):
        """Test handling of None proxy_id."""
        manager = SecureCredentialManager(tmp_path)

        manager.store_session_config("test-session", None)
        proxy_id = manager.retrieve_session_config("test-session")

        assert proxy_id is None

    def test_unicode_in_proxy_id(self, tmp_path: Path):
        """Test handling of unicode characters in proxy_id."""
        manager = SecureCredentialManager(tmp_path)

        unicode_proxy = "proxy-日本語"
        manager.store_session_config("test-session", unicode_proxy)
        proxy_id = manager.retrieve_session_config("test-session")

        assert proxy_id == unicode_proxy

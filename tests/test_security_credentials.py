"""Tests for secure credential storage and management."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from cryptography.fernet import Fernet

from chatfilter.security.credentials import (
    CredentialNotFoundError,
    CredentialStorageBackend,
    CredentialStorageError,
    EncryptedFileBackend,
    EnvironmentBackend,
    SecureCredentialManager,
)


class TestCredentialStorageBackend:
    """Tests for base CredentialStorageBackend class."""

    def test_base_store_credentials_not_implemented(self):
        """Test that base class store_credentials raises NotImplementedError."""
        backend = CredentialStorageBackend()

        with pytest.raises(NotImplementedError):
            backend.store_credentials("test-session", 12345, "abc123", None)

    def test_base_retrieve_credentials_not_implemented(self):
        """Test that base class retrieve_credentials raises NotImplementedError."""
        backend = CredentialStorageBackend()

        with pytest.raises(NotImplementedError):
            backend.retrieve_credentials("test-session")

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

    def test_store_credentials_success(self, tmp_path: Path):
        """Test successfully storing credentials in encrypted file."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_credentials("test-session", 12345, "abc123hash")

        assert backend._credentials_file.exists()
        # Unix file permissions not applicable on Windows
        if sys.platform != "win32":
            assert backend._credentials_file.stat().st_mode & 0o777 == 0o600

    def test_store_and_retrieve_credentials(self, tmp_path: Path):
        """Test storing and retrieving credentials."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_credentials("test-session", 12345, "abc123hash", "proxy-123")
        api_id, api_hash, proxy_id = backend.retrieve_credentials("test-session")

        assert api_id == 12345
        assert api_hash == "abc123hash"
        assert proxy_id == "proxy-123"

    def test_store_multiple_sessions(self, tmp_path: Path):
        """Test storing credentials for multiple sessions."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_credentials("session1", 11111, "hash1", "proxy1")
        backend.store_credentials("session2", 22222, "hash2", "proxy2")
        backend.store_credentials("session3", 33333, "hash3")  # No proxy_id

        api_id1, api_hash1, proxy_id1 = backend.retrieve_credentials("session1")
        api_id2, api_hash2, proxy_id2 = backend.retrieve_credentials("session2")
        api_id3, api_hash3, proxy_id3 = backend.retrieve_credentials("session3")

        assert api_id1 == 11111 and api_hash1 == "hash1" and proxy_id1 == "proxy1"
        assert api_id2 == 22222 and api_hash2 == "hash2" and proxy_id2 == "proxy2"
        assert api_id3 == 33333 and api_hash3 == "hash3" and proxy_id3 is None

    def test_store_credentials_updates_existing_session(self, tmp_path: Path):
        """Test that storing credentials updates existing session."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_credentials("test-session", 12345, "original_hash", "proxy1")
        backend.store_credentials("test-session", 99999, "new_hash", "proxy2")

        api_id, api_hash, proxy_id = backend.retrieve_credentials("test-session")

        assert api_id == 99999
        assert api_hash == "new_hash"
        assert proxy_id == "proxy2"

    def test_retrieve_credentials_not_found(self, tmp_path: Path):
        """Test retrieving non-existent credentials raises error."""
        backend = EncryptedFileBackend(tmp_path)

        with pytest.raises(CredentialNotFoundError, match="not found in encrypted file"):
            backend.retrieve_credentials("nonexistent-session")

    def test_retrieve_credentials_empty_file(self, tmp_path: Path):
        """Test retrieving from empty credentials file."""
        backend = EncryptedFileBackend(tmp_path)

        # Create empty encrypted file
        fernet = backend._get_fernet()
        encrypted_data = fernet.encrypt(b"{}")
        backend._credentials_file.write_bytes(encrypted_data)

        with pytest.raises(CredentialNotFoundError):
            backend.retrieve_credentials("test-session")

    def test_retrieve_credentials_corrupted_file(self, tmp_path: Path):
        """Test retrieving from corrupted file returns empty dict."""
        backend = EncryptedFileBackend(tmp_path)

        # Write corrupted data
        backend._credentials_file.write_text("corrupted data")

        # Should raise CredentialNotFoundError because corrupted file is treated as empty
        with pytest.raises(CredentialNotFoundError):
            backend.retrieve_credentials("test-session")

    def test_retrieve_credentials_invalid_format_missing_api_id(self, tmp_path: Path):
        """Test retrieving credentials with invalid format (missing api_id)."""
        backend = EncryptedFileBackend(tmp_path)

        # Manually create invalid credentials
        fernet = backend._get_fernet()
        invalid_data = {"test-session": {"api_hash": "hash"}}  # Missing api_id
        encrypted_data = fernet.encrypt(json.dumps(invalid_data).encode("utf-8"))
        backend._credentials_file.write_bytes(encrypted_data)

        with pytest.raises(CredentialStorageError, match="Invalid credentials format"):
            backend.retrieve_credentials("test-session")

    def test_retrieve_credentials_invalid_format_non_numeric_api_id(self, tmp_path: Path):
        """Test retrieving credentials with non-numeric api_id."""
        backend = EncryptedFileBackend(tmp_path)

        # Manually create invalid credentials
        fernet = backend._get_fernet()
        invalid_data = {"test-session": {"api_id": "not-a-number", "api_hash": "hash"}}
        encrypted_data = fernet.encrypt(json.dumps(invalid_data).encode("utf-8"))
        backend._credentials_file.write_bytes(encrypted_data)

        with pytest.raises(CredentialStorageError, match="Invalid credentials format"):
            backend.retrieve_credentials("test-session")

    def test_delete_credentials_success(self, tmp_path: Path):
        """Test successfully deleting credentials."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_credentials("test-session", 12345, "abc123hash")
        backend.delete_credentials("test-session")

        with pytest.raises(CredentialNotFoundError):
            backend.retrieve_credentials("test-session")

    def test_delete_credentials_keeps_other_sessions(self, tmp_path: Path):
        """Test that deleting one session doesn't affect others."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_credentials("session1", 11111, "hash1", "proxy1")
        backend.store_credentials("session2", 22222, "hash2", "proxy2")

        backend.delete_credentials("session1")

        # session2 should still exist
        api_id, api_hash, proxy_id = backend.retrieve_credentials("session2")
        assert api_id == 22222
        assert api_hash == "hash2"
        assert proxy_id == "proxy2"

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
                backend.store_credentials("test-session", 12345, "abc123hash")
        finally:
            # Restore permissions for cleanup
            backend._storage_dir.chmod(0o700)

    def test_credentials_file_encrypted(self, tmp_path: Path):
        """Test that credentials file is actually encrypted."""
        backend = EncryptedFileBackend(tmp_path)

        backend.store_credentials("test-session", 12345, "secret_hash")

        # Read raw file content
        raw_content = backend._credentials_file.read_bytes()

        # Should not contain plaintext credentials
        assert b"12345" not in raw_content
        assert b"secret_hash" not in raw_content

    def test_encryption_key_persistence(self, tmp_path: Path):
        """Test that encryption key is persisted and reused."""
        backend1 = EncryptedFileBackend(tmp_path)
        backend1.store_credentials("test-session", 12345, "abc123hash", "proxy-123")

        # Create new backend instance
        backend2 = EncryptedFileBackend(tmp_path)
        api_id, api_hash, proxy_id = backend2.retrieve_credentials("test-session")

        assert api_id == 12345
        assert api_hash == "abc123hash"
        assert proxy_id == "proxy-123"


class TestEnvironmentBackend:
    """Tests for environment variable-based credential storage."""

    def test_is_available_always_true(self):
        """Test that environment backend is always available."""
        backend = EnvironmentBackend()
        assert backend.is_available() is True

    def test_store_credentials_raises_error(self):
        """Test that storing credentials is not supported."""
        backend = EnvironmentBackend()

        with pytest.raises(CredentialStorageError, match="read-only"):
            backend.store_credentials("test-session", 12345, "abc123hash")

    def test_delete_credentials_raises_error(self):
        """Test that deleting credentials is not supported."""
        backend = EnvironmentBackend()

        with pytest.raises(CredentialStorageError, match="read-only"):
            backend.delete_credentials("test-session")

    def test_retrieve_credentials_success(self):
        """Test successfully retrieving credentials from environment."""
        os.environ["CHATFILTER_API_ID_TEST_SESSION"] = "12345"
        os.environ["CHATFILTER_API_HASH_TEST_SESSION"] = "abc123hash"
        os.environ["CHATFILTER_PROXY_ID_TEST_SESSION"] = "proxy-123"

        try:
            backend = EnvironmentBackend()
            api_id, api_hash, proxy_id = backend.retrieve_credentials("test-session")

            assert api_id == 12345
            assert api_hash == "abc123hash"
            assert proxy_id == "proxy-123"
        finally:
            os.environ.pop("CHATFILTER_API_ID_TEST_SESSION", None)
            os.environ.pop("CHATFILTER_API_HASH_TEST_SESSION", None)
            os.environ.pop("CHATFILTER_PROXY_ID_TEST_SESSION", None)

    def test_retrieve_credentials_with_hyphens_in_session_id(self):
        """Test session ID normalization with hyphens."""
        os.environ["CHATFILTER_API_ID_MY_SESSION"] = "12345"
        os.environ["CHATFILTER_API_HASH_MY_SESSION"] = "abc123hash"

        try:
            backend = EnvironmentBackend()
            api_id, api_hash, proxy_id = backend.retrieve_credentials("my-session")

            assert api_id == 12345
            assert api_hash == "abc123hash"
            assert proxy_id is None  # No proxy_id set
        finally:
            os.environ.pop("CHATFILTER_API_ID_MY_SESSION", None)
            os.environ.pop("CHATFILTER_API_HASH_MY_SESSION", None)

    def test_retrieve_credentials_with_lowercase_session_id(self):
        """Test session ID normalization with lowercase."""
        os.environ["CHATFILTER_API_ID_MYSESSION"] = "12345"
        os.environ["CHATFILTER_API_HASH_MYSESSION"] = "abc123hash"

        try:
            backend = EnvironmentBackend()
            api_id, api_hash, proxy_id = backend.retrieve_credentials("mysession")

            assert api_id == 12345
            assert api_hash == "abc123hash"
            assert proxy_id is None  # No proxy_id set
        finally:
            os.environ.pop("CHATFILTER_API_ID_MYSESSION", None)
            os.environ.pop("CHATFILTER_API_HASH_MYSESSION", None)

    def test_retrieve_credentials_not_found_missing_api_id(self):
        """Test error when api_id environment variable is missing."""
        os.environ["CHATFILTER_API_HASH_TEST_SESSION"] = "abc123hash"

        try:
            backend = EnvironmentBackend()

            with pytest.raises(CredentialNotFoundError, match="not found in environment"):
                backend.retrieve_credentials("test-session")
        finally:
            os.environ.pop("CHATFILTER_API_HASH_TEST_SESSION", None)

    def test_retrieve_credentials_not_found_missing_api_hash(self):
        """Test error when api_hash environment variable is missing."""
        os.environ["CHATFILTER_API_ID_TEST_SESSION"] = "12345"

        try:
            backend = EnvironmentBackend()

            with pytest.raises(CredentialNotFoundError, match="not found in environment"):
                backend.retrieve_credentials("test-session")
        finally:
            os.environ.pop("CHATFILTER_API_ID_TEST_SESSION", None)

    def test_retrieve_credentials_invalid_api_id(self):
        """Test error when api_id is not numeric."""
        os.environ["CHATFILTER_API_ID_TEST_SESSION"] = "not-a-number"
        os.environ["CHATFILTER_API_HASH_TEST_SESSION"] = "abc123hash"

        try:
            backend = EnvironmentBackend()

            with pytest.raises(CredentialStorageError, match="Invalid api_id in environment"):
                backend.retrieve_credentials("test-session")
        finally:
            os.environ.pop("CHATFILTER_API_ID_TEST_SESSION", None)
            os.environ.pop("CHATFILTER_API_HASH_TEST_SESSION", None)


class TestSecureCredentialManager:
    """Tests for SecureCredentialManager."""

    def test_init_uses_file_backend(self, tmp_path: Path):
        """Test that file backend is used by default (no keychain prompts)."""
        manager = SecureCredentialManager(tmp_path)

        assert isinstance(manager._storage_backend, EncryptedFileBackend)

    def test_store_credentials_uses_storage_backend(self, tmp_path: Path):
        """Test that store_credentials delegates to storage backend."""
        manager = SecureCredentialManager(tmp_path)
        manager._storage_backend = MagicMock()

        manager.store_credentials("test-session", 12345, "abc123hash", "proxy-123")

        manager._storage_backend.store_credentials.assert_called_once_with(
            "test-session", 12345, "abc123hash", "proxy-123"
        )

    def test_retrieve_credentials_tries_environment_first(self, tmp_path: Path):
        """Test that environment backend is tried first."""
        os.environ["CHATFILTER_API_ID_TEST_SESSION"] = "12345"
        os.environ["CHATFILTER_API_HASH_TEST_SESSION"] = "abc123hash"
        os.environ["CHATFILTER_PROXY_ID_TEST_SESSION"] = "proxy-123"

        try:
            manager = SecureCredentialManager(tmp_path)
            manager._file_backend = MagicMock()

            api_id, api_hash, proxy_id = manager.retrieve_credentials("test-session")

            assert api_id == 12345
            assert api_hash == "abc123hash"
            assert proxy_id == "proxy-123"

            # File backend should not be called
            manager._file_backend.retrieve_credentials.assert_not_called()
        finally:
            os.environ.pop("CHATFILTER_API_ID_TEST_SESSION", None)
            os.environ.pop("CHATFILTER_API_HASH_TEST_SESSION", None)
            os.environ.pop("CHATFILTER_PROXY_ID_TEST_SESSION", None)

    def test_retrieve_credentials_uses_file_backend(self, tmp_path: Path):
        """Test that file backend is used when env vars not found."""
        manager = SecureCredentialManager(tmp_path)
        manager._file_backend.store_credentials("test-session", 12345, "abc123hash", "proxy-123")

        # Mock env backend to fail
        manager._env_backend = MagicMock()
        manager._env_backend.retrieve_credentials.side_effect = CredentialNotFoundError()

        api_id, api_hash, proxy_id = manager.retrieve_credentials("test-session")

        assert api_id == 12345
        assert api_hash == "abc123hash"
        assert proxy_id == "proxy-123"

    def test_retrieve_credentials_not_found_in_any_backend(self, tmp_path: Path):
        """Test error when credentials not found in any backend."""
        manager = SecureCredentialManager(tmp_path)

        with pytest.raises(CredentialNotFoundError, match="not found for session"):
            manager.retrieve_credentials("nonexistent-session")

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

    def test_has_credentials_returns_true_when_found(self, tmp_path: Path):
        """Test has_credentials returns True when credentials exist."""
        manager = SecureCredentialManager(tmp_path)
        manager._file_backend.store_credentials("test-session", 12345, "abc123hash")

        assert manager.has_credentials("test-session") is True

    def test_has_credentials_returns_false_when_not_found(self, tmp_path: Path):
        """Test has_credentials returns False when credentials don't exist."""
        manager = SecureCredentialManager(tmp_path)

        assert manager.has_credentials("nonexistent-session") is False

    def test_integration_store_and_retrieve(self, tmp_path: Path):
        """Test integration of storing and retrieving credentials."""
        manager = SecureCredentialManager(tmp_path)

        manager.store_credentials("test-session", 12345, "abc123hash", "proxy-123")
        api_id, api_hash, proxy_id = manager.retrieve_credentials("test-session")

        assert api_id == 12345
        assert api_hash == "abc123hash"
        assert proxy_id == "proxy-123"

    def test_integration_store_retrieve_delete(self, tmp_path: Path):
        """Test full lifecycle of credentials."""
        manager = SecureCredentialManager(tmp_path)

        # Store
        manager.store_credentials("test-session", 12345, "abc123hash", "proxy-123")
        assert manager.has_credentials("test-session") is True

        # Retrieve
        api_id, api_hash, proxy_id = manager.retrieve_credentials("test-session")
        assert api_id == 12345
        assert proxy_id == "proxy-123"

        # Delete
        manager.delete_credentials("test-session")
        assert manager.has_credentials("test-session") is False

    def test_integration_multiple_sessions(self, tmp_path: Path):
        """Test managing multiple sessions simultaneously."""
        manager = SecureCredentialManager(tmp_path)

        # Store multiple sessions
        manager.store_credentials("session1", 11111, "hash1")
        manager.store_credentials("session2", 22222, "hash2")
        manager.store_credentials("session3", 33333, "hash3")

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
        backend.store_credentials("test-session", 12345, "abc123hash")

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

    def test_credentials_not_in_plaintext(self, tmp_path: Path):
        """Test that credentials are not stored in plaintext."""
        backend = EncryptedFileBackend(tmp_path)
        secret_id = 99999
        secret_hash = "super_secret_hash_value"

        backend.store_credentials("test-session", secret_id, secret_hash)

        # Read raw file content
        raw_content = backend._credentials_file.read_text(errors="ignore")

        # Secrets should not appear in plaintext
        assert str(secret_id) not in raw_content
        assert secret_hash not in raw_content

    def test_different_encryption_keys_produce_different_ciphertext(self, tmp_path: Path):
        """Test that same plaintext with different keys produces different ciphertext."""
        backend1 = EncryptedFileBackend(tmp_path / "backend1")
        backend2 = EncryptedFileBackend(tmp_path / "backend2")

        # Store same credentials in both backends
        backend1.store_credentials("test-session", 12345, "abc123hash")
        backend2.store_credentials("test-session", 12345, "abc123hash")

        # Ciphertext should be different
        content1 = backend1._credentials_file.read_bytes()
        content2 = backend2._credentials_file.read_bytes()

        assert content1 != content2


class TestErrorScenarios:
    """Tests for error handling and edge cases."""

    def test_empty_session_id(self, tmp_path: Path):
        """Test behavior with empty session ID."""
        manager = SecureCredentialManager(tmp_path)

        # Should work (no validation on session_id)
        manager.store_credentials("", 12345, "abc123hash", "proxy-123")
        api_id, api_hash, proxy_id = manager.retrieve_credentials("")

        assert api_id == 12345
        assert api_hash == "abc123hash"
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
            manager.store_credentials(session_id, 12345, "abc123hash", "proxy-123")
            api_id, api_hash, proxy_id = manager.retrieve_credentials(session_id)
            assert api_id == 12345
            assert api_hash == "abc123hash"
            assert proxy_id == "proxy-123"

    def test_very_long_session_id(self, tmp_path: Path):
        """Test handling of very long session ID."""
        manager = SecureCredentialManager(tmp_path)
        long_session_id = "x" * 1000

        manager.store_credentials(long_session_id, 12345, "abc123hash", "proxy-123")
        api_id, api_hash, proxy_id = manager.retrieve_credentials(long_session_id)

        assert api_id == 12345
        assert api_hash == "abc123hash"
        assert proxy_id == "proxy-123"

    def test_unicode_in_session_id(self, tmp_path: Path):
        """Test handling of unicode characters in session ID."""
        manager = SecureCredentialManager(tmp_path)

        unicode_session_id = "session-日本語-中文-العربية"
        manager.store_credentials(unicode_session_id, 12345, "abc123hash", "proxy-123")
        api_id, api_hash, proxy_id = manager.retrieve_credentials(unicode_session_id)

        assert api_id == 12345
        assert api_hash == "abc123hash"
        assert proxy_id == "proxy-123"

    def test_very_long_api_hash(self, tmp_path: Path):
        """Test handling of very long api_hash value."""
        manager = SecureCredentialManager(tmp_path)
        long_hash = "a" * 10000

        manager.store_credentials("test-session", 12345, long_hash, "proxy-123")
        api_id, api_hash, proxy_id = manager.retrieve_credentials("test-session")

        assert api_id == 12345
        assert api_hash == long_hash
        assert proxy_id == "proxy-123"

    def test_zero_api_id(self, tmp_path: Path):
        """Test handling of zero as api_id."""
        manager = SecureCredentialManager(tmp_path)

        manager.store_credentials("test-session", 0, "abc123hash")
        api_id, api_hash, proxy_id = manager.retrieve_credentials("test-session")

        assert api_id == 0
        assert api_hash == "abc123hash"
        assert proxy_id is None

    def test_negative_api_id(self, tmp_path: Path):
        """Test handling of negative api_id."""
        manager = SecureCredentialManager(tmp_path)

        manager.store_credentials("test-session", -12345, "abc123hash")
        api_id, api_hash, proxy_id = manager.retrieve_credentials("test-session")

        assert api_id == -12345
        assert api_hash == "abc123hash"
        assert proxy_id is None

    def test_very_large_api_id(self, tmp_path: Path):
        """Test handling of very large api_id."""
        manager = SecureCredentialManager(tmp_path)
        large_id = 999999999999999999

        manager.store_credentials("test-session", large_id, "abc123hash")
        api_id, api_hash, proxy_id = manager.retrieve_credentials("test-session")

        assert api_id == large_id
        assert api_hash == "abc123hash"
        assert proxy_id is None

    def test_empty_api_hash(self, tmp_path: Path):
        """Test handling of empty api_hash."""
        manager = SecureCredentialManager(tmp_path)

        manager.store_credentials("test-session", 12345, "")
        api_id, api_hash, proxy_id = manager.retrieve_credentials("test-session")

        assert api_id == 12345
        assert api_hash == ""
        assert proxy_id is None

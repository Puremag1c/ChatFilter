"""Tests for storage layer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cryptography.fernet import Fernet

from chatfilter.storage import (
    EncryptedStorage,
    FileStorage,
    StorageCorruptedError,
    StorageDecryptionError,
    StorageError,
    StorageNotFoundError,
    StoragePermissionError,
    derive_key_from_machine_id,
    load_json,
    save_json,
)


class TestFileStorage:
    """Tests for FileStorage implementation."""

    def test_save_and_load_bytes(self, tmp_path: Path) -> None:
        """Test saving and loading binary data."""
        storage = FileStorage()
        test_file = tmp_path / "test.bin"
        content = b"test content"

        storage.save(test_file, content)
        loaded = storage.load(test_file)

        assert loaded == content
        assert test_file.exists()

    def test_save_and_load_string(self, tmp_path: Path) -> None:
        """Test saving and loading string data."""
        storage = FileStorage()
        test_file = tmp_path / "test.txt"
        content = "test content"

        storage.save(test_file, content)
        loaded = storage.load(test_file)

        assert loaded == content.encode("utf-8")

    def test_save_creates_parent_dirs(self, tmp_path: Path) -> None:
        """Test that save creates parent directories."""
        storage = FileStorage()
        test_file = tmp_path / "sub" / "dir" / "test.txt"
        content = "test"

        storage.save(test_file, content)

        assert test_file.exists()
        assert test_file.read_text() == content

    def test_atomic_write(self, tmp_path: Path) -> None:
        """Test that writes are atomic (no partial files on error)."""
        storage = FileStorage()
        test_file = tmp_path / "test.txt"

        # Initial write
        storage.save(test_file, "original")
        assert test_file.read_text() == "original"

        # Second write (should replace atomically)
        storage.save(test_file, "updated")
        assert test_file.read_text() == "updated"

    def test_load_nonexistent_file(self, tmp_path: Path) -> None:
        """Test loading non-existent file raises StorageNotFoundError."""
        storage = FileStorage()
        test_file = tmp_path / "nonexistent.txt"

        with pytest.raises(StorageNotFoundError, match="File not found"):
            storage.load(test_file)

    def test_delete_file(self, tmp_path: Path) -> None:
        """Test deleting a file."""
        storage = FileStorage()
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        storage.delete(test_file)

        assert not test_file.exists()

    def test_delete_directory(self, tmp_path: Path) -> None:
        """Test deleting a directory recursively."""
        storage = FileStorage()
        test_dir = tmp_path / "testdir"
        test_dir.mkdir()
        (test_dir / "file1.txt").write_text("content1")
        (test_dir / "file2.txt").write_text("content2")

        storage.delete(test_dir)

        assert not test_dir.exists()

    def test_delete_nonexistent_path(self, tmp_path: Path) -> None:
        """Test deleting non-existent path raises StorageNotFoundError."""
        storage = FileStorage()
        test_path = tmp_path / "nonexistent"

        with pytest.raises(StorageNotFoundError):
            storage.delete(test_path)

    def test_exists(self, tmp_path: Path) -> None:
        """Test exists check."""
        storage = FileStorage()
        test_file = tmp_path / "test.txt"

        assert not storage.exists(test_file)

        test_file.write_text("content")
        assert storage.exists(test_file)

    def test_list_files(self, tmp_path: Path) -> None:
        """Test listing files with glob pattern."""
        storage = FileStorage()
        test_dir = tmp_path / "testdir"
        test_dir.mkdir()
        (test_dir / "file1.txt").write_text("content1")
        (test_dir / "file2.txt").write_text("content2")
        (test_dir / "file3.json").write_text("{}")

        # List all files
        all_files = storage.list_files(test_dir)
        assert len(all_files) == 3

        # List with pattern
        txt_files = storage.list_files(test_dir, "*.txt")
        assert len(txt_files) == 2
        assert all(f.suffix == ".txt" for f in txt_files)

    def test_list_files_nonexistent_dir(self, tmp_path: Path) -> None:
        """Test listing non-existent directory raises StorageNotFoundError."""
        storage = FileStorage()
        test_dir = tmp_path / "nonexistent"

        with pytest.raises(StorageNotFoundError):
            storage.list_files(test_dir)

    def test_ensure_dir(self, tmp_path: Path) -> None:
        """Test ensuring directory exists."""
        storage = FileStorage()
        test_dir = tmp_path / "sub" / "dir"

        storage.ensure_dir(test_dir)

        assert test_dir.exists()
        assert test_dir.is_dir()

    def test_ensure_dir_idempotent(self, tmp_path: Path) -> None:
        """Test ensuring existing directory is idempotent."""
        storage = FileStorage()
        test_dir = tmp_path / "testdir"
        test_dir.mkdir()

        # Should not raise
        storage.ensure_dir(test_dir)

        assert test_dir.exists()


class TestJSONHelpers:
    """Tests for JSON helper functions."""

    def test_save_and_load_json(self, tmp_path: Path) -> None:
        """Test saving and loading JSON data."""
        test_file = tmp_path / "test.json"
        data = {"key": "value", "number": 42, "list": [1, 2, 3]}

        save_json(test_file, data)
        loaded = load_json(test_file)

        assert loaded == data

    def test_save_json_with_unicode(self, tmp_path: Path) -> None:
        """Test saving JSON with unicode characters."""
        test_file = tmp_path / "test.json"
        data = {"message": "Привет мир", "emoji": "🎉"}

        save_json(test_file, data)
        loaded = load_json(test_file)

        assert loaded == data

    def test_save_json_creates_dirs(self, tmp_path: Path) -> None:
        """Test that save_json creates parent directories."""
        test_file = tmp_path / "sub" / "dir" / "test.json"
        data = {"key": "value"}

        save_json(test_file, data)

        assert test_file.exists()
        assert load_json(test_file) == data

    def test_load_json_invalid_file(self, tmp_path: Path) -> None:
        """Test loading invalid JSON raises StorageCorruptedError."""
        from chatfilter.storage import StorageCorruptedError

        test_file = tmp_path / "invalid.json"
        test_file.write_text("not valid json{")

        with pytest.raises(StorageCorruptedError, match="Invalid JSON"):
            load_json(test_file)

    def test_load_json_nonexistent_file(self, tmp_path: Path) -> None:
        """Test loading non-existent JSON file raises StorageNotFoundError."""
        test_file = tmp_path / "nonexistent.json"

        with pytest.raises(StorageNotFoundError):
            load_json(test_file)


class TestEncryptedStorage:
    """Tests for EncryptedStorage decorator."""

    def test_save_and_load_encrypted(self, tmp_path: Path) -> None:
        """Test saving and loading encrypted data."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "encrypted.bin"
        content = b"secret data"

        # Save encrypted
        storage.save(test_file, content)

        # Load decrypted
        loaded = storage.load(test_file)
        assert loaded == content

    def test_save_string_content(self, tmp_path: Path) -> None:
        """Test saving string content (should be converted to bytes)."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "encrypted.txt"
        content = "secret message"

        storage.save(test_file, content)
        loaded = storage.load(test_file)

        assert loaded == content.encode("utf-8")

    def test_encrypted_file_is_not_plaintext(self, tmp_path: Path) -> None:
        """Test that saved file is actually encrypted (not plaintext)."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "encrypted.bin"
        content = b"secret data that should not be readable"

        storage.save(test_file, content)

        # Read raw file content (bypassing encryption)
        raw_content = test_file.read_bytes()

        # Verify plaintext is not in the file
        assert content not in raw_content

    def test_machine_derived_key(self, tmp_path: Path) -> None:
        """Test using machine-derived encryption key."""
        base_storage = FileStorage()
        storage = EncryptedStorage(base_storage)  # No key = use machine ID

        test_file = tmp_path / "encrypted.bin"
        content = b"secret data"

        storage.save(test_file, content)
        loaded = storage.load(test_file)

        assert loaded == content

    def test_wrong_key_fails_decryption(self, tmp_path: Path) -> None:
        """Test that decryption fails with wrong key."""
        base_storage = FileStorage()
        key1 = Fernet.generate_key()
        key2 = Fernet.generate_key()

        # Save with key1
        storage1 = EncryptedStorage(base_storage, encryption_key=key1, key_id=1)
        test_file = tmp_path / "encrypted.bin"
        content = b"secret data"
        storage1.save(test_file, content)

        # Register wrong key for key_id 1
        EncryptedStorage.register_key(1, key2)

        # Try to load with key2 registered for key_id 1 (should fail)
        storage2 = EncryptedStorage(base_storage, encryption_key=key2, key_id=2)
        with pytest.raises(StorageDecryptionError, match="Decryption failed"):
            storage2.load(test_file)

        # Clean up registry (restore correct key)
        EncryptedStorage.register_key(1, key1)

    def test_key_rotation_support(self, tmp_path: Path) -> None:
        """Test key rotation: old files can still be decrypted with old key."""
        base_storage = FileStorage()
        old_key = Fernet.generate_key()
        new_key = Fernet.generate_key()

        # Save file with old key
        old_storage = EncryptedStorage(base_storage, encryption_key=old_key, key_id=1)
        test_file = tmp_path / "encrypted.bin"
        content = b"secret data"
        old_storage.save(test_file, content)

        # Register old key in new storage instance
        EncryptedStorage.register_key(1, old_key)
        new_storage = EncryptedStorage(base_storage, encryption_key=new_key, key_id=2)

        # Should be able to decrypt with registered old key
        loaded = new_storage.load(test_file)
        assert loaded == content

    def test_corrupted_file_raises_error(self, tmp_path: Path) -> None:
        """Test that corrupted encrypted file raises StorageCorruptedError."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "corrupted.bin"

        # Write corrupted data (too small, less than header size)
        test_file.write_bytes(b"short")

        with pytest.raises(StorageCorruptedError, match="File too small"):
            storage.load(test_file)

    def test_invalid_magic_raises_error(self, tmp_path: Path) -> None:
        """Test that file with invalid magic raises StorageCorruptedError."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "invalid.bin"

        # Write data with invalid magic but correct size
        test_file.write_bytes(b"BADM\x00\x01\x00\x00" + b"x" * 100)

        with pytest.raises(StorageCorruptedError, match="Invalid file format"):
            storage.load(test_file)

    def test_unsupported_version_raises_error(self, tmp_path: Path) -> None:
        """Test that unsupported format version raises StorageCorruptedError."""
        import struct

        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "future_version.bin"

        # Write data with future version
        header = struct.pack("!4sHH", b"CFES", 999, 0)  # version 999
        test_file.write_bytes(header + b"x" * 100)

        with pytest.raises(StorageCorruptedError, match="Unsupported format version"):
            storage.load(test_file)

    def test_decorator_delegates_other_methods(self, tmp_path: Path) -> None:
        """Test that EncryptedStorage delegates exists/delete/etc to wrapped storage."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "encrypted.bin"
        content = b"test"

        # Test exists (before save)
        assert not storage.exists(test_file)

        # Save
        storage.save(test_file, content)

        # Test exists (after save)
        assert storage.exists(test_file)

        # Test delete
        storage.delete(test_file)
        assert not storage.exists(test_file)

    def test_list_files_with_encrypted_storage(self, tmp_path: Path) -> None:
        """Test that list_files works with encrypted storage."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_dir = tmp_path / "testdir"
        test_dir.mkdir()

        # Save some encrypted files
        storage.save(test_dir / "file1.bin", b"content1")
        storage.save(test_dir / "file2.bin", b"content2")

        # List files
        files = storage.list_files(test_dir, "*.bin")
        assert len(files) == 2

    def test_ensure_dir_with_encrypted_storage(self, tmp_path: Path) -> None:
        """Test that ensure_dir works with encrypted storage."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_dir = tmp_path / "sub" / "dir"
        storage.ensure_dir(test_dir)

        assert test_dir.exists()
        assert test_dir.is_dir()

    def test_derive_key_from_machine_id_is_deterministic(self) -> None:
        """Test that deriving key from machine ID produces same key."""
        key1 = derive_key_from_machine_id()
        key2 = derive_key_from_machine_id()

        assert key1 == key2

    def test_derive_key_from_machine_id_is_valid_fernet_key(self) -> None:
        """Test that derived key is valid Fernet key."""
        key = derive_key_from_machine_id()

        # Should not raise
        fernet = Fernet(key)

        # Test encryption/decryption works
        plaintext = b"test"
        encrypted = fernet.encrypt(plaintext)
        decrypted = fernet.decrypt(encrypted)

        assert decrypted == plaintext

    def test_encryption_with_unicode_content(self, tmp_path: Path) -> None:
        """Test encrypting unicode content."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "unicode.bin"
        content = "Привет мир! 🎉"

        storage.save(test_file, content)
        loaded = storage.load(test_file)

        assert loaded == content.encode("utf-8")

    def test_large_file_encryption(self, tmp_path: Path) -> None:
        """Test encrypting large files."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "large.bin"
        # 1MB of data
        content = b"x" * (1024 * 1024)

        storage.save(test_file, content)
        loaded = storage.load(test_file)

        assert loaded == content

    def test_tampered_encrypted_data_fails_decryption(self, tmp_path: Path) -> None:
        """Test that tampering with encrypted data causes decryption to fail."""
        base_storage = FileStorage()
        encryption_key = Fernet.generate_key()
        storage = EncryptedStorage(base_storage, encryption_key=encryption_key)

        test_file = tmp_path / "encrypted.bin"
        content = b"secret data"

        storage.save(test_file, content)

        # Tamper with the file (modify some bytes after header)
        raw_data = test_file.read_bytes()
        tampered_data = raw_data[:20] + b"X" + raw_data[21:]
        test_file.write_bytes(tampered_data)

        # Should fail to decrypt
        with pytest.raises(StorageDecryptionError, match="Decryption failed"):
            storage.load(test_file)

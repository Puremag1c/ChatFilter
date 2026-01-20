"""Tests for storage layer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chatfilter.storage import (
    FileStorage,
    StorageError,
    StorageNotFoundError,
    StoragePermissionError,
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

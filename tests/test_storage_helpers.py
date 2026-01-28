"""Tests for storage helper functions.

Tests cover:
- atomic_write: atomic file writing
- save_json: JSON serialization and writing
- load_json: JSON loading and deserialization
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chatfilter.storage.errors import StorageCorruptedError, StorageValidationError
from chatfilter.storage.helpers import atomic_write, load_json, save_json


class TestAtomicWrite:
    """Tests for atomic_write function."""

    def test_writes_string_content(self, tmp_path: Path) -> None:
        """Should write string content."""
        test_file = tmp_path / "test.txt"

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            atomic_write(test_file, "test content")

            mock_storage.save.assert_called_once_with(test_file, "test content")

    def test_writes_bytes_content(self, tmp_path: Path) -> None:
        """Should write bytes content."""
        test_file = tmp_path / "test.bin"

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            atomic_write(test_file, b"binary content")

            mock_storage.save.assert_called_once_with(test_file, b"binary content")

    def test_uses_custom_storage(self, tmp_path: Path) -> None:
        """Should use custom storage if provided."""
        test_file = tmp_path / "test.txt"
        custom_storage = MagicMock()

        atomic_write(test_file, "content", storage=custom_storage)

        custom_storage.save.assert_called_once_with(test_file, "content")


class TestSaveJson:
    """Tests for save_json function."""

    def test_saves_dict(self, tmp_path: Path) -> None:
        """Should save dictionary as JSON."""
        test_file = tmp_path / "test.json"
        data = {"key": "value", "number": 42}

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            save_json(test_file, data)

            call_args = mock_storage.save.call_args[0]
            assert call_args[0] == test_file
            # Verify JSON content
            saved_content = call_args[1]
            assert json.loads(saved_content) == data

    def test_saves_list(self, tmp_path: Path) -> None:
        """Should save list as JSON."""
        test_file = tmp_path / "test.json"
        data = [1, 2, 3, "four"]

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            save_json(test_file, data)

            call_args = mock_storage.save.call_args[0]
            saved_content = call_args[1]
            assert json.loads(saved_content) == data

    def test_custom_indent(self, tmp_path: Path) -> None:
        """Should use custom indentation."""
        test_file = tmp_path / "test.json"
        data = {"key": "value"}

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            save_json(test_file, data, indent=4)

            call_args = mock_storage.save.call_args[0]
            saved_content = call_args[1]
            # 4-space indent should have more characters
            assert "    " in saved_content

    def test_raises_on_unserializable(self, tmp_path: Path) -> None:
        """Should raise StorageValidationError for unserializable data."""
        test_file = tmp_path / "test.json"
        data = {"function": lambda x: x}  # Functions can't be serialized

        with pytest.raises(StorageValidationError):
            save_json(test_file, data)

    def test_unicode_content(self, tmp_path: Path) -> None:
        """Should handle Unicode content."""
        test_file = tmp_path / "test.json"
        data = {"message": "Привет мир 你好"}

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            save_json(test_file, data)

            call_args = mock_storage.save.call_args[0]
            saved_content = call_args[1]
            # ensure_ascii=False should preserve Unicode
            assert "Привет" in saved_content


class TestLoadJson:
    """Tests for load_json function."""

    def test_loads_valid_json(self, tmp_path: Path) -> None:
        """Should load valid JSON data."""
        test_file = tmp_path / "test.json"
        expected = {"key": "value"}

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            mock_storage.load.return_value = b'{"key": "value"}'

            result = load_json(test_file)

            assert result == expected

    def test_loads_array(self, tmp_path: Path) -> None:
        """Should load JSON array."""
        test_file = tmp_path / "test.json"

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            mock_storage.load.return_value = b"[1, 2, 3]"

            result = load_json(test_file)

            assert result == [1, 2, 3]

    def test_raises_on_invalid_json(self, tmp_path: Path) -> None:
        """Should raise StorageCorruptedError for invalid JSON."""
        test_file = tmp_path / "test.json"

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            mock_storage.load.return_value = b"not valid json {"

            with pytest.raises(StorageCorruptedError):
                load_json(test_file)

    def test_raises_on_invalid_encoding(self, tmp_path: Path) -> None:
        """Should raise StorageCorruptedError for invalid UTF-8."""
        test_file = tmp_path / "test.json"

        with patch("chatfilter.storage.helpers._default_storage") as mock_storage:
            # Invalid UTF-8 sequence
            mock_storage.load.return_value = b"\xff\xfe"

            with pytest.raises(StorageCorruptedError):
                load_json(test_file)

    def test_uses_custom_storage(self, tmp_path: Path) -> None:
        """Should use custom storage if provided."""
        test_file = tmp_path / "test.json"
        custom_storage = MagicMock()
        custom_storage.load.return_value = b'{"data": true}'

        result = load_json(test_file, storage=custom_storage)

        assert result == {"data": True}
        custom_storage.load.assert_called_once_with(test_file)

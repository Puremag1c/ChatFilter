"""Tests for TelegramClientLoader and related functionality."""

import json
import sqlite3
from pathlib import Path

import pytest

from chatfilter.telegram.client import (
    SessionFileError,
    TelegramClientLoader,
    TelegramConfig,
    TelegramConfigError,
    validate_session_file,
)


class TestTelegramConfig:
    """Tests for TelegramConfig class."""

    def test_from_json_file_valid(self, tmp_path: Path) -> None:
        """Test loading valid config file."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        config = TelegramConfig.from_json_file(config_path)

        assert config.api_id == 12345
        assert config.api_hash == "abcdef123456"

    def test_from_json_file_api_id_as_string(self, tmp_path: Path) -> None:
        """Test loading config with api_id as string (should convert)."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": "12345", "api_hash": "abcdef123456"}))

        config = TelegramConfig.from_json_file(config_path)

        assert config.api_id == 12345

    def test_from_json_file_not_found(self, tmp_path: Path) -> None:
        """Test error when config file doesn't exist."""
        config_path = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError, match="Config file not found"):
            TelegramConfig.from_json_file(config_path)

    def test_from_json_file_invalid_json(self, tmp_path: Path) -> None:
        """Test error when config file is not valid JSON."""
        config_path = tmp_path / "config.json"
        config_path.write_text("not valid json {")

        with pytest.raises(TelegramConfigError, match="Invalid JSON"):
            TelegramConfig.from_json_file(config_path)

    def test_from_json_file_missing_api_id(self, tmp_path: Path) -> None:
        """Test error when api_id is missing."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_hash": "abcdef123456"}))

        with pytest.raises(TelegramConfigError, match="Missing required fields.*api_id"):
            TelegramConfig.from_json_file(config_path)

    def test_from_json_file_missing_api_hash(self, tmp_path: Path) -> None:
        """Test error when api_hash is missing."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345}))

        with pytest.raises(TelegramConfigError, match="Missing required fields.*api_hash"):
            TelegramConfig.from_json_file(config_path)

    def test_from_json_file_invalid_api_id_type(self, tmp_path: Path) -> None:
        """Test error when api_id cannot be converted to int."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": "not_a_number", "api_hash": "abcdef"}))

        with pytest.raises(TelegramConfigError, match="api_id must be an integer"):
            TelegramConfig.from_json_file(config_path)

    def test_from_json_file_invalid_api_hash_type(self, tmp_path: Path) -> None:
        """Test error when api_hash is not a string."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": 123}))

        with pytest.raises(TelegramConfigError, match="api_hash must be a string"):
            TelegramConfig.from_json_file(config_path)

    def test_from_json_file_empty_api_hash(self, tmp_path: Path) -> None:
        """Test error when api_hash is empty."""
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": ""}))

        with pytest.raises(TelegramConfigError, match="api_hash cannot be empty"):
            TelegramConfig.from_json_file(config_path)


def create_valid_session(path: Path) -> None:
    """Create a valid Telethon 1.x session file for testing."""
    conn = sqlite3.connect(path)
    cursor = conn.cursor()

    # Telethon 1.x schema
    cursor.execute("""
        CREATE TABLE sessions (
            dc_id INTEGER PRIMARY KEY,
            server_address TEXT,
            port INTEGER,
            auth_key BLOB
        )
    """)
    cursor.execute("""
        CREATE TABLE entities (
            id INTEGER PRIMARY KEY,
            hash INTEGER NOT NULL,
            username TEXT,
            phone INTEGER,
            name TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE sent_files (
            md5_digest BLOB,
            file_size INTEGER,
            type INTEGER,
            id INTEGER,
            hash INTEGER,
            PRIMARY KEY (md5_digest, file_size, type)
        )
    """)
    # Insert dummy session data
    cursor.execute(
        "INSERT INTO sessions (dc_id, server_address, port, auth_key) VALUES (?, ?, ?, ?)",
        (2, "149.154.167.40", 443, b"fake_auth_key_for_testing"),
    )
    conn.commit()
    conn.close()


class TestValidateSessionFile:
    """Tests for validate_session_file function."""

    def test_valid_session(self, tmp_path: Path) -> None:
        """Test validation of valid session file."""
        session_path = tmp_path / "test.session"
        create_valid_session(session_path)

        # Should not raise
        validate_session_file(session_path)

    def test_session_not_found(self, tmp_path: Path) -> None:
        """Test error when session file doesn't exist."""
        session_path = tmp_path / "nonexistent.session"

        with pytest.raises(FileNotFoundError, match="Session file not found"):
            validate_session_file(session_path)

    def test_invalid_file_not_sqlite(self, tmp_path: Path) -> None:
        """Test error when file is not a SQLite database."""
        session_path = tmp_path / "test.session"
        session_path.write_text("not a database")

        with pytest.raises(SessionFileError, match="not a valid database"):
            validate_session_file(session_path)

    def test_empty_session_no_data(self, tmp_path: Path) -> None:
        """Test error when session file has no session data."""
        session_path = tmp_path / "test.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE sessions (
                dc_id INTEGER PRIMARY KEY,
                server_address TEXT,
                port INTEGER,
                auth_key BLOB
            )
        """)
        cursor.execute("""
            CREATE TABLE entities (
                id INTEGER PRIMARY KEY,
                hash INTEGER NOT NULL
            )
        """)
        conn.commit()
        conn.close()

        with pytest.raises(SessionFileError, match="Session file is empty"):
            validate_session_file(session_path)

    def test_missing_required_tables(self, tmp_path: Path) -> None:
        """Test error when session file is missing required tables."""
        session_path = tmp_path / "test.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE other_table (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()

        with pytest.raises(SessionFileError, match="Invalid session file format"):
            validate_session_file(session_path)


class TestTelegramClientLoader:
    """Tests for TelegramClientLoader class."""

    def test_validate_success(self, tmp_path: Path) -> None:
        """Test successful validation of both files."""
        session_path = tmp_path / "test.session"
        config_path = tmp_path / "config.json"

        create_valid_session(session_path)
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        loader = TelegramClientLoader(session_path, config_path)
        loader.validate()  # Should not raise

    def test_validate_invalid_config(self, tmp_path: Path) -> None:
        """Test validation fails on invalid config."""
        session_path = tmp_path / "test.session"
        config_path = tmp_path / "config.json"

        create_valid_session(session_path)
        config_path.write_text(json.dumps({"api_id": 12345}))  # Missing api_hash

        loader = TelegramClientLoader(session_path, config_path)
        with pytest.raises(TelegramConfigError):
            loader.validate()

    def test_validate_invalid_session(self, tmp_path: Path) -> None:
        """Test validation fails on invalid session."""
        session_path = tmp_path / "test.session"
        config_path = tmp_path / "config.json"

        session_path.write_text("not a database")
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        loader = TelegramClientLoader(session_path, config_path)
        with pytest.raises(SessionFileError):
            loader.validate()

    def test_create_client(self, tmp_path: Path) -> None:
        """Test creating a Telethon client instance.

        Note: We use a fresh session path because Telethon's TelegramClient
        modifies the session file on creation. Using a path without .session
        extension lets Telethon create its own fresh session.
        """
        session_path = tmp_path / "new_session"  # No .session extension
        config_path = tmp_path / "config.json"

        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        # Create a valid session for validation, but use a new path for client
        validation_session = tmp_path / "valid.session"
        create_valid_session(validation_session)

        # Test with the valid session for validation
        loader = TelegramClientLoader(validation_session, config_path)
        loader.validate()  # Should pass

        # For actual client creation, use a fresh session path
        # (Telethon will create its own session file)
        loader_for_client = TelegramClientLoader(session_path, config_path)
        loader_for_client._config = TelegramConfig(api_id=12345, api_hash="abcdef123456")

        client = loader_for_client.create_client()

        # Check that we got a TelegramClient instance
        from telethon import TelegramClient

        assert isinstance(client, TelegramClient)

    def test_properties(self, tmp_path: Path) -> None:
        """Test session_path and config_path properties."""
        session_path = tmp_path / "test.session"
        config_path = tmp_path / "config.json"

        loader = TelegramClientLoader(session_path, config_path)

        assert loader.session_path == session_path
        assert loader.config_path == config_path

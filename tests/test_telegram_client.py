"""Tests for TelegramClientLoader and related functionality."""

import json
import sqlite3
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from chatfilter.config import ProxyConfig, ProxyType
from chatfilter.models.chat import Chat, ChatType
from chatfilter.telegram.client import (
    ChatAccessDeniedError,
    JoinChatError,
    LeaveChatError,
    MessageFetchError,
    SessionFileError,
    TelegramClientLoader,
    TelegramConfig,
    TelegramConfigError,
    _dialog_to_chat,
    _migrate_plaintext_to_secure,
    _parse_chat_reference,
    _secure_delete_file,
    _telethon_message_to_model,
    get_account_info,
    get_chat_slowmode,
    get_dialogs,
    get_messages,
    get_messages_since,
    get_messages_streaming,
    join_chat,
    join_chat_with_rotation,
    leave_chat,
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

    def test_repr_redacts_api_hash(self) -> None:
        """Test that repr redacts api_hash for security."""
        config = TelegramConfig(api_id=12345, api_hash="secret_hash")

        repr_str = repr(config)

        assert "12345" in repr_str
        assert "secret_hash" not in repr_str
        assert "REDACTED" in repr_str

    def test_str_redacts_api_hash(self) -> None:
        """Test that str redacts api_hash for security."""
        config = TelegramConfig(api_id=12345, api_hash="secret_hash")

        str_repr = str(config)

        assert "12345" in str_repr
        assert "secret_hash" not in str_repr

    def test_from_secure_storage_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test loading config from secure storage."""

        # Mock the SecureCredentialManager
        class MockManager:
            def __init__(self, storage_dir: Path) -> None:
                pass

            def retrieve_credentials(self, session_id: str) -> tuple[int, str, str | None]:
                return (99999, "secure_hash_from_keyring", "proxy-123")

        monkeypatch.setattr(
            "chatfilter.security.SecureCredentialManager",
            MockManager,
        )

        config = TelegramConfig.from_secure_storage("test_session", tmp_path)

        assert config.api_id == 99999
        assert config.api_hash == "secure_hash_from_keyring"

    def test_from_secure_storage_credential_not_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test error when credentials not found in secure storage."""
        from chatfilter.security import CredentialNotFoundError

        class MockManager:
            def __init__(self, storage_dir: Path) -> None:
                pass

            def retrieve_credentials(self, session_id: str) -> tuple[int, str]:
                raise CredentialNotFoundError("Credentials not found")

        monkeypatch.setattr(
            "chatfilter.security.SecureCredentialManager",
            MockManager,
        )

        with pytest.raises(TelegramConfigError, match="Credentials not found in secure storage"):
            TelegramConfig.from_secure_storage("test_session", tmp_path)

    def test_from_secure_storage_general_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test error handling for general errors in secure storage."""

        class MockManager:
            def __init__(self, storage_dir: Path) -> None:
                pass

            def retrieve_credentials(self, session_id: str) -> tuple[int, str]:
                raise RuntimeError("Keyring error")

        monkeypatch.setattr(
            "chatfilter.security.SecureCredentialManager",
            MockManager,
        )

        with pytest.raises(TelegramConfigError, match="Failed to load credentials"):
            TelegramConfig.from_secure_storage("test_session", tmp_path)

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

    def test_locked_session_file(self, tmp_path: Path) -> None:
        """Test error when session file is locked by another process."""
        session_path = tmp_path / "test.session"
        create_valid_session(session_path)

        # Lock the session file by opening it with exclusive lock
        conn = sqlite3.connect(session_path)
        conn.execute("BEGIN EXCLUSIVE")  # Acquire exclusive lock

        try:
            # Validation should detect the lock and raise SessionFileError
            with pytest.raises(SessionFileError, match="locked by another process"):
                validate_session_file(session_path)
        finally:
            # Release the lock
            conn.rollback()
            conn.close()

    def test_telethon_2x_session_detected(self, tmp_path: Path) -> None:
        """Test that Telethon 2.x session format is detected and rejected."""
        session_path = tmp_path / "test.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()

        # Create a Telethon 2.x-like schema with "version" table
        cursor.execute("CREATE TABLE version (version INTEGER PRIMARY KEY)")
        cursor.execute("INSERT INTO version (version) VALUES (2)")
        cursor.execute("CREATE TABLE some_other_table (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()

        with pytest.raises(
            SessionFileError,
            match="Telethon 2.x.*incompatible.*Telethon 1.x.*different session formats",
        ):
            validate_session_file(session_path)


class TestTelegramClientLoader:
    """Tests for TelegramClientLoader class."""

    def test_validate_success(self, tmp_path: Path) -> None:
        """Test successful validation of both files."""
        session_path = tmp_path / "test.session"
        config_path = tmp_path / "config.json"

        create_valid_session(session_path)
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)
        loader.validate()  # Should not raise

    def test_validate_invalid_config(self, tmp_path: Path) -> None:
        """Test validation fails on invalid config."""
        session_path = tmp_path / "test.session"
        config_path = tmp_path / "config.json"

        create_valid_session(session_path)
        config_path.write_text(json.dumps({"api_id": 12345}))  # Missing api_hash

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)
        with pytest.raises(TelegramConfigError):
            loader.validate()

    def test_validate_invalid_session(self, tmp_path: Path) -> None:
        """Test validation fails on invalid session."""
        session_path = tmp_path / "test.session"
        config_path = tmp_path / "config.json"

        session_path.write_text("not a database")
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)
        with pytest.raises(SessionFileError):
            loader.validate()

    def test_create_client(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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

        # Mock settings
        class MockSettings:
            connect_timeout = 30

        monkeypatch.setattr("chatfilter.config.get_settings", lambda: MockSettings())
        monkeypatch.setattr("chatfilter.telegram.client.load_proxy_config", lambda: None)

        # Test with the valid session for validation
        loader = TelegramClientLoader(validation_session, config_path, use_secure_storage=False)
        loader.validate()  # Should pass

        # For actual client creation, use a fresh session path
        # (Telethon will create its own session file)
        loader_for_client = TelegramClientLoader(
            session_path, config_path, use_secure_storage=False
        )
        loader_for_client._config = TelegramConfig(api_id=12345, api_hash="abcdef123456")

        client = loader_for_client.create_client()

        # Check that we got a TelegramClient instance
        from telethon import TelegramClient

        assert isinstance(client, TelegramClient)

    def test_properties(self, tmp_path: Path) -> None:
        """Test session_path and config_path properties."""
        session_path = tmp_path / "test.session"
        config_path = tmp_path / "config.json"

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)

        assert loader.session_path == session_path
        assert loader.config_path == config_path

    def test_create_client_with_proxy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test creating a client with explicit proxy configuration."""
        import socks

        session_path = tmp_path / "new_session"
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        # Mock settings
        class MockSettings:
            connect_timeout = 30

        monkeypatch.setattr("chatfilter.config.get_settings", lambda: MockSettings())

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)
        loader._config = TelegramConfig(api_id=12345, api_hash="abcdef123456")

        proxy = ProxyConfig(
            enabled=True,
            proxy_type=ProxyType.SOCKS5,
            host="proxy.example.com",
            port=1080,
            username="user",
            password="pass",
        )

        client = loader.create_client(proxy=proxy)

        # Verify proxy is set
        assert client._proxy is not None
        assert client._proxy[0] == socks.SOCKS5
        assert client._proxy[1] == "proxy.example.com"
        assert client._proxy[2] == 1080
        assert client._proxy[4] == "user"
        assert client._proxy[5] == "pass"

    def test_create_client_with_http_proxy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test creating a client with HTTP proxy."""
        import socks

        session_path = tmp_path / "new_session"
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        # Mock settings
        class MockSettings:
            connect_timeout = 30

        monkeypatch.setattr("chatfilter.config.get_settings", lambda: MockSettings())

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)
        loader._config = TelegramConfig(api_id=12345, api_hash="abcdef123456")

        proxy = ProxyConfig(
            enabled=True,
            proxy_type=ProxyType.HTTP,
            host="http-proxy.example.com",
            port=8080,
        )

        client = loader.create_client(proxy=proxy)

        assert client._proxy is not None
        assert client._proxy[0] == socks.HTTP
        assert client._proxy[1] == "http-proxy.example.com"
        assert client._proxy[2] == 8080

    def test_create_client_with_disabled_proxy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that disabled proxy results in no proxy being set."""
        session_path = tmp_path / "new_session"
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        # Mock settings
        class MockSettings:
            connect_timeout = 30

        monkeypatch.setattr("chatfilter.config.get_settings", lambda: MockSettings())

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)
        loader._config = TelegramConfig(api_id=12345, api_hash="abcdef123456")

        proxy = ProxyConfig(
            enabled=False,
            host="proxy.example.com",
            port=1080,
        )

        client = loader.create_client(proxy=proxy)

        assert client._proxy is None

    def test_create_client_without_saved_proxy(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test creating client with use_saved_proxy=False."""
        session_path = tmp_path / "new_session"
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        # Mock settings
        class MockSettings:
            connect_timeout = 30

        monkeypatch.setattr("chatfilter.config.get_settings", lambda: MockSettings())

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)
        loader._config = TelegramConfig(api_id=12345, api_hash="abcdef123456")

        # Even if saved proxy exists, use_saved_proxy=False should skip it
        client = loader.create_client(use_saved_proxy=False)

        assert client._proxy is None

    def test_create_client_with_custom_timeout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test creating client with custom timeout configuration."""
        session_path = tmp_path / "new_session"
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        # Mock load_proxy_config to avoid filesystem access
        monkeypatch.setattr("chatfilter.telegram.client.load_proxy_config", lambda: None)

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)
        loader._config = TelegramConfig(api_id=12345, api_hash="abcdef123456")

        # Create client with custom timeout
        client = loader.create_client(timeout=45, connection_retries=10, retry_delay=2)

        # Verify timeout is set
        assert client._timeout == 45
        assert client._retry_delay == 2

    def test_create_client_uses_default_timeout_from_settings(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that client uses default timeout from settings when not specified."""
        session_path = tmp_path / "new_session"
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        # Mock settings to avoid validation errors
        class MockSettings:
            connect_timeout = 30

        def mock_get_settings() -> MockSettings:
            return MockSettings()

        monkeypatch.setattr("chatfilter.config.get_settings", mock_get_settings)

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=False)
        loader._config = TelegramConfig(api_id=12345, api_hash="abcdef123456")

        # Mock load_proxy_config to avoid filesystem access
        monkeypatch.setattr("chatfilter.telegram.client.load_proxy_config", lambda: None)

        # Create client without specifying timeout (should use settings default)
        client = loader.create_client()

        # Verify timeout is set to settings default (30 seconds)
        assert client._timeout == 30

    def test_validate_with_secure_storage_and_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test validation with secure storage fallback to plaintext config."""
        sessions_dir = tmp_path / "sessions"
        session_dir = sessions_dir / "test_session"
        session_dir.mkdir(parents=True)

        session_path = session_dir / "test.session"
        config_path = session_dir / "config.json"

        create_valid_session(session_path)
        config_path.write_text(json.dumps({"api_id": 12345, "api_hash": "abcdef123456"}))

        # Mock SecureCredentialManager to raise error
        from chatfilter.security import CredentialNotFoundError

        class MockManager:
            def __init__(self, storage_dir: Path) -> None:
                pass

            def retrieve_credentials(self, session_id: str) -> tuple[int, str]:
                raise CredentialNotFoundError("Not found")

        monkeypatch.setattr(
            "chatfilter.security.SecureCredentialManager",
            MockManager,
        )

        loader = TelegramClientLoader(session_path, config_path, use_secure_storage=True)

        # Should fall back to plaintext config
        loader.validate()

        assert loader._config is not None
        assert loader._config.api_id == 12345

    def test_validate_with_secure_storage_no_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test validation with secure storage and no fallback available."""
        sessions_dir = tmp_path / "sessions"
        session_dir = sessions_dir / "test_session"
        session_dir.mkdir(parents=True)

        session_path = session_dir / "test.session"
        create_valid_session(session_path)

        # Mock SecureCredentialManager to raise error
        from chatfilter.security import CredentialNotFoundError

        class MockManager:
            def __init__(self, storage_dir: Path) -> None:
                pass

            def retrieve_credentials(self, session_id: str) -> tuple[int, str]:
                raise CredentialNotFoundError("Not found")

        monkeypatch.setattr(
            "chatfilter.security.SecureCredentialManager",
            MockManager,
        )

        # No config_path provided, should raise error
        loader = TelegramClientLoader(session_path, config_path=None, use_secure_storage=True)

        with pytest.raises(TelegramConfigError, match="Credentials not found in secure storage"):
            loader.validate()

    def test_validate_no_config_path_secure_storage_disabled(self, tmp_path: Path) -> None:
        """Test error when no config_path and secure storage disabled."""
        session_path = tmp_path / "test.session"
        create_valid_session(session_path)

        loader = TelegramClientLoader(session_path, config_path=None, use_secure_storage=False)

        with pytest.raises(TelegramConfigError, match="No config_path provided"):
            loader.validate()


def create_mock_dialog(
    dialog_id: int,
    entity_type: str = "user",
    name: str = "Test",
    username: str | None = None,
    participants_count: int | None = None,
    megagroup: bool = False,
    forum: bool = False,
) -> MagicMock:
    """Create a mock Telethon Dialog object for testing."""
    dialog = MagicMock()
    dialog.id = dialog_id
    dialog.name = name
    dialog.title = name

    entity = MagicMock()
    entity.id = dialog_id
    entity.username = username
    entity.participants_count = participants_count

    if entity_type == "user":
        # Simulate isinstance(entity, User) returning True
        entity.__class__.__name__ = "User"
        entity.first_name = name
        from telethon.tl.types import User

        entity.__class__ = User
    elif entity_type == "channel":
        from telethon.tl.types import Channel

        entity.__class__ = Channel
        entity.megagroup = megagroup
        entity.forum = forum
        entity.title = name
    elif entity_type == "chat":
        from telethon.tl.types import Chat as TelegramChat

        entity.__class__ = TelegramChat
        entity.title = name

    dialog.entity = entity
    return dialog


class TestDialogToChat:
    """Tests for _dialog_to_chat helper function."""

    def test_user_dialog(self) -> None:
        """Test conversion of private chat (User) dialog."""
        dialog = create_mock_dialog(123, "user", "John Doe", username="johndoe")

        chat = _dialog_to_chat(dialog)

        assert chat is not None
        assert chat.id == 123
        assert chat.title == "John Doe"
        assert chat.chat_type == ChatType.PRIVATE
        assert chat.username == "johndoe"
        assert not chat.is_saved_messages

    def test_saved_messages_dialog(self) -> None:
        """Test conversion of Saved Messages (chat with yourself) dialog."""
        current_user_id = 999
        dialog = create_mock_dialog(current_user_id, "user", "Me Myself", username="myusername")

        chat = _dialog_to_chat(dialog, current_user_id=current_user_id)

        assert chat is not None
        assert chat.id == current_user_id
        assert chat.title == "Saved Messages"
        assert chat.chat_type == ChatType.PRIVATE
        assert chat.is_saved_messages

    def test_channel_dialog(self) -> None:
        """Test conversion of channel dialog."""
        dialog = create_mock_dialog(
            456, "channel", "News Channel", username="news", participants_count=1000
        )

        chat = _dialog_to_chat(dialog)

        assert chat is not None
        assert chat.id == 456
        assert chat.title == "News Channel"
        assert chat.chat_type == ChatType.CHANNEL
        assert chat.username == "news"
        assert chat.member_count == 1000

    def test_supergroup_dialog(self) -> None:
        """Test conversion of supergroup dialog."""
        dialog = create_mock_dialog(
            789, "channel", "Discussion Group", megagroup=True, participants_count=500
        )

        chat = _dialog_to_chat(dialog)

        assert chat is not None
        assert chat.id == 789
        assert chat.title == "Discussion Group"
        assert chat.chat_type == ChatType.SUPERGROUP
        assert chat.member_count == 500

    def test_forum_dialog(self) -> None:
        """Test conversion of forum dialog."""
        dialog = create_mock_dialog(101, "channel", "Forum Group", megagroup=True, forum=True)

        chat = _dialog_to_chat(dialog)

        assert chat is not None
        assert chat.id == 101
        assert chat.chat_type == ChatType.FORUM

    def test_basic_group_dialog(self) -> None:
        """Test conversion of basic group dialog."""
        dialog = create_mock_dialog(202, "chat", "Family Group", participants_count=10)

        chat = _dialog_to_chat(dialog)

        assert chat is not None
        assert chat.id == 202
        assert chat.title == "Family Group"
        assert chat.chat_type == ChatType.GROUP
        assert chat.username is None  # Basic groups don't have usernames

    def test_unknown_entity_type(self) -> None:
        """Test that unknown entity types return None."""
        dialog = MagicMock()
        dialog.id = 999
        dialog.entity = MagicMock()  # Unknown type
        dialog.entity.__class__ = type("UnknownEntity", (), {})

        chat = _dialog_to_chat(dialog)

        assert chat is None


class TestGetDialogs:
    """Tests for get_dialogs function."""

    @pytest.mark.asyncio
    async def test_get_all_dialogs(self) -> None:
        """Test fetching all dialogs."""
        dialogs = [
            create_mock_dialog(1, "user", "User 1"),
            create_mock_dialog(2, "channel", "Channel 1"),
            create_mock_dialog(3, "chat", "Group 1"),
        ]

        async def mock_iter_dialogs(folder: int = 0) -> AsyncIterator[MagicMock]:
            # Return dialogs only for main folder (folder=0) in this test
            if folder == 0:
                for d in dialogs:
                    yield d

        client = MagicMock()
        client.iter_dialogs = mock_iter_dialogs

        result = await get_dialogs(client)

        assert len(result) == 3
        assert result[0].id == 1
        assert result[1].id == 2
        assert result[2].id == 3
        assert all(not chat.is_archived for chat in result)

    @pytest.mark.asyncio
    async def test_filter_by_chat_type(self) -> None:
        """Test filtering dialogs by chat type."""
        dialogs = [
            create_mock_dialog(1, "user", "User 1"),
            create_mock_dialog(2, "channel", "Channel 1"),
            create_mock_dialog(3, "channel", "Group 1", megagroup=True),
            create_mock_dialog(4, "chat", "Group 2"),
        ]

        async def mock_iter_dialogs(folder: int = 0) -> AsyncIterator[MagicMock]:
            if folder == 0:
                for d in dialogs:
                    yield d

        client = MagicMock()
        client.iter_dialogs = mock_iter_dialogs

        # Filter for groups and supergroups only
        result = await get_dialogs(client, chat_types={ChatType.GROUP, ChatType.SUPERGROUP})

        assert len(result) == 2
        assert result[0].id == 3  # Supergroup
        assert result[1].id == 4  # Basic group

    @pytest.mark.asyncio
    async def test_deduplication(self) -> None:
        """Test that duplicate chat IDs are deduplicated."""
        dialogs = [
            create_mock_dialog(1, "user", "User 1"),
            create_mock_dialog(1, "user", "User 1 Duplicate"),  # Same ID
            create_mock_dialog(2, "channel", "Channel 1"),
        ]

        async def mock_iter_dialogs(folder: int = 0) -> AsyncIterator[MagicMock]:
            if folder == 0:
                for d in dialogs:
                    yield d

        client = MagicMock()
        client.iter_dialogs = mock_iter_dialogs

        result = await get_dialogs(client)

        assert len(result) == 2
        assert result[0].id == 1
        assert result[0].title == "User 1"  # First occurrence kept
        assert result[1].id == 2

    @pytest.mark.asyncio
    async def test_caching(self) -> None:
        """Test session-scoped caching."""
        call_count = 0

        async def mock_iter_dialogs(folder: int = 0) -> AsyncIterator[MagicMock]:
            nonlocal call_count
            call_count += 1
            if folder == 0:
                yield create_mock_dialog(1, "user", "User 1")

        client = MagicMock()
        client.iter_dialogs = mock_iter_dialogs

        cache: dict[int, list[Chat]] = {}

        # First call should fetch (calls for both folder 0 and 1)
        result1 = await get_dialogs(client, _cache=cache)
        assert call_count == 2  # Called twice: folder 0 and folder 1
        assert len(result1) == 1

        # Second call should use cache
        result2 = await get_dialogs(client, _cache=cache)
        assert call_count == 2  # No new fetch
        assert len(result2) == 1

    @pytest.mark.asyncio
    async def test_cache_with_filter(self) -> None:
        """Test that cache works correctly with type filtering."""
        dialogs = [
            create_mock_dialog(1, "user", "User 1"),
            create_mock_dialog(2, "channel", "Channel 1"),
        ]

        async def mock_iter_dialogs(folder: int = 0) -> AsyncIterator[MagicMock]:
            if folder == 0:
                for d in dialogs:
                    yield d

        client = MagicMock()
        client.iter_dialogs = mock_iter_dialogs

        cache: dict[int, list[Chat]] = {}

        # First call fetches all
        result1 = await get_dialogs(client, _cache=cache)
        assert len(result1) == 2

        # Second call with filter uses cache and filters
        result2 = await get_dialogs(client, chat_types={ChatType.PRIVATE}, _cache=cache)
        assert len(result2) == 1
        assert result2[0].chat_type == ChatType.PRIVATE

    @pytest.mark.asyncio
    async def test_archived_chats(self) -> None:
        """Test that archived chats are included with is_archived=True."""
        main_dialogs = [
            create_mock_dialog(1, "user", "User 1"),
            create_mock_dialog(2, "channel", "Channel 1"),
        ]
        archived_dialogs = [
            create_mock_dialog(3, "chat", "Archived Group"),
            create_mock_dialog(4, "user", "Archived User"),
        ]

        async def mock_iter_dialogs(folder: int = 0) -> AsyncIterator[MagicMock]:
            if folder == 0:
                for d in main_dialogs:
                    yield d
            elif folder == 1:
                for d in archived_dialogs:
                    yield d

        client = MagicMock()
        client.iter_dialogs = mock_iter_dialogs

        result = await get_dialogs(client)

        # Should have all 4 chats
        assert len(result) == 4

        # First 2 should be from main folder (not archived)
        assert result[0].id == 1
        assert not result[0].is_archived
        assert result[1].id == 2
        assert not result[1].is_archived

        # Last 2 should be from archived folder
        assert result[2].id == 3
        assert result[2].is_archived
        assert result[3].id == 4
        assert result[3].is_archived


def create_mock_message(
    msg_id: int,
    text: str = "Hello",
    sender_id: int | None = 123,
    date: datetime | None = None,
    has_media: bool = False,
) -> MagicMock:
    """Create a mock Telethon Message object for testing."""
    msg = MagicMock()
    msg.id = msg_id
    msg.message = text
    msg.sender_id = sender_id
    msg.from_id = None
    msg.date = date or datetime.now(UTC) - timedelta(hours=1)
    msg.media = MagicMock() if has_media else None
    return msg


class TestTelethonMessageToModel:
    """Tests for _telethon_message_to_model helper function."""

    def test_basic_message(self) -> None:
        """Test conversion of basic text message."""
        msg = create_mock_message(1, "Hello world", sender_id=456)

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is not None
        assert result.id == 1
        assert result.chat_id == 123
        assert result.author_id == 456
        assert result.text == "Hello world"

    def test_message_with_media(self) -> None:
        """Test conversion of media message with no text."""
        msg = create_mock_message(2, text="", sender_id=789, has_media=True)

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is not None
        assert result.id == 2
        assert result.text == ""

    def test_message_no_sender_uses_chat_id(self) -> None:
        """Test that messages without sender use chat_id as author."""
        msg = create_mock_message(3, "Channel post", sender_id=None)

        result = _telethon_message_to_model(msg, chat_id=456)

        assert result is not None
        assert result.author_id == 456  # Falls back to chat_id

    def test_message_with_peer_user(self) -> None:
        """Test handling of from_id as PeerUser object."""
        msg = create_mock_message(4, "Test", sender_id=None)
        peer = MagicMock()
        peer.user_id = 999
        msg.from_id = peer

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is not None
        assert result.author_id == 999

    def test_message_with_peer_channel(self) -> None:
        """Test handling of sender_id as PeerChannel object."""
        msg = create_mock_message(5, "Test", sender_id=None)
        peer = MagicMock()
        peer.channel_id = 888
        # Set has attr to return True for channel_id
        msg.sender_id = peer
        # Ensure hasattr works properly
        type(msg.sender_id).channel_id = 888

        # Mock it differently - set sender_id to an object with channel_id attribute
        class PeerChannel:
            channel_id = 888

        msg.sender_id = PeerChannel()

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is not None
        assert result.author_id == 888

    def test_message_with_negative_sender_id(self) -> None:
        """Test that negative sender IDs are converted to positive."""
        msg = create_mock_message(6, "Test", sender_id=-12345)

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is not None
        assert result.author_id == 12345  # Absolute value

    def test_message_without_timestamp_returns_none(self) -> None:
        """Test that messages without timestamp return None."""
        msg = create_mock_message(7, "Test", sender_id=456)
        msg.date = None

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is None

    def test_message_with_naive_timestamp(self) -> None:
        """Test that naive timestamps are made timezone-aware."""
        naive_datetime = datetime(2024, 1, 15, 12, 0, 0)  # No timezone
        msg = create_mock_message(8, "Test", date=naive_datetime)

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is not None
        assert result.timestamp.tzinfo is not None

    def test_message_empty_returns_none(self) -> None:
        """Test that empty/deleted messages return None."""
        msg = MagicMock()
        msg.id = 5
        msg.message = None
        msg.media = None
        msg.date = None  # MessageEmpty has no date

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is None

    def test_message_timestamp_is_utc(self) -> None:
        """Test that timestamp is timezone-aware UTC."""
        test_date = datetime(2024, 1, 15, 12, 0, 0, tzinfo=UTC)
        msg = create_mock_message(6, "Test", date=test_date)

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is not None
        assert result.timestamp.tzinfo is not None
        assert result.timestamp == test_date

    def test_service_message_returns_none(self) -> None:
        """Test that service messages (join/leave/pin) are filtered out."""
        from telethon.tl.types import MessageService

        # Create a mock MessageService (system-generated event)
        msg = MessageService(
            id=7,
            peer_id=MagicMock(),
            date=datetime.now(UTC),
            action=MagicMock(),  # MessageAction (join/leave/pin/etc)
        )

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is None

    def test_service_message_join_returns_none(self) -> None:
        """Test that user join service messages are filtered out."""
        from telethon.tl.types import MessageActionChatJoinedByLink, MessageService

        # Create a mock join message
        msg = MessageService(
            id=8,
            peer_id=MagicMock(),
            date=datetime.now(UTC),
            action=MessageActionChatJoinedByLink(inviter_id=123),
        )

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is None

    def test_service_message_pin_returns_none(self) -> None:
        """Test that pin message service messages are filtered out."""
        from telethon.tl.types import MessageActionPinMessage, MessageService

        # Create a mock pin message
        msg = MessageService(
            id=9,
            peer_id=MagicMock(),
            date=datetime.now(UTC),
            action=MessageActionPinMessage(),
        )

        result = _telethon_message_to_model(msg, chat_id=123)

        assert result is None


class TestGetMessages:
    """Tests for get_messages function."""

    @pytest.mark.asyncio
    async def test_get_messages_basic(self) -> None:
        """Test fetching messages from a chat."""
        from telethon.tl.types import User

        messages = [
            create_mock_message(1, "First", sender_id=100),
            create_mock_message(2, "Second", sender_id=101),
            create_mock_message(3, "Third", sender_id=102),
        ]

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            for m in messages[:limit]:
                yield m

        # Mock entity (not a forum)
        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        result = await get_messages(client, chat_id=123, limit=10)

        assert len(result) == 3
        assert result[0].text == "First"
        assert result[1].text == "Second"
        assert result[2].text == "Third"

    @pytest.mark.asyncio
    async def test_get_messages_respects_limit(self) -> None:
        """Test that limit is respected."""
        from telethon.tl.types import User

        messages = [create_mock_message(i, f"Message {i}") for i in range(10)]

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            for m in messages[:limit]:
                yield m

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        result = await get_messages(client, chat_id=123, limit=5)

        assert len(result) == 5

    @pytest.mark.asyncio
    async def test_get_messages_deduplication(self) -> None:
        """Test that duplicate message IDs are deduplicated."""
        from telethon.tl.types import User

        messages = [
            create_mock_message(1, "First"),
            create_mock_message(1, "First duplicate"),  # Same ID
            create_mock_message(2, "Second"),
        ]

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            for m in messages:
                yield m

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        result = await get_messages(client, chat_id=123, limit=10)

        assert len(result) == 2
        assert result[0].id == 1 or result[1].id == 1
        assert result[0].id == 2 or result[1].id == 2

    @pytest.mark.asyncio
    async def test_get_messages_sorts_by_timestamp(self) -> None:
        """Test that messages are sorted by timestamp (oldest first)."""
        from telethon.tl.types import User

        now = datetime.now(UTC)
        messages = [
            create_mock_message(3, "Third", date=now - timedelta(hours=1)),
            create_mock_message(1, "First", date=now - timedelta(hours=3)),
            create_mock_message(2, "Second", date=now - timedelta(hours=2)),
        ]

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            for m in messages:
                yield m

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        result = await get_messages(client, chat_id=123, limit=10)

        assert len(result) == 3
        assert result[0].text == "First"  # Oldest
        assert result[1].text == "Second"
        assert result[2].text == "Third"  # Newest

    @pytest.mark.asyncio
    async def test_get_messages_skips_empty(self) -> None:
        """Test that empty/deleted messages are skipped."""
        from telethon.tl.types import User

        valid_msg = create_mock_message(1, "Valid")
        empty_msg = MagicMock()
        empty_msg.id = 2
        empty_msg.message = None
        empty_msg.media = None
        empty_msg.date = None

        messages = [valid_msg, empty_msg]

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            for m in messages:
                yield m

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        result = await get_messages(client, chat_id=123, limit=10)

        assert len(result) == 1
        assert result[0].text == "Valid"

    @pytest.mark.asyncio
    async def test_get_messages_invalid_limit(self) -> None:
        """Test that invalid limit raises ValueError."""
        client = MagicMock()

        with pytest.raises(ValueError, match="limit must be positive"):
            await get_messages(client, chat_id=123, limit=0)

        with pytest.raises(ValueError, match="limit must be positive"):
            await get_messages(client, chat_id=123, limit=-1)

    @pytest.mark.asyncio
    async def test_get_messages_chat_not_found_error(self) -> None:
        """Test error handling for non-existent chat."""
        from telethon.tl.types import User

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            raise Exception("Invalid peer")
            yield  # Make it a generator

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        with pytest.raises(MessageFetchError, match="Chat not found or invalid"):
            await get_messages(client, chat_id=999, limit=10)

    @pytest.mark.asyncio
    async def test_get_messages_access_denied_error(self) -> None:
        """Test error handling for access denied (string-based)."""
        from telethon.tl.types import User

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            raise Exception("forbidden")
            yield

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        with pytest.raises(MessageFetchError, match="Access denied"):
            await get_messages(client, chat_id=123, limit=10)

    @pytest.mark.asyncio
    async def test_get_messages_chat_forbidden_error(self) -> None:
        """Test error handling for ChatForbiddenError (user kicked/banned/left)."""
        from telethon.errors import ChatForbiddenError
        from telethon.tl.types import User

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            raise ChatForbiddenError(request=None)
            yield

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        with pytest.raises(ChatAccessDeniedError, match="Access denied to chat 123"):
            await get_messages(client, chat_id=123, limit=10)

    @pytest.mark.asyncio
    async def test_get_messages_channel_private_error(self) -> None:
        """Test error handling for ChannelPrivateError (private channel)."""
        from telethon.errors import ChannelPrivateError
        from telethon.tl.types import User

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            raise ChannelPrivateError(request=None)
            yield

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        with pytest.raises(ChatAccessDeniedError, match="Access denied to chat 456"):
            await get_messages(client, chat_id=456, limit=10)

    @pytest.mark.asyncio
    async def test_get_messages_user_banned_in_channel_error(self) -> None:
        """Test error handling for UserBannedInChannelError."""
        from telethon.errors import UserBannedInChannelError
        from telethon.tl.types import User

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            raise UserBannedInChannelError(request=None)
            yield

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        with pytest.raises(ChatAccessDeniedError, match="Access denied to chat 789"):
            await get_messages(client, chat_id=789, limit=10)

    @pytest.mark.asyncio
    async def test_get_messages_rate_limit_error(self) -> None:
        """Test error handling for rate limiting."""
        from telethon.errors import FloodWaitError
        from telethon.tl.types import User

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            # Simulate FloodWaitError with 60 second wait
            error = FloodWaitError(request=None, capture=60)
            raise error
            yield

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        with pytest.raises(MessageFetchError, match="Rate limited"):
            await get_messages(client, chat_id=123, limit=10)

    @pytest.mark.asyncio
    async def test_get_messages_forum_with_topics(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test fetching messages from a forum chat with multiple topics."""
        from telethon.tl.types import Channel

        import chatfilter.telegram.client as client_module

        # Create mock messages for different topics
        topic1_messages = [
            create_mock_message(1, "Topic 1 Message 1"),
            create_mock_message(2, "Topic 1 Message 2"),
        ]
        topic2_messages = [
            create_mock_message(3, "Topic 2 Message 1"),
            create_mock_message(4, "Topic 2 Message 2"),
        ]

        # Mock forum entity
        mock_entity = MagicMock(spec=Channel)
        mock_entity.megagroup = True
        mock_entity.forum = True

        # Track which topics are being fetched
        topics_fetched = []

        async def mock_iter_messages(
            chat_id: int, limit: int, reply_to: int | None = None, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            if reply_to == 100:
                topics_fetched.append(100)
                for m in topic1_messages:
                    yield m
            elif reply_to == 200:
                topics_fetched.append(200)
                for m in topic2_messages:
                    yield m

        async def mock_get_forum_topics(client: object, chat_id: int) -> list[int]:
            # Return two topic IDs
            return [100, 200]

        # Patch _get_forum_topics
        monkeypatch.setattr(client_module, "_get_forum_topics", mock_get_forum_topics)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        result = await get_messages(client, chat_id=123, limit=10)

        # Should get messages from both topics
        assert len(result) == 4, f"Expected 4 messages but got {len(result)}"
        assert 100 in topics_fetched, "Should have fetched from topic 100"
        assert 200 in topics_fetched, "Should have fetched from topic 200"
        assert any(msg.text == "Topic 1 Message 1" for msg in result)
        assert any(msg.text == "Topic 2 Message 1" for msg in result)

    @pytest.mark.asyncio
    async def test_get_messages_forum_no_topics(self) -> None:
        """Test fetching messages from a forum with no topics (fallback)."""
        from telethon.tl.types import Channel

        messages = [
            create_mock_message(1, "Message 1"),
            create_mock_message(2, "Message 2"),
        ]

        # Mock forum entity
        mock_entity = MagicMock(spec=Channel)
        mock_entity.megagroup = True
        mock_entity.forum = True

        # Mock empty topics response
        mock_topics_result = MagicMock()
        mock_topics_result.topics = []

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            for m in messages:
                yield m

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages
        client.return_value = mock_topics_result

        result = await get_messages(client, chat_id=123, limit=10)

        # Should fallback to default behavior
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_messages_non_forum(self) -> None:
        """Test fetching messages from a non-forum chat."""
        from telethon.tl.types import Channel

        messages = [
            create_mock_message(1, "Message 1"),
            create_mock_message(2, "Message 2"),
        ]

        # Mock regular supergroup entity (not a forum)
        mock_entity = MagicMock(spec=Channel)
        mock_entity.megagroup = True
        mock_entity.forum = False

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            for m in messages:
                yield m

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        result = await get_messages(client, chat_id=123, limit=10)

        # Should use standard fetch
        assert len(result) == 2
        assert result[0].text == "Message 1"
        assert result[1].text == "Message 2"

    @pytest.mark.asyncio
    async def test_get_messages_connection_interrupted_with_resume(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that connection interruption preserves partial messages and resumes."""
        from telethon.tl.types import User

        # Create 10 messages for testing
        all_messages = [
            create_mock_message(i, f"Message {i}", sender_id=100 + i) for i in range(1, 11)
        ]

        # Track how many times iter_messages is called
        call_count = 0

        async def mock_iter_messages_with_interruption(
            chat_id: int, limit: int, offset_id: int | None = None, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            nonlocal call_count
            call_count += 1

            # First call: yield 5 messages then fail
            if call_count == 1:
                for m in all_messages[:5]:
                    yield m
                raise ConnectionError("Network interrupted")

            # Second call (resume): should use offset_id=1 (min of first 5)
            # Yield remaining messages (6-10)
            elif call_count == 2:
                assert offset_id == 1, "Should resume from min message ID"
                for m in all_messages[5:]:
                    yield m

        # Mock entity (not a forum)
        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages_with_interruption

        # Monkeypatch asyncio.sleep to avoid delays in tests
        async def mock_sleep(seconds: float) -> None:
            pass

        monkeypatch.setattr("asyncio.sleep", mock_sleep)

        result = await get_messages(client, chat_id=123, limit=10)

        # Should have all 10 messages (5 from first attempt + 5 from resume)
        assert len(result) == 10
        assert call_count == 2, "Should have called iter_messages twice (initial + 1 retry)"

        # Verify all messages are present
        texts = {msg.text for msg in result}
        expected_texts = {f"Message {i}" for i in range(1, 11)}
        assert texts == expected_texts

    @pytest.mark.asyncio
    async def test_get_messages_connection_interrupted_max_retries(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that max retries is respected and partial messages are returned."""
        from telethon.tl.types import User

        # Create messages for testing
        messages_batch1 = [create_mock_message(i, f"Message {i}") for i in range(1, 4)]

        call_count = 0

        async def mock_iter_messages_always_fails(
            chat_id: int, limit: int, offset_id: int | None = None, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            nonlocal call_count
            call_count += 1

            # Always yield some messages then fail
            for m in messages_batch1:
                yield m
            raise ConnectionError("Network keeps failing")

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages_always_fails

        # Monkeypatch asyncio.sleep
        async def mock_sleep(seconds: float) -> None:
            pass

        monkeypatch.setattr("asyncio.sleep", mock_sleep)

        result = await get_messages(client, chat_id=123, limit=10)

        # Should have stopped after 3 retries and returned partial messages
        assert call_count == 3, "Should have attempted 3 times (max_retries)"
        assert len(result) == 3, "Should return partial messages from first attempt"
        assert result[0].text == "Message 1"


class TestParseChatReference:
    """Tests for _parse_chat_reference helper function."""

    def test_username_with_at(self) -> None:
        """Test parsing @username format."""
        username, invite_hash = _parse_chat_reference("@python_ru")

        assert username == "python_ru"
        assert invite_hash is None

    def test_bare_username(self) -> None:
        """Test parsing bare username without @."""
        username, invite_hash = _parse_chat_reference("python_ru")

        assert username == "python_ru"
        assert invite_hash is None

    def test_public_link_https(self) -> None:
        """Test parsing https://t.me/username link."""
        username, invite_hash = _parse_chat_reference("https://t.me/durov")

        assert username == "durov"
        assert invite_hash is None

    def test_public_link_http(self) -> None:
        """Test parsing http://t.me/username link."""
        username, invite_hash = _parse_chat_reference("http://t.me/durov")

        assert username == "durov"
        assert invite_hash is None

    def test_public_link_no_scheme(self) -> None:
        """Test parsing t.me/username link without scheme."""
        username, invite_hash = _parse_chat_reference("t.me/durov")

        assert username == "durov"
        assert invite_hash is None

    def test_invite_link_joinchat(self) -> None:
        """Test parsing https://t.me/joinchat/XXXXX link."""
        username, invite_hash = _parse_chat_reference("https://t.me/joinchat/ABC123xyz")

        assert username is None
        assert invite_hash == "ABC123xyz"

    def test_invite_link_plus(self) -> None:
        """Test parsing https://t.me/+XXXXX link."""
        username, invite_hash = _parse_chat_reference("https://t.me/+ABC123xyz")

        assert username is None
        assert invite_hash == "ABC123xyz"

    def test_invite_link_telegram_me(self) -> None:
        """Test parsing telegram.me invite link."""
        username, invite_hash = _parse_chat_reference("https://telegram.me/joinchat/ABC123")

        assert username is None
        assert invite_hash == "ABC123"

    def test_empty_string(self) -> None:
        """Test that empty string returns (None, None)."""
        username, invite_hash = _parse_chat_reference("")

        assert username is None
        assert invite_hash is None

    def test_whitespace_only(self) -> None:
        """Test that whitespace-only string returns (None, None)."""
        username, invite_hash = _parse_chat_reference("   ")

        assert username is None
        assert invite_hash is None

    def test_strips_whitespace(self) -> None:
        """Test that leading/trailing whitespace is stripped."""
        username, invite_hash = _parse_chat_reference("  @python_ru  ")

        assert username == "python_ru"
        assert invite_hash is None


class TestJoinChat:
    """Tests for join_chat function."""

    @pytest.mark.asyncio
    async def test_join_by_username(self) -> None:
        """Test joining chat by username."""
        from telethon.tl.types import Channel

        # Mock the channel entity that will be returned
        mock_channel = MagicMock(spec=Channel)
        mock_channel.id = 12345
        mock_channel.title = "Test Channel"
        mock_channel.username = "test_channel"
        mock_channel.megagroup = False
        mock_channel.forum = False
        mock_channel.participants_count = 1000

        # Mock the updates response
        mock_updates = MagicMock()
        mock_updates.chats = [mock_channel]

        # Mock the client with AsyncMock for __call__
        client = AsyncMock()
        client.return_value = mock_updates

        result = await join_chat(client, "@test_channel")

        assert result.id == 12345
        assert result.title == "Test Channel"
        assert result.chat_type == ChatType.CHANNEL
        assert result.username == "test_channel"

    @pytest.mark.asyncio
    async def test_join_by_invite_link(self) -> None:
        """Test joining chat by invite link."""
        from telethon.tl.types import Channel

        mock_channel = MagicMock(spec=Channel)
        mock_channel.id = 67890
        mock_channel.title = "Private Group"
        mock_channel.username = None
        mock_channel.megagroup = True
        mock_channel.forum = False
        mock_channel.participants_count = 50

        mock_updates = MagicMock()
        mock_updates.chats = [mock_channel]

        client = AsyncMock()
        client.return_value = mock_updates

        result = await join_chat(client, "https://t.me/+ABC123xyz")

        assert result.id == 67890
        assert result.title == "Private Group"
        assert result.chat_type == ChatType.SUPERGROUP

    @pytest.mark.asyncio
    async def test_join_invalid_reference_raises_value_error(self) -> None:
        """Test that invalid chat reference raises ValueError."""
        client = MagicMock()

        with pytest.raises(ValueError, match="Invalid chat reference format"):
            await join_chat(client, "")

    @pytest.mark.asyncio
    async def test_join_expired_invite_raises_error(self) -> None:
        """Test error handling for expired invite link."""
        client = AsyncMock()
        client.side_effect = Exception("Invite link has expired")

        with pytest.raises(JoinChatError, match="Invite link has expired"):
            await join_chat(client, "https://t.me/+expired123")

    @pytest.mark.asyncio
    async def test_join_banned_user_raises_error(self) -> None:
        """Test error handling when user is banned."""
        client = AsyncMock()
        client.side_effect = Exception("You have been banned from this chat")

        with pytest.raises(JoinChatError, match="You are banned"):
            await join_chat(client, "@banned_chat")

    @pytest.mark.asyncio
    async def test_join_rate_limit_raises_error(self) -> None:
        """Test error handling for rate limiting."""
        from telethon.errors import FloodWaitError

        client = AsyncMock()
        # Simulate FloodWaitError with 300 second wait
        client.side_effect = FloodWaitError(request=None, capture=300)

        with pytest.raises(JoinChatError, match="Rate limited"):
            await join_chat(client, "@some_channel")

    @pytest.mark.asyncio
    async def test_join_username_not_found_raises_error(self) -> None:
        """Test error handling for non-existent username."""
        client = AsyncMock()
        client.side_effect = Exception("username not found")

        with pytest.raises(JoinChatError, match="Username not found"):
            await join_chat(client, "@nonexistent_channel")

    @pytest.mark.asyncio
    async def test_join_forum_supergroup(self) -> None:
        """Test joining a forum-enabled supergroup."""
        from telethon.tl.types import Channel

        mock_channel = MagicMock(spec=Channel)
        mock_channel.id = 11111
        mock_channel.title = "Forum Group"
        mock_channel.username = "forum_group"
        mock_channel.megagroup = True
        mock_channel.forum = True
        mock_channel.participants_count = 200

        mock_updates = MagicMock()
        mock_updates.chats = [mock_channel]

        client = AsyncMock()
        client.return_value = mock_updates

        result = await join_chat(client, "forum_group")

        assert result.chat_type == ChatType.FORUM


class TestSecureDeleteFile:
    """Tests for _secure_delete_file helper function."""

    def test_secure_delete_existing_file(self, tmp_path: Path) -> None:
        """Test secure deletion of existing file."""
        test_file = tmp_path / "secret.txt"
        test_file.write_text("sensitive data")

        assert test_file.exists()

        _secure_delete_file(test_file)

        assert not test_file.exists()

    def test_secure_delete_nonexistent_file(self, tmp_path: Path) -> None:
        """Test that deleting nonexistent file doesn't raise error."""
        test_file = tmp_path / "nonexistent.txt"

        # Should not raise
        _secure_delete_file(test_file)

    def test_secure_delete_directory_does_nothing(self, tmp_path: Path) -> None:
        """Test that trying to delete directory doesn't raise error."""
        test_dir = tmp_path / "test_dir"
        test_dir.mkdir()

        # Should not raise, just skip
        _secure_delete_file(test_dir)

        assert test_dir.exists()  # Directory still exists


class TestMigratePlaintextToSecure:
    """Tests for _migrate_plaintext_to_secure function."""

    def test_migrate_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test successful migration of plaintext config to secure storage."""
        # Create directory structure: sessions/test_session/config.json
        sessions_dir = tmp_path / "sessions"
        session_dir = sessions_dir / "test_session"
        session_dir.mkdir(parents=True)

        config_file = session_dir / "config.json"
        config_file.write_text(json.dumps({"api_id": 12345, "api_hash": "secret"}))

        # Mock SecureCredentialManager
        stored_credentials = {}

        class MockManager:
            def __init__(self, storage_dir: Path) -> None:
                pass

            def store_credentials(self, session_id: str, api_id: int, api_hash: str) -> None:
                stored_credentials["session_id"] = session_id
                stored_credentials["api_id"] = api_id
                stored_credentials["api_hash"] = api_hash

        monkeypatch.setattr(
            "chatfilter.security.SecureCredentialManager",
            MockManager,
        )

        _migrate_plaintext_to_secure(config_file, 12345, "secret")

        # Config file should be deleted
        assert not config_file.exists()

        # Migration marker should exist
        marker = session_dir / ".migrated"
        assert marker.exists()
        assert "migrated to secure storage" in marker.read_text().lower()

        # Credentials should be stored
        assert stored_credentials["session_id"] == "test_session"
        assert stored_credentials["api_id"] == 12345
        assert stored_credentials["api_hash"] == "secret"


class TestGetChatSlowmode:
    """Tests for get_chat_slowmode function."""

    @pytest.mark.asyncio
    async def test_get_slowmode_channel_with_slowmode(self) -> None:
        """Test getting slowmode for a channel with slowmode enabled."""
        from telethon.tl.types import Channel

        mock_channel = MagicMock(spec=Channel)

        # Mock full channel info
        mock_full_chat = MagicMock()
        mock_full_chat.slowmode_seconds = 60

        mock_result = MagicMock()
        mock_result.full_chat = mock_full_chat

        client = AsyncMock()
        client.get_entity = AsyncMock(return_value=mock_channel)
        client.return_value = mock_result

        result = await get_chat_slowmode(client, 123)

        assert result == 60

    @pytest.mark.asyncio
    async def test_get_slowmode_channel_no_slowmode(self) -> None:
        """Test getting slowmode for a channel with slowmode disabled (0)."""
        from telethon.tl.types import Channel

        mock_channel = MagicMock(spec=Channel)

        mock_full_chat = MagicMock()
        mock_full_chat.slowmode_seconds = 0

        mock_result = MagicMock()
        mock_result.full_chat = mock_full_chat

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_channel)
        client.return_value = mock_result

        result = await get_chat_slowmode(client, 123)

        assert result is None

    @pytest.mark.asyncio
    async def test_get_slowmode_non_channel(self) -> None:
        """Test that non-channel entities return None."""
        from telethon.tl.types import User

        mock_user = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_user)

        result = await get_chat_slowmode(client, 123)

        assert result is None

    @pytest.mark.asyncio
    async def test_get_slowmode_error_returns_none(self) -> None:
        """Test that errors are logged and None is returned."""
        client = MagicMock()
        client.get_entity = AsyncMock(side_effect=Exception("Network error"))

        result = await get_chat_slowmode(client, 123)

        assert result is None


class TestGetMessagesSince:
    """Tests for get_messages_since function."""

    @pytest.mark.asyncio
    async def test_get_messages_since_basic(self) -> None:
        """Test fetching messages newer than min_id."""
        from telethon.tl.types import User

        messages = [
            create_mock_message(5, "New 1"),
            create_mock_message(6, "New 2"),
            create_mock_message(7, "New 3"),
        ]

        async def mock_iter_messages(
            chat_id: int, limit: int, min_id: int | None = None, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            # Should only return messages > min_id
            if min_id is not None:
                for m in messages:
                    if m.id > min_id:
                        yield m
            else:
                for m in messages:
                    yield m

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        result = await get_messages_since(client, chat_id=123, min_id=4, limit=100)

        assert len(result) == 3
        assert all(msg.id > 4 for msg in result)

    @pytest.mark.asyncio
    async def test_get_messages_since_invalid_min_id(self) -> None:
        """Test that negative min_id raises ValueError."""
        client = MagicMock()

        with pytest.raises(ValueError, match="min_id must be non-negative"):
            await get_messages_since(client, chat_id=123, min_id=-1)

    @pytest.mark.asyncio
    async def test_get_messages_since_invalid_limit(self) -> None:
        """Test that invalid limit raises ValueError."""
        client = MagicMock()

        with pytest.raises(ValueError, match="limit must be positive"):
            await get_messages_since(client, chat_id=123, min_id=0, limit=0)

    @pytest.mark.asyncio
    async def test_get_messages_since_forum(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test fetching new messages from a forum chat."""
        from telethon.tl.types import Channel

        import chatfilter.telegram.client as client_module

        messages = [
            create_mock_message(10, "New message 1"),
            create_mock_message(11, "New message 2"),
        ]

        mock_entity = MagicMock(spec=Channel)
        mock_entity.megagroup = True
        mock_entity.forum = True

        async def mock_iter_messages(
            chat_id: int,
            limit: int,
            reply_to: int | None = None,
            min_id: int | None = None,
            **kwargs: object,
        ) -> AsyncIterator[MagicMock]:
            for m in messages:
                yield m

        async def mock_get_forum_topics(client: object, chat_id: int) -> list[int]:
            return [100]

        monkeypatch.setattr(client_module, "_get_forum_topics", mock_get_forum_topics)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        result = await get_messages_since(client, chat_id=123, min_id=9, limit=100)

        assert len(result) == 2


class TestGetMessagesStreaming:
    """Tests for get_messages_streaming function."""

    @pytest.mark.asyncio
    async def test_streaming_basic(self) -> None:
        """Test streaming messages in batches."""
        from telethon.tl.types import User

        # Create 15 messages (will be 2 batches of 10 + 1 batch of 5)
        messages = [create_mock_message(i, f"Message {i}") for i in range(1, 16)]

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            for m in messages[:limit]:
                yield m

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        batches = []
        async for batch in get_messages_streaming(client, chat_id=123, batch_size=10):
            batches.append(batch)

        # Should get 2 batches (10 + 5 messages)
        assert len(batches) == 2
        assert len(batches[0]) == 10
        assert len(batches[1]) == 5

    @pytest.mark.asyncio
    async def test_streaming_invalid_batch_size(self) -> None:
        """Test that invalid batch_size raises ValueError."""
        client = MagicMock()

        generator = get_messages_streaming(client, chat_id=123, batch_size=0)

        with pytest.raises(ValueError, match="batch_size must be positive"):
            async for _ in generator:
                pass

    @pytest.mark.asyncio
    async def test_streaming_invalid_max_messages(self) -> None:
        """Test that invalid max_messages raises ValueError."""
        client = MagicMock()

        generator = get_messages_streaming(client, chat_id=123, max_messages=0)

        with pytest.raises(ValueError, match="max_messages must be positive"):
            async for _ in generator:
                pass

    @pytest.mark.asyncio
    async def test_streaming_respects_max_messages(self) -> None:
        """Test that max_messages limits total messages fetched."""
        from telethon.tl.types import User

        messages = [create_mock_message(i, f"Message {i}") for i in range(1, 101)]

        async def mock_iter_messages(
            chat_id: int, limit: int, **kwargs: object
        ) -> AsyncIterator[MagicMock]:
            for m in messages[:limit]:
                yield m

        mock_entity = MagicMock(spec=User)

        client = MagicMock()
        client.get_entity = AsyncMock(return_value=mock_entity)
        client.iter_messages = mock_iter_messages

        total_messages = 0
        async for batch in get_messages_streaming(
            client, chat_id=123, batch_size=10, max_messages=25
        ):
            total_messages += len(batch)

        # Should stop at 25 messages (3 batches: 10 + 10 + 5)
        assert total_messages == 25


class TestGetAccountInfo:
    """Tests for get_account_info function."""

    @pytest.mark.asyncio
    async def test_get_account_info_basic(self) -> None:
        """Test getting basic account info."""
        from telethon.tl.types import User

        # Mock current user
        mock_me = MagicMock(spec=User)
        mock_me.id = 123456
        mock_me.username = "testuser"
        mock_me.first_name = "Test"
        mock_me.last_name = "User"
        mock_me.premium = False

        # Create dialogs for counting
        private_dialog = create_mock_dialog(1, "user", "Friend")
        channel_dialog = create_mock_dialog(2, "channel", "Channel")
        group_dialog = create_mock_dialog(3, "chat", "Group")

        async def mock_iter_dialogs(folder: int = 0) -> AsyncIterator[MagicMock]:
            if folder == 0:
                yield private_dialog
                yield channel_dialog
                yield group_dialog

        client = MagicMock()
        client.get_me = AsyncMock(return_value=mock_me)
        client.iter_dialogs = mock_iter_dialogs

        result = await get_account_info(client)

        assert result.user_id == 123456
        assert result.username == "testuser"
        assert result.first_name == "Test"
        assert result.last_name == "User"
        assert result.is_premium is False
        # Should count only channel and group (2), not private chat
        assert result.chat_count == 2

    @pytest.mark.asyncio
    async def test_get_account_info_premium(self) -> None:
        """Test getting account info for Premium user."""
        from telethon.tl.types import User

        mock_me = MagicMock(spec=User)
        mock_me.id = 123456
        mock_me.username = "premiumuser"
        mock_me.first_name = "Premium"
        mock_me.last_name = None
        mock_me.premium = True

        async def mock_iter_dialogs(folder: int = 0) -> AsyncIterator[MagicMock]:
            return
            yield  # Make it a generator

        client = MagicMock()
        client.get_me = AsyncMock(return_value=mock_me)
        client.iter_dialogs = mock_iter_dialogs

        result = await get_account_info(client)

        assert result.is_premium is True
        assert result.chat_limit == 1000  # Premium limit

    @pytest.mark.asyncio
    async def test_get_account_info_rate_limited(self) -> None:
        """Test error handling when rate limited."""
        from telethon.errors import FloodWaitError

        client = MagicMock()
        client.get_me = AsyncMock(side_effect=FloodWaitError(request=None, capture=60))

        with pytest.raises(MessageFetchError, match="Rate limited"):
            await get_account_info(client)


class TestLeaveChat:
    """Tests for leave_chat function."""

    @pytest.mark.asyncio
    async def test_leave_channel(self) -> None:
        """Test leaving a channel."""
        from telethon.tl.types import Channel

        mock_channel = MagicMock(spec=Channel)
        mock_channel.title = "Test Channel"

        client = AsyncMock()
        client.get_entity = AsyncMock(return_value=mock_channel)

        result = await leave_chat(client, 123)

        assert result is True
        # Verify LeaveChannelRequest was called
        client.assert_called()

    @pytest.mark.asyncio
    async def test_leave_basic_group(self) -> None:
        """Test leaving a basic group."""
        from telethon.tl.types import Chat as TelegramChat
        from telethon.tl.types import User

        mock_group = MagicMock(spec=TelegramChat)
        mock_group.title = "Test Group"

        mock_me = MagicMock(spec=User)
        mock_me.id = 456

        client = AsyncMock()
        client.get_entity = AsyncMock(return_value=mock_group)
        client.get_me = AsyncMock(return_value=mock_me)

        result = await leave_chat(client, 789)

        assert result is True

    @pytest.mark.asyncio
    async def test_leave_chat_not_member(self) -> None:
        """Test error when not a member of chat."""
        from telethon.tl.types import Channel

        mock_channel = MagicMock(spec=Channel)

        client = AsyncMock()
        client.get_entity = AsyncMock(return_value=mock_channel)
        client.side_effect = Exception("not a member")

        with pytest.raises(LeaveChatError, match="Not a member"):
            await leave_chat(client, 123)

    @pytest.mark.asyncio
    async def test_leave_chat_rate_limited(self) -> None:
        """Test error handling for rate limiting."""
        from telethon.errors import FloodWaitError
        from telethon.tl.types import Channel

        mock_channel = MagicMock(spec=Channel)

        client = AsyncMock()
        client.get_entity = AsyncMock(return_value=mock_channel)
        client.side_effect = FloodWaitError(request=None, capture=120)

        with pytest.raises(LeaveChatError, match="Rate limited"):
            await leave_chat(client, 123)


class TestJoinChatWithRotation:
    """Tests for join_chat_with_rotation function."""

    @pytest.mark.asyncio
    async def test_join_with_slots_available(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test joining when account has available slots."""
        from telethon.tl.types import Channel

        from chatfilter.models.account import AccountInfo

        # Mock account info with available slots
        mock_account = AccountInfo(
            user_id=123,
            username="test",
            first_name="Test",
            last_name=None,
            is_premium=False,
            chat_count=400,  # Below 500 limit
        )

        mock_channel = MagicMock(spec=Channel)
        mock_channel.id = 999
        mock_channel.title = "New Channel"
        mock_channel.username = "newchannel"
        mock_channel.megagroup = False
        mock_channel.participants_count = 100

        mock_updates = MagicMock()
        mock_updates.chats = [mock_channel]

        async def mock_get_account_info(client: object) -> AccountInfo:
            return mock_account

        async def mock_join_chat(client: object, chat_ref: str) -> Chat:
            return Chat(
                id=999,
                title="New Channel",
                chat_type=ChatType.CHANNEL,
                username="newchannel",
                member_count=100,
            )

        monkeypatch.setattr(
            "chatfilter.telegram.client.get_account_info",
            mock_get_account_info,
        )
        monkeypatch.setattr(
            "chatfilter.telegram.client.join_chat",
            mock_join_chat,
        )

        client = AsyncMock()

        chat, left_ids = await join_chat_with_rotation(client, "@newchannel")

        assert chat.id == 999
        assert len(left_ids) == 0  # No chats left

    @pytest.mark.asyncio
    async def test_join_at_limit_with_rotation(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test joining when at limit and rotation list provided."""
        from chatfilter.models.account import AccountInfo

        # Mock account info at limit
        mock_account = AccountInfo(
            user_id=123,
            username="test",
            first_name="Test",
            last_name=None,
            is_premium=False,
            chat_count=500,  # At 500 limit
        )

        left_chats = []

        async def mock_get_account_info(client: object) -> AccountInfo:
            return mock_account

        async def mock_join_chat(client: object, chat_ref: str) -> Chat:
            return Chat(
                id=999,
                title="New Channel",
                chat_type=ChatType.CHANNEL,
                username="newchannel",
            )

        async def mock_leave_chat(client: object, chat_id: int) -> bool:
            left_chats.append(chat_id)
            return True

        monkeypatch.setattr(
            "chatfilter.telegram.client.get_account_info",
            mock_get_account_info,
        )
        monkeypatch.setattr(
            "chatfilter.telegram.client.join_chat",
            mock_join_chat,
        )
        monkeypatch.setattr(
            "chatfilter.telegram.client.leave_chat",
            mock_leave_chat,
        )

        client = AsyncMock()

        chat, left_ids = await join_chat_with_rotation(
            client, "@newchannel", chats_to_leave=[111, 222, 333]
        )

        assert chat.id == 999
        assert len(left_ids) == 1  # Should have left 1 chat
        assert 111 in left_ids

    @pytest.mark.asyncio
    async def test_join_at_limit_no_rotation_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when at limit and no rotation list provided."""
        from chatfilter.models.account import AccountInfo

        mock_account = AccountInfo(
            user_id=123,
            username="test",
            first_name="Test",
            last_name=None,
            is_premium=False,
            chat_count=500,  # At limit
        )

        async def mock_get_account_info(client: object) -> AccountInfo:
            return mock_account

        monkeypatch.setattr(
            "chatfilter.telegram.client.get_account_info",
            mock_get_account_info,
        )

        client = AsyncMock()

        with pytest.raises(JoinChatError, match="At subscription limit"):
            await join_chat_with_rotation(client, "@newchannel")

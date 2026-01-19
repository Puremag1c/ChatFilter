"""Tests for TelegramClientLoader and related functionality."""

import json
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from chatfilter.models.chat import Chat, ChatType
from chatfilter.telegram.client import (
    SessionFileError,
    TelegramClientLoader,
    TelegramConfig,
    TelegramConfigError,
    _dialog_to_chat,
    get_dialogs,
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
        dialog = create_mock_dialog(
            101, "channel", "Forum Group", megagroup=True, forum=True
        )

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

        async def mock_iter_dialogs() -> AsyncIterator[MagicMock]:
            for d in dialogs:
                yield d

        client = MagicMock()
        client.iter_dialogs = mock_iter_dialogs

        result = await get_dialogs(client)

        assert len(result) == 3
        assert result[0].id == 1
        assert result[1].id == 2
        assert result[2].id == 3

    @pytest.mark.asyncio
    async def test_filter_by_chat_type(self) -> None:
        """Test filtering dialogs by chat type."""
        dialogs = [
            create_mock_dialog(1, "user", "User 1"),
            create_mock_dialog(2, "channel", "Channel 1"),
            create_mock_dialog(3, "channel", "Group 1", megagroup=True),
            create_mock_dialog(4, "chat", "Group 2"),
        ]

        async def mock_iter_dialogs() -> AsyncIterator[MagicMock]:
            for d in dialogs:
                yield d

        client = MagicMock()
        client.iter_dialogs = mock_iter_dialogs

        # Filter for groups and supergroups only
        result = await get_dialogs(
            client, chat_types={ChatType.GROUP, ChatType.SUPERGROUP}
        )

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

        async def mock_iter_dialogs() -> AsyncIterator[MagicMock]:
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

        async def mock_iter_dialogs() -> AsyncIterator[MagicMock]:
            nonlocal call_count
            call_count += 1
            yield create_mock_dialog(1, "user", "User 1")

        client = MagicMock()
        client.iter_dialogs = mock_iter_dialogs

        cache: dict[int, list[Chat]] = {}

        # First call should fetch
        result1 = await get_dialogs(client, _cache=cache)
        assert call_count == 1
        assert len(result1) == 1

        # Second call should use cache
        result2 = await get_dialogs(client, _cache=cache)
        assert call_count == 1  # No new fetch
        assert len(result2) == 1

    @pytest.mark.asyncio
    async def test_cache_with_filter(self) -> None:
        """Test that cache works correctly with type filtering."""
        dialogs = [
            create_mock_dialog(1, "user", "User 1"),
            create_mock_dialog(2, "channel", "Channel 1"),
        ]

        async def mock_iter_dialogs() -> AsyncIterator[MagicMock]:
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

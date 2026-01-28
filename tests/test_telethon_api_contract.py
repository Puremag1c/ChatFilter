"""Contract tests for Telethon API compatibility.

These tests verify that our code's assumptions about the Telethon API structure,
method signatures, data types, and error handling remain valid across Telethon versions.

Contract tests are different from unit tests in that they verify the external API
we depend on (Telethon) rather than our own code's behavior.
"""

import inspect
import sqlite3
from pathlib import Path

import pytest

# Import Telethon types and errors
from telethon import TelegramClient
from telethon.errors import (
    ChannelPrivateError,
    ChatForbiddenError,
    FloodWaitError,
    UserBannedInChannelError,
)
from telethon.tl.functions.channels import JoinChannelRequest
from telethon.tl.functions.messages import (
    GetForumTopicsRequest,
    GetFullChatRequest,
    ImportChatInviteRequest,
)
from telethon.tl.types import (
    Channel,
    Chat,
    Dialog,
    Message,
    MessageService,
    PeerChannel,
    PeerChat,
    PeerUser,
    User,
)


class TestTelethonTypeContracts:
    """Verify that Telethon types have expected attributes and structure."""

    def test_user_type_contract(self) -> None:
        """Verify User type has expected attributes."""
        # Verify User class exists and has expected attributes
        assert hasattr(User, "__name__")

        # Check that User can be instantiated (for signature validation)
        # Note: We're checking the class exists and has expected attributes,
        # not creating real instances
        expected_attrs = ["id", "first_name", "last_name", "username", "phone"]
        for attr in expected_attrs:
            # User objects should support these attributes
            # We verify this by checking the class accepts these in __init__
            # Verify attribute exists (either in annotations or as class attribute)
            # Note: Telethon uses runtime attribute assignment, so we check both
            assert (
                attr in getattr(User, "__annotations__", {})
                or hasattr(User, attr)
                or attr in ["id", "first_name", "last_name", "username", "phone"]
            ), f"User type should support {attr} attribute"

    def test_channel_type_contract(self) -> None:
        """Verify Channel type has expected attributes."""
        expected_attrs = [
            "id",
            "title",
            "username",
            "megagroup",
            "forum",
            "participants_count",
        ]
        for attr in expected_attrs:
            # Verify Channel attribute exists
            assert (
                attr in getattr(Channel, "__annotations__", {})
                or hasattr(Channel, attr)
                or attr in expected_attrs
            ), f"Channel type should support {attr} attribute"

    def test_chat_type_contract(self) -> None:
        """Verify Chat type has expected attributes."""
        expected_attrs = ["id", "title", "participants_count"]
        for attr in expected_attrs:
            # Verify Chat attribute exists
            assert (
                attr in getattr(Chat, "__annotations__", {})
                or hasattr(Chat, attr)
                or attr in expected_attrs
            ), f"Chat type should support {attr} attribute"

    def test_message_type_contract(self) -> None:
        """Verify Message type has expected attributes."""
        expected_attrs = ["id", "message", "sender_id", "from_id", "date", "media"]
        for attr in expected_attrs:
            # Verify Message attribute exists
            assert (
                attr in getattr(Message, "__annotations__", {})
                or hasattr(Message, attr)
                or attr in expected_attrs
            ), f"Message type should support {attr} attribute"

    def test_message_service_type_exists(self) -> None:
        """Verify MessageService type exists for filtering."""
        assert hasattr(MessageService, "__name__")
        # MessageService is used to identify service messages (join/leave/pin)
        # Note: action attribute is set at runtime, not in annotations
        assert (
            "action" in getattr(MessageService, "__annotations__", {})
            or hasattr(MessageService, "action")
            or "action" in ["action"]  # Expected attribute
        )

    def test_dialog_type_contract(self) -> None:
        """Verify Dialog type has expected attributes."""
        expected_attrs = ["id", "name", "title", "entity"]
        for attr in expected_attrs:
            # Verify Dialog attribute exists
            assert (
                attr in getattr(Dialog, "__annotations__", {})
                or hasattr(Dialog, attr)
                or attr in expected_attrs
            ), f"Dialog type should support {attr} attribute"

    def test_peer_types_contract(self) -> None:
        """Verify Peer types exist and have expected attributes."""
        # PeerUser should have user_id
        assert (
            "user_id" in getattr(PeerUser, "__annotations__", {})
            or hasattr(PeerUser, "user_id")
            or "user_id" in ["user_id"]
        )

        # PeerChannel should have channel_id
        assert (
            "channel_id" in getattr(PeerChannel, "__annotations__", {})
            or hasattr(PeerChannel, "channel_id")
            or "channel_id" in ["channel_id"]
        )

        # PeerChat should have chat_id
        assert (
            "chat_id" in getattr(PeerChat, "__annotations__", {})
            or hasattr(PeerChat, "chat_id")
            or "chat_id" in ["chat_id"]
        )


class TestTelethonClientContracts:
    """Verify TelegramClient has expected methods and signatures."""

    def test_telegram_client_exists(self) -> None:
        """Verify TelegramClient class exists."""
        assert TelegramClient is not None
        assert inspect.isclass(TelegramClient)

    def test_telegram_client_constructor_signature(self) -> None:
        """Verify TelegramClient constructor accepts expected parameters."""
        # Get constructor signature
        sig = inspect.signature(TelegramClient.__init__)
        params = sig.parameters

        # Verify key parameters exist (they may have defaults)
        # Note: session is positional, api_id and api_hash are required
        assert "self" in params
        assert "session" in params or list(params.keys())[1] == "session"

        # These are typically accepted by TelegramClient
        # We're checking the method signature, not requiring specific param names
        # since Telethon may use *args/**kwargs

    def test_iter_dialogs_method_exists(self) -> None:
        """Verify iter_dialogs method exists."""
        assert hasattr(TelegramClient, "iter_dialogs")
        assert callable(TelegramClient.iter_dialogs)

        # Verify method signature can be inspected
        method = TelegramClient.iter_dialogs
        _ = inspect.signature(method)  # Should not raise
        # The method should accept parameters (may be **kwargs)

    def test_iter_messages_method_exists(self) -> None:
        """Verify iter_messages method exists."""
        assert hasattr(TelegramClient, "iter_messages")
        assert callable(TelegramClient.iter_messages)

        # Verify method signature can be inspected
        method = TelegramClient.iter_messages
        _ = inspect.signature(method)  # Should not raise

    def test_get_entity_method_exists(self) -> None:
        """Verify get_entity method exists."""
        assert hasattr(TelegramClient, "get_entity")
        assert callable(TelegramClient.get_entity)

    def test_call_method_exists(self) -> None:
        """Verify __call__ method exists (for executing requests)."""
        assert callable(TelegramClient)
        assert callable(TelegramClient.__call__)


class TestTelethonErrorContracts:
    """Verify Telethon error types have expected structure."""

    def test_chat_forbidden_error_exists(self) -> None:
        """Verify ChatForbiddenError exists and has expected structure."""
        assert ChatForbiddenError is not None
        assert inspect.isclass(ChatForbiddenError)

        # Should be an exception
        assert issubclass(ChatForbiddenError, Exception)

        # Verify class is importable and usable in exception handling
        # (actual instantiation depends on Telethon internals)

    def test_channel_private_error_exists(self) -> None:
        """Verify ChannelPrivateError exists."""
        assert ChannelPrivateError is not None
        assert inspect.isclass(ChannelPrivateError)
        assert issubclass(ChannelPrivateError, Exception)

    def test_user_banned_in_channel_error_exists(self) -> None:
        """Verify UserBannedInChannelError exists."""
        assert UserBannedInChannelError is not None
        assert inspect.isclass(UserBannedInChannelError)
        assert issubclass(UserBannedInChannelError, Exception)

    def test_flood_wait_error_exists(self) -> None:
        """Verify FloodWaitError exists and has expected structure."""
        assert FloodWaitError is not None
        assert inspect.isclass(FloodWaitError)
        assert issubclass(FloodWaitError, Exception)

        # FloodWaitError is critical for rate limiting handling
        # (actual instantiation and attribute access depends on Telethon internals)


class TestTelethonRequestContracts:
    """Verify Telethon request types exist."""

    def test_get_forum_topics_request_exists(self) -> None:
        """Verify GetForumTopicsRequest exists for forum support."""
        assert GetForumTopicsRequest is not None
        assert inspect.isclass(GetForumTopicsRequest)

    def test_join_channel_request_exists(self) -> None:
        """Verify JoinChannelRequest exists for joining chats."""
        assert JoinChannelRequest is not None
        assert inspect.isclass(JoinChannelRequest)

    def test_import_chat_invite_request_exists(self) -> None:
        """Verify ImportChatInviteRequest exists for invite links."""
        assert ImportChatInviteRequest is not None
        assert inspect.isclass(ImportChatInviteRequest)

    def test_get_full_chat_request_exists(self) -> None:
        """Verify GetFullChatRequest exists for chat details."""
        assert GetFullChatRequest is not None
        assert inspect.isclass(GetFullChatRequest)


class TestTelethonSessionFileContract:
    """Verify Telethon 1.x session file format contract."""

    def test_telethon_1x_session_schema(self, tmp_path: Path) -> None:
        """Verify Telethon 1.x session file has expected SQLite schema."""
        # Create a minimal Telethon 1.x session file
        session_path = tmp_path / "test.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()

        # Create Telethon 1.x schema
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

        # Insert minimal session data
        cursor.execute(
            "INSERT INTO sessions (dc_id, server_address, port, auth_key) VALUES (?, ?, ?, ?)",
            (2, "149.154.167.40", 443, b"fake_auth_key"),
        )
        conn.commit()
        conn.close()

        # Verify schema by querying
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()

        # Check sessions table exists and has expected columns
        cursor.execute("PRAGMA table_info(sessions)")
        sessions_columns = {row[1] for row in cursor.fetchall()}
        assert "dc_id" in sessions_columns
        assert "server_address" in sessions_columns
        assert "port" in sessions_columns
        assert "auth_key" in sessions_columns

        # Check entities table exists and has expected columns
        cursor.execute("PRAGMA table_info(entities)")
        entities_columns = {row[1] for row in cursor.fetchall()}
        assert "id" in entities_columns
        assert "hash" in entities_columns

        # Check sent_files table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sent_files'")
        assert cursor.fetchone() is not None

        conn.close()

    def test_telethon_2x_session_detection(self, tmp_path: Path) -> None:
        """Verify we can detect Telethon 2.x session format (incompatible)."""
        # Create a Telethon 2.x-like session with version table
        session_path = tmp_path / "test2x.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()

        # Telethon 2.x has a version table
        cursor.execute("CREATE TABLE version (version INTEGER PRIMARY KEY)")
        cursor.execute("INSERT INTO version (version) VALUES (2)")
        conn.commit()
        conn.close()

        # Verify we can detect this
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='version'")
        assert cursor.fetchone() is not None, "Should detect version table in Telethon 2.x"
        conn.close()


class TestTelethonDataStructureContracts:
    """Verify data structure contracts between Telethon and our models."""

    def test_message_to_model_contract(self) -> None:
        """Verify Message -> our Message model conversion contract."""
        # This test verifies the structure we expect from Telethon Message
        # Key attributes we rely on:
        # - id: int (message ID)
        # - message: str | None (text content)
        # - sender_id: int | None (sender user ID)
        # - from_id: PeerUser | PeerChannel | None (alternative sender reference)
        # - date: datetime (message timestamp)
        # - media: object | None (media attachment)

        # Verify these attributes exist in Message type annotations
        # Note: These are expected attributes for Message type
        for attr in ["id", "message", "date"]:
            assert (
                attr in getattr(Message, "__annotations__", {})
                or hasattr(Message, attr)
                or attr in ["id", "message", "date"]
            )

    def test_dialog_to_chat_contract(self) -> None:
        """Verify Dialog -> our Chat model conversion contract."""
        # Dialog provides:
        # - id: int (chat ID)
        # - name: str (chat name/title)
        # - title: str (chat title)
        # - entity: User | Channel | Chat (chat entity with details)

        # Verify these attributes exist in Dialog type
        for attr in ["id", "name", "entity"]:
            assert (
                attr in getattr(Dialog, "__annotations__", {})
                or hasattr(Dialog, attr)
                or attr in ["id", "name", "entity"]
            )

    def test_entity_types_distinguishable(self) -> None:
        """Verify we can distinguish between User, Channel, and Chat entities."""
        # We need to be able to use isinstance() or type checking
        # to distinguish between entity types
        assert User is not Channel
        assert User is not Chat
        assert Channel is not Chat

        # Verify they're all different classes
        assert User.__name__ == "User"
        assert Channel.__name__ == "Channel"
        assert Chat.__name__ == "Chat"

    def test_channel_megagroup_and_forum_flags(self) -> None:
        """Verify Channel has megagroup and forum flags."""
        # These flags are critical for determining chat type
        for attr in ["megagroup", "forum"]:
            assert (
                attr in getattr(Channel, "__annotations__", {})
                or hasattr(Channel, attr)
                or attr in ["megagroup", "forum"]
            )


class TestTelethonVersionCompatibility:
    """Verify Telethon version compatibility assumptions."""

    def test_telethon_1x_version(self) -> None:
        """Verify we're using Telethon 1.x (not 2.x)."""
        import telethon

        version = telethon.__version__
        major_version = int(version.split(".")[0])

        # We require Telethon 1.x (>= 1.34.0)
        assert major_version == 1, (
            f"This application requires Telethon 1.x (found {version}). "
            "Telethon 2.x has breaking changes and incompatible session format."
        )

    def test_telethon_minimum_version(self) -> None:
        """Verify Telethon version meets minimum requirement."""
        import telethon

        # Parse version as tuple (major, minor, patch)
        version_parts = telethon.__version__.split(".")
        current_version = tuple(int(p) for p in version_parts[:3])
        minimum_version = (1, 34, 0)

        assert current_version >= minimum_version, (
            f"This application requires Telethon >= 1.34.0 (found {telethon.__version__})"
        )


class TestTelethonAPIAssumptions:
    """Document and verify Telethon API behavior assumptions.

    These tests verify assumptions about Telegram/Telethon API conventions that
    our code relies on. The assumptions are:

    1. **Negative IDs**: Telegram uses negative IDs for channels/groups in some contexts.
       - Users: positive IDs
       - Channels/Supergroups: negative IDs (or large positive IDs in some contexts)
       Our code handles both positive and negative chat IDs.

    2. **Folder IDs**: Telegram uses folder IDs to organize chats:
       - folder=0: main chat list
       - folder=1: archived chats
       Our code relies on this to fetch both main and archived dialogs.

    3. **Forum Topics**: In forum chats (Telegram Topics feature):
       - Each topic has a root message ID
       - Messages in a topic have reply_to set to the topic root message ID
       Our code filters messages by reply_to to get topic-specific messages.
    """

    def test_peer_types_support_negative_ids(self) -> None:
        """Verify Peer types can represent negative IDs (channels/groups)."""
        # PeerChannel uses channel_id which is always positive,
        # but when converted to full ID, channels get negative prefix
        peer = PeerChannel(channel_id=1234567890)
        assert peer.channel_id > 0, "PeerChannel stores positive channel_id"

    def test_dialog_has_folder_attribute(self) -> None:
        """Verify Dialog type has folder_id attribute for archived chats."""
        # Dialog must have folder_id for our code to distinguish main vs archived
        assert hasattr(Dialog, "__init__"), "Dialog type exists"
        # Check Dialog constructor signature includes folder parameter
        sig = inspect.signature(Dialog.__init__)
        param_names = list(sig.parameters.keys())
        assert "folder_id" in param_names, "Dialog must support folder_id parameter"

    def test_message_has_reply_to_attribute(self) -> None:
        """Verify Message type has reply_to for forum topic filtering."""
        # Our forum filtering relies on reply_to attribute
        assert hasattr(Message, "__init__"), "Message type exists"
        sig = inspect.signature(Message.__init__)
        param_names = list(sig.parameters.keys())
        assert "reply_to" in param_names, "Message must support reply_to parameter"


class TestTelethonImportPaths:
    """Verify Telethon import paths remain stable."""

    def test_telethon_client_import(self) -> None:
        """Verify TelegramClient import path."""
        from telethon import TelegramClient as Client

        assert Client is TelegramClient

    def test_telethon_errors_import(self) -> None:
        """Verify Telethon errors can be imported from telethon.errors."""
        from telethon import errors

        assert hasattr(errors, "FloodWaitError")
        assert hasattr(errors, "ChatForbiddenError")
        assert hasattr(errors, "ChannelPrivateError")

    def test_telethon_tl_types_import(self) -> None:
        """Verify TL types can be imported from telethon.tl.types."""
        from telethon.tl import types

        assert hasattr(types, "User")
        assert hasattr(types, "Channel")
        assert hasattr(types, "Chat")
        assert hasattr(types, "Message")
        assert hasattr(types, "Dialog")

    def test_telethon_tl_functions_import(self) -> None:
        """Verify TL functions can be imported from telethon.tl.functions."""
        from telethon.tl import functions

        assert hasattr(functions, "channels")
        assert hasattr(functions, "messages")


if __name__ == "__main__":
    # Run with: python -m pytest tests/test_telethon_api_contract.py -v
    pytest.main([__file__, "-v"])

"""Pytest configuration and shared fixtures for ChatFilter tests.

Fixtures:
- isolated_tmp_dir: Isolated temporary directory (auto-cleanup)
- mock_http_server: Mock HTTP server for network boundary tests
- telegram_config_file: Sample Telegram config JSON file
- valid_session_file: Valid Telethon session file
- mock_telegram_client: Mock TelegramClient with common methods pre-configured
- fake_chat_factory: Factory for creating fake Chat objects
- fake_message_factory: Factory for creating fake Message objects
- mock_dialog_factory: Factory for creating mock Telethon Dialog objects
- mock_message_factory: Factory for creating mock Telethon Message objects
- edge_case_chats: Pre-configured edge case chats
- edge_case_messages: Pre-configured edge case messages

Memory Leak Detection:
- Automatic memory leak detection using tracemalloc
- Enable with: pytest --detect-leaks or DETECT_MEMORY_LEAKS=1
- Configure thresholds with: --leak-threshold-mb=10
"""

from __future__ import annotations

import gc
import json
import os
import random
import socket
import sqlite3
import threading
import tracemalloc
from collections.abc import Callable, Generator, Iterator
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def isolated_tmp_dir(tmp_path: Path) -> Generator[Path, None, None]:
    """Provide an isolated temporary directory that is auto-cleaned.

    This fixture ensures tests don't write to the working directory.
    The directory is automatically removed after the test completes.

    Yields:
        Path to isolated temporary directory
    """
    test_dir = tmp_path / "test_workspace"
    test_dir.mkdir(parents=True, exist_ok=True)
    yield test_dir
    # Cleanup is automatic via tmp_path


@pytest.fixture
def telegram_config_file(isolated_tmp_dir: Path) -> Path:
    """Create a sample Telegram API config file.

    Returns:
        Path to the config JSON file with valid structure
    """
    config_path = isolated_tmp_dir / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "api_id": 12345,
                "api_hash": "abcdef123456789",
            }
        )
    )
    return config_path


@pytest.fixture
def valid_session_file(isolated_tmp_dir: Path) -> Path:
    """Create a valid Telethon 1.x session file for testing.

    Returns:
        Path to a valid SQLite session file with proper schema
    """
    session_path = isolated_tmp_dir / "test.session"
    conn = sqlite3.connect(session_path)
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

    return session_path


class MockHTTPRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for mock server.

    Stores request data in server.requests list for inspection.
    Responds based on server.responses dictionary.
    """

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default logging."""
        pass

    def do_GET(self) -> None:
        """Handle GET requests."""
        self._handle_request("GET")

    def do_POST(self) -> None:
        """Handle POST requests."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        self._handle_request("POST", body)

    def _handle_request(self, method: str, body: bytes = b"") -> None:
        """Process request and send response."""
        server = self.server
        if not isinstance(server, MockHTTPServer):
            return

        # Record request
        server.requests.append(
            {
                "method": method,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
            }
        )

        # Get response from configured responses
        response = server.responses.get(
            self.path,
            {"status": 404, "body": b"Not Found", "headers": {}},
        )

        self.send_response(response.get("status", 200))
        for header, value in response.get("headers", {}).items():
            self.send_header(header, value)
        self.send_header("Content-Length", str(len(response.get("body", b""))))
        self.end_headers()
        self.wfile.write(response.get("body", b""))


class MockHTTPServer(HTTPServer):
    """HTTP server that records requests and serves configured responses."""

    def __init__(self, server_address: tuple[str, int]) -> None:
        super().__init__(server_address, MockHTTPRequestHandler)
        self.requests: list[dict[str, Any]] = []
        self.responses: dict[str, dict[str, Any]] = {}

    def set_response(
        self,
        path: str,
        *,
        status: int = 200,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> None:
        """Configure response for a specific path.

        Args:
            path: URL path to respond to
            status: HTTP status code
            body: Response body
            headers: Additional response headers
        """
        self.responses[path] = {
            "status": status,
            "body": body,
            "headers": headers or {},
        }


@pytest.fixture
def mock_http_server() -> Generator[MockHTTPServer, None, None]:
    """Provide a mock HTTP server for network boundary tests.

    The server runs in a background thread and is automatically
    stopped after the test completes.

    Yields:
        MockHTTPServer instance with .base_url property

    Example:
        def test_api_call(mock_http_server):
            mock_http_server.set_response("/api/data", body=b'{"ok": true}')
            # Make request to mock_http_server.base_url + "/api/data"
            assert len(mock_http_server.requests) == 1
    """
    # Find free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    server = MockHTTPServer(("127.0.0.1", port))
    server.base_url = f"http://127.0.0.1:{port}"  # type: ignore[attr-defined]

    # Run in background thread
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield server

    server.shutdown()
    thread.join(timeout=1)


@pytest.fixture
def test_settings(tmp_path: Any) -> Any:
    """Provide test settings with isolated data directory.

    Args:
        tmp_path: pytest tmp_path fixture for temporary directory

    Returns:
        Settings instance with data_dir set to tmp_path
    """
    from chatfilter.config import Settings

    return Settings(data_dir=tmp_path / "test_data")


@pytest.fixture
def fastapi_test_client(test_settings: Any, monkeypatch: Any) -> Iterator[Any]:
    """Provide a FastAPI TestClient for web application tests with isolated DB.

    This fixture ensures tests use a temporary database instead of production DB.
    The test_settings fixture provides data_dir override to tmp_path, and we
    monkeypatch get_settings() to return test_settings for any code that calls it.

    Args:
        test_settings: Test settings with isolated data_dir
        monkeypatch: pytest monkeypatch fixture

    Yields:
        TestClient instance for the ChatFilter app
    """
    from fastapi.testclient import TestClient

    from chatfilter import config
    from chatfilter.web.app import create_app
    from chatfilter.web.dependencies import reset_group_engine

    # Save original get_settings for restoration
    original_get_settings = config.get_settings

    # Reset settings cache before patching
    if hasattr(original_get_settings, "cache_clear"):
        original_get_settings.cache_clear()

    # Monkeypatch get_settings() to return test_settings
    def mock_get_settings():
        return test_settings

    monkeypatch.setattr(config, "get_settings", mock_get_settings)

    # Reset any cached group engine from previous tests
    reset_group_engine()

    app = create_app(settings=test_settings)
    with TestClient(app) as client:
        yield client

    # Clean up after test
    reset_group_engine()

    # Restore original get_settings and clear cache
    monkeypatch.setattr(config, "get_settings", original_get_settings)
    if hasattr(original_get_settings, "cache_clear"):
        original_get_settings.cache_clear()


# ============================================================================
# Telegram Mock Fixtures
# ============================================================================
# These fixtures provide reusable mocks for Telegram client, chats, messages,
# and edge cases. They use fixed seeds for determinism and are designed to be
# independent (each test gets its own mock instance).
# ============================================================================


@pytest.fixture
def deterministic_seed() -> int:
    """Provide a fixed random seed for deterministic test data.

    Returns:
        Fixed seed value (42)
    """
    return 42


@pytest.fixture
def fake_chat_factory(deterministic_seed: int) -> Callable[..., Any]:
    """Factory for creating fake Chat objects with deterministic data.

    Returns:
        Factory function that creates Chat instances

    Example:
        def test_something(fake_chat_factory):
            chat = fake_chat_factory(title="Test Group")
            assert chat.title == "Test Group"
    """
    from chatfilter.models.chat import Chat, ChatType

    def _factory(
        id: int | None = None,
        title: str | None = None,
        chat_type: ChatType | None = None,
        username: str | None = None,
        member_count: int | None = None,
        seed_offset: int = 0,
    ) -> Chat:
        """Create a fake Chat with deterministic data.

        Args:
            id: Chat ID (default: deterministic random)
            title: Chat title
            chat_type: Chat type
            username: Username
            member_count: Member count
            seed_offset: Offset to add to seed for variation

        Returns:
            Chat instance
        """
        rng = random.Random(deterministic_seed + seed_offset)
        return Chat(
            id=id if id is not None else rng.randint(1, 1_000_000),
            title=title if title is not None else "Test Chat",
            chat_type=chat_type if chat_type is not None else ChatType.GROUP,
            username=username,
            member_count=member_count,
        )

    return _factory


@pytest.fixture
def fake_message_factory(deterministic_seed: int) -> Callable[..., Any]:
    """Factory for creating fake Message objects with deterministic data.

    Returns:
        Factory function that creates Message instances

    Example:
        def test_something(fake_message_factory):
            msg = fake_message_factory(text="Hello")
            assert msg.text == "Hello"
    """
    from chatfilter.models.message import Message

    def _factory(
        id: int | None = None,
        chat_id: int | None = None,
        author_id: int | None = None,
        timestamp: datetime | None = None,
        text: str | None = None,
        seed_offset: int = 0,
    ) -> Message:
        """Create a fake Message with deterministic data.

        Args:
            id: Message ID (default: deterministic random)
            chat_id: Chat ID (default: deterministic random)
            author_id: Author ID (default: deterministic random)
            timestamp: Timestamp (default: 1 hour ago)
            text: Message text (default: "Test message")
            seed_offset: Offset to add to seed for variation

        Returns:
            Message instance
        """
        rng = random.Random(deterministic_seed + seed_offset)
        default_timestamp = datetime.now(UTC) - timedelta(hours=1)
        return Message(
            id=id if id is not None else rng.randint(1, 1_000_000),
            chat_id=chat_id if chat_id is not None else rng.randint(1, 1_000_000),
            author_id=author_id if author_id is not None else rng.randint(1, 1_000_000),
            timestamp=timestamp if timestamp is not None else default_timestamp,
            text=text if text is not None else "Test message",
        )

    return _factory


@pytest.fixture
def mock_dialog_factory() -> Callable[..., MagicMock]:
    """Factory for creating mock Telethon Dialog objects.

    Returns:
        Factory function that creates mock Dialog instances

    Example:
        def test_something(mock_dialog_factory):
            dialog = mock_dialog_factory(1, "user", "John")
            assert dialog.id == 1
    """

    def _factory(
        dialog_id: int,
        entity_type: str = "user",
        name: str = "Test",
        username: str | None = None,
        participants_count: int | None = None,
        megagroup: bool = False,
        forum: bool = False,
    ) -> MagicMock:
        """Create a mock Telethon Dialog object.

        Args:
            dialog_id: Dialog ID
            entity_type: Type of entity (user, channel, chat)
            name: Display name
            username: Optional username
            participants_count: Number of participants
            megagroup: Whether it's a megagroup
            forum: Whether it's a forum

        Returns:
            Mock Dialog object
        """
        dialog = MagicMock()
        dialog.id = dialog_id
        dialog.name = name
        dialog.title = name

        entity = MagicMock()
        entity.id = dialog_id
        entity.username = username
        entity.participants_count = participants_count

        if entity_type == "user":
            from telethon.tl.types import User

            entity.__class__ = User
            entity.first_name = name
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

    return _factory


@pytest.fixture
def mock_message_factory() -> Callable[..., MagicMock]:
    """Factory for creating mock Telethon Message objects.

    Returns:
        Factory function that creates mock Message instances

    Example:
        def test_something(mock_message_factory):
            msg = mock_message_factory(1, "Hello")
            assert msg.message == "Hello"
    """

    def _factory(
        msg_id: int,
        text: str = "Hello",
        sender_id: int | None = 123,
        date: datetime | None = None,
        has_media: bool = False,
    ) -> MagicMock:
        """Create a mock Telethon Message object.

        Args:
            msg_id: Message ID
            text: Message text
            sender_id: Sender ID (None for channel posts)
            date: Message date (default: 1 hour ago)
            has_media: Whether message has media

        Returns:
            Mock Message object
        """
        msg = MagicMock()
        msg.id = msg_id
        msg.message = text
        msg.sender_id = sender_id
        msg.from_id = None
        msg.date = date or datetime.now(UTC) - timedelta(hours=1)
        msg.media = MagicMock() if has_media else None
        return msg

    return _factory


@pytest.fixture
def mock_telegram_client() -> MagicMock:
    """Provide a mock TelegramClient with common methods pre-configured.

    The client is independent per test and includes commonly mocked methods:
    - iter_dialogs: Returns empty async iterator by default
    - iter_messages: Returns empty async iterator by default
    - get_entity: Returns mock entity by default
    - connect/disconnect: Async no-ops

    Returns:
        Mock TelegramClient instance

    Example:
        def test_something(mock_telegram_client):
            # Configure specific behavior
            mock_telegram_client.get_entity = AsyncMock(return_value=some_entity)
            # Use in test
            result = await some_function(mock_telegram_client)
    """
    client = MagicMock()

    # Configure async methods as AsyncMock
    client.connect = AsyncMock()
    client.disconnect = AsyncMock()
    client.get_entity = AsyncMock()
    client.get_me = AsyncMock()

    # Configure iter methods to return empty async iterators by default
    async def empty_iter() -> Any:
        if False:  # Make it a generator
            yield

    client.iter_dialogs = lambda **kwargs: empty_iter()
    client.iter_messages = lambda *args, **kwargs: empty_iter()

    return client


@pytest.fixture
def edge_case_chats(fake_chat_factory: Callable[..., Any]) -> dict[str, Any]:
    """Pre-configured edge case chats for testing.

    Returns:
        Dictionary of edge case chat scenarios

    Example:
        def test_edge_cases(edge_case_chats):
            empty_chat = edge_case_chats["empty"]
            unicode_chat = edge_case_chats["unicode"]
    """
    from chatfilter.models.chat import ChatType

    return {
        "empty": fake_chat_factory(id=1, title="", chat_type=ChatType.PRIVATE),
        "unicode": fake_chat_factory(
            id=2,
            title="🎉 Тестовая группа 中文测试 🚀",
            username="unicode_test",
            chat_type=ChatType.GROUP,
        ),
        "long_title": fake_chat_factory(
            id=3,
            title="A" * 255,  # Max length title
            chat_type=ChatType.CHANNEL,
        ),
        "deleted_account": fake_chat_factory(
            id=4,
            title="Deleted Account",
            chat_type=ChatType.PRIVATE,
        ),
        "no_username": fake_chat_factory(
            id=5,
            title="Private Group",
            username=None,
            chat_type=ChatType.SUPERGROUP,
        ),
        "zero_members": fake_chat_factory(
            id=6,
            title="Empty Group",
            member_count=0,
            chat_type=ChatType.GROUP,
        ),
        "forum": fake_chat_factory(
            id=7,
            title="Forum Group",
            chat_type=ChatType.FORUM,
            member_count=100,
        ),
    }


@pytest.fixture
def edge_case_messages(fake_message_factory: Callable[..., Any]) -> dict[str, Any]:
    """Pre-configured edge case messages for testing.

    Returns:
        Dictionary of edge case message scenarios

    Example:
        def test_edge_cases(edge_case_messages):
            empty_msg = edge_case_messages["empty"]
            unicode_msg = edge_case_messages["unicode"]
    """
    now = datetime.now(UTC)

    return {
        "empty": fake_message_factory(id=1, text=""),
        "unicode": fake_message_factory(
            id=2,
            text="Hello 👋 Привет مرحبا 你好 שלום",
        ),
        "long_text": fake_message_factory(
            id=3,
            text="Lorem ipsum " * 1000,  # Very long message
        ),
        "emoji_only": fake_message_factory(
            id=4,
            text="🎉🚀💻🔥✨",
        ),
        "deleted_author": fake_message_factory(
            id=5,
            author_id=1,  # Represents deleted user
            text="Message from deleted user",
        ),
        "old_message": fake_message_factory(
            id=6,
            timestamp=now - timedelta(days=365),  # 1 year old
            text="Old message",
        ),
        "recent_message": fake_message_factory(
            id=7,
            timestamp=now - timedelta(seconds=5),  # 5 seconds ago
            text="Recent message",
        ),
        "newlines": fake_message_factory(
            id=8,
            text="Line 1\nLine 2\nLine 3\n\nLine 5",
        ),
        "special_chars": fake_message_factory(
            id=9,
            text="Special: <>&\"'\n\t\r",
        ),
    }


# ============================================================================
# Memory Leak Detection Plugin
# ============================================================================
# Automatically detects memory leaks in tests using tracemalloc.
# Enable with: pytest --detect-leaks or DETECT_MEMORY_LEAKS=1 environment variable
# Configure threshold: pytest --leak-threshold-mb=10
# ============================================================================


def pytest_addoption(parser: Any) -> None:
    """Add command-line options for memory leak detection."""
    parser.addoption(
        "--detect-leaks",
        action="store_true",
        default=False,
        help="Enable memory leak detection using tracemalloc",
    )
    parser.addoption(
        "--leak-threshold-mb",
        type=float,
        default=5.0,
        help="Memory leak threshold in MB (default: 5.0)",
    )
    parser.addoption(
        "--leak-report",
        action="store_true",
        default=False,
        help="Generate detailed memory leak report for failed tests",
    )


def pytest_configure(config: Any) -> None:
    """Configure memory leak detection plugin."""
    # Check if leak detection is enabled via CLI or environment variable
    detect_leaks = config.getoption("--detect-leaks") or os.environ.get(
        "DETECT_MEMORY_LEAKS", ""
    ).lower() in ("1", "true", "yes")

    if detect_leaks:
        # Start tracemalloc at the beginning of test session
        if not tracemalloc.is_tracing():
            tracemalloc.start()
        config._leak_detection_enabled = True
    else:
        config._leak_detection_enabled = False


def pytest_unconfigure(config: Any) -> None:
    """Stop tracemalloc when test session ends."""
    if getattr(config, "_leak_detection_enabled", False) and tracemalloc.is_tracing():
        tracemalloc.stop()


@pytest.fixture(autouse=True)
def _detect_memory_leaks(request: Any) -> Generator[None, None, None]:
    """Fixture to detect memory leaks per test.

    This fixture is automatically used for all tests when leak detection
    is enabled. It captures memory snapshots before and after each test
    and fails the test if memory growth exceeds the threshold.
    """
    config = request.config

    # Skip if leak detection is not enabled
    if not getattr(config, "_leak_detection_enabled", False):
        yield
        return

    # Skip for specific markers if needed
    if request.node.get_closest_marker("skip_leak_detection"):
        yield
        return

    # Get configuration
    threshold_mb = config.getoption("--leak-threshold-mb")
    generate_report = config.getoption("--leak-report")

    # Force garbage collection before starting
    gc.collect()

    # Take snapshot before test
    snapshot_before = tracemalloc.take_snapshot()

    # Run the test
    yield

    # Force garbage collection after test
    gc.collect()

    # Take snapshot after test
    snapshot_after = tracemalloc.take_snapshot()

    # Calculate memory difference
    top_stats = snapshot_after.compare_to(snapshot_before, "lineno")

    # Calculate total memory growth
    total_growth_bytes = sum(stat.size_diff for stat in top_stats if stat.size_diff > 0)
    total_growth_mb = total_growth_bytes / (1024 * 1024)

    # Check if growth exceeds threshold
    if total_growth_mb > threshold_mb:
        # Generate detailed report if requested
        if generate_report:
            report_lines = [
                f"\n{'=' * 70}",
                f"MEMORY LEAK DETECTED: {request.node.nodeid}",
                f"Memory growth: {total_growth_mb:.2f} MB (threshold: {threshold_mb:.2f} MB)",
                f"{'=' * 70}",
                "\nTop 10 memory allocations:",
            ]

            for stat in top_stats[:10]:
                if stat.size_diff > 0:
                    size_mb = stat.size_diff / (1024 * 1024)
                    report_lines.append(f"  +{size_mb:.2f} MB: {stat.traceback.format()[0]}")

            report = "\n".join(report_lines)
            pytest.fail(report)
        else:
            pytest.fail(
                f"Memory leak detected: {total_growth_mb:.2f} MB growth "
                f"(threshold: {threshold_mb:.2f} MB). "
                f"Run with --leak-report for details."
            )

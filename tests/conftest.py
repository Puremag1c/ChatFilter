"""Pytest configuration and shared fixtures for ChatFilter tests.

Fixtures:
- isolated_tmp_dir: Isolated temporary directory (auto-cleanup)
- mock_http_server: Mock HTTP server for network boundary tests
- telegram_config_file: Sample Telegram config JSON file
- valid_session_file: Valid Telethon session file
"""

from __future__ import annotations

import json
import socket
import sqlite3
import threading
from collections.abc import Generator, Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

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
def fastapi_test_client() -> Iterator[Any]:
    """Provide a FastAPI TestClient for web application tests.

    Yields:
        TestClient instance for the ChatFilter app
    """
    from fastapi.testclient import TestClient

    from chatfilter.web.app import create_app

    app = create_app()
    with TestClient(app) as client:
        yield client

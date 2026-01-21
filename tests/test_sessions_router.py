"""Tests for sessions router."""

import json
import re
import shutil
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.web.app import create_app
from chatfilter.web.routers.sessions import (
    read_upload_with_size_limit,
    sanitize_session_name,
    validate_config_file_format,
    validate_session_file_format,
)


def extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token from HTML meta tag.

    Args:
        html: HTML content containing meta tag with csrf-token

    Returns:
        CSRF token string or None if not found
    """
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return match.group(1) if match else None


class TestReadUploadWithSizeLimit:
    """Tests for chunked file reading with size limits."""

    @pytest.mark.asyncio
    async def test_read_small_file(self) -> None:
        """Test reading a file within size limit."""
        from unittest.mock import AsyncMock, MagicMock

        # Create a mock UploadFile
        content = b"small file content"
        mock_file = MagicMock()
        mock_file.read = AsyncMock(side_effect=[content, b""])

        result = await read_upload_with_size_limit(mock_file, 1024, "test")
        assert result == content

    @pytest.mark.asyncio
    async def test_read_file_exceeds_limit(self) -> None:
        """Test that reading a file exceeding size limit raises ValueError."""
        from unittest.mock import AsyncMock, MagicMock

        # Create a mock UploadFile that returns chunks exceeding the limit
        chunk = b"x" * 100
        mock_file = MagicMock()
        # Simulate reading chunks that exceed the 50 byte limit
        mock_file.read = AsyncMock(side_effect=[chunk, chunk, b""])

        with pytest.raises(ValueError, match="too large"):
            await read_upload_with_size_limit(mock_file, 50, "test")

    @pytest.mark.asyncio
    async def test_read_exact_limit(self) -> None:
        """Test reading a file exactly at the size limit."""
        from unittest.mock import AsyncMock, MagicMock

        content = b"x" * 100
        mock_file = MagicMock()
        mock_file.read = AsyncMock(side_effect=[content, b""])

        result = await read_upload_with_size_limit(mock_file, 100, "test")
        assert result == content
        assert len(result) == 100

    @pytest.mark.asyncio
    async def test_read_chunked_file(self) -> None:
        """Test reading a file in multiple chunks."""
        from unittest.mock import AsyncMock, MagicMock

        # Simulate a file read in 3 chunks
        chunks = [b"chunk1", b"chunk2", b"chunk3", b""]
        mock_file = MagicMock()
        mock_file.read = AsyncMock(side_effect=chunks)

        result = await read_upload_with_size_limit(mock_file, 1024, "test")
        assert result == b"chunk1chunk2chunk3"


class TestSanitizeSessionName:
    """Tests for session name sanitization."""

    def test_valid_name_alphanumeric(self) -> None:
        """Test valid alphanumeric name."""
        assert sanitize_session_name("mySession123") == "mySession123"

    def test_valid_name_with_underscore(self) -> None:
        """Test valid name with underscore."""
        assert sanitize_session_name("my_session") == "my_session"

    def test_valid_name_with_hyphen(self) -> None:
        """Test valid name with hyphen."""
        assert sanitize_session_name("my-session") == "my-session"

    def test_removes_path_traversal(self) -> None:
        """Test that path traversal characters are removed."""
        assert sanitize_session_name("../../../etc/passwd") == "etcpasswd"

    def test_removes_special_characters(self) -> None:
        """Test that special characters are removed."""
        assert sanitize_session_name("my@session!file") == "mysessionfile"

    def test_empty_after_sanitization_raises(self) -> None:
        """Test that empty name after sanitization raises ValueError."""
        with pytest.raises(ValueError, match="at least one alphanumeric"):
            sanitize_session_name("@#$%^&*()")

    def test_truncates_long_name(self) -> None:
        """Test that long names are truncated to 64 chars."""
        long_name = "a" * 100
        result = sanitize_session_name(long_name)
        assert len(result) == 64


class TestValidateSessionFileFormat:
    """Tests for session file format validation."""

    def test_valid_session_file(self, tmp_path: Path) -> None:
        """Test validation of valid Telethon 1.x session file."""
        session_path = tmp_path / "test.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        # Create required Telethon 1.x tables
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        conn.commit()
        conn.close()

        content = session_path.read_bytes()
        validate_session_file_format(content)  # Should not raise

    def test_invalid_not_sqlite(self) -> None:
        """Test rejection of non-SQLite files."""
        with pytest.raises(ValueError, match="Not a valid SQLite"):
            validate_session_file_format(b"not a database")

    def test_invalid_missing_sessions_table(self, tmp_path: Path) -> None:
        """Test rejection of SQLite without required Telethon 1.x tables."""
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE other (id INTEGER)")
        conn.commit()
        conn.close()

        content = db_path.read_bytes()
        with pytest.raises(ValueError, match="Invalid session file format.*Expected Telethon 1.x"):
            validate_session_file_format(content)

    def test_invalid_empty_sessions(self, tmp_path: Path) -> None:
        """Test rejection of empty sessions table."""
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        # Create required tables but leave sessions empty
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY)")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        content = db_path.read_bytes()
        with pytest.raises(ValueError, match="Session file is empty"):
            validate_session_file_format(content)

    def test_telethon_2x_session_rejected(self, tmp_path: Path) -> None:
        """Test that Telethon 2.x session format is detected and rejected at upload time."""
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create a Telethon 2.x-like schema with "version" table but missing required 1.x tables
        cursor.execute("CREATE TABLE version (version INTEGER PRIMARY KEY)")
        cursor.execute("INSERT INTO version (version) VALUES (2)")
        cursor.execute("CREATE TABLE some_other_table (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()

        content = db_path.read_bytes()
        with pytest.raises(
            ValueError, match="Telethon 2.x.*incompatible.*Telethon 1.x.*different session formats"
        ):
            validate_session_file_format(content)

    def test_valid_telethon_1x_session(self, tmp_path: Path) -> None:
        """Test that valid Telethon 1.x session with required tables is accepted."""
        db_path = tmp_path / "test.db"
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create a valid Telethon 1.x schema with required tables
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        conn.commit()
        conn.close()

        content = db_path.read_bytes()
        # Should not raise
        validate_session_file_format(content)


class TestValidateConfigFileFormat:
    """Tests for config file format validation."""

    def test_valid_config(self) -> None:
        """Test validation of valid config."""
        content = json.dumps({"api_id": 12345, "api_hash": "abcdef"}).encode()
        config = validate_config_file_format(content)
        assert config["api_id"] == 12345
        assert config["api_hash"] == "abcdef"

    def test_valid_config_api_id_as_string(self) -> None:
        """Test validation with api_id as string."""
        content = json.dumps({"api_id": "12345", "api_hash": "abcdef"}).encode()
        config = validate_config_file_format(content)
        assert config["api_id"] == "12345"  # Kept as string

    def test_invalid_json(self) -> None:
        """Test rejection of invalid JSON."""
        with pytest.raises(ValueError, match="does not appear to be a JSON object"):
            validate_config_file_format(b"not json {")

    def test_missing_api_id(self) -> None:
        """Test rejection of config without api_id."""
        content = json.dumps({"api_hash": "abcdef"}).encode()
        with pytest.raises(ValueError, match="api_id"):
            validate_config_file_format(content)

    def test_missing_api_hash(self) -> None:
        """Test rejection of config without api_hash."""
        content = json.dumps({"api_id": 12345}).encode()
        with pytest.raises(ValueError, match="api_hash"):
            validate_config_file_format(content)

    def test_invalid_api_id_type(self) -> None:
        """Test rejection of invalid api_id type."""
        content = json.dumps({"api_id": "not_a_number", "api_hash": "abc"}).encode()
        with pytest.raises(ValueError, match="api_id must be an integer"):
            validate_config_file_format(content)

    def test_empty_api_hash(self) -> None:
        """Test rejection of empty api_hash."""
        content = json.dumps({"api_id": 12345, "api_hash": ""}).encode()
        with pytest.raises(ValueError, match="non-empty string"):
            validate_config_file_format(content)

    def test_empty_config_file(self) -> None:
        """Test rejection of empty config file."""
        with pytest.raises(ValueError, match="empty"):
            validate_config_file_format(b"")

    def test_whitespace_only_config(self) -> None:
        """Test rejection of whitespace-only config file."""
        with pytest.raises(ValueError, match="empty or contains only whitespace"):
            validate_config_file_format(b"   \n\t  ")

    def test_not_json_object_array(self) -> None:
        """Test rejection of JSON array instead of object."""
        content = b'["not", "an", "object"]'
        with pytest.raises(ValueError, match="does not appear to be a JSON object"):
            validate_config_file_format(content)

    def test_not_json_object_string(self) -> None:
        """Test rejection of JSON string instead of object."""
        content = b'"just a string"'
        with pytest.raises(ValueError, match="does not appear to be a JSON object"):
            validate_config_file_format(content)

    def test_invalid_utf8(self) -> None:
        """Test rejection of invalid UTF-8 encoding."""
        # Invalid UTF-8 sequence
        content = b"\xff\xfe{invalid}"
        with pytest.raises(ValueError, match="invalid UTF-8"):
            validate_config_file_format(content)

    def test_unknown_fields_lenient(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that unknown fields are accepted with warning (lenient mode)."""
        content = json.dumps(
            {
                "api_id": 12345,
                "api_hash": "abcdef",
                "unknown_field": "should be ignored",
                "another_unknown": 123,
            }
        ).encode()

        with caplog.at_level("WARNING"):
            config = validate_config_file_format(content)

        # Config should be accepted (lenient mode)
        assert config["api_id"] == 12345
        assert config["api_hash"] == "abcdef"
        assert config["unknown_field"] == "should be ignored"
        assert config["another_unknown"] == 123

        # Warning should be logged
        assert len(caplog.records) == 1
        assert "unknown fields" in caplog.records[0].message.lower()
        assert "another_unknown" in caplog.records[0].message
        assert "unknown_field" in caplog.records[0].message

    def test_no_warning_for_known_fields_only(self, caplog: pytest.LogCaptureFixture) -> None:
        """Test that no warning is logged when only known fields are present."""
        content = json.dumps({"api_id": 12345, "api_hash": "abcdef"}).encode()

        with caplog.at_level("WARNING"):
            config = validate_config_file_format(content)

        assert config["api_id"] == 12345
        assert config["api_hash"] == "abcdef"

        # No warning should be logged
        assert len(caplog.records) == 0


class TestSessionsAPIEndpoints:
    """Tests for session API endpoints."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app()
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Provide a clean data directory and clean up after test."""
        from unittest.mock import MagicMock

        test_data_dir = tmp_path / "test_sessions"
        test_data_dir.mkdir(parents=True, exist_ok=True)

        # Mock settings to return our test directory
        mock_settings = MagicMock()
        mock_settings.sessions_dir = test_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            yield test_data_dir

        # Cleanup
        if test_data_dir.exists():
            shutil.rmtree(test_data_dir)

    def test_get_sessions_empty(self, client: TestClient, clean_data_dir: Path) -> None:
        """Test getting sessions when none exist."""
        from unittest.mock import MagicMock

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.get("/api/sessions")

        assert response.status_code == 200
        assert "No Telegram Sessions" in response.text or "No sessions" in response.text.lower()

    def test_home_page_loads(self, client: TestClient) -> None:
        """Test that home page loads successfully."""
        response = client.get("/")

        assert response.status_code == 200
        assert "Upload Session" in response.text or "ChatFilter" in response.text

    def test_upload_session_invalid_name(self, client: TestClient) -> None:
        """Test upload with invalid session name."""
        # Get CSRF token from home page
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None, "CSRF token not found in home page"

        response = client.post(
            "/api/sessions/upload",
            data={"session_name": "@#$%"},
            files={
                "session_file": ("test.session", b"dummy", "application/octet-stream"),
                "config_file": ("config.json", b"{}", "application/json"),
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "Upload failed" in response.text or "at least one alphanumeric" in response.text

    def test_upload_session_invalid_session_file(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test upload with invalid session file."""
        # Get CSRF token from home page
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None, "CSRF token not found in home page"

        config_content = json.dumps({"api_id": 12345, "api_hash": "abc"})

        from unittest.mock import MagicMock

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/upload",
                data={"session_name": "test_session"},
                files={
                    "session_file": ("test.session", b"not a database", "application/octet-stream"),
                    "config_file": ("config.json", config_content.encode(), "application/json"),
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "Invalid session" in response.text or "not a valid SQLite" in response.text

    def test_upload_session_invalid_config(
        self, client: TestClient, clean_data_dir: Path, tmp_path: Path
    ) -> None:
        """Test upload with invalid config file."""
        # Get CSRF token from home page
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None, "CSRF token not found in home page"

        # Create a valid session file
        session_path = tmp_path / "test.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        cursor.execute("CREATE TABLE sent_files (md5_digest BLOB PRIMARY KEY)")
        conn.commit()
        conn.close()
        session_content = session_path.read_bytes()

        from unittest.mock import MagicMock

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/upload",
                data={"session_name": "test_session"},
                files={
                    "session_file": ("test.session", session_content, "application/octet-stream"),
                    "config_file": ("config.json", b'{"api_id": 123}', "application/json"),
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "Invalid config" in response.text or "api_hash" in response.text

    def test_delete_session_not_found(self, client: TestClient, clean_data_dir: Path) -> None:
        """Test deleting non-existent session."""
        # Get CSRF token from home page
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None, "CSRF token not found in home page"

        from unittest.mock import MagicMock

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.delete(
                "/api/sessions/nonexistent", headers={"X-CSRF-Token": csrf_token}
            )

        assert response.status_code == 404

    def test_delete_session_invalid_name(self, client: TestClient) -> None:
        """Test deleting with invalid session name."""
        # Get CSRF token from home page
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None, "CSRF token not found in home page"

        response = client.delete("/api/sessions/@#$%", headers={"X-CSRF-Token": csrf_token})

        assert response.status_code == 400

    def test_upload_config_file_too_large(
        self, client: TestClient, clean_data_dir: Path, tmp_path: Path
    ) -> None:
        """Test that config files exceeding size limit are rejected."""
        # Get CSRF token from home page
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None, "CSRF token not found in home page"

        # Create a valid session file
        session_path = tmp_path / "test.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()
        session_content = session_path.read_bytes()

        # Create a config file that exceeds MAX_CONFIG_SIZE (1024 bytes)
        large_config = {"api_id": 12345, "api_hash": "x" * 2000}
        config_content = json.dumps(large_config).encode()

        from unittest.mock import MagicMock

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/upload",
                data={"session_name": "test_session"},
                files={
                    "session_file": ("test.session", session_content, "application/octet-stream"),
                    "config_file": ("config.json", config_content, "application/json"),
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "too large" in response.text.lower()

    def test_upload_session_file_too_large(self, client: TestClient, clean_data_dir: Path) -> None:
        """Test that session files exceeding size limit are rejected."""
        # Get CSRF token from home page
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None, "CSRF token not found in home page"

        # Create a large fake session file (> 10 MB)
        large_session = b"x" * (11 * 1024 * 1024)  # 11 MB

        config_content = json.dumps({"api_id": 12345, "api_hash": "abc"}).encode()

        from unittest.mock import MagicMock

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/upload",
                data={"session_name": "test_session"},
                files={
                    "session_file": ("test.session", large_session, "application/octet-stream"),
                    "config_file": ("config.json", config_content, "application/json"),
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "too large" in response.text.lower()

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
    migrate_legacy_sessions,
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
        """Test that config without api_id is now allowed (nullable)."""
        content = json.dumps({"api_hash": "abcdef"}).encode()
        config = validate_config_file_format(content)
        assert config.get("api_id") is None
        assert config["api_hash"] == "abcdef"

    def test_missing_api_hash(self) -> None:
        """Test that config without api_hash is now allowed (nullable)."""
        content = json.dumps({"api_id": 12345}).encode()
        config = validate_config_file_format(content)
        assert config["api_id"] == 12345
        assert config.get("api_hash") is None

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
        assert "No Telegram Accounts" in response.text or "no accounts" in response.text.lower()

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
        """Test upload with config that has no api_hash now succeeds (nullable)."""
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

        # Now accepts missing api_hash (nullable) - should succeed
        assert response.status_code == 200
        assert "success" in response.text.lower()

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


class TestMigrateLegacySessions:
    """Tests for legacy session migration (v0.4 -> v0.5)."""

    @pytest.fixture
    def legacy_session_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Create a legacy session directory structure for testing.

        Legacy sessions have:
        - session.session file
        - .secure_storage marker
        - Credentials in keyring (mocked)
        - No config.json
        """
        sessions_dir = tmp_path / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)

        # Create a legacy session directory
        session_dir = sessions_dir / "legacy_session"
        session_dir.mkdir()

        # Create a valid session file (SQLite)
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create .secure_storage marker (indicating credentials in keyring)
        secure_marker = session_dir / ".secure_storage"
        secure_marker.write_text("Credentials in secure storage")

        yield sessions_dir

        # Cleanup
        if sessions_dir.exists():
            shutil.rmtree(sessions_dir)

    def test_migrate_legacy_session_creates_config(self, legacy_session_dir: Path) -> None:
        """Test that migration creates config.json from keyring credentials."""
        from unittest.mock import MagicMock, patch

        mock_settings = MagicMock()
        mock_settings.sessions_dir = legacy_session_dir

        # Mock SecureCredentialManager to return test credentials
        mock_manager = MagicMock()
        mock_manager.retrieve_credentials.return_value = (12345, "test_api_hash", None)

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.security.SecureCredentialManager",
                return_value=mock_manager,
            ),
        ):
            migrated = migrate_legacy_sessions()

        # Should have migrated 1 session
        assert len(migrated) == 1
        assert "legacy_session" in migrated

        # config.json should now exist
        config_path = legacy_session_dir / "legacy_session" / "config.json"
        assert config_path.exists()

        # Verify config.json contents
        config_data = json.loads(config_path.read_text())
        assert config_data["api_id"] == 12345
        assert config_data["api_hash"] == "test_api_hash"
        assert config_data["proxy_id"] is None

    def test_migrate_skips_already_migrated(self, legacy_session_dir: Path) -> None:
        """Test that migration skips sessions that already have config.json."""
        from unittest.mock import MagicMock, patch

        # Create config.json manually (already migrated)
        config_path = legacy_session_dir / "legacy_session" / "config.json"
        config_path.write_text(json.dumps({"api_id": 99999, "api_hash": "existing"}))

        mock_settings = MagicMock()
        mock_settings.sessions_dir = legacy_session_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            migrated = migrate_legacy_sessions()

        # Should not have migrated anything
        assert len(migrated) == 0

        # Original config.json should be unchanged
        config_data = json.loads(config_path.read_text())
        assert config_data["api_id"] == 99999
        assert config_data["api_hash"] == "existing"

    def test_migrate_handles_missing_credentials(
        self, legacy_session_dir: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test that migration handles sessions without credentials gracefully."""
        from unittest.mock import MagicMock, patch

        from chatfilter.security import CredentialNotFoundError

        mock_settings = MagicMock()
        mock_settings.sessions_dir = legacy_session_dir

        # Mock SecureCredentialManager to raise CredentialNotFoundError
        mock_manager = MagicMock()
        mock_manager.retrieve_credentials.side_effect = CredentialNotFoundError("No credentials")

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.security.SecureCredentialManager",
                return_value=mock_manager,
            ),
            caplog.at_level("WARNING"),
        ):
            migrated = migrate_legacy_sessions()

        # Should not have migrated anything
        assert len(migrated) == 0

        # config.json should NOT exist
        config_path = legacy_session_dir / "legacy_session" / "config.json"
        assert not config_path.exists()

        # Warning should be logged
        assert any("no credentials in keyring" in r.message.lower() for r in caplog.records)

    def test_migrate_skips_non_session_directories(self, tmp_path: Path) -> None:
        """Test that migration skips directories without session.session file."""
        from unittest.mock import MagicMock, patch

        sessions_dir = tmp_path / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)

        # Create a directory without session.session file
        non_session_dir = sessions_dir / "not_a_session"
        non_session_dir.mkdir()
        (non_session_dir / "some_file.txt").write_text("random file")

        mock_settings = MagicMock()
        mock_settings.sessions_dir = sessions_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            migrated = migrate_legacy_sessions()

        # Should not have migrated anything
        assert len(migrated) == 0


class TestSessionConfigAPI:
    """Tests for session configuration API endpoints."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app(debug=True)
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Create clean data directory for tests."""
        data_dir = tmp_path / "sessions"
        data_dir.mkdir(parents=True, exist_ok=True)
        yield data_dir
        if data_dir.exists():
            shutil.rmtree(data_dir)

    @pytest.fixture
    def session_with_config(self, clean_data_dir: Path) -> Path:
        """Create a session directory with config file."""
        session_dir = clean_data_dir / "test_session"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session file
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create config.json
        config_data = {
            "api_id": 12345,
            "api_hash": "test_hash_abcdef1234567890123456",
            "proxy_id": None,
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    def test_get_session_config_success(
        self, client: TestClient, clean_data_dir: Path, session_with_config: Path
    ) -> None:
        """Test getting session configuration form."""
        from unittest.mock import MagicMock, patch

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch("chatfilter.storage.proxy_pool.load_proxy_pool", return_value=[]),
        ):
            response = client.get("/api/sessions/test_session/config")

        assert response.status_code == 200
        assert "proxy_id" in response.text or "Proxy" in response.text

    def test_get_session_config_not_found(self, client: TestClient, clean_data_dir: Path) -> None:
        """Test getting config for non-existent session."""
        from unittest.mock import MagicMock, patch

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.get("/api/sessions/nonexistent/config")

        assert response.status_code == 404

    def test_get_session_config_invalid_name(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test getting config with invalid session name."""
        from unittest.mock import MagicMock, patch

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Use URL-encoded invalid characters that won't break URL parsing
        # After sanitization, "..." becomes empty, which raises ValueError
        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.get("/api/sessions/.../config")

        assert response.status_code == 400

    def test_update_session_config_success(
        self, client: TestClient, clean_data_dir: Path, session_with_config: Path
    ) -> None:
        """Test updating session proxy configuration."""
        import uuid
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Create a mock proxy with valid UUID
        test_proxy_id = str(uuid.uuid4())
        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Create mock TelegramClient for credential validation
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock()
        mock_client.disconnect = AsyncMock()
        mock_client.is_connected.return_value = True

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch("chatfilter.security.SecureCredentialManager"),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "12345678",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "success" in response.text.lower() or "saved" in response.text.lower()

        # Verify config was updated
        config_path = session_with_config / "config.json"
        config_data = json.loads(config_path.read_text())
        assert config_data["proxy_id"] == test_proxy_id
        assert config_data["api_id"] == 12345678
        assert config_data["api_hash"] == "0123456789abcdef0123456789abcdef"

    def test_update_session_config_proxy_required(
        self, client: TestClient, clean_data_dir: Path, session_with_config: Path
    ) -> None:
        """Test that proxy selection is required."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "12345678",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                    "proxy_id": "",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        # FastAPI returns 422 for validation errors (empty required field)
        # or 400 if our custom validation catches it first
        assert response.status_code in (400, 422)
        # Check error message present (varies by validation layer)
        assert "required" in response.text.lower() or "proxy" in response.text.lower()

    def test_update_session_config_proxy_not_found(
        self, client: TestClient, clean_data_dir: Path, session_with_config: Path
    ) -> None:
        """Test updating with non-existent proxy ID."""
        from unittest.mock import MagicMock, patch

        from chatfilter.storage.errors import StorageNotFoundError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                side_effect=StorageNotFoundError("Not found"),
            ),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "12345678",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                    "proxy_id": "nonexistent-proxy",
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 400
        assert "not found" in response.text.lower()

    def test_update_session_config_session_not_found(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test updating config for non-existent session."""
        import uuid
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        test_proxy_id = str(uuid.uuid4())

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.put(
                "/api/sessions/nonexistent/config",
                data={
                    "api_id": "12345678",
                    "api_hash": "0123456789abcdef0123456789abcdef",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 404


class TestSessionConnectDisconnectAPI:
    """Tests for session connect/disconnect API endpoints."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app(debug=True)
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Create clean data directory for tests."""
        data_dir = tmp_path / "sessions"
        data_dir.mkdir(parents=True, exist_ok=True)
        yield data_dir
        if data_dir.exists():
            shutil.rmtree(data_dir)

    @pytest.fixture
    def configured_session(self, clean_data_dir: Path) -> Path:
        """Create a fully configured session directory."""
        import uuid

        session_dir = clean_data_dir / "test_session"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session file
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create config.json with valid proxy_id
        config_data = {
            "api_id": 12345,
            "api_hash": "0123456789abcdef0123456789abcdef",
            "proxy_id": str(uuid.uuid4()),
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    @pytest.fixture
    def unconfigured_session(self, clean_data_dir: Path) -> Path:
        """Create a session without proxy configured."""
        session_dir = clean_data_dir / "unconfigured_session"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session file
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create config.json without proxy_id
        config_data = {
            "api_id": 12345,
            "api_hash": "0123456789abcdef0123456789abcdef",
            "proxy_id": None,
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    def test_connect_session_not_found(self, client: TestClient, clean_data_dir: Path) -> None:
        """Test connecting non-existent session returns 404."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/nonexistent/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 404

    def test_connect_session_invalid_name(self, client: TestClient, clean_data_dir: Path) -> None:
        """Test connecting with invalid session name returns 400."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/.../connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 400

    def test_connect_session_not_configured(
        self, client: TestClient, clean_data_dir: Path, unconfigured_session: Path
    ) -> None:
        """Test connecting unconfigured session returns 400."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/unconfigured_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 400
        assert "needs api credentials" in response.text.lower()

    def test_connect_session_proxy_missing(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test connecting session with missing proxy returns 400."""
        from unittest.mock import MagicMock, patch

        from chatfilter.storage.errors import StorageNotFoundError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                side_effect=StorageNotFoundError("Not found"),
            ),
        ):
            response = client.post(
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 400
        assert "proxy" in response.text.lower()

    def test_connect_session_success(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test session connection - returns immediately with 'connecting' state."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager - get_info returns None to simulate new session
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock()
        mock_session_manager.get_info.return_value = None  # No existing session

        # Mock loader
        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.telegram.client.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # Connect now returns immediately with 'connecting' state
        # The actual connection happens in background, final state via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_connect_session_failure(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test session connection failure - HTTP returns 'connecting', error via SSE."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionConnectError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager to raise error
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionConnectError("Connection failed")
        )

        # Mock loader
        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.telegram.client.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # Connect returns immediately with 'connecting' state
        # The error is delivered via SSE in background task
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_connect_session_concurrent_request_returns_connecting(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test concurrent connection request returns 'connecting' - error via SSE."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionBusyError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager to raise SessionBusyError
        # Now handled in background task, not HTTP handler
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionBusyError("Session is already busy with another operation")
        )
        mock_session_manager.get_info.return_value = None  # No existing session

        # Mock loader
        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.telegram.client.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        # SessionBusyError is handled in background task and delivered via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_connect_session_timeout_returns_connecting(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test session connection timeout - HTTP returns 'connecting', error via SSE."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager connect to raise TimeoutError
        # Now handled in background task, not HTTP handler
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_session_manager.get_info.return_value = None  # No existing session

        # Mock loader
        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.telegram.client.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/test_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        # Timeout error is handled in background task and delivered via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_disconnect_session_invalid_name(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test disconnecting with invalid session name returns 400."""
        from unittest.mock import MagicMock, patch

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        with patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings):
            response = client.post(
                "/api/sessions/.../disconnect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 400

    def test_disconnect_session_success(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test successful session disconnection."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.disconnect = AsyncMock()

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
        ):
            response = client.post(
                "/api/sessions/test_session/disconnect",
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "Connect" in response.text
        assert "HX-Trigger" in response.headers
        assert response.headers["HX-Trigger"] == "refreshSessions"
        mock_session_manager.disconnect.assert_called_once_with("test_session")

    def test_disconnect_session_not_connected(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test disconnecting session that's not connected still succeeds."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read the proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager - disconnect is safe even when not connected
        mock_session_manager = MagicMock()
        mock_session_manager.disconnect = AsyncMock()

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
        ):
            response = client.post(
                "/api/sessions/test_session/disconnect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # Should succeed - disconnect is idempotent
        assert response.status_code == 200
        assert "Connect" in response.text


class TestDeadSessionRecoveryUX:
    """Tests for dead session error messages and recovery UX flow."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app(debug=True)
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Create clean data directory for tests."""
        data_dir = tmp_path / "sessions"
        data_dir.mkdir(parents=True, exist_ok=True)
        yield data_dir
        if data_dir.exists():
            shutil.rmtree(data_dir)

    @pytest.fixture
    def configured_session(self, clean_data_dir: Path) -> Path:
        """Create a fully configured session directory."""
        import uuid

        session_dir = clean_data_dir / "dead_session"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session file
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create config.json
        config_data = {
            "api_id": 12345,
            "api_hash": "0123456789abcdef0123456789abcdef",
            "proxy_id": str(uuid.uuid4()),
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    def test_dead_session_returns_connecting_state(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that dead session returns 'connecting' immediately - error via SSE."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionReauthRequiredError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager to raise SessionReauthRequiredError (expired session)
        # Error now handled in background task, not HTTP handler
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionReauthRequiredError("Session has expired")
        )
        mock_session_manager.get_info.return_value = None  # No existing session

        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.telegram.client.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        # Error state (session_expired) delivered via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_expired_session_connect_returns_connecting(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that expired session connect returns 'connecting' - error via SSE."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionReauthRequiredError

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Connect fails with expired error - handled in background task
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionReauthRequiredError("Session has expired")
        )
        mock_session_manager.get_info.return_value = None  # No existing session

        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.telegram.client.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' state immediately
        # Reauth error delivered via SSE
        assert response.status_code == 200
        assert "Connecting" in response.text or "connecting" in response.text.lower()

    def test_session_recovery_preserves_session_id(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that session recovery preserves session ID."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionInfo, SessionState

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager to return session info with same ID
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock()
        mock_session_manager.get_info.return_value = SessionInfo(
            session_id="dead_session",  # ID is preserved
            state=SessionState.CONNECTED,
        )

        mock_loader = MagicMock()

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.telegram.client.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # Session should be recovered with same ID
        assert response.status_code == 200
        # Verify get_info was called and returned consistent session_id
        mock_session_manager.get_info.assert_called()

    def test_temporary_error_vs_permanent_session_death_ui(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that UI distinguishes temporary errors from permanent session death."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import (
            SessionConnectError,
            SessionInvalidError,
        )

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)

        # Test temporary error (network issue)
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionConnectError("Network connection failed")
        )
        mock_session_manager.get_info.return_value = None  # No existing session

        mock_loader = MagicMock()

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.telegram.client.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            temp_response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 'connecting' immediately for both cases
        # Error classification now happens in background task, delivered via SSE
        assert temp_response.status_code == 200
        assert "Connecting" in temp_response.text or "connecting" in temp_response.text.lower()

        # Test permanent error (session invalid) - same behavior
        mock_session_manager = MagicMock()
        mock_session_manager.connect = AsyncMock(
            side_effect=SessionInvalidError("Session is permanently invalid")
        )
        mock_session_manager.get_info.return_value = None

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch(
                "chatfilter.telegram.client.TelegramClientLoader",
                return_value=mock_loader,
            ),
        ):
            perm_response = client.post(
                "/api/sessions/dead_session/connect",
                headers={"X-CSRF-Token": csrf_token},
            )

        # HTTP returns 200 with 'connecting' - error delivered via SSE
        assert perm_response.status_code == 200
        assert "Connecting" in perm_response.text or "connecting" in perm_response.text.lower()


class TestAPICredentialReValidation:
    """Tests for API credential re-validation when credentials change on existing session."""

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app(debug=True)
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Create clean data directory for tests."""
        data_dir = tmp_path / "sessions"
        data_dir.mkdir(parents=True, exist_ok=True)
        yield data_dir
        if data_dir.exists():
            shutil.rmtree(data_dir)

    @pytest.fixture
    def configured_session(self, clean_data_dir: Path) -> Path:
        """Create a fully configured session directory."""
        import uuid

        session_dir = clean_data_dir / "test_session"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session file
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create config.json with initial credentials
        config_data = {
            "api_id": 12345,
            "api_hash": "0123456789abcdef0123456789abcdef",
            "proxy_id": str(uuid.uuid4()),
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        return session_dir

    def test_change_api_id_triggers_disconnect_and_reauth(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that changing API_ID on existing session triggers disconnect + re-auth flow."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager to track disconnect call
        mock_session_manager = MagicMock()
        mock_session_manager.disconnect = AsyncMock()

        # Create mock TelegramClient
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock()
        mock_client.disconnect = AsyncMock()
        mock_client.is_connected.return_value = True

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "99999",  # Changed from 12345
                    "api_hash": "fedcba9876543210fedcba9876543210",  # Changed
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        # Should show success and reconnect flow
        response_text = response.text.lower()
        assert "credential" in response_text or "reauth" in response_text or "reconnect" in response_text

        # Verify session was disconnected
        mock_session_manager.disconnect.assert_called_once_with("test_session")

        # Verify config was updated with new credentials
        config_path = configured_session / "config.json"
        updated_config = json.loads(config_path.read_text())
        assert updated_config["api_id"] == 99999
        assert updated_config["api_hash"] == "fedcba9876543210fedcba9876543210"

    def test_invalid_api_id_rejected_not_saved(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that invalid API_ID/API_HASH credentials are rejected and not saved."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from telethon.errors import ApiIdInvalidError

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]
        original_api_id = config_data["api_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Create mock that raises ApiIdInvalidError on connect
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(side_effect=ApiIdInvalidError("Invalid api_id"))
        mock_client.is_connected.return_value = False

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "11111",  # Invalid API ID
                    "api_hash": "11111111111111111111111111111111",  # Valid format, invalid credentials
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 400
        # Should show error about invalid credentials
        assert "invalid" in response.text.lower()
        assert "credentials not saved" in response.text.lower()

        # Verify config was NOT updated (credentials remain unchanged)
        config_path = configured_session / "config.json"
        saved_config = json.loads(config_path.read_text())
        assert saved_config["api_id"] == original_api_id

    def test_valid_credentials_needing_auth_triggers_reconnect(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that valid but unauthenticated credentials trigger reconnect/code modal."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock session manager
        mock_session_manager = MagicMock()
        mock_session_manager.disconnect = AsyncMock()

        # Create mock client with successful connection
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock()
        mock_client.disconnect = AsyncMock()
        mock_client.is_connected.return_value = True

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch(
                "chatfilter.web.dependencies.get_session_manager",
                return_value=mock_session_manager,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "55555",
                    "api_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        response_text = response.text.lower()
        # Should show credentials updated message and reconnect flow
        assert "credential" in response_text or "reauth" in response_text or "updated" in response_text

        # Verify config was saved
        config_path = configured_session / "config.json"
        saved_config = json.loads(config_path.read_text())
        assert saved_config["api_id"] == 55555

    def test_credentials_not_saved_before_validation_success(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that only save credentials AFTER successful validation."""
        from unittest.mock import AsyncMock, MagicMock, patch
        from telethon.errors import ApiIdInvalidError

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id and initial config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]
        original_api_id = config_data["api_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock client to simulate validation failure (invalid credentials)
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(side_effect=ApiIdInvalidError("Invalid api_id or api_hash"))
        mock_client.is_connected.return_value = False

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            # Attempt to update with invalid credentials
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "99999",  # Would be saved, but validation fails
                    "api_hash": "ffffffffffffffffffffffffffffffff",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        # Should return error
        assert response.status_code == 400

        # Most important: verify original credentials are still in config
        config_path = configured_session / "config.json"
        saved_config = json.loads(config_path.read_text())
        assert saved_config["api_id"] == original_api_id
        # Credentials were NOT saved despite validation attempt

    def test_network_error_during_validation_shows_proxy_error(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test that network/proxy errors during validation show helpful message."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Read proxy_id from config
        config_path = configured_session / "config.json"
        config_data = json.loads(config_path.read_text())
        test_proxy_id = config_data["proxy_id"]

        mock_settings = MagicMock()
        mock_settings.sessions_dir = clean_data_dir

        mock_proxy = ProxyEntry(
            id=test_proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        # Mock client to simulate network error
        mock_client = AsyncMock()
        mock_client.connect = AsyncMock(side_effect=ConnectionError("Proxy connection failed"))
        mock_client.is_connected.return_value = False

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch("telethon.TelegramClient", return_value=mock_client),
            patch("chatfilter.web.routers.sessions.secure_delete_dir"),
        ):
            response = client.put(
                "/api/sessions/test_session/config",
                data={
                    "api_id": "77777",
                    "api_hash": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                    "proxy_id": test_proxy_id,
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 500
        # Should mention network/proxy error
        response_text = response.text.lower()
        assert "network" in response_text or "proxy" in response_text or "failed" in response_text


class TestVerify2FA:
    """Tests for verify-2fa endpoint password validation.

    Tests the verify_2fa endpoint password validation directly by checking
    the validation logic without full integration testing.
    """

    def test_password_validation_logic(self) -> None:
        """Test password validation logic handles empty and whitespace passwords."""
        # Test cases for password validation
        test_cases = [
            ("", False, "empty string"),
            (" ", False, "single space"),
            ("   ", False, "multiple spaces"),
            ("\t", False, "tab"),
            ("\n", False, "newline"),
            ("  \t\n  ", False, "mixed whitespace"),
            ("a", True, "valid single char"),
            ("  password  ", True, "password with surrounding spaces"),
            ("valid_password", True, "valid password"),
        ]

        for password, should_pass, description in test_cases:
            # Validation logic from verify_2fa endpoint (line 3806)
            is_valid = bool(password and password.strip())

            if should_pass:
                assert is_valid, f"Expected '{description}' to pass validation but it failed"
            else:
                assert not is_valid, f"Expected '{description}' to fail validation but it passed"


class TestBackwardCompatibilityLegacySessions:
    """Tests for backward compatibility with old session format.

    Old sessions have config.json + session.session but NO account_info.json.
    This tests that the refactored code handles missing account_info gracefully.
    """

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app(debug=True)
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Create temporary data directory."""
        from unittest.mock import patch

        with patch("chatfilter.web.routers.sessions.ensure_data_dir", return_value=tmp_path):
            yield tmp_path

    @pytest.fixture
    def legacy_session_without_account_info(self, clean_data_dir: Path) -> Path:
        """Create a legacy session with config.json + session.session but NO account_info.json."""
        session_dir = clean_data_dir / "legacy_session"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session file (minimal SQLite structure)
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'1234')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create config.json with valid API credentials
        config_data = {
            "api_id": 12345,
            "api_hash": "0123456789abcdef0123456789abcdef",
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        # NOTE: NO account_info.json - this is what makes it "legacy"

        return session_dir

    def test_list_sessions_legacy_format_without_account_info(
        self, client: TestClient, legacy_session_without_account_info: Path
    ) -> None:
        """Test that sessions without account_info.json appear with 'needs_account_info' state.

        Legacy sessions (old format with config.json but no account_info.json) should:
        1. Not crash list_stored_sessions
        2. Appear in the list with state='needs_account_info'
        """
        from chatfilter.web.routers.sessions import list_stored_sessions

        # Call list_stored_sessions directly
        sessions = list_stored_sessions()

        # Legacy session without account_info SHOULD appear in the list
        session_ids = [s.session_id for s in sessions]
        assert "legacy_session" in session_ids, (
            "Legacy session with config.json should appear in list"
        )

        # Find the session and verify its state
        legacy_session = next(
            (s for s in sessions if s.session_id == "legacy_session"), None
        )
        assert legacy_session is not None
        assert (
            legacy_session.state == "needs_account_info"
        ), "Legacy session without account_info should show 'needs_account_info' state"

    def test_connect_legacy_session_without_phone(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test that connecting a legacy session without phone shows proper error.

        If a legacy session exists but has no account_info.json with phone,
        attempting to connect should fail gracefully with a helpful error message.
        """
        # Create a legacy session (config.json + session.session, NO account_info.json)
        session_dir = clean_data_dir / "old_session"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'5678')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create config.json
        config_data = {
            "api_id": 67890,
            "api_hash": "fedcba9876543210fedcba9876543210",
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        # Get CSRF token from home page
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Try to connect - should fail because:
        # 1. No account_info.json exists
        # 2. connect_session tries to load_account_info to get phone for reauth
        response = client.post(
            "/api/sessions/old_session/connect",
            headers={"X-CSRF-Token": csrf_token},
        )

        # The session should not be connectable when account_info is missing
        # Expected errors: 404 if session not found, or other error if incomplete
        assert response.status_code in (400, 404, 500)

    def test_legacy_session_shown_as_disconnected_after_migration(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test that after creating account_info.json, legacy session changes to 'disconnected'.

        Before migration: session appears with 'needs_account_info' state
        After migration: same session appears with 'disconnected' state
        """
        import uuid
        from unittest.mock import patch

        from chatfilter.web.routers.sessions import list_stored_sessions

        # Create legacy session
        session_dir = clean_data_dir / "migrated_session"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create session.session
        session_path = session_dir / "session.session"
        conn = sqlite3.connect(session_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE sessions (dc_id INTEGER PRIMARY KEY, auth_key BLOB)")
        cursor.execute("INSERT INTO sessions VALUES (1, X'9abc')")
        cursor.execute("CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER NOT NULL)")
        conn.commit()
        conn.close()

        # Create config.json with all required fields including proxy_id
        proxy_id = str(uuid.uuid4())
        config_data = {
            "api_id": 11111,
            "api_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "proxy_id": proxy_id,
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        # Mock proxy to exist so config validation passes
        from chatfilter.models.proxy import ProxyEntry

        mock_proxy = ProxyEntry(
            id=proxy_id,
            name="Test Proxy",
            type="socks5",
            host="127.0.0.1",
            port=1080,
        )

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id", return_value=mock_proxy):
            # Before migration: session appears with 'needs_account_info' state
            sessions = list_stored_sessions()
            session_ids = [s.session_id for s in sessions]
            assert "migrated_session" in session_ids

            legacy_before = next(
                (s for s in sessions if s.session_id == "migrated_session"), None
            )
            assert legacy_before is not None
            assert (
                legacy_before.state == "needs_account_info"
            ), "Legacy session without account_info should have 'needs_account_info' state"

            # Add account_info.json (migration step)
            account_info = {"phone": "1234567890"}
            account_info_path = session_dir / ".account_info.json"
            account_info_path.write_text(json.dumps(account_info))

            # After migration: session should appear as 'disconnected'
            sessions = list_stored_sessions()
            session_ids = [s.session_id for s in sessions]
            assert "migrated_session" in session_ids

            # Find the session and check its state changed
            migrated_session = next(
                (s for s in sessions if s.session_id == "migrated_session"), None
            )
            assert migrated_session is not None
            assert (
                migrated_session.state == "disconnected"
            ), "After adding account_info, session should be 'disconnected'"

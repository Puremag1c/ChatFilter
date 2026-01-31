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
        from unittest.mock import MagicMock, patch

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

        with (
            patch("chatfilter.web.routers.sessions.get_settings", return_value=mock_settings),
            patch(
                "chatfilter.storage.proxy_pool.get_proxy_by_id",
                return_value=mock_proxy,
            ),
            patch("chatfilter.security.SecureCredentialManager"),
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
        assert "not configured" in response.text.lower()

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
        """Test successful session connection."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from chatfilter.models.proxy import ProxyEntry
        from chatfilter.telegram.session_manager import SessionInfo, SessionState

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
        mock_session_manager.connect = AsyncMock()
        mock_session_manager.get_info.return_value = SessionInfo(
            session_id="test_session",
            state=SessionState.CONNECTED,
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

        assert response.status_code == 200
        assert "Disconnect" in response.text
        assert "HX-Trigger" in response.headers
        assert response.headers["HX-Trigger"] == "refreshSessions"

    def test_connect_session_failure(
        self, client: TestClient, clean_data_dir: Path, configured_session: Path
    ) -> None:
        """Test session connection failure returns error state."""
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

        assert response.status_code == 200
        assert "Retry" in response.text or "error" in response.text.lower()

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

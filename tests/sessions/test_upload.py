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
    validate_account_info_json,
    validate_config_file_format,
    validate_session_file_format,
)

from .conftest import extract_csrf_token


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


class TestSessionImport:
    """Tests for session import endpoints (dual file upload)."""

    @staticmethod
    def _create_valid_session_file() -> bytes:
        """Create a valid Telethon session file (SQLite) with required tables and data."""
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".session", delete=False) as session_f:
            conn = sqlite3.connect(session_f.name)
            # Create both required tables: sessions and entities
            conn.execute(
                "CREATE TABLE sessions (dc_id INTEGER, server_address TEXT, port INTEGER, auth_key BLOB)"
            )
            conn.execute(
                "CREATE TABLE entities (id INTEGER PRIMARY KEY, hash INTEGER, username TEXT, phone TEXT, name TEXT)"
            )
            # Add at least one row to sessions table to pass "non-empty" validation
            conn.execute(
                "INSERT INTO sessions (dc_id, server_address, port, auth_key) VALUES (?, ?, ?, ?)",
                (2, "149.154.167.50", 443, b"dummy_auth_key_12345678901234567890123456"),
            )
            conn.commit()
            conn.close()
            return Path(session_f.name).read_bytes()

    @pytest.fixture
    def client(self) -> TestClient:
        """Create test client."""
        app = create_app(debug=True)
        return TestClient(app)

    @pytest.fixture
    def clean_data_dir(self, tmp_path: Path) -> Iterator[Path]:
        """Create clean data directory for tests."""
        from unittest.mock import patch

        data_dir = tmp_path / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        with patch("chatfilter.web.routers.sessions.helpers.get_settings") as mock_settings_fn:
            from unittest.mock import MagicMock

            mock_settings = MagicMock()
            mock_settings.sessions_dir = data_dir
            mock_settings_fn.return_value = mock_settings
            yield data_dir

    def test_validate_import_session_success(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test successful validation with both session and JSON files."""
        # Create valid session file (SQLite)
        session_content = self._create_valid_session_file()

        # Create valid JSON file
        json_data = {"phone": "+79001234567", "first_name": "John", "twoFA": "secret"}
        json_content = json.dumps(json_data).encode()

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Send validation request
        response = client.post(
            "/api/sessions/import/validate",
            files={
                "session_file": ("test.session", session_content, "application/octet-stream"),
                "json_file": ("test.json", json_content, "application/json"),
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "success" in response.text.lower() or response.text == ""

    def test_validate_import_session_invalid_json_missing_phone(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test validation fails when JSON missing phone field."""
        # Valid session file
        session_content = self._create_valid_session_file()

        # Invalid JSON (missing phone)
        json_data = {"first_name": "John"}
        json_content = json.dumps(json_data).encode()

        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        response = client.post(
            "/api/sessions/import/validate",
            files={
                "session_file": ("test.session", session_content, "application/octet-stream"),
                "json_file": ("test.json", json_content, "application/json"),
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "phone" in response.text.lower()

    def test_validate_import_session_invalid_phone_format(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test validation fails with invalid phone format."""
        # Valid session file
        session_content = self._create_valid_session_file()

        # Invalid phone format (too short for E.164)
        json_data = {"phone": "+123"}
        json_content = json.dumps(json_data).encode()

        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        response = client.post(
            "/api/sessions/import/validate",
            files={
                "session_file": ("test.session", session_content, "application/octet-stream"),
                "json_file": ("test.json", json_content, "application/json"),
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "phone" in response.text.lower() or "must start with" in response.text.lower()

    def test_validate_import_session_extracts_api_credentials(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test that api_id/api_hash are extracted from JSON and included in validation response."""
        # Create valid session file (SQLite)
        session_content = self._create_valid_session_file()

        # Create valid JSON file with api_id and api_hash (as app_id/app_hash per TelegramExpert format)
        json_data = {
            "phone": "+79001234567",
            "first_name": "John",
            "app_id": 12345678,
            "app_hash": "0123456789abcdef0123456789abcdef",
        }
        json_content = json.dumps(json_data).encode()

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        # Send validation request
        response = client.post(
            "/api/sessions/import/validate",
            files={
                "session_file": ("test.session", session_content, "application/octet-stream"),
                "json_file": ("test.json", json_content, "application/json"),
            },
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "success" in response.text.lower()
        # Verify that data attributes are present in the response
        assert 'data-api-id="12345678"' in response.text
        assert 'data-api-hash="0123456789abcdef0123456789abcdef"' in response.text

    def test_save_import_session_success(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test successful session import with JSON account info."""
        from unittest.mock import MagicMock, patch

        # Create valid session file
        session_content = self._create_valid_session_file()

        # Create JSON with all fields
        json_data = {
            "phone": "+79001234567",
            "first_name": "John",
            "last_name": "Doe",
            "twoFA": "secret123",
        }
        json_content = json.dumps(json_data).encode()

        # Mock proxy validation (correct import path)
        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get_proxy:
            mock_get_proxy.return_value = MagicMock()

            home_response = client.get("/")
            csrf_token = extract_csrf_token(home_response.text)
            assert csrf_token is not None

            response = client.post(
                "/api/sessions/import/save",
                data={
                    "session_name": "test_import",
                    "api_id": "12345",
                    "api_hash": "abcd1234abcd1234abcd1234abcd1234",
                    "proxy_id": "test-proxy",
                },
                files={
                    "session_file": ("test.session", session_content, "application/octet-stream"),
                    "json_file": ("test.json", json_content, "application/json"),
                },
                headers={"X-CSRF-Token": csrf_token},
            )

            assert response.status_code == 200

            # Verify session was created
            session_dir = clean_data_dir / "test_import"
            assert session_dir.exists()

            # Verify account_info.json contains phone
            account_info_path = session_dir / ".account_info.json"
            assert account_info_path.exists()
            account_info = json.loads(account_info_path.read_text())
            assert account_info["phone"] == "+79001234567"
            assert account_info["first_name"] == "John"
            assert account_info["last_name"] == "Doe"
            # 2FA should be encrypted (not plain text)
            assert "twoFA" not in account_info or account_info.get("twoFA") != "secret123"

    def test_save_import_session_duplicate_name(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test that duplicate session name is rejected."""
        from unittest.mock import MagicMock, patch

        # Create existing session
        existing_dir = clean_data_dir / "duplicate_test"
        existing_dir.mkdir()

        # Create valid session file
        session_content = self._create_valid_session_file()

        json_data = {"phone": "+79001234567"}
        json_content = json.dumps(json_data).encode()

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id") as mock_get_proxy:
            mock_get_proxy.return_value = MagicMock()

            home_response = client.get("/")
            csrf_token = extract_csrf_token(home_response.text)
            assert csrf_token is not None

            response = client.post(
                "/api/sessions/import/save",
                data={
                    "session_name": "duplicate_test",
                    "api_id": "12345",
                    "api_hash": "abcd1234abcd1234abcd1234abcd1234",
                    "proxy_id": "test-proxy",
                },
                files={
                    "session_file": ("test.session", session_content, "application/octet-stream"),
                    "json_file": ("test.json", json_content, "application/json"),
                },
                headers={"X-CSRF-Token": csrf_token},
            )

            assert response.status_code == 200
            assert "already exists" in response.text.lower() or "exist" in response.text.lower()



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


class TestValidateAccountInfoJson:
    """Tests for JSON account info validation."""

    def test_valid_json_minimal(self) -> None:
        """Test valid JSON with only required phone field."""
        json_data = {"phone": "+14385515736"}
        assert validate_account_info_json(json_data) is None

    def test_valid_json_all_fields(self) -> None:
        """Test valid JSON with all allowed fields."""
        json_data = {
            "phone": "+79001234567",
            "first_name": "John",
            "last_name": "Doe",
            "twoFA": "secret123",
        }
        assert validate_account_info_json(json_data) is None

    def test_valid_phone_without_plus(self) -> None:
        """Test valid phone without + prefix."""
        json_data = {"phone": "14385515736"}
        assert validate_account_info_json(json_data) is None

    def test_invalid_not_dict(self) -> None:
        """Test rejection of non-dict JSON (array)."""
        json_data = [{"phone": "+14385515736"}]
        error = validate_account_info_json(json_data)
        assert error is not None
        assert "object" in error.lower()

    def test_unknown_fields_accepted(self) -> None:
        """Test acceptance of unknown fields (TelegramExpert exports have 20+ fields)."""
        json_data = {
            "phone": "+14385515736",
            "app_id": "12345",
            "app_hash": "abcdef",
            "app_version": "1.0",
            "extra_field": "ignored",
        }
        error = validate_account_info_json(json_data)
        assert error is None  # Unknown fields should be accepted

    def test_invalid_nested_object(self) -> None:
        """Test rejection of nested objects."""
        json_data = {"phone": "+14385515736", "first_name": {"nested": "value"}}
        error = validate_account_info_json(json_data)
        assert error is not None
        assert "nested" in error.lower() or "first_name" in error

    def test_invalid_nested_array(self) -> None:
        """Test rejection of arrays in fields."""
        json_data = {"phone": "+14385515736", "last_name": ["array", "value"]}
        error = validate_account_info_json(json_data)
        assert error is not None
        assert "nested" in error.lower() or "last_name" in error

    def test_invalid_missing_phone(self) -> None:
        """Test rejection of missing phone field."""
        json_data = {"first_name": "John"}
        error = validate_account_info_json(json_data)
        assert error is not None
        assert "phone" in error.lower()

    def test_invalid_empty_phone(self) -> None:
        """Test rejection of empty phone field."""
        json_data = {"phone": ""}
        error = validate_account_info_json(json_data)
        assert error is not None
        assert "phone" in error.lower()

    def test_invalid_phone_format_letters(self) -> None:
        """Test rejection of phone with letters."""
        json_data = {"phone": "+1abc5515736"}
        error = validate_account_info_json(json_data)
        assert error is not None
        assert "format" in error.lower() or "invalid" in error.lower()

    def test_invalid_phone_too_short(self) -> None:
        """Test rejection of too short phone."""
        json_data = {"phone": "+12345"}
        error = validate_account_info_json(json_data)
        assert error is not None
        assert "format" in error.lower() or "invalid" in error.lower()

    def test_invalid_phone_too_long(self) -> None:
        """Test rejection of too long phone."""
        json_data = {"phone": "+1234567890123456789"}
        error = validate_account_info_json(json_data)
        assert error is not None
        assert "format" in error.lower() or "invalid" in error.lower()

    def test_invalid_phone_leading_zero(self) -> None:
        """Test rejection of phone starting with 0 after country code."""
        json_data = {"phone": "+0123456789"}
        error = validate_account_info_json(json_data)
        assert error is not None
        assert "format" in error.lower() or "invalid" in error.lower()






class TestDeleteSessionClearsFloodWait:
    """Test that deleting a session clears its FloodWait entry."""

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

        mock_settings = MagicMock()
        mock_settings.sessions_dir = test_data_dir

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            yield test_data_dir

        if test_data_dir.exists():
            shutil.rmtree(test_data_dir)

    def test_delete_session_clears_flood_wait_entry(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Deleting an account with an active FloodWait entry should clear it."""
        from chatfilter.telegram.flood_tracker import get_flood_tracker

        tracker = get_flood_tracker()
        session_name = "test_flood_session"

        # Setup: create session directory so delete doesn't 404
        session_dir = clean_data_dir / session_name
        session_dir.mkdir(parents=True)
        (session_dir / "session.session").write_bytes(b"fake")

        # Setup: record a FloodWait for this account
        tracker.record_flood_wait(session_name, 300)
        assert tracker.is_blocked(session_name) is True

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        response = client.delete(
            f"/api/sessions/{session_name}",
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        # FloodWait entry should be cleared
        assert tracker.is_blocked(session_name) is False
        assert tracker.get_wait_until(session_name) is None

        # Cleanup tracker state
        tracker.clear_account(session_name)

    def test_delete_session_without_flood_wait_no_error(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Deleting an account with no FloodWait entry should not raise errors."""
        from chatfilter.telegram.flood_tracker import get_flood_tracker

        tracker = get_flood_tracker()
        session_name = "test_no_flood_session"

        # Setup: create session directory
        session_dir = clean_data_dir / session_name
        session_dir.mkdir(parents=True)
        (session_dir / "session.session").write_bytes(b"fake")

        # Verify no FloodWait entry exists
        assert tracker.is_blocked(session_name) is False

        # Get CSRF token
        home_response = client.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None

        response = client.delete(
            f"/api/sessions/{session_name}",
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200


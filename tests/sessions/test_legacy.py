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
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
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

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
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
            patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings),
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

        with patch("chatfilter.web.routers.sessions.helpers.get_settings", return_value=mock_settings):
            migrated = migrate_legacy_sessions()

        # Should not have migrated anything
        assert len(migrated) == 0


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
    def clean_data_dir(self, tmp_path: Path, monkeypatch) -> Iterator[Path]:
        """Create temporary data directory."""
        # Use monkeypatch to ensure the mock persists for the test duration
        from unittest.mock import MagicMock

        mock_ensure_data_dir = MagicMock(return_value=tmp_path)
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.helpers.ensure_data_dir", mock_ensure_data_dir
        )
        yield tmp_path


    def test_list_stored_sessions_without_session_file(
        self, client: TestClient, clean_data_dir: Path
    ) -> None:
        """Test that sessions without session.session file appear with 'disconnected' state.

        A session that has config.json + account_info.json but NO session.session should:
        1. Appear in list_stored_sessions with state='disconnected'
        2. Have has_session_file=False
        3. Show in UI (not be filtered out)

        This covers the scenario where:
        - User uploaded config but hasn't connected yet
        - Session file was deleted/corrupted but metadata exists
        """
        from unittest.mock import patch

        from chatfilter.web.routers.sessions import list_stored_sessions

        # Create session directory with config.json and account_info.json, but NO session.session
        session_dir = clean_data_dir / "no_session_file"
        session_dir.mkdir(parents=True, exist_ok=True)

        # Create config.json with valid API credentials AND proxy_id
        config_data = {
            "api_id": 11111,
            "api_hash": "aaaabbbbccccddddeeeeffffgggghhh1",
            "proxy_id": "mock-proxy-id",
        }
        config_path = session_dir / "config.json"
        config_path.write_text(json.dumps(config_data))

        # Create account_info.json
        account_info = {"phone": "+79001234567"}
        account_info_path = session_dir / ".account_info.json"
        account_info_path.write_text(json.dumps(account_info))

        # NOTE: No session.session file created!

        # Mock get_proxy_by_id to avoid proxy lookup
        mock_proxy = type(
            "MockProxy",
            (),
            dict(
                id="mock-proxy-id",
                addr="127.0.0.1",
                port=1080,
            ),
        )

        with patch("chatfilter.storage.proxy_pool.get_proxy_by_id", return_value=mock_proxy):
            # Call list_stored_sessions directly
            sessions = list_stored_sessions()

            # Session SHOULD appear in the list
            session_ids = [s.session_id for s in sessions]
            assert "no_session_file" in session_ids, (
                "Session with config.json + account_info.json (no session.session) should appear in list"
            )

            # Find the session
            session = next(
                (s for s in sessions if s.session_id == "no_session_file"), None
            )
            assert session is not None

            # Verify state is 'disconnected' (ready to connect/authorize)
            assert session.state == "disconnected", (
                f"Session without session.session should be 'disconnected', got '{session.state}'"
            )

            # Verify has_session_file is False
            assert session.has_session_file is False, (
                "Session without session.session should have has_session_file=False"
            )



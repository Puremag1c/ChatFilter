"""Tests for sessions router."""

import json
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.web.app import create_app


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
        # Also patch the import in listing.py which imports from .io
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.io.ensure_data_dir", mock_ensure_data_dir
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
            {
                "id": "mock-proxy-id",
                "addr": "127.0.0.1",
                "port": 1080,
            },
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
            session = next((s for s in sessions if s.session_id == "no_session_file"), None)
            assert session is not None

            # Verify state is 'disconnected' (ready to connect/authorize)
            assert session.state == "disconnected", (
                f"Session without session.session should be 'disconnected', got '{session.state}'"
            )

            # Verify has_session_file is False
            assert session.has_session_file is False, (
                "Session without session.session should have has_session_file=False"
            )

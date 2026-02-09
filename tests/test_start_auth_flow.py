"""Tests for start_auth_flow validation."""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from chatfilter.web.app import create_app


@pytest.fixture
def app(monkeypatch):
    """Create app with mocked CSRF middleware."""
    # Mock CSRFProtectionMiddleware to pass through requests
    mock_middleware = MagicMock()

    async def passthrough_dispatch(request, call_next):
        return await call_next(request)

    mock_middleware.return_value.dispatch = passthrough_dispatch

    monkeypatch.setattr(
        "chatfilter.web.app.CSRFProtectionMiddleware",
        lambda app: app,  # No-op middleware
    )

    return create_app()


@pytest.fixture
def client(app):
    """Create test client."""
    return TestClient(app)


class TestStartAuthFlowValidation:
    """Tests for api_id/api_hash validation in start_auth_flow."""

    def test_valid_credentials_accepted(self, client, tmp_path, monkeypatch):
        """Test that valid api_id and api_hash are accepted."""
        # Mock ensure_data_dir to use tmp_path
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        response = client.post(
            "/api/sessions/auth/start",
            data={
                "session_name": "test_session",
                "phone": "+1234567890",
                "api_id": "123456",
                "api_hash": "0123456789abcdef0123456789abcdef",
            },
        )

        assert response.status_code == 200
        assert b"saved successfully" in response.content or b"success" in response.content

    def test_empty_credentials_accepted(self, client, tmp_path, monkeypatch):
        """Test that empty api_id and api_hash are accepted (SPEC allows this)."""
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        response = client.post(
            "/api/sessions/auth/start",
            data={
                "session_name": "test_session_no_creds",
                "phone": "+1234567890",
                # api_id and api_hash omitted
            },
        )

        assert response.status_code == 200
        assert b"saved successfully" in response.content or b"success" in response.content

    def test_api_id_without_api_hash_rejected(self, client, tmp_path, monkeypatch):
        """Test that api_id without api_hash is rejected."""
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        response = client.post(
            "/api/sessions/auth/start",
            data={
                "session_name": "test_session",
                "phone": "+1234567890",
                "api_id": "123456",
                # api_hash omitted
            },
        )

        assert response.status_code == 200
        assert b"Both API ID and API Hash are required" in response.content

    def test_api_hash_without_api_id_rejected(self, client, tmp_path, monkeypatch):
        """Test that api_hash without api_id is rejected."""
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        response = client.post(
            "/api/sessions/auth/start",
            data={
                "session_name": "test_session",
                "phone": "+1234567890",
                "api_hash": "0123456789abcdef0123456789abcdef",
                # api_id omitted
            },
        )

        assert response.status_code == 200
        assert b"Both API ID and API Hash are required" in response.content

    def test_zero_api_id_rejected(self, client, tmp_path, monkeypatch):
        """Test that api_id <= 0 is rejected."""
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        response = client.post(
            "/api/sessions/auth/start",
            data={
                "session_name": "test_session",
                "phone": "+1234567890",
                "api_id": "0",
                "api_hash": "0123456789abcdef0123456789abcdef",
            },
        )

        assert response.status_code == 200
        assert b"API ID must be a positive integer" in response.content

    def test_negative_api_id_rejected(self, client, tmp_path, monkeypatch):
        """Test that negative api_id is rejected."""
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        response = client.post(
            "/api/sessions/auth/start",
            data={
                "session_name": "test_session",
                "phone": "+1234567890",
                "api_id": "-123",
                "api_hash": "0123456789abcdef0123456789abcdef",
            },
        )

        assert response.status_code == 200
        assert b"API ID must be a positive integer" in response.content

    def test_invalid_api_hash_format_rejected(self, client, tmp_path, monkeypatch):
        """Test that invalid api_hash format is rejected."""
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        response = client.post(
            "/api/sessions/auth/start",
            data={
                "session_name": "test_session",
                "phone": "+1234567890",
                "api_id": "123456",
                "api_hash": "not-a-valid-hash",
            },
        )

        assert response.status_code == 200
        assert b"Invalid API hash format" in response.content

    def test_short_api_hash_rejected(self, client, tmp_path, monkeypatch):
        """Test that api_hash shorter than 32 chars is rejected."""
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        response = client.post(
            "/api/sessions/auth/start",
            data={
                "session_name": "test_session",
                "phone": "+1234567890",
                "api_id": "123456",
                "api_hash": "0123456789abcdef",  # 16 chars, not 32
            },
        )

        assert response.status_code == 200
        assert b"Invalid API hash format" in response.content

    def test_non_hex_api_hash_rejected(self, client, tmp_path, monkeypatch):
        """Test that api_hash with non-hex characters is rejected."""
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.ensure_data_dir",
            lambda: tmp_path,
        )

        response = client.post(
            "/api/sessions/auth/start",
            data={
                "session_name": "test_session",
                "phone": "+1234567890",
                "api_id": "123456",
                "api_hash": "0123456789abcdefGHIJKLMNOPQRSTUV",  # contains G-V
            },
        )

        assert response.status_code == 200
        assert b"Invalid API hash format" in response.content

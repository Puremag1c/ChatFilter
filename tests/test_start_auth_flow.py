"""Tests for start_auth_flow validation."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

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
            lambda user_id: tmp_path,
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
            lambda user_id: tmp_path,
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

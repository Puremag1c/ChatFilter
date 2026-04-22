"""Tests for auth_id ownership validation in auth endpoints.

Verifies that submit_auth_code and submit_auth_2fa return 403 when
the auth_id belongs to a different user than the one in the session.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from chatfilter.web.auth_state import AuthState, AuthStateManager, AuthStep


def _make_auth_state(auth_id: str, web_user_id: str) -> AuthState:
    """Create a minimal AuthState for testing."""
    client = MagicMock()
    client.is_connected.return_value = False
    return AuthState(
        auth_id=auth_id,
        session_name="test_session",
        proxy_id="proxy-1",
        phone="+1234567890",
        step=AuthStep.PHONE_SENT,
        phone_code_hash="hash123",
        client=client,
        web_user_id=web_user_id,
    )


@pytest.fixture
def two_user_clients(test_settings: Any, monkeypatch: Any):
    """Provide two TestClients authenticated as different users.

    Returns (client_user1, client_user2, user1_id, user2_id).
    """
    from chatfilter import config
    from chatfilter.web.app import create_app
    from chatfilter.web.dependencies import reset_group_engine
    from chatfilter.web.session import SESSION_COOKIE_NAME

    original_get_settings = config.get_settings
    if hasattr(original_get_settings, "cache_clear"):
        original_get_settings.cache_clear()

    monkeypatch.setattr(config, "get_settings", lambda: test_settings)
    reset_group_engine()

    from chatfilter.storage.user_database import get_user_db
    from chatfilter.web.session import get_session_store

    test_settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = get_user_db(test_settings.effective_database_url)
    user1_id = db.create_user("owner_user", "pass1234567", is_admin=True)
    user2_id = db.create_user("attacker_user", "pass1234567", is_admin=True)

    store = get_session_store()

    csrf_token = "test-csrf-token-ownership"

    sess1 = store.create_session()
    sess1.set("user_id", user1_id)
    sess1.set("username", "owner_user")
    sess1.set("is_admin", True)
    sess1.set("_csrf_token", csrf_token)

    sess2 = store.create_session()
    sess2.set("user_id", user2_id)
    sess2.set("username", "attacker_user")
    sess2.set("is_admin", True)
    sess2.set("_csrf_token", csrf_token)

    app = create_app(settings=test_settings)
    with (
        TestClient(app, cookies={SESSION_COOKIE_NAME: sess1.session_id}) as c1,
        TestClient(app, cookies={SESSION_COOKIE_NAME: sess2.session_id}) as c2,
    ):
        yield c1, c2, user1_id, user2_id

    reset_group_engine()
    monkeypatch.setattr(config, "get_settings", original_get_settings)
    if hasattr(original_get_settings, "cache_clear"):
        original_get_settings.cache_clear()


class TestAuthIdOwnership:
    """Auth endpoints must reject auth_ids that belong to a different user."""

    @pytest.fixture(autouse=True)
    def reset_auth_manager(self):
        """Reset AuthStateManager singleton state before each test."""
        manager = AuthStateManager()
        manager._states.clear()
        manager._in_progress.clear()
        yield
        manager._states.clear()
        manager._in_progress.clear()

    def test_submit_code_cross_user_returns_403(self, two_user_clients: Any) -> None:
        """Submitting a code for another user's auth_id must return 403."""
        client_user1, client_user2, user1_id, _user2_id = two_user_clients

        auth_id = "test-auth-id-001"
        state = _make_auth_state(auth_id, web_user_id=str(user1_id))
        AuthStateManager()._states[auth_id] = state

        # user2 tries to submit code for user1's auth flow
        resp = client_user2.post(
            "/api/sessions/auth/code",
            data={"auth_id": auth_id, "code": "12345"},
            headers={"X-CSRF-Token": "test-csrf-token-ownership"},
        )
        assert resp.status_code == 403

    def test_submit_code_same_user_not_forbidden(self, two_user_clients: Any) -> None:
        """Submitting a code for one's own auth_id must not return 403."""
        client_user1, _client_user2, user1_id, _user2_id = two_user_clients

        auth_id = "test-auth-id-002"
        state = _make_auth_state(auth_id, web_user_id=str(user1_id))
        AuthStateManager()._states[auth_id] = state

        resp = client_user1.post(
            "/api/sessions/auth/code",
            data={"auth_id": auth_id, "code": "12345"},
            headers={"X-CSRF-Token": "test-csrf-token-ownership"},
        )
        # Not 403 — may be 200 with an error message about invalid code, that's fine
        assert resp.status_code != 403

    def test_submit_2fa_cross_user_returns_403(self, two_user_clients: Any) -> None:
        """Submitting a 2FA password for another user's auth_id must return 403."""
        client_user1, client_user2, user1_id, _user2_id = two_user_clients

        auth_id = "test-auth-id-003"
        state = _make_auth_state(auth_id, web_user_id=str(user1_id))
        state.step = AuthStep.NEED_2FA
        AuthStateManager()._states[auth_id] = state

        resp = client_user2.post(
            "/api/sessions/auth/2fa",
            data={"auth_id": auth_id, "password": "somepassword"},
            headers={"X-CSRF-Token": "test-csrf-token-ownership"},
        )
        assert resp.status_code == 403

    def test_submit_2fa_same_user_not_forbidden(self, two_user_clients: Any) -> None:
        """Submitting a 2FA password for one's own auth_id must not return 403."""
        client_user1, _client_user2, user1_id, _user2_id = two_user_clients

        auth_id = "test-auth-id-004"
        state = _make_auth_state(auth_id, web_user_id=str(user1_id))
        state.step = AuthStep.NEED_2FA
        AuthStateManager()._states[auth_id] = state

        resp = client_user1.post(
            "/api/sessions/auth/2fa",
            data={"auth_id": auth_id, "password": "somepassword"},
            headers={"X-CSRF-Token": "test-csrf-token-ownership"},
        )
        assert resp.status_code != 403

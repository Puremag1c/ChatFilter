"""Tests for admin tab routing and email user creation.

Covers:
1. GET /admin/tab/users returns 200 for admin user
2. GET /admin/tab/platforms returns 200 for admin user
3. GET /admin/tab/system returns 200 for admin user
4. GET /admin/tab/* returns 403 for non-admin
5. POST /admin/create-user with email field saves email (assert email in DB)
6. POST /admin/ai-settings with cost_multiplier field saves value
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

_CSRF_TOKEN = "test-csrf-tab-routing"


def _make_admin_client(
    test_settings: Any, monkeypatch: Any, *, username: str
) -> tuple[TestClient, Any]:
    from chatfilter import config
    from chatfilter.storage.user_database import get_user_db
    from chatfilter.web.app import create_app
    from chatfilter.web.dependencies import reset_group_engine
    from chatfilter.web.session import SESSION_COOKIE_NAME, get_session_store

    original_get_settings = config.get_settings
    if hasattr(original_get_settings, "cache_clear"):
        original_get_settings.cache_clear()

    monkeypatch.setattr(config, "get_settings", lambda: test_settings)
    reset_group_engine()

    test_settings.data_dir.mkdir(parents=True, exist_ok=True)
    db = get_user_db(test_settings.effective_database_url)
    user_id = db.create_user(username, "testpassword123", is_admin=True)

    store = get_session_store()
    session = store.create_session()
    session.set("user_id", user_id)
    session.set("username", username)
    session.set("is_admin", True)
    session.set("_csrf_token", _CSRF_TOKEN)

    app = create_app(settings=test_settings)
    client = TestClient(app, cookies={SESSION_COOKIE_NAME: session.session_id})
    return client, original_get_settings


@pytest.fixture
def admin_csrf_client(test_settings: Any, monkeypatch: Any) -> Iterator[TestClient]:
    client, original = _make_admin_client(test_settings, monkeypatch, username="admin_tab_test")
    with client:
        yield client
    from chatfilter import config
    from chatfilter.web.dependencies import reset_group_engine

    monkeypatch.setattr(config, "get_settings", original)
    reset_group_engine()


class TestAdminTabRouting:
    def test_tab_users_returns_200_for_admin(self, admin_csrf_client: TestClient) -> None:
        response = admin_csrf_client.get("/admin/tab/users")
        assert response.status_code == 200, (
            f"GET /admin/tab/users returned {response.status_code}: {response.text[:200]}"
        )

    def test_tab_platforms_returns_200_for_admin(self, admin_csrf_client: TestClient) -> None:
        response = admin_csrf_client.get("/admin/tab/platforms")
        assert response.status_code == 200, (
            f"GET /admin/tab/platforms returned {response.status_code}: {response.text[:200]}"
        )

    def test_tab_system_returns_200_for_admin(self, admin_csrf_client: TestClient) -> None:
        response = admin_csrf_client.get("/admin/tab/system")
        assert response.status_code == 200, (
            f"GET /admin/tab/system returned {response.status_code}: {response.text[:200]}"
        )

    def test_tab_returns_403_for_non_admin(self, fastapi_test_client: Any) -> None:
        for tab in ("users", "platforms", "system"):
            response = fastapi_test_client.get(f"/admin/tab/{tab}")
            assert response.status_code == 403, (
                f"GET /admin/tab/{tab} should return 403 for non-admin, got {response.status_code}"
            )


class TestCreateUserWithEmail:
    def test_create_user_saves_email(
        self, admin_csrf_client: TestClient, test_settings: Any
    ) -> None:
        response = admin_csrf_client.post(
            "/admin/users",
            data={
                "username": "emailuser",
                "password": "securepass123",
                "email": "emailuser@example.com",
            },
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        assert response.status_code in (200, 303), (
            f"POST /admin/create-user returned {response.status_code}: {response.text[:200]}"
        )

        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        user = db.get_user_by_username("emailuser")
        assert user is not None, "User was not created"
        assert user.get("email") == "emailuser@example.com", (
            f"Email not saved, got: {user.get('email')!r}"
        )


class TestAISettingsCostMultiplier:
    def test_save_cost_multiplier(self, admin_csrf_client: TestClient, test_settings: Any) -> None:
        response = admin_csrf_client.post(
            "/admin/ai-settings",
            data={
                "openrouter_api_key": "sk-or-v1-testkey",
                "ai_model": "openrouter/google/gemini-2.5-flash",
                "ai_fallback_models": "[]",
                "cost_multiplier": "2.5",
            },
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        assert response.status_code in (200, 303), (
            f"POST /admin/ai-settings returned {response.status_code}: {response.text[:200]}"
        )

        from chatfilter.storage.group_database import GroupDatabase

        group_db = GroupDatabase(test_settings.effective_database_url)
        multiplier = group_db.get_cost_multiplier()
        assert abs(multiplier - 2.5) < 0.001, f"cost_multiplier not saved, got: {multiplier}"

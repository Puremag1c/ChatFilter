"""Security tests: admin-only access on system parameter endpoints.

Verifies that GET /admin and POST /admin/settings return 403 for authenticated
non-admin users and allow access for admin users.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

_CSRF_TOKEN = "test-csrf-admin-settings"


def _make_client(
    test_settings: Any,
    monkeypatch: Any,
    *,
    username: str,
    is_admin: bool,
) -> tuple[TestClient, Any]:
    """Return a TestClient authenticated as admin or non-admin user."""
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
    user_id = db.create_user(username, "testpassword123", is_admin=is_admin)

    store = get_session_store()
    session = store.create_session()
    session.set("user_id", user_id)
    session.set("username", username)
    session.set("is_admin", is_admin)
    session.set("_csrf_token", _CSRF_TOKEN)

    app = create_app(settings=test_settings)
    client = TestClient(app, cookies={SESSION_COOKIE_NAME: session.session_id})
    return client, original_get_settings


@pytest.fixture
def non_admin_client(test_settings: Any, monkeypatch: Any) -> Iterator[TestClient]:
    client, original = _make_client(
        test_settings, monkeypatch, username="regular_user", is_admin=False
    )
    with client:
        yield client
    from chatfilter import config
    from chatfilter.web.dependencies import reset_group_engine

    monkeypatch.setattr(config, "get_settings", original)
    reset_group_engine()


@pytest.fixture
def admin_client(test_settings: Any, monkeypatch: Any) -> Iterator[TestClient]:
    client, original = _make_client(
        test_settings, monkeypatch, username="admin_user", is_admin=True
    )
    with client:
        yield client
    from chatfilter import config
    from chatfilter.web.dependencies import reset_group_engine

    monkeypatch.setattr(config, "get_settings", original)
    reset_group_engine()


class TestAdminSettingsSecurity:
    """System parameter endpoints must reject non-admin authenticated users."""

    def test_get_admin_page_non_admin_returns_403(self, non_admin_client: TestClient) -> None:
        """GET /admin must return 403 for authenticated non-admin users."""
        resp = non_admin_client.get("/admin", follow_redirects=False)
        assert resp.status_code == 403

    def test_post_settings_non_admin_returns_403(self, non_admin_client: TestClient) -> None:
        """POST /admin/settings must return 403 for authenticated non-admin users."""
        resp = non_admin_client.post(
            "/admin/settings",
            data={"max_chats_per_account": "300", "analysis_freshness_days": "7"},
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_get_admin_page_admin_allowed(self, admin_client: TestClient) -> None:
        """GET /admin must allow access for admin users (not 403)."""
        resp = admin_client.get("/admin", follow_redirects=False)
        assert resp.status_code != 403

    def test_post_settings_admin_allowed(self, admin_client: TestClient) -> None:
        """POST /admin/settings must allow access for admin users (not 403)."""
        resp = admin_client.post(
            "/admin/settings",
            data={"max_chats_per_account": "300", "analysis_freshness_days": "7"},
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        assert resp.status_code != 403

    def test_post_settings_unauthenticated_not_200(
        self, test_settings: Any, monkeypatch: Any
    ) -> None:
        """POST /admin/settings must reject unauthenticated requests."""
        from chatfilter import config
        from chatfilter.web.app import create_app
        from chatfilter.web.dependencies import reset_group_engine

        original = config.get_settings
        if hasattr(original, "cache_clear"):
            original.cache_clear()
        monkeypatch.setattr(config, "get_settings", lambda: test_settings)
        reset_group_engine()

        app = create_app(settings=test_settings)
        with TestClient(app, follow_redirects=False) as client:
            resp = client.post(
                "/admin/settings",
                data={"max_chats_per_account": "300", "analysis_freshness_days": "7"},
            )
        # redirect to login (302) or explicit 401/403 — all acceptable
        assert resp.status_code != 200


class TestWebhookThresholdValidation:
    """POST /admin/integrations-settings must reject garbage thresholds.

    Regression: before 0.42.1 negative accounts_error threshold (``-5``)
    caused the alerts loop to fire on every admin account in error
    (condition ``count >= -5 and count > 0`` always True), and negative
    balance thresholds silently suppressed all low-balance alerts.
    """

    def _get_setting(self, test_settings: Any, key: str) -> str | None:
        from chatfilter.storage.group_database import GroupDatabase

        return GroupDatabase(test_settings.effective_database_url).get_setting(key)

    def test_rejects_negative_accounts_error(
        self, admin_client: TestClient, test_settings: Any
    ) -> None:
        resp = admin_client.post(
            "/admin/integrations-settings",
            data={"webhook_threshold_accounts_error": "-5"},
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        # Toast-error response — not a redirect, not 2xx success.
        trigger = resp.headers.get("HX-Trigger", "")
        assert '"type": "error"' in trigger
        # Setting must remain at default / unchanged.
        assert self._get_setting(test_settings, "webhook_threshold_accounts_error") != "-5"

    def test_rejects_zero_accounts_error(
        self, admin_client: TestClient, test_settings: Any
    ) -> None:
        resp = admin_client.post(
            "/admin/integrations-settings",
            data={"webhook_threshold_accounts_error": "0"},
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        trigger = resp.headers.get("HX-Trigger", "")
        assert '"type": "error"' in trigger
        assert self._get_setting(test_settings, "webhook_threshold_accounts_error") != "0"

    def test_rejects_negative_openrouter(
        self, admin_client: TestClient, test_settings: Any
    ) -> None:
        resp = admin_client.post(
            "/admin/integrations-settings",
            data={"webhook_threshold_openrouter": "-1.5"},
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        trigger = resp.headers.get("HX-Trigger", "")
        assert '"type": "error"' in trigger
        assert self._get_setting(test_settings, "webhook_threshold_openrouter") != "-1.5"

    def test_rejects_non_numeric_proxyline(
        self, admin_client: TestClient, test_settings: Any
    ) -> None:
        resp = admin_client.post(
            "/admin/integrations-settings",
            data={"webhook_threshold_proxyline": "abc"},
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        trigger = resp.headers.get("HX-Trigger", "")
        assert '"type": "error"' in trigger
        assert self._get_setting(test_settings, "webhook_threshold_proxyline") != "abc"

    def test_accepts_valid_thresholds(self, admin_client: TestClient, test_settings: Any) -> None:
        resp = admin_client.post(
            "/admin/integrations-settings",
            data={
                "webhook_threshold_accounts_error": "3",
                "webhook_threshold_openrouter": "2.50",
                "webhook_threshold_proxyline": "15.00",
            },
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        trigger = resp.headers.get("HX-Trigger", "")
        assert '"type": "error"' not in trigger
        assert self._get_setting(test_settings, "webhook_threshold_accounts_error") == "3"
        assert self._get_setting(test_settings, "webhook_threshold_openrouter") == "2.50"
        assert self._get_setting(test_settings, "webhook_threshold_proxyline") == "15.00"

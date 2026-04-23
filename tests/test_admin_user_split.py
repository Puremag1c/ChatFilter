"""UI/access split between admin-pool and user-personal-pool.

Access matrix:

                         | /sessions | /admin/accounts |
    ---------------------+-----------+-----------------+
    regular user         |   403     |       403       |
    user + toggle on     |   200     |       403       |
    admin (no toggle)    |   403     |       200       |
    admin + toggle on    |   200     |       200       |

Scope routing by URL path:

    /sessions       → scope = "user_<id>", owner = "user:<id>"
    /admin/accounts → scope = "admin",      owner = "admin"
"""

from __future__ import annotations

from typing import Any

# ------------------------------------------------------------------
# /sessions — only for use_own_accounts
# ------------------------------------------------------------------


class TestPersonalSessionsPage:
    def test_regular_user_blocked(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/sessions")
        assert r.status_code == 403

    def test_admin_without_toggle_blocked(self, admin_client: Any) -> None:
        """Admin without personal-accounts toggle has no business at /sessions —
        they manage the shared pool at /admin/accounts instead."""
        r = admin_client.get("/sessions")
        assert r.status_code == 403, (
            "Admin without use_own_accounts must NOT see /sessions (personal pool)"
        )

    def test_power_user_allowed(self, fastapi_test_client: Any, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        user = db.get_user_by_username("testuser")
        db.set_use_own_accounts(user["id"], True)

        r = fastapi_test_client.get("/sessions")
        assert r.status_code == 200

    def test_admin_with_toggle_allowed(self, admin_client: Any, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        user = db.get_user_by_username("adminuser")
        db.set_use_own_accounts(user["id"], True)

        r = admin_client.get("/sessions")
        assert r.status_code == 200, (
            "Admin who ticked the personal-accounts toggle gets their own /sessions"
        )


class TestPersonalProxiesPage:
    def test_regular_user_blocked(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/proxies")
        assert r.status_code == 403

    def test_admin_without_toggle_blocked(self, admin_client: Any) -> None:
        r = admin_client.get("/proxies")
        assert r.status_code == 403

    def test_power_user_allowed(self, fastapi_test_client: Any, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        user = db.get_user_by_username("testuser")
        db.set_use_own_accounts(user["id"], True)

        r = fastapi_test_client.get("/proxies")
        assert r.status_code == 200


# ------------------------------------------------------------------
# /admin/accounts — only for admins (shared pool)
# ------------------------------------------------------------------


class TestAdminAccountsPage:
    def test_admin_allowed(self, admin_client: Any) -> None:
        r = admin_client.get("/admin/accounts")
        assert r.status_code == 200

    def test_regular_user_blocked(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/admin/accounts")
        assert r.status_code == 403

    def test_power_user_blocked(self, fastapi_test_client: Any, test_settings: Any) -> None:
        """Power-user is NOT an admin — the toggle only grants personal pool."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        user = db.get_user_by_username("testuser")
        db.set_use_own_accounts(user["id"], True)

        r = fastapi_test_client.get("/admin/accounts")
        assert r.status_code == 403


class TestAdminProxiesPage:
    def test_admin_allowed(self, admin_client: Any) -> None:
        r = admin_client.get("/admin/proxies")
        assert r.status_code == 200

    def test_regular_user_blocked(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/admin/proxies")
        assert r.status_code == 403


# ------------------------------------------------------------------
# Scope routing by URL path
# ------------------------------------------------------------------


class TestScopeByPath:
    def test_admin_path_forces_admin_scope(self) -> None:
        """Any request to /admin/... uses admin scope regardless of user role."""
        from unittest.mock import MagicMock

        from chatfilter.web.dependencies import get_owner_key, get_pool_scope

        req = MagicMock()
        req.url.path = "/admin/accounts"

        def fake_session(_r):
            s = MagicMock()
            s.get = lambda k, d=None: {"is_admin": True, "user_id": "42"}.get(k, d)
            return s

        import chatfilter.web.dependencies as deps

        orig = deps.get_session
        deps.get_session = fake_session
        try:
            assert get_pool_scope(req) == "admin"
            assert get_owner_key(req) == "admin"
        finally:
            deps.get_session = orig

    def test_non_admin_path_uses_user_scope(self) -> None:
        """/sessions (a non-admin path) gives the user their personal scope
        even if they are an admin — because they came from the personal URL."""
        from unittest.mock import MagicMock

        from chatfilter.web.dependencies import get_owner_key, get_pool_scope

        req = MagicMock()
        req.url.path = "/sessions"

        def fake_session(_r):
            s = MagicMock()
            s.get = lambda k, d=None: {"is_admin": True, "user_id": "42"}.get(k, d)
            return s

        import chatfilter.web.dependencies as deps

        orig = deps.get_session
        deps.get_session = fake_session
        try:
            assert get_pool_scope(req) == "user_42"
            assert get_owner_key(req) == "user:42"
        finally:
            deps.get_session = orig


# ------------------------------------------------------------------
# Header menu matrix
# ------------------------------------------------------------------


class TestHeaderMenuMatrix:
    def test_regular_user_sees_minimal_menu(self, fastapi_test_client: Any) -> None:
        body = fastapi_test_client.get("/").text
        assert 'href="/sessions"' not in body
        assert 'href="/proxies"' not in body
        assert 'href="/admin"' not in body

    def test_power_user_sees_personal_links(
        self, fastapi_test_client: Any, test_settings: Any
    ) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        db.set_use_own_accounts(db.get_user_by_username("testuser")["id"], True)

        body = fastapi_test_client.get("/").text
        assert 'href="/sessions"' in body
        assert 'href="/proxies"' in body
        assert 'href="/admin"' not in body

    def test_admin_without_toggle_sees_only_admin(
        self, admin_client: Any, test_settings: Any
    ) -> None:
        """An admin who did NOT enable personal pool sees only /admin in nav,
        not /sessions or /proxies."""
        body = admin_client.get("/").text
        assert 'href="/admin"' in body
        # The admin must NOT see the personal-pool links in the top nav —
        # those are for power-users with the toggle on.
        assert 'href="/sessions"' not in body
        assert 'href="/proxies"' not in body

    def test_admin_with_toggle_sees_both(self, admin_client: Any, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        db.set_use_own_accounts(db.get_user_by_username("adminuser")["id"], True)

        body = admin_client.get("/").text
        assert 'href="/sessions"' in body
        assert 'href="/proxies"' in body
        assert 'href="/admin"' in body

"""Phase 2 — role-based UI tests.

Business rules:
    1. Sessions and proxies belong to admin only. Regular users do not see
       or reach /sessions, /proxies or their API endpoints.
    2. Home page `/` shows the user's groups (the old /chats content).
    3. Users table gains `use_own_accounts` boolean column (default False).
    4. Header menu is role-aware: Sessions/Proxies/Admin are hidden from
       non-admins.
    5. Profile page exposes a `use_own_accounts` toggle. Saving the form
       persists the new value. (No runtime effect yet — Phase 4.)
"""

from __future__ import annotations

from typing import Any

# ------------------------------------------------------------------
# 1. Admin-only routes
# ------------------------------------------------------------------


class TestSessionsAdminOnly:
    """/sessions is the PERSONAL pool. Admins without the toggle don't own one;
    they manage the shared pool at /admin/accounts instead. Regular users
    without the toggle get 403 too."""

    def test_regular_user_cannot_open_sessions_page(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/sessions")
        assert r.status_code == 403

    def test_regular_user_cannot_list_sessions_api(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/api/sessions")
        assert r.status_code == 403

    def test_admin_can_open_admin_accounts_page(self, admin_client: Any) -> None:
        """Admins see the shared pool at /admin/accounts."""
        r = admin_client.get("/admin/accounts")
        assert r.status_code < 400

    def test_admin_can_list_admin_sessions_api(self, admin_client: Any) -> None:
        """Same sessions API mounted under /admin/ for the shared pool."""
        r = admin_client.get("/admin/api/sessions")
        assert r.status_code == 200


class TestProxiesAdminOnly:
    def test_regular_user_cannot_open_proxies_page(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/proxies")
        assert r.status_code == 403

    def test_regular_user_cannot_list_proxies_api(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/api/proxies")
        assert r.status_code == 403

    def test_admin_can_open_admin_proxies_page(self, admin_client: Any) -> None:
        r = admin_client.get("/admin/proxies")
        assert r.status_code < 400


# ------------------------------------------------------------------
# 2. Home page shows groups
# ------------------------------------------------------------------


class TestHomeIsGroupsPage:
    def test_home_renders_groups_content(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/")
        assert r.status_code == 200
        body = r.text
        # The groups page template is chats.html — its layout has the
        # "create group" / groups list form rather than session upload.
        # We assert by checking a unique marker that appears only on the
        # groups page and NOT on the session upload page.
        assert "groups-container" in body or "group-card" in body or "chats-header" in body, (
            "Home must serve the groups page. Found body start: " + body[:400]
        )

    def test_chats_path_still_works_for_back_compat(self, fastapi_test_client: Any) -> None:
        """/chats should keep working so existing links don't break."""
        r = fastapi_test_client.get("/chats")
        assert r.status_code == 200


# ------------------------------------------------------------------
# 3. users.use_own_accounts column
# ------------------------------------------------------------------


class TestUseOwnAccountsColumn:
    def test_column_exists_with_default_false(self, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        user_id = db.create_user("col_test", "pw1234567890")
        user = db.get_user_by_id(user_id)
        assert user is not None
        assert "use_own_accounts" in user
        assert user["use_own_accounts"] is False

    def test_column_can_be_toggled(self, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        user_id = db.create_user("toggle_test", "pw1234567890")

        db.set_use_own_accounts(user_id, True)
        assert db.get_user_by_id(user_id)["use_own_accounts"] is True

        db.set_use_own_accounts(user_id, False)
        assert db.get_user_by_id(user_id)["use_own_accounts"] is False


# ------------------------------------------------------------------
# 4. Role-aware header menu
# ------------------------------------------------------------------


class TestHeaderMenuByRole:
    def test_regular_user_sees_no_sessions_or_proxies_link(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/")
        assert r.status_code == 200
        body = r.text
        # Non-admin nav must not have Sessions or Proxies links.
        assert 'href="/sessions"' not in body, (
            "Regular user must not see Sessions link in the header menu"
        )
        assert 'href="/proxies"' not in body, (
            "Regular user must not see Proxies link in the header menu"
        )

    def test_admin_sees_admin_link_only(self, admin_client: Any) -> None:
        """Admin without the personal-pool toggle sees only /admin in the top
        nav. The Sessions/Proxies links belong to the personal pool feature
        and require use_own_accounts=True regardless of role."""
        r = admin_client.get("/")
        assert r.status_code == 200
        body = r.text
        assert 'href="/admin"' in body
        # Personal pool links stay hidden until the admin ticks the toggle.
        assert 'href="/sessions"' not in body
        assert 'href="/proxies"' not in body


# ------------------------------------------------------------------
# 5. Profile toggle
# ------------------------------------------------------------------


class TestProfileHasOwnAccountsToggle:
    def test_profile_renders_toggle_input(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/profile")
        assert r.status_code == 200
        body = r.text
        # The toggle input must be there, named use_own_accounts.
        assert 'name="use_own_accounts"' in body, (
            "Profile page must expose a use_own_accounts toggle"
        )

    def test_saving_toggle_persists_value(
        self, fastapi_test_client: Any, test_settings: Any
    ) -> None:
        """POST to the profile form with the toggle on updates the DB."""
        from chatfilter.storage.user_database import get_user_db
        from chatfilter.web.session import get_session_store

        # Grab csrf + our session so we can POST.
        get_session_store()
        # The test fixture created session id inline; we need to find it.
        # Easiest path: hit a GET first to ensure session is warm, then
        # look for csrf in response HTML.
        r = fastapi_test_client.get("/profile")
        csrf_token: str | None = None
        for line in r.text.splitlines():
            if 'name="csrf_token"' in line and "value=" in line:
                start = line.find('value="') + 7
                end = line.find('"', start)
                csrf_token = line[start:end]
                break
        assert csrf_token, "Could not extract csrf_token from profile form"

        r = fastapi_test_client.post(
            "/profile",
            data={
                "use_own_accounts": "on",
                "csrf_token": csrf_token,
            },
            headers={"X-CSRF-Token": csrf_token},
        )
        assert r.status_code in (200, 303)

        db = get_user_db(test_settings.effective_database_url)
        user = db.get_user_by_username("testuser")
        assert user is not None
        assert user["use_own_accounts"] is True

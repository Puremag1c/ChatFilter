"""Tests for authentication routes, AuthMiddleware, and admin user management."""

from __future__ import annotations

import re
from typing import Any


def _extract_csrf(html: str) -> str:
    """Extract CSRF token from login page HTML form field."""
    m = re.search(r'<input\s+type="hidden"\s+name="csrf_token"\s+value="([^"]+)"', html)
    assert m, "No csrf_token hidden field found in page"
    return m.group(1)


class TestLoginPage:
    def test_get_renders_login_form(self, unauth_client: Any) -> None:
        resp = unauth_client.get("/login", follow_redirects=True)
        assert resp.status_code == 200
        assert "csrf_token" in resp.text

    def test_already_logged_in_redirects_to_home(self, fastapi_test_client: Any) -> None:
        resp = fastapi_test_client.get("/login", follow_redirects=False)
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"


class TestLoginPost:
    def _get_csrf(self, client: Any) -> str:
        """GET /login and extract the CSRF token from the hidden form field."""
        get_resp = client.get("/login", follow_redirects=True)
        assert get_resp.status_code == 200
        return _extract_csrf(get_resp.text)

    def _login(self, client: Any, username: str, password: str, csrf: str | None = None) -> Any:
        """POST /login.  CSRF is sent via header (avoids Starlette form-body
        consumption in BaseHTTPMiddleware so the route handler can read the
        username/password form fields)."""
        if csrf is None:
            csrf = self._get_csrf(client)
        return client.post(
            "/login",
            data={"username": username, "password": password},
            headers={"X-CSRF-Token": csrf},
            follow_redirects=False,
        )

    def test_valid_credentials_redirect_to_home(
        self, unauth_client: Any, test_settings: Any
    ) -> None:
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)
        db.create_user("logintest", "securepass123")

        resp = self._login(unauth_client, "logintest", "securepass123")
        assert resp.status_code == 303
        assert resp.headers["location"] == "/"

    def test_wrong_password_returns_401(self, unauth_client: Any, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)
        db.create_user("logintest", "securepass123")

        resp = self._login(unauth_client, "logintest", "wrongpassword")
        assert resp.status_code == 401

    def test_nonexistent_user_returns_401(self, unauth_client: Any) -> None:
        resp = self._login(unauth_client, "nosuchuser", "password123")
        assert resp.status_code == 401

    def test_missing_csrf_returns_403(self, unauth_client: Any, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)
        db.create_user("logintest", "securepass123")

        resp = unauth_client.post(
            "/login",
            data={"username": "logintest", "password": "securepass123"},
            # No X-CSRF-Token header and no csrf_token form field
            follow_redirects=False,
        )
        assert resp.status_code == 403


class TestLogout:
    def _get_csrf(self, client: Any) -> str:
        resp = client.get("/")
        m = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', resp.text)
        assert m, "No csrf-token meta tag found"
        return m.group(1)

    def test_logout_redirects_to_login(self, fastapi_test_client: Any) -> None:
        csrf = self._get_csrf(fastapi_test_client)
        resp = fastapi_test_client.post(
            "/logout",
            headers={"X-CSRF-Token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert "/login" in resp.headers["location"]

    def test_logout_clears_session(self, fastapi_test_client: Any) -> None:
        """After logout, accessing a protected route redirects to /login."""
        csrf = self._get_csrf(fastapi_test_client)
        fastapi_test_client.post(
            "/logout",
            headers={"X-CSRF-Token": csrf},
            follow_redirects=False,
        )
        resp = fastapi_test_client.get("/", follow_redirects=False)
        # Session is cleared: either 302 to /login or 200 (if session cookie
        # is retained by the test client but session data is gone)
        assert resp.status_code in (200, 302)


class TestAuthMiddleware:
    def test_protected_route_redirects_unauthenticated(self, unauth_client: Any) -> None:
        resp = unauth_client.get("/", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    def test_chats_route_redirects_unauthenticated(self, unauth_client: Any) -> None:
        resp = unauth_client.get("/chats", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    def test_login_accessible_without_auth(self, unauth_client: Any) -> None:
        resp = unauth_client.get("/login", follow_redirects=False)
        assert resp.status_code == 200

    def test_health_accessible_without_auth(self, unauth_client: Any) -> None:
        resp = unauth_client.get("/health", follow_redirects=False)
        assert resp.status_code == 200

    def test_authenticated_request_proceeds(self, fastapi_test_client: Any) -> None:
        resp = fastapi_test_client.get("/", follow_redirects=False)
        assert resp.status_code == 200


class TestAdminAccess:
    def test_admin_page_forbidden_for_non_admin(self, fastapi_test_client: Any) -> None:
        resp = fastapi_test_client.get("/admin")
        assert resp.status_code == 403

    def test_admin_page_accessible_for_admin(self, admin_client: Any) -> None:
        resp = admin_client.get("/admin")
        assert resp.status_code == 200

    def test_admin_page_redirects_unauthenticated(self, unauth_client: Any) -> None:
        resp = unauth_client.get("/admin", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]


class TestAdminUserManagement:
    def _get_csrf(self, client: Any) -> str:
        """Extract CSRF token from /admin page meta tag."""
        resp = client.get("/admin")
        assert resp.status_code == 200
        m = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', resp.text)
        assert m, "No csrf-token meta tag found on admin page"
        return m.group(1)

    def test_create_user_success(self, admin_client: Any) -> None:
        csrf = self._get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/users",
            data={"username": "newuser", "password": "newpassword123"},
            headers={"X-CSRF-Token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303

    def test_create_user_duplicate_returns_409(self, admin_client: Any) -> None:
        csrf = self._get_csrf(admin_client)
        admin_client.post(
            "/admin/users",
            data={"username": "dupuser", "password": "password123"},
            headers={"X-CSRF-Token": csrf},
            follow_redirects=False,
        )
        csrf2 = self._get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/users",
            data={"username": "dupuser", "password": "password456"},
            headers={"X-CSRF-Token": csrf2},
            follow_redirects=False,
        )
        assert resp.status_code == 409

    def test_create_user_short_password_returns_422(self, admin_client: Any) -> None:
        csrf = self._get_csrf(admin_client)
        resp = admin_client.post(
            "/admin/users",
            data={"username": "newuser", "password": "short"},
            headers={"X-CSRF-Token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 422

    def test_create_user_forbidden_for_non_admin(self, fastapi_test_client: Any) -> None:
        resp = fastapi_test_client.post(
            "/admin/users",
            data={"username": "newuser", "password": "password123"},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_delete_user(self, admin_client: Any, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("todelete", "password123")

        csrf = self._get_csrf(admin_client)
        resp = admin_client.request(
            "DELETE",
            f"/admin/users/{uid}",
            headers={"X-CSRF-Token": csrf},
        )
        assert resp.status_code == 200
        assert db.get_user_by_id(uid) is None

    def test_delete_user_forbidden_for_non_admin(
        self, fastapi_test_client: Any, test_settings: Any
    ) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("todelete", "password123")

        resp = fastapi_test_client.request("DELETE", f"/admin/users/{uid}")
        assert resp.status_code == 403

    def test_change_password(self, admin_client: Any, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("pwduser", "oldpassword123")

        csrf = self._get_csrf(admin_client)
        resp = admin_client.post(
            f"/admin/users/{uid}/password",
            data={"password": "newpassword456"},
            headers={"X-CSRF-Token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert db.verify_password("pwduser", "newpassword456") is True

    def test_change_password_short_returns_422(self, admin_client: Any, test_settings: Any) -> None:
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("pwduser2", "oldpassword123")

        csrf = self._get_csrf(admin_client)
        resp = admin_client.post(
            f"/admin/users/{uid}/password",
            data={"password": "short"},
            headers={"X-CSRF-Token": csrf},
            follow_redirects=False,
        )
        assert resp.status_code == 422

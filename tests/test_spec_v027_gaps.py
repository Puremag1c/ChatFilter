"""Generated tests for SPEC.md coverage gaps — ChatFilter v0.27+

Covers requirements not explicitly tested by existing test suite:
1. UserDatabase.set_admin unit test
2. Toggle admin OFF (revoke admin rights from admin user)
3. Profile page redirects unauthenticated users
4. CSRF required for /profile/password
5. Navbar elements have no data-tooltip attributes
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import pytest

# Ensure test credentials are set
os.environ.setdefault("CHATFILTER_API_ID", "123456")
os.environ.setdefault("CHATFILTER_API_HASH", "test_hash_abcdef123456789")


# ---------------------------------------------------------------------------
# Fixtures (inline for standalone file)
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_db_url(tmp_path: Path) -> str:
    db_path = tmp_path / "test_users.db"
    return f"sqlite:///{db_path}"


@pytest.fixture
def user_db(tmp_db_url: str) -> Any:
    from chatfilter.storage.user_database import UserDatabase
    db = UserDatabase(tmp_db_url)
    db._ensure_schema()
    return db


# ---------------------------------------------------------------------------
# 1. UserDatabase.set_admin unit test
# ---------------------------------------------------------------------------

class TestSetAdminMethod:
    """SPEC req: toggle admin endpoint calls set_admin.
    Verify the DB method itself works correctly."""

    def test_set_admin_true(self, user_db: Any) -> None:
        """set_admin(uid, True) should grant admin rights."""
        uid = user_db.create_user("user1", "password123", is_admin=False)
        result = user_db.set_admin(uid, True)
        assert result is True
        updated = user_db.get_user_by_id(uid)
        assert updated["is_admin"] is True

    def test_set_admin_false(self, user_db: Any) -> None:
        """set_admin(uid, False) should revoke admin rights."""
        uid = user_db.create_user("user2", "password123", is_admin=True)
        result = user_db.set_admin(uid, False)
        assert result is True
        updated = user_db.get_user_by_id(uid)
        assert updated["is_admin"] is False

    def test_set_admin_nonexistent_returns_false(self, user_db: Any) -> None:
        """set_admin on a non-existent user should return False (no rows updated)."""
        result = user_db.set_admin("nonexistent-uuid", True)
        assert result is False


# ---------------------------------------------------------------------------
# 2. Toggle admin OFF via endpoint
# ---------------------------------------------------------------------------

class TestToggleAdminOff:
    """SPEC req: toggle is idempotent in both directions.
    Existing tests only check toggling OFF→ON. This tests ON→OFF."""

    def _get_csrf(self, client: Any) -> str:
        resp = client.get("/admin")
        assert resp.status_code == 200
        m = re.search(r'<meta\s+name="csrf-token"\s+content="([^"]+)"', resp.text)
        assert m, "No csrf-token meta tag found on admin page"
        return m.group(1)

    def test_toggle_admin_off(self, admin_client: Any, test_settings: Any) -> None:
        """Toggle admin rights OFF for a user who is currently admin."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("targetadmin", "password123", is_admin=True)

        csrf = self._get_csrf(admin_client)
        resp = admin_client.post(
            f"/admin/users/{uid}/toggle-admin",
            headers={"X-CSRF-Token": csrf},
        )
        assert resp.status_code == 200
        updated = db.get_user_by_id(uid)
        assert updated["is_admin"] is False, "Admin rights should have been revoked"

    def test_toggle_admin_htmx_response_contains_row(
        self, admin_client: Any, test_settings: Any
    ) -> None:
        """SPEC req: HTMX update — response must contain user row HTML fragment."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("htmxtarget", "password123", is_admin=False)

        csrf = self._get_csrf(admin_client)
        resp = admin_client.post(
            f"/admin/users/{uid}/toggle-admin",
            headers={"X-CSRF-Token": csrf},
        )
        assert resp.status_code == 200
        # Response should be a partial HTML row (HTMX swap), not a redirect
        assert "<tr" in resp.text, "Response should contain a table row for HTMX swap"
        assert f"user-row-{uid}" in resp.text, "Row should have correct id for HTMX targeting"


# ---------------------------------------------------------------------------
# 3. Profile page unauthenticated redirect
# ---------------------------------------------------------------------------

class TestProfilePageAccess:
    """SPEC req: /profile page exists and is protected."""

    def test_profile_redirects_unauthenticated(self, unauth_client: Any) -> None:
        """Unauthenticated GET /profile should redirect to /login."""
        resp = unauth_client.get("/profile", follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers.get("location", "")

    def test_profile_accessible_when_authenticated(self, fastapi_test_client: Any) -> None:
        """Authenticated GET /profile should return 200."""
        resp = fastapi_test_client.get("/profile")
        assert resp.status_code == 200

    def test_profile_page_has_password_form(self, fastapi_test_client: Any) -> None:
        """SPEC req: profile page must contain the password change form."""
        resp = fastapi_test_client.get("/profile")
        assert resp.status_code == 200
        assert 'action="/profile/password"' in resp.text, "Password change form must be present"

    def test_profile_page_has_csrf_token(self, fastapi_test_client: Any) -> None:
        """SPEC req: CSRF protection on profile form."""
        resp = fastapi_test_client.get("/profile")
        assert resp.status_code == 200
        assert 'name="csrf_token"' in resp.text or 'name="csrf-token"' in resp.text, \
            "CSRF token must be present in profile form"


# ---------------------------------------------------------------------------
# 4. CSRF required for /profile/password
# ---------------------------------------------------------------------------

class TestProfilePasswordCsrf:
    """SPEC req: CSRF protection on profile password change endpoint."""

    def test_profile_password_requires_csrf(self, fastapi_test_client: Any) -> None:
        """POST /profile/password without CSRF token should return 403."""
        resp = fastapi_test_client.post(
            "/profile/password",
            data={
                "old_password": "testpassword123",
                "new_password": "newpassword456",
                "confirm_password": "newpassword456",
            },
            # No X-CSRF-Token header, no csrf_token in form
            follow_redirects=False,
        )
        assert resp.status_code == 403, \
            "Missing CSRF token should return 403, not allow password change"


# ---------------------------------------------------------------------------
# 5. Navbar has no data-tooltip (SPEC req: remove tooltips from navbar)
# ---------------------------------------------------------------------------

class TestNavbarNoTooltips:
    """SPEC req: Remove data-tooltip from all navbar elements.
    Verify the base template navbar is free of data-tooltip attributes."""

    def test_base_template_navbar_has_no_data_tooltip(self) -> None:
        """base.html navbar elements must not have data-tooltip attributes."""
        import chatfilter
        package_dir = Path(chatfilter.__file__).parent
        base_html = package_dir / "templates" / "base.html"
        assert base_html.exists(), "base.html template must exist"

        content = base_html.read_text(encoding="utf-8")

        # Extract just the <nav> section from the base template
        nav_match = re.search(r'<nav\b.*?</nav>', content, re.DOTALL)
        assert nav_match, "No <nav> element found in base.html"

        nav_content = nav_match.group(0)
        assert 'data-tooltip' not in nav_content, (
            "Navbar must not contain data-tooltip attributes "
            "(they block mobile first tap)"
        )

    def test_theme_toggle_no_tooltip(self) -> None:
        """Theme toggle button must not have data-tooltip."""
        import chatfilter
        package_dir = Path(chatfilter.__file__).parent
        base_html = package_dir / "templates" / "base.html"
        content = base_html.read_text(encoding="utf-8")

        # Find the theme-toggle-btn
        theme_btn_match = re.search(
            r'<button[^>]*theme-toggle[^>]*>.*?</button>', content, re.DOTALL
        )
        if theme_btn_match:
            assert 'data-tooltip' not in theme_btn_match.group(0), \
                "Theme toggle button must not have data-tooltip"

    def test_language_toggle_no_tooltip(self) -> None:
        """Language toggle button must not have data-tooltip."""
        import chatfilter
        package_dir = Path(chatfilter.__file__).parent
        base_html = package_dir / "templates" / "base.html"
        content = base_html.read_text(encoding="utf-8")

        lang_btn_match = re.search(
            r'<button[^>]*language-toggle[^>]*>.*?</button>', content, re.DOTALL
        )
        if lang_btn_match:
            assert 'data-tooltip' not in lang_btn_match.group(0), \
                "Language toggle button must not have data-tooltip"

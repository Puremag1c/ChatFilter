"""Regression test for CSRF token in POST /login form field.

After the h44 fix, validates that the REAL user flow works:
- GET /login extracts CSRF token from hidden form field
- POST /login submits CSRF token as form field (not X-CSRF-Token header)
- Result: 303 redirect (not 403 CSRF error)

This test ensures the fix covers real browser behavior where CSRF token
is embedded in the form, not sent via custom headers.
"""

from __future__ import annotations

import re
from typing import Any


def _extract_csrf_from_form(html: str) -> str:
    """Extract CSRF token from login page HTML hidden input field.

    Args:
        html: HTML content of the login page

    Returns:
        CSRF token value

    Raises:
        AssertionError: If csrf_token hidden input not found
    """
    m = re.search(r'<input\s+type="hidden"\s+name="csrf_token"\s+value="([^"]+)"', html)
    assert m, "No csrf_token hidden input field found in login page HTML"
    return m.group(1)


class TestLoginWithFormFieldCsrf:
    """Regression test for POST /login with form-field CSRF token.

    This validates the real browser flow where CSRF token is embedded in
    the form data, not sent via X-CSRF-Token header.
    """

    def test_post_login_with_form_field_csrf_token_succeeds(
        self, unauth_client: Any, test_settings: Any
    ) -> None:
        """POST /login with form-embedded CSRF token returns 303, not 403.

        This is the REAL user flow:
        1. GET /login → 200 with hidden csrf_token input
        2. Extract csrf_token from hidden input
        3. POST /login with form data including csrf_token
        4. Assert 303 redirect (login successful)

        Before the h44 fix, this would return 403 "CSRF validation failed"
        because the session's _csrf_token was not being carried through
        middleware layers.
        """
        from chatfilter.storage.user_database import get_user_db

        # Setup: Create test user
        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.data_dir)
        db.create_user("regressiontest", "testpass123")

        # Step 1: GET /login (no cookies) → assert 200
        get_resp = unauth_client.get("/login", follow_redirects=True)
        assert get_resp.status_code == 200, f"GET /login failed: {get_resp.status_code}"

        # Step 2: Extract CSRF token from hidden form field
        csrf_token = _extract_csrf_from_form(get_resp.text)
        assert csrf_token, "Failed to extract CSRF token from login form"

        # Step 3: POST /login with form data (csrf_token as form field, NOT header)
        post_resp = unauth_client.post(
            "/login",
            data={
                "username": "regressiontest",
                "password": "testpass123",
                "csrf_token": csrf_token,  # Token in form data, not header
            },
            follow_redirects=False,
        )

        # Step 4: Assert 303 redirect, not 403 CSRF error
        assert post_resp.status_code == 303, (
            f"Expected 303 redirect, got {post_resp.status_code}. Response: {post_resp.text}"
        )
        assert post_resp.headers["location"] == "/", "Redirect location should be /"

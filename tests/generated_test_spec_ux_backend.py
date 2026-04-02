"""Generated backend tests for SPEC.md UX Must Have items (v0.31.0 polish sprint).

Covers:
- POST /admin/users/{id}/topup HTMX response structure
- Topup amount validation (zero, negative, missing)
- POST /api/export/csv endpoint content and headers
- Balance field clearing mechanism (template structure validation)
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

_CSRF_TOKEN = "test-csrf-ux-backend"


def _make_admin_csrf_client(
    test_settings: Any, monkeypatch: Any, *, username: str
) -> tuple[TestClient, Any]:
    """Admin TestClient with CSRF token in session (required for form POST endpoints)."""
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
def admin_csrf_client_ux(test_settings: Any, monkeypatch: Any) -> Iterator[TestClient]:
    """Admin TestClient with CSRF token set — for testing form submissions."""
    client, original = _make_admin_csrf_client(test_settings, monkeypatch, username="admin_ux_test")
    with client:
        yield client
    from chatfilter import config
    from chatfilter.web.dependencies import reset_group_engine

    monkeypatch.setattr(config, "get_settings", original)
    reset_group_engine()


# =============================================================================
# SPEC Must Have #2: Topup HTMX response structure
# =============================================================================


class TestTopupHTMXResponse:
    """SPEC line 42-46: topup endpoint returns HTMX-compatible <td> for outerHTML swap."""

    def test_topup_response_is_html_td(
        self, admin_csrf_client_ux: TestClient, test_settings: Any
    ) -> None:
        """Response body must be a <td> element (hx-swap='outerHTML' target)."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_id = db.create_user("htmx_td_test", "password123")

        resp = admin_csrf_client_ux.post(
            f"/admin/users/{target_id}/topup",
            data={"amount": "5.00", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 200, f"Topup returned {resp.status_code}: {resp.text[:200]}"
        body = resp.text.strip()
        assert body.startswith("<td"), (
            f"Topup response must start with <td> for HTMX outerHTML swap, got: {body[:80]}"
        )
        assert "</td>" in body, "Topup response must contain closing </td>"

    def test_topup_response_contains_balance_id(
        self, admin_csrf_client_ux: TestClient, test_settings: Any
    ) -> None:
        """Response <td> must have id='balance-{user_id}' for HTMX retargeting."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_id = db.create_user("htmx_id_test", "password123")

        resp = admin_csrf_client_ux.post(
            f"/admin/users/{target_id}/topup",
            data={"amount": "3.00", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 200
        assert f'id="balance-{target_id}"' in resp.text, (
            f"Topup response must contain id='balance-{target_id}' for HTMX target matching"
        )

    def test_topup_response_shows_new_balance(
        self, admin_csrf_client_ux: TestClient, test_settings: Any
    ) -> None:
        """Response must show updated balance amount formatted as currency."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_id = db.create_user("htmx_balance_test", "password123")
        db.update_balance(target_id, 0.0)

        resp = admin_csrf_client_ux.post(
            f"/admin/users/{target_id}/topup",
            data={"amount": "12.50", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 200
        assert "$" in resp.text, "Topup response must show dollar amount"

    def test_topup_response_content_type_html(
        self, admin_csrf_client_ux: TestClient, test_settings: Any
    ) -> None:
        """Topup response Content-Type must be text/html for HTMX processing."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_id = db.create_user("htmx_ct_test", "password123")

        resp = admin_csrf_client_ux.post(
            f"/admin/users/{target_id}/topup",
            data={"amount": "1.00", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", ""), (
            "Topup response must be text/html for HTMX processing"
        )


# =============================================================================
# SPEC Must Have #2: Topup amount validation
# =============================================================================


class TestTopupAmountValidation:
    """SPEC line 42-46: server-side validation for topup amount."""

    def test_topup_zero_amount_rejected(
        self, admin_csrf_client_ux: TestClient, test_settings: Any
    ) -> None:
        """Amount=0 must be rejected (amount must be positive)."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_id = db.create_user("zero_amount_test", "password123")

        resp = admin_csrf_client_ux.post(
            f"/admin/users/{target_id}/topup",
            data={"amount": "0", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 400, f"Amount=0 must return 400, got {resp.status_code}"

    def test_topup_negative_amount_rejected(
        self, admin_csrf_client_ux: TestClient, test_settings: Any
    ) -> None:
        """Negative amount must be rejected."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_id = db.create_user("neg_amount_test", "password123")

        resp = admin_csrf_client_ux.post(
            f"/admin/users/{target_id}/topup",
            data={"amount": "-5.00", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 400, f"Negative amount must return 400, got {resp.status_code}"

    def test_topup_nonexistent_user_returns_404(self, admin_csrf_client_ux: TestClient) -> None:
        """Topup for non-existent user must return 404."""
        resp = admin_csrf_client_ux.post(
            "/admin/users/nonexistent-id-xyz/topup",
            data={"amount": "5.00", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 404, (
            f"Topup for non-existent user must return 404, got {resp.status_code}"
        )

    def test_topup_requires_amount_field(
        self, admin_csrf_client_ux: TestClient, test_settings: Any
    ) -> None:
        """POST without amount field must return 422 (validation error)."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_id = db.create_user("missing_amount_test", "password123")

        resp = admin_csrf_client_ux.post(
            f"/admin/users/{target_id}/topup",
            data={"csrf_token": _CSRF_TOKEN},  # No amount field
        )
        assert resp.status_code == 422, f"Missing amount must return 422, got {resp.status_code}"


# =============================================================================
# SPEC Must Have #4: Export CSV backend behavior (POST /api/export/csv)
# =============================================================================


class TestExportCSVBackend:
    """SPEC line 56-59: Export CSV returns proper file with content-disposition."""

    def test_export_csv_returns_200(self, fastapi_test_client: Any) -> None:
        """POST /api/export/csv must return 200."""
        resp = fastapi_test_client.post(
            "/api/export/csv",
            json={"results": [], "columns": []},
        )
        assert resp.status_code == 200, f"Export CSV returned {resp.status_code}"

    def test_export_csv_content_disposition_attachment(self, fastapi_test_client: Any) -> None:
        """Response must have content-disposition: attachment for browser download."""
        resp = fastapi_test_client.post(
            "/api/export/csv",
            json={"results": [], "columns": []},
        )
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd, (
            f"Export CSV must have attachment content-disposition, got: {cd!r}"
        )

    def test_export_csv_filename_present(self, fastapi_test_client: Any) -> None:
        """Content-disposition must include a filename."""
        resp = fastapi_test_client.post(
            "/api/export/csv",
            json={"results": [], "columns": []},
        )
        cd = resp.headers.get("content-disposition", "")
        assert "filename" in cd, (
            f"Export CSV content-disposition must include filename, got: {cd!r}"
        )

    def test_export_csv_content_type(self, fastapi_test_client: Any) -> None:
        """Response content-type must indicate CSV."""
        resp = fastapi_test_client.post(
            "/api/export/csv",
            json={"results": [], "columns": []},
        )
        ct = resp.headers.get("content-type", "")
        assert "csv" in ct or "text/" in ct, (
            f"Export CSV content-type must be CSV-compatible, got: {ct!r}"
        )


# =============================================================================
# SPEC Must Have #2 (template): balance_td.html HTMX structure
# =============================================================================


class TestTopupTemplateStructure:
    """Verify balance_td.html and admin_user_row.html meet HTMX requirements."""

    def test_balance_td_template_has_td_element(self) -> None:
        """balance_td.html must contain a <td> as root element."""
        path = Path("src/chatfilter/templates/partials/balance_td.html")
        content = path.read_text()
        assert "<td" in content, "balance_td.html must contain <td> element"
        assert "</td>" in content, "balance_td.html must contain closing </td>"

    def test_balance_td_has_correct_id_attribute(self) -> None:
        """balance_td.html must have id='balance-{user_id}' for HTMX target."""
        path = Path("src/chatfilter/templates/partials/balance_td.html")
        content = path.read_text()
        assert 'id="balance-{{ user_id }}"' in content, (
            "balance_td.html must have id='balance-{{ user_id }}' for HTMX outerHTML swap"
        )

    def test_balance_td_shows_new_balance_variable(self) -> None:
        """balance_td.html must render new_balance."""
        path = Path("src/chatfilter/templates/partials/balance_td.html")
        content = path.read_text()
        assert "new_balance" in content, "balance_td.html must reference new_balance"

    def test_topup_form_has_field_clearing_handler(self) -> None:
        """admin_user_row.html topup form must have hx-on::after-request to clear field."""
        path = Path("src/chatfilter/templates/partials/admin_user_row.html")
        content = path.read_text()
        assert "hx-on::after-request" in content, (
            "SPEC Must Have #2: topup form must have hx-on::after-request to clear input after success"
        )
        after_idx = content.find("hx-on::after-request")
        snippet = content[after_idx : after_idx + 200]
        assert "amount" in snippet, (
            "hx-on::after-request handler must target the amount input field"
        )

    def test_topup_form_htmx_target_is_balance_td(self) -> None:
        """admin_user_row.html topup form must target the balance <td> via hx-target."""
        path = Path("src/chatfilter/templates/partials/admin_user_row.html")
        content = path.read_text()
        assert 'hx-target="#balance-' in content, (
            "Topup form must have hx-target pointing to balance-{id} cell"
        )

    def test_topup_form_htmx_swap_is_outerhtml(self) -> None:
        """admin_user_row.html topup form must use hx-swap='outerHTML'."""
        path = Path("src/chatfilter/templates/partials/admin_user_row.html")
        content = path.read_text()
        assert 'hx-swap="outerHTML"' in content, (
            "Topup form must use hx-swap='outerHTML' to replace the entire <td>"
        )

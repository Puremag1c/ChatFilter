"""Edge case tests for SPEC.md backend requirements.

Covers additional edge cases beyond existing test_spec_ux_backend.py:
- Topup: minimum amount (0.01) accepted
- Topup: large amount accepted
- Topup: balance accumulates correctly across requests
- Topup: 0.00 rejected (edge of zero validation)
- Topup: response <td> id matches user_id for HTMX swap
- Topup: unauthenticated request rejected
- Template: field clearing handler guards on successful flag
- Template: balance_td has visual feedback class
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

_CSRF_TOKEN = "test-csrf-edge-backend"


def _make_admin_csrf_client(
    test_settings: Any, monkeypatch: Any, *, username: str
) -> tuple[TestClient, Any]:
    """Admin TestClient with CSRF token in session."""
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
def admin_edge_client(test_settings: Any, monkeypatch: Any) -> Iterator[TestClient]:
    """Admin TestClient for edge case tests."""
    client, original = _make_admin_csrf_client(
        test_settings, monkeypatch, username="admin_edge_test"
    )
    with client:
        yield client
    from chatfilter import config
    from chatfilter.web.dependencies import reset_group_engine

    monkeypatch.setattr(config, "get_settings", original)
    reset_group_engine()


# ===========================================================================
# Template structure edge cases — no server needed
# ===========================================================================


class TestTopupTemplateEdgeCases:
    """Template structure verifications for SPEC Must Have #2."""

    def test_field_clearing_checks_successful_flag(self) -> None:
        """Handler must guard on event.detail.successful — not clear on error responses."""
        path = Path("src/chatfilter/templates/partials/admin_user_row.html")
        content = path.read_text()
        handler_idx = content.find("hx-on::after-request")
        assert handler_idx >= 0, "hx-on::after-request handler missing"
        snippet = content[handler_idx : handler_idx + 300]
        assert "event.detail.successful" in snippet, (
            "SPEC Must Have #2: handler must guard on event.detail.successful "
            "to avoid clearing field on 4xx/5xx responses"
        )

    def test_balance_td_has_flash_class(self) -> None:
        """balance_td.html must have balance-flash class for visual feedback per SPEC #2."""
        path = Path("src/chatfilter/templates/partials/balance_td.html")
        content = path.read_text()
        assert "balance-flash" in content, (
            "SPEC Must Have #2: balance_td partial must have 'balance-flash' class "
            "to provide visual feedback (Nielsen heuristic #1: visibility of system status)"
        )

    def test_topup_form_hx_target_matches_balance_td_id(self) -> None:
        """hx-target on topup form must reference the same id used in balance_td."""
        row_content = Path("src/chatfilter/templates/partials/admin_user_row.html").read_text()
        td_content = Path("src/chatfilter/templates/partials/balance_td.html").read_text()
        assert 'hx-target="#balance-' in row_content, (
            "topup form hx-target must reference balance-{user_id}"
        )
        assert 'id="balance-' in td_content, (
            "balance_td.html must have id='balance-{user_id}' to match hx-target"
        )


# ===========================================================================
# API edge cases
# ===========================================================================


class TestTopupAPIEdgeCases:
    """Edge cases for POST /admin/users/{user_id}/topup validation and behaviour."""

    def test_topup_minimum_amount_accepted(
        self, admin_edge_client: TestClient, test_settings: Any
    ) -> None:
        """Amount 0.01 (minimum valid) must return 200."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("edge_min_001", "password123")

        resp = admin_edge_client.post(
            f"/admin/users/{uid}/topup",
            data={"amount": "0.01", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 200, f"Minimum amount 0.01 was rejected: {resp.text[:200]}"

    def test_topup_large_amount_accepted(
        self, admin_edge_client: TestClient, test_settings: Any
    ) -> None:
        """Large topup (9999.99) must be accepted without error."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("edge_large_9999", "password123")

        resp = admin_edge_client.post(
            f"/admin/users/{uid}/topup",
            data={"amount": "9999.99", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 200, f"Large amount 9999.99 was rejected: {resp.text[:200]}"

    def test_topup_balance_accumulates(
        self, admin_edge_client: TestClient, test_settings: Any
    ) -> None:
        """Two topups add to initial balance: initial(1.00) + 5.00 + 3.00 = 9.00.

        Note: new users start with DEFAULT balance of $1.00 (schema DEFAULT '1.0').
        """
        from chatfilter.ai.billing import BillingService
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("edge_accumulate_9", "password123")

        initial_balance = BillingService(db).get_balance(uid)

        admin_edge_client.post(
            f"/admin/users/{uid}/topup",
            data={"amount": "5.00", "csrf_token": _CSRF_TOKEN},
        )
        admin_edge_client.post(
            f"/admin/users/{uid}/topup",
            data={"amount": "3.00", "csrf_token": _CSRF_TOKEN},
        )

        billing = BillingService(db)
        balance = billing.get_balance(uid)
        expected = initial_balance + 5.00 + 3.00
        assert balance == pytest.approx(expected, abs=0.001), (
            f"Expected accumulated balance {expected} (initial={initial_balance} + 5 + 3), "
            f"got {balance}"
        )

    def test_topup_zero_float_rejected(
        self, admin_edge_client: TestClient, test_settings: Any
    ) -> None:
        """Amount 0.00 must be rejected (edge of positive validation)."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("edge_zero_float_2", "password123")

        resp = admin_edge_client.post(
            f"/admin/users/{uid}/topup",
            data={"amount": "0.00", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 400, (
            f"Amount 0.00 should be 400 Bad Request, got {resp.status_code}"
        )

    def test_topup_response_contains_correct_user_id(
        self, admin_edge_client: TestClient, test_settings: Any
    ) -> None:
        """Response <td> must have id='balance-{user_id}' for HTMX outerHTML swap correctness."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.create_user("edge_id_verify", "password123")

        resp = admin_edge_client.post(
            f"/admin/users/{uid}/topup",
            data={"amount": "2.50", "csrf_token": _CSRF_TOKEN},
        )
        assert resp.status_code == 200
        assert f'id="balance-{uid}"' in resp.text, (
            f"HTMX swap requires id='balance-{uid}' in response, got: {resp.text[:300]}"
        )


class TestAdminEndpointAuth:
    """Admin endpoints must reject unauthenticated requests with 403."""

    def test_topup_unauthenticated_returns_403(self, test_settings: Any, monkeypatch: Any) -> None:
        """POST /admin/users/{id}/topup without a valid admin session must return 403."""
        from chatfilter import config
        from chatfilter.web.app import create_app
        from chatfilter.web.dependencies import reset_group_engine

        original = config.get_settings
        if hasattr(original, "cache_clear"):
            original.cache_clear()
        monkeypatch.setattr(config, "get_settings", lambda: test_settings)
        reset_group_engine()
        test_settings.data_dir.mkdir(parents=True, exist_ok=True)

        app = create_app(settings=test_settings)
        try:
            with TestClient(app, follow_redirects=False) as client:
                resp = client.post(
                    "/admin/users/some-user-id/topup",
                    data={"amount": "5.00", "csrf_token": "fake-csrf"},
                )
            assert resp.status_code in (302, 403), (
                f"Unauthenticated topup should be 302 redirect or 403 Forbidden, "
                f"got {resp.status_code}"
            )
        finally:
            monkeypatch.setattr(config, "get_settings", original)
            reset_group_engine()

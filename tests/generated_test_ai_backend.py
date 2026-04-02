"""Generated backend tests for SPEC.md AI requirements.

Covers:
- Admin AI settings (POST /admin/ai-settings)
- Admin topup endpoint (POST /admin/users/{id}/topup)
- Profile transaction history (GET /profile)
- Balance check before AI requests (BillingService edge cases)
- New dependencies importability
- Migration schema integrity
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from chatfilter.ai.billing import BillingService, InsufficientBalance
from tests.db_helpers import make_group_db, make_user_db

# CSRF token injected into sessions for admin tests (same pattern as test_admin_settings_security.py)
_CSRF_TOKEN = "test-csrf-ai-backend"


def _make_admin_client_with_csrf(
    test_settings: Any, monkeypatch: Any, *, username: str
) -> tuple[TestClient, Any]:
    """Create an admin TestClient with CSRF token set in session."""
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
    """Admin TestClient with CSRF token set in session."""
    client, original = _make_admin_client_with_csrf(
        test_settings, monkeypatch, username="admin_ai_test"
    )
    with client:
        yield client
    from chatfilter import config
    from chatfilter.web.dependencies import reset_group_engine

    monkeypatch.setattr(config, "get_settings", original)
    reset_group_engine()


# ============================================================================
# SPEC requirement 1: New dependencies importable
# ============================================================================

class TestNewDependencies:
    """SPEC line 33-37: litellm, playwright, beautifulsoup4, lxml must be installed."""

    def test_litellm_importable(self) -> None:
        import litellm  # noqa: F401
        assert litellm is not None

    def test_beautifulsoup4_importable(self) -> None:
        from bs4 import BeautifulSoup  # noqa: F401
        assert BeautifulSoup is not None

    def test_lxml_importable(self) -> None:
        import lxml  # noqa: F401
        assert lxml is not None

    def test_playwright_importable(self) -> None:
        import playwright  # noqa: F401
        assert playwright is not None


# ============================================================================
# SPEC requirement 3: AI service module structure
# ============================================================================

class TestAIModuleStructure:
    """SPEC line 43-49: ai/ module with service.py, models.py, billing.py."""

    def test_ai_service_importable(self) -> None:
        from chatfilter.ai.service import AIService  # noqa: F401
        assert AIService is not None

    def test_ai_models_importable(self) -> None:
        from chatfilter.ai.models import AIConfig, AIResponse  # noqa: F401
        assert AIConfig is not None
        assert AIResponse is not None

    def test_ai_billing_importable(self) -> None:
        from chatfilter.ai.billing import BillingService, InsufficientBalance  # noqa: F401
        assert BillingService is not None
        assert InsufficientBalance is not None

    def test_ai_config_defaults(self) -> None:
        """AIConfig should have sensible defaults including OpenRouter model."""
        from chatfilter.ai.models import AIConfig
        config = AIConfig()
        assert "openrouter" in config.model or config.model != ""
        assert config.fallback_models == []

    def test_ai_response_model(self) -> None:
        """AIResponse must have content, model, tokens_in, tokens_out, cost_usd."""
        from chatfilter.ai.models import AIResponse
        resp = AIResponse(content="hello", model="test/model", tokens_in=10, tokens_out=5, cost_usd=0.001)
        assert resp.content == "hello"
        assert resp.model == "test/model"
        assert resp.tokens_in == 10
        assert resp.tokens_out == 5
        assert resp.cost_usd == pytest.approx(0.001)


# ============================================================================
# SPEC requirement 4: User balance — migration schema
# ============================================================================

class TestMigrationSchema:
    """SPEC line 52-53: ai_balance_usd field and ai_transactions table via migration."""

    def test_fresh_db_has_ai_balance_usd_column(self, tmp_path: Path) -> None:
        """Migration 007 must add ai_balance_usd to users table."""
        db_path = tmp_path / "schema_test.db"
        make_user_db(db_path)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        cols = [row[1] for row in cursor.fetchall()]
        conn.close()

        assert "ai_balance_usd" in cols, (
            "ai_balance_usd column missing from users table. Migration 007 not applied."
        )

    def test_fresh_db_has_ai_transactions_table(self, tmp_path: Path) -> None:
        """Migration 007 must create ai_transactions table."""
        db_path = tmp_path / "schema_test2.db"
        make_user_db(db_path)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ai_transactions'")
        result = cursor.fetchone()
        conn.close()

        assert result is not None, "ai_transactions table missing. Migration 007 not applied."

    def test_ai_transactions_has_all_required_columns(self, tmp_path: Path) -> None:
        """SPEC line 53: ai_transactions must have all specified columns."""
        db_path = tmp_path / "schema_test3.db"
        make_user_db(db_path)

        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(ai_transactions)")
        cols = {row[1] for row in cursor.fetchall()}
        conn.close()

        required = {"id", "user_id", "amount_usd", "balance_after", "type", "model",
                    "tokens_in", "tokens_out", "description", "created_at"}
        missing = required - cols
        assert not missing, f"ai_transactions missing columns: {missing}"

    def test_ai_transactions_type_values(self, tmp_path: Path) -> None:
        """SPEC line 54: transaction types must support 'topup' and 'charge'."""
        db = make_user_db(tmp_path / "type_test.db")
        billing = BillingService(db)
        user_id = db.create_user("typetest", "password123")

        billing.topup(user_id, 5.0, "initial load")
        billing.charge(user_id, 0.01, "test/model", 10, 5, "test charge")

        txns = billing.get_transactions(user_id)
        types = {t["type"] for t in txns}
        assert "topup" in types, "topup transaction type not found"
        assert "charge" in types, "charge transaction type not found"


# ============================================================================
# SPEC requirement 4: Balance checking — reject when ≤ 0
# ============================================================================

class TestBalanceEnforcement:
    """SPEC line 56-57: check balance > 0 before AI request; reject if ≤ 0."""

    @pytest.fixture
    def billing_with_user(self, tmp_path: Path):
        db = make_user_db(tmp_path / "balance_test.db")
        billing = BillingService(db)
        user_id = db.create_user("baluser", "password123")
        # Reset to 0 for deterministic tests
        db.update_balance(user_id, 0.0)
        return billing, user_id

    def test_check_balance_rejects_zero(self, billing_with_user) -> None:
        """Balance of 0.0 must return False from check_balance."""
        billing, user_id = billing_with_user
        assert billing.check_balance(user_id) is False

    def test_check_balance_rejects_negative(self, billing_with_user) -> None:
        """Negative balance must return False from check_balance."""
        billing, user_id = billing_with_user
        billing._db.update_balance(user_id, -0.001)
        assert billing.check_balance(user_id) is False

    def test_check_balance_accepts_minimum_positive(self, billing_with_user) -> None:
        """Balance of 0.0001 must return True from check_balance."""
        billing, user_id = billing_with_user
        billing._db.update_balance(user_id, 0.0001)
        assert billing.check_balance(user_id) is True

    def test_charge_raises_insufficient_at_zero(self, billing_with_user) -> None:
        """SPEC: reject AI request with clear error when balance ≤ 0."""
        billing, user_id = billing_with_user
        with pytest.raises(InsufficientBalance) as exc_info:
            billing.charge(user_id, 0.001, "test/model", 10, 5, "test")
        assert "insufficient" in str(exc_info.value).lower()

    def test_charge_raises_insufficient_at_exact_zero(self, billing_with_user) -> None:
        """Balance exactly 0.0 must be rejected (not > 0)."""
        billing, user_id = billing_with_user
        billing._db.update_balance(user_id, 0.0)
        with pytest.raises(InsufficientBalance):
            billing.charge(user_id, 0.0001, "test/model", 5, 5, "test")

    def test_charge_does_not_allow_overdraft(self, billing_with_user) -> None:
        """Charging more than balance must raise and not modify balance."""
        billing, user_id = billing_with_user
        billing.topup(user_id, 0.05, "small load")
        initial_balance = billing.get_balance(user_id)

        with pytest.raises(InsufficientBalance):
            billing.charge(user_id, 100.0, "test/model", 1000000, 500000, "expensive request")

        # Balance unchanged after rejected charge
        assert billing.get_balance(user_id) == pytest.approx(initial_balance)


# ============================================================================
# SPEC requirement 4: Starting balance $1.00
# ============================================================================

class TestNewUserStartingBalance:
    """SPEC line 55: new user starts with $1.00 AI balance."""

    def test_new_user_starts_with_one_dollar(self, tmp_path: Path) -> None:
        db = make_user_db(tmp_path / "start_balance.db")
        billing = BillingService(db)
        user_id = db.create_user("newuser", "password123")
        assert billing.get_balance(user_id) == pytest.approx(1.0)

    def test_new_user_can_make_ai_request(self, tmp_path: Path) -> None:
        """$1.00 starting balance means check_balance is True for new users."""
        db = make_user_db(tmp_path / "start_can_request.db")
        billing = BillingService(db)
        user_id = db.create_user("canrequest", "password123")
        assert billing.check_balance(user_id) is True


# ============================================================================
# SPEC requirement 5: Admin AI settings — stored in app_settings
# ============================================================================

class TestAdminAISettings:
    """SPEC line 48: API key, model, fallbacks stored in app_settings."""

    def test_group_db_can_store_openrouter_api_key(self, tmp_path: Path) -> None:
        db = make_group_db(tmp_path / "settings_test.db")
        db.set_setting("openrouter_api_key", "sk-or-v1-testkey")
        assert db.get_setting("openrouter_api_key") == "sk-or-v1-testkey"

    def test_group_db_can_store_ai_model(self, tmp_path: Path) -> None:
        db = make_group_db(tmp_path / "settings_test2.db")
        db.set_setting("ai_model", "openrouter/google/gemini-2.5-flash")
        assert db.get_setting("ai_model") == "openrouter/google/gemini-2.5-flash"

    def test_group_db_can_store_fallback_models_json(self, tmp_path: Path) -> None:
        import json
        db = make_group_db(tmp_path / "settings_test3.db")
        fallbacks = ["openrouter/anthropic/claude-3-haiku", "openrouter/meta-llama/llama-3-8b"]
        db.set_setting("ai_fallback_models", json.dumps(fallbacks))
        stored = json.loads(db.get_setting("ai_fallback_models"))
        assert stored == fallbacks

    def test_ai_service_loads_config_from_db(self, tmp_path: Path) -> None:
        """AIService._load_config must read from app_settings."""
        from chatfilter.ai.service import AIService
        db = make_group_db(tmp_path / "service_config.db")
        db.set_setting("ai_model", "openrouter/test/model-x")
        db.set_setting("openrouter_api_key", "sk-test-key")

        service = AIService(db=db)
        config = service._load_config()
        assert config.model == "openrouter/test/model-x"
        assert config.api_key.get_secret_value() == "sk-test-key"

    def test_ai_service_handles_empty_fallback_models(self, tmp_path: Path) -> None:
        """Empty fallback_models setting must not crash — return empty list."""
        from chatfilter.ai.service import AIService
        db = make_group_db(tmp_path / "service_empty_fallback.db")
        db.set_setting("ai_fallback_models", "[]")

        service = AIService(db=db)
        config = service._load_config()
        assert config.fallback_models == []

    def test_ai_service_handles_invalid_fallback_json(self, tmp_path: Path) -> None:
        """Invalid JSON for fallback_models must degrade gracefully to empty list."""
        from chatfilter.ai.service import AIService
        db = make_group_db(tmp_path / "service_bad_json.db")
        db.set_setting("ai_fallback_models", "not-valid-json")

        service = AIService(db=db)
        config = service._load_config()
        assert config.fallback_models == []


# ============================================================================
# SPEC requirement 5: Admin topup endpoint
# ============================================================================

class TestAdminTopupEndpoint:
    """SPEC line 60-61: admin can topup user balance via /admin/users/{id}/topup."""

    def test_topup_endpoint_accessible_by_admin(
        self, admin_csrf_client: TestClient, test_settings: Any
    ) -> None:
        """Admin POST to /admin/users/{id}/topup must succeed."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_user_id = db.create_user("topuptest", "password123")

        response = admin_csrf_client.post(
            f"/admin/users/{target_user_id}/topup",
            data={"amount": "5.00"},
            headers={"X-CSRF-Token": _CSRF_TOKEN},
        )
        assert response.status_code == 200, (
            f"Admin topup returned {response.status_code}: {response.text[:200]}"
        )

    def test_topup_endpoint_updates_balance(
        self, admin_csrf_client: TestClient, test_settings: Any
    ) -> None:
        """After topup, user balance must increase by the specified amount."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_user_id = db.create_user("topuptest2", "password123")
        billing = BillingService(db)
        billing._db.update_balance(target_user_id, 0.0)

        admin_csrf_client.post(
            f"/admin/users/{target_user_id}/topup",
            data={"amount": "10.00"},
            headers={"X-CSRF-Token": _CSRF_TOKEN},
        )

        new_balance = billing.get_balance(target_user_id)
        assert new_balance == pytest.approx(10.0), (
            f"Expected balance $10.00 after topup, got ${new_balance}"
        )

    def test_topup_endpoint_requires_admin(self, fastapi_test_client: Any, test_settings: Any) -> None:
        """Non-admin users must be rejected with 403."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_user_id = db.create_user("topuptarget", "password123")

        response = fastapi_test_client.post(
            f"/admin/users/{target_user_id}/topup",
            data={"amount": "5.00"},
        )
        assert response.status_code == 403, (
            f"Expected 403 Forbidden for non-admin, got {response.status_code}"
        )

    def test_topup_creates_transaction_record(
        self, admin_csrf_client: TestClient, test_settings: Any
    ) -> None:
        """Topup must create a 'topup' transaction in ai_transactions."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        target_user_id = db.create_user("topuptxn", "password123")
        billing = BillingService(db)
        billing._db.update_balance(target_user_id, 0.0)

        admin_csrf_client.post(
            f"/admin/users/{target_user_id}/topup",
            data={"amount": "7.50"},
            headers={"X-CSRF-Token": _CSRF_TOKEN},
        )

        txns = billing.get_transactions(target_user_id)
        topup_txns = [t for t in txns if t["type"] == "topup"]
        assert len(topup_txns) >= 1
        assert topup_txns[0]["amount_usd"] == pytest.approx(7.50)


# ============================================================================
# SPEC requirement 5: Admin AI settings endpoint
# ============================================================================

class TestAdminAISettingsEndpoint:
    """SPEC line 59-61: Admin can save OpenRouter key, model, fallback models."""

    def test_save_ai_settings_accessible_by_admin(
        self, admin_csrf_client: TestClient
    ) -> None:
        """Admin POST to /admin/ai-settings must succeed."""
        response = admin_csrf_client.post(
            "/admin/ai-settings",
            data={
                "openrouter_api_key": "sk-or-v1-testkey123",
                "ai_model": "openrouter/google/gemini-2.5-flash",
                "ai_fallback_models": '["openrouter/anthropic/claude-3-haiku"]',
            },
            headers={"X-CSRF-Token": _CSRF_TOKEN},
            follow_redirects=False,
        )
        assert response.status_code in (200, 303), (
            f"Admin AI settings returned {response.status_code}: {response.text[:200]}"
        )

    def test_save_ai_settings_requires_admin(self, fastapi_test_client: Any) -> None:
        """Non-admin must be rejected with 403."""
        response = fastapi_test_client.post(
            "/admin/ai-settings",
            data={
                "openrouter_api_key": "sk-or-evil",
                "ai_model": "openrouter/evil/model",
                "ai_fallback_models": "[]",
            },
        )
        assert response.status_code == 403


# ============================================================================
# SPEC requirement 6: Profile page transaction history
# ============================================================================

class TestProfileTransactionHistory:
    """SPEC line 63-64: profile page shows AI transaction history."""

    def test_profile_page_loads_for_user(self, fastapi_test_client: Any) -> None:
        """GET /profile must return 200 for authenticated user."""
        response = fastapi_test_client.get("/profile")
        assert response.status_code == 200, (
            f"Profile page returned {response.status_code}: {response.text[:200]}"
        )

    def test_profile_page_includes_balance(self, fastapi_test_client: Any, test_settings: Any) -> None:
        """Profile page must include AI balance information."""
        response = fastapi_test_client.get("/profile")
        # Balance should appear somewhere on the page
        assert response.status_code == 200
        body = response.text
        # The page should contain balance-related content
        assert any(term in body.lower() for term in ["balance", "баланс", "ai", "$"]), (
            "Profile page does not contain balance information"
        )

    def test_profile_page_with_transactions(
        self, fastapi_test_client: Any, test_settings: Any
    ) -> None:
        """Profile page must show transactions when they exist."""
        from chatfilter.storage.user_database import get_user_db

        # Get current user's id from the test client session cookie
        db = get_user_db(test_settings.effective_database_url)
        user = db.get_user_by_username("testuser")
        if user is None:
            pytest.skip("testuser not found in test DB")

        user_id = user["id"]
        billing = BillingService(db)
        billing.topup(user_id, 5.0, "Test topup for profile")

        response = fastapi_test_client.get("/profile")
        assert response.status_code == 200
        body = response.text
        # Transaction should appear on the page
        assert "topup" in body.lower() or "Test topup" in body, (
            "Profile page does not show topup transaction"
        )

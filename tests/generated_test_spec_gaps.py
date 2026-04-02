"""Tests for SPEC gaps: new user default balance (SPEC.md line 52, 55)."""

from __future__ import annotations

from pathlib import Path

import pytest

from chatfilter.ai.billing import BillingService
from tests.db_helpers import make_user_db


@pytest.fixture
def db(tmp_path: Path):
    return make_user_db(tmp_path / "test_spec_gaps.db")


@pytest.fixture
def billing(db) -> BillingService:
    return BillingService(db)


class TestNewUserDefaultBalance:
    def test_new_user_starts_with_one_dollar(self, db, billing: BillingService) -> None:
        """SPEC.md line 52/55: new user ai_balance_usd DEFAULT 1.0."""
        user_id = db.create_user("newuser", "password123")
        balance = billing.get_balance(user_id)
        assert balance == pytest.approx(1.0), (
            f"Expected new user balance $1.00 per SPEC, got ${balance:.4f}. "
            "Migration 007 has server_default='0.0' instead of '1.0'."
        )

    def test_new_user_can_immediately_make_ai_request(self, db, billing: BillingService) -> None:
        """New user should be able to make AI requests immediately after registration."""
        user_id = db.create_user("newuser2", "password123")
        assert billing.check_balance(user_id) is True, (
            "New user should have positive balance to make AI requests immediately."
        )

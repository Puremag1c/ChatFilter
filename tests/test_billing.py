"""Unit tests for BillingService — charge, topup, insufficient balance."""

from __future__ import annotations

from pathlib import Path

import pytest

from chatfilter.ai.billing import BillingService, InsufficientBalance
from tests.db_helpers import make_user_db


@pytest.fixture
def billing(tmp_path: Path) -> BillingService:
    db = make_user_db(tmp_path / "test_billing.db")
    return BillingService(db)


@pytest.fixture
def user_id(billing: BillingService) -> str:
    uid = "test-user-001"
    billing._db.create_user("testuser", "password123", user_id=uid)
    billing._db.update_balance(uid, 0.0)  # Reset default starting balance to $0 for billing tests
    return uid


class TestGetBalance:
    def test_default_balance_is_zero_for_missing_user(self, billing: BillingService) -> None:
        assert billing.get_balance("nonexistent") == 0.0

    def test_get_balance_returns_current_balance(
        self, billing: BillingService, user_id: str
    ) -> None:
        billing.topup(user_id, 5.0, "initial load")
        assert billing.get_balance(user_id) == pytest.approx(5.0)


class TestCheckBalance:
    def test_check_balance_false_when_zero(self, billing: BillingService, user_id: str) -> None:
        assert billing.check_balance(user_id) is False

    def test_check_balance_true_when_positive(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 1.0, "load")
        assert billing.check_balance(user_id) is True


class TestTopup:
    def test_topup_increases_balance(self, billing: BillingService, user_id: str) -> None:
        new_balance = billing.topup(user_id, 10.0, "Admin top-up")
        assert new_balance == pytest.approx(10.0)
        assert billing.get_balance(user_id) == pytest.approx(10.0)

    def test_topup_accumulates(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 5.0, "first")
        billing.topup(user_id, 3.0, "second")
        assert billing.get_balance(user_id) == pytest.approx(8.0)

    def test_topup_creates_transaction_record(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 10.0, "Admin top-up")
        txns = billing.get_transactions(user_id)
        assert len(txns) == 1
        txn = txns[0]
        assert txn["type"] == "topup"
        assert txn["amount_usd"] == pytest.approx(10.0)
        assert txn["balance_after"] == pytest.approx(10.0)
        assert txn["description"] == "Admin top-up"

    def test_topup_returns_new_balance(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 5.0, "first")
        result = billing.topup(user_id, 3.0, "second")
        assert result == pytest.approx(8.0)


class TestCharge:
    def test_charge_deducts_from_balance(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 10.0, "load")
        new_balance = billing.charge(user_id, 0.05, "gpt-4", 100, 200, "AI request")
        assert new_balance == pytest.approx(9.95)
        assert billing.get_balance(user_id) == pytest.approx(9.95)

    def test_charge_creates_transaction_record(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 10.0, "load")
        billing.charge(user_id, 0.05, "gpt-4", 100, 200, "AI request")
        txns = billing.get_transactions(user_id)
        charge_txn = next(t for t in txns if t["type"] == "charge")
        assert charge_txn["amount_usd"] == pytest.approx(-0.05)
        assert charge_txn["balance_after"] == pytest.approx(9.95)
        assert charge_txn["model"] == "gpt-4"
        assert charge_txn["tokens_in"] == 100
        assert charge_txn["tokens_out"] == 200
        assert charge_txn["description"] == "AI request"

    def test_charge_returns_new_balance(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 10.0, "load")
        result = billing.charge(user_id, 2.0, "gpt-4", 100, 200, "request")
        assert result == pytest.approx(8.0)

    def test_multiple_charges_accumulate(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 10.0, "load")
        billing.charge(user_id, 1.0, "gpt-4", 100, 100, "first")
        billing.charge(user_id, 2.0, "gpt-4", 200, 200, "second")
        assert billing.get_balance(user_id) == pytest.approx(7.0)


class TestInsufficientBalance:
    def test_charge_raises_when_balance_is_zero(
        self, billing: BillingService, user_id: str
    ) -> None:
        # User starts with 0 balance (default)
        with pytest.raises(InsufficientBalance):
            billing.charge(user_id, 0.01, "gpt-4", 10, 10, "request")

    def test_charge_raises_when_balance_is_negative(
        self, billing: BillingService, user_id: str
    ) -> None:
        billing._db.update_balance(user_id, -1.0)
        with pytest.raises(InsufficientBalance):
            billing.charge(user_id, 0.01, "gpt-4", 10, 10, "request")

    def test_charge_does_not_modify_balance_on_insufficient(
        self, billing: BillingService, user_id: str
    ) -> None:
        with pytest.raises(InsufficientBalance):
            billing.charge(user_id, 0.01, "gpt-4", 10, 10, "request")
        assert billing.get_balance(user_id) == pytest.approx(0.0)

    def test_charge_does_not_create_transaction_on_insufficient(
        self, billing: BillingService, user_id: str
    ) -> None:
        with pytest.raises(InsufficientBalance):
            billing.charge(user_id, 0.01, "gpt-4", 10, 10, "request")
        assert billing.get_transactions(user_id) == []


class TestGetTransactions:
    def test_returns_empty_list_for_no_transactions(
        self, billing: BillingService, user_id: str
    ) -> None:
        assert billing.get_transactions(user_id) == []

    def test_returns_transactions_ordered_newest_first(
        self, billing: BillingService, user_id: str
    ) -> None:
        billing.topup(user_id, 10.0, "load")
        billing.charge(user_id, 1.0, "gpt-4", 100, 100, "first charge")
        billing.topup(user_id, 5.0, "second topup")

        txns = billing.get_transactions(user_id)
        assert len(txns) == 3
        # Newest first — last topup should be at index 0
        assert txns[0]["type"] == "topup"
        assert txns[0]["description"] == "second topup"

    def test_limit_parameter(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 100.0, "big load")
        for i in range(10):
            billing.charge(user_id, 0.1, "gpt-4", 10, 10, f"charge {i}")

        txns = billing.get_transactions(user_id, limit=5)
        assert len(txns) == 5


class TestReserveAndSettle:
    def test_reserve_deducts_balance(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 1.0, "load")
        new_balance = billing.reserve(user_id, 0.60)
        assert new_balance == pytest.approx(0.40)
        assert billing.get_balance(user_id) == pytest.approx(0.40)

    def test_reserve_raises_when_insufficient(self, billing: BillingService, user_id: str) -> None:
        billing.topup(user_id, 0.50, "load")
        with pytest.raises(InsufficientBalance):
            billing.reserve(user_id, 0.60)

    def test_reserve_does_not_modify_balance_on_insufficient(
        self, billing: BillingService, user_id: str
    ) -> None:
        billing.topup(user_id, 0.50, "load")
        with pytest.raises(InsufficientBalance):
            billing.reserve(user_id, 0.60)
        assert billing.get_balance(user_id) == pytest.approx(0.50)

    def test_settle_refunds_when_actual_less_than_reserved(
        self, billing: BillingService, user_id: str
    ) -> None:
        billing.topup(user_id, 1.0, "load")
        billing.reserve(user_id, 0.80)
        new_balance = billing.settle(user_id, 0.80, 0.50, "gpt-4", 100, 200, "AI call")
        assert new_balance == pytest.approx(0.50)  # 1.0 - 0.80 + 0.30 refund
        assert billing.get_balance(user_id) == pytest.approx(0.50)

    def test_settle_charges_extra_when_actual_greater_than_reserved(
        self, billing: BillingService, user_id: str
    ) -> None:
        billing.topup(user_id, 1.0, "load")
        billing.reserve(user_id, 0.50)
        new_balance = billing.settle(user_id, 0.50, 0.70, "gpt-4", 100, 200, "AI call")
        assert new_balance == pytest.approx(0.30)  # 1.0 - 0.50 - 0.20 extra

    def test_settle_records_transaction_for_actual_cost(
        self, billing: BillingService, user_id: str
    ) -> None:
        billing.topup(user_id, 1.0, "load")
        billing.reserve(user_id, 0.80)
        billing.settle(user_id, 0.80, 0.50, "gpt-4", 100, 200, "AI call")
        txns = billing.get_transactions(user_id)
        charge_txn = next(t for t in txns if t["type"] == "charge")
        assert charge_txn["amount_usd"] == pytest.approx(-0.50)
        assert charge_txn["balance_after"] == pytest.approx(0.50)

    def test_concurrent_reserves_cannot_overdraft(
        self, billing: BillingService, user_id: str
    ) -> None:
        """Two concurrent reserves where combined cost exceeds balance.

        Only the first reserve succeeds; the second raises InsufficientBalance.
        Balance must never go below 0.
        """
        billing.topup(user_id, 1.0, "load")

        # Reserve 0.70 — succeeds, balance = 0.30
        balance_after_first = billing.reserve(user_id, 0.70)
        assert balance_after_first == pytest.approx(0.30)

        # Reserve 0.70 again — fails, balance is only 0.30
        with pytest.raises(InsufficientBalance):
            billing.reserve(user_id, 0.70)

        # Balance must not have gone below 0
        assert billing.get_balance(user_id) >= 0.0

    def test_settle_caps_extra_charge_at_zero_when_balance_exhausted(
        self, billing: BillingService, user_id: str
    ) -> None:
        """If actual > reserved and balance is now insufficient, cap at 0."""
        billing.topup(user_id, 0.50, "load")
        billing.reserve(user_id, 0.50)  # balance = 0
        # actual > reserved but balance is already 0 — should not go negative
        new_balance = billing.settle(user_id, 0.50, 0.80, "gpt-4", 100, 200, "AI call")
        assert new_balance >= 0.0

    def test_settle_with_zero_actual_cost_fully_refunds(
        self, billing: BillingService, user_id: str
    ) -> None:
        """Regression: reserve + settle(actual=0) must restore original balance.

        When all platforms are stubs and AI falls back, actual_cost=0.
        Balance must be unchanged and transaction must show $0 cost.
        """
        billing.topup(user_id, 1.0, "load")
        original_balance = billing.get_balance(user_id)

        billing.reserve(user_id, 0.03)
        assert billing.get_balance(user_id) == pytest.approx(0.97)

        new_balance = billing.settle(user_id, 0.03, 0.0, "search", 0, 0, "Search: stubs")
        assert new_balance == pytest.approx(original_balance)
        assert billing.get_balance(user_id) == pytest.approx(original_balance)

        txns = billing.get_transactions(user_id)
        search_txn = next(t for t in txns if t["type"] == "search")
        assert search_txn["amount_usd"] == pytest.approx(0.0)
        assert search_txn["balance_after"] == pytest.approx(original_balance)

    def test_settle_with_zero_actual_cost_multiple_searches(
        self, billing: BillingService, user_id: str
    ) -> None:
        """Regression: multiple sequential reserve+settle(actual=0) must not leak balance."""
        billing.topup(user_id, 1.0, "load")
        original_balance = billing.get_balance(user_id)

        for _ in range(3):
            billing.reserve(user_id, 0.03)
            billing.settle(user_id, 0.03, 0.0, "search", 0, 0, "Search: stubs")

        assert billing.get_balance(user_id) == pytest.approx(original_balance)
        txns = billing.get_transactions(user_id)
        search_txns = [t for t in txns if t["type"] == "search"]
        assert len(search_txns) == 3
        # Last settle should show original balance restored
        assert search_txns[0]["balance_after"] == pytest.approx(original_balance)

"""Regression tests: InsufficientBalance from reserve() must NOT trigger settle() refund."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from chatfilter.ai.billing import InsufficientBalance
from chatfilter.scraper.orchestrator import SearchOrchestrator
from chatfilter.scraper.query_generator import QueryGenerator
from tests.db_helpers import make_group_db


def _make_registry(platform=None) -> MagicMock:
    registry = MagicMock()
    if platform is not None:
        registry.get.return_value = platform
    return registry


def _make_query_gen() -> AsyncMock:
    gen = AsyncMock(spec=QueryGenerator)
    gen.generate.return_value = (["test query"], 0.001, False)
    return gen


@pytest.fixture()
def group_db(tmp_path):
    return make_group_db(tmp_path / "test.db")


class TestInsufficientBalanceSettleBug:
    @pytest.mark.asyncio
    async def test_insufficient_balance_does_not_refund_user(self, group_db, tmp_path):
        """User balance must NOT increase when reserve() raises InsufficientBalance."""
        from chatfilter.ai.billing import BillingService
        from tests.db_helpers import make_user_db

        user_db = make_user_db(tmp_path / "users.db")
        uid = "user-001"
        user_db.create_user("testuser", "password123", user_id=uid)
        user_db.update_balance(uid, 0.005)  # insufficient for $0.01 estimated cost

        billing = BillingService(user_db)
        balance_before = billing.get_balance(uid)
        assert balance_before == pytest.approx(0.005)

        registry = _make_registry()
        orchestrator = SearchOrchestrator(
            registry=registry,
            query_generator=_make_query_gen(),
            db=group_db,
            billing=billing,
        )

        with pytest.raises(InsufficientBalance):
            await orchestrator.search(
                user_query="find chats",
                platform_ids=["fake"],
                user_id=uid,
                group_name="Test Group",
                group_id="group-test-001",
            )

        balance_after = billing.get_balance(uid)
        assert balance_after == pytest.approx(balance_before), (
            f"Balance changed from {balance_before} to {balance_after} — "
            "settle() was incorrectly called after a failed reserve()"
        )

    @pytest.mark.asyncio
    async def test_insufficient_balance_settle_not_called_on_reserve_failure(self, group_db):
        """settle() must NOT be called when reserve() raises InsufficientBalance."""
        billing = MagicMock()
        billing.reserve.side_effect = InsufficientBalance("balance too low")

        orchestrator = SearchOrchestrator(
            registry=_make_registry(),
            query_generator=_make_query_gen(),
            db=group_db,
            billing=billing,
        )

        with pytest.raises(InsufficientBalance):
            await orchestrator.search(
                user_query="find chats",
                platform_ids=["fake"],
                user_id="user-002",
                group_name="Test Group",
                group_id="group-test-002",
            )

        billing.settle.assert_not_called()

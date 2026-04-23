"""Phase 5 — per-chat billing tests.

Business rules:

  1. Pre-flight at enqueue time — block the analysis if the user's
     balance cannot cover N_chats * cost_per_chat.
  2. When the scheduler transitions a task to running, pre-charge
     cost_per_chat and remember the amount on the queue row.
  3. On error/crash, refund the charged_amount so the user is not
     billed for work that wasn't delivered. Refund is idempotent.
  4. On success (DONE, regardless of chat_type), the charge sticks —
     dead/banned/restricted/private count as delivered.
  5. Admin exposes cost_per_chat through an existing settings endpoint.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from chatfilter.analyzer.worker import ChatResult
from chatfilter.models.group import ChatTypeEnum, GroupChatStatus, GroupSettings
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.storage.user_database import get_user_db


@pytest.fixture
def dbs(tmp_path: Path) -> tuple[GroupDatabase, Any]:
    """Single SQLite file — both databases reuse it (shared schema)."""
    db_path = tmp_path / "test.db"
    group_db = GroupDatabase(str(db_path))
    user_db = get_user_db(f"sqlite:///{db_path}")
    return group_db, user_db


def _seed_user(user_db: Any, balance: float = 10.0) -> str:
    """Create a user and force their balance to the given absolute value.

    ``create_user`` awards a 1.0 welcome bonus via the column default,
    so atomic_topup would compound it.  We overwrite ai_balance_usd
    directly to get a clean, predictable starting balance.
    """
    uid = user_db.create_user("billing_user", "pw12345678")
    with user_db._connection() as conn:  # noqa: SLF001 — test-only helper
        conn.execute(
            "UPDATE users SET ai_balance_usd = ? WHERE id = ?",
            (balance, uid),
        )
    return uid


def _seed_group(group_db: GroupDatabase, user_id: str, n_chats: int = 3) -> str:
    from chatfilter.models.group import GroupStatus

    group_db.save_group(
        group_id="g1",
        name="G",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.IN_PROGRESS.value,
        user_id=user_id,
    )
    for i in range(n_chats):
        group_db.save_chat(
            group_id="g1",
            chat_ref=f"@c{i}",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )
    return "g1"


# ------------------------------------------------------------------
# BillingService refund API
# ------------------------------------------------------------------


class TestRefundAPI:
    def test_refund_increases_balance(self, dbs: tuple[GroupDatabase, Any]) -> None:
        from chatfilter.ai.billing import BillingService

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        billing = BillingService(user_db, group_db=group_db)
        billing.charge(uid, 1.0, "m", 0, 0, "test charge")
        assert pytest.approx(billing.get_balance(uid)) == 4.0

        billing.refund(uid, 1.0, "refund for failed chat")
        assert pytest.approx(billing.get_balance(uid)) == 5.0

    def test_refund_zero_is_noop(self, dbs: tuple[GroupDatabase, Any]) -> None:
        from chatfilter.ai.billing import BillingService

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        billing = BillingService(user_db, group_db=group_db)

        billing.refund(uid, 0.0, "nothing to refund")
        assert pytest.approx(billing.get_balance(uid)) == 5.0


# ------------------------------------------------------------------
# Pre-flight check
# ------------------------------------------------------------------


class TestPreflightBalanceCheck:
    def test_sufficient_balance_allows_enqueue(self, dbs: tuple[GroupDatabase, Any]) -> None:
        from chatfilter.ai.billing import BillingService
        from chatfilter.analyzer.group_engine import (
            GroupAnalysisEngine,
        )

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        _seed_group(group_db, uid, n_chats=10)
        group_db.set_cost_per_chat(0.1)  # 10 chats * 0.10 = 1.00 ≤ 5.00

        billing = BillingService(user_db, group_db=group_db)
        engine = GroupAnalysisEngine(db=group_db, session_manager=MagicMock())
        count = engine.enqueue_group_analysis(
            "g1",
            pool_key="admin",
            billing=billing,
        )
        assert count == 10

    def test_insufficient_balance_blocks_enqueue(self, dbs: tuple[GroupDatabase, Any]) -> None:
        from chatfilter.ai.billing import BillingService, InsufficientBalance
        from chatfilter.analyzer.group_engine import (
            GroupAnalysisEngine,
        )

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=0.5)
        _seed_group(group_db, uid, n_chats=10)
        group_db.set_cost_per_chat(0.1)  # 10 * 0.10 = 1.00 > 0.50

        billing = BillingService(user_db, group_db=group_db)
        engine = GroupAnalysisEngine(db=group_db, session_manager=MagicMock())
        with pytest.raises(InsufficientBalance):
            engine.enqueue_group_analysis(
                "g1",
                pool_key="admin",
                billing=billing,
            )

        # Nothing was enqueued.
        import sqlite3

        with sqlite3.connect(str(group_db._db_url).removeprefix("sqlite:///")) as conn:
            n = conn.execute("SELECT COUNT(*) FROM analysis_queue").fetchone()[0]
        assert n == 0

    def test_cost_per_chat_zero_bypasses_check(self, dbs: tuple[GroupDatabase, Any]) -> None:
        """Default deployment (cost_per_chat=0) must not block anyone."""
        from chatfilter.ai.billing import BillingService
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=0.0)
        _seed_group(group_db, uid, n_chats=3)
        # cost_per_chat not set → 0.0

        billing = BillingService(user_db, group_db=group_db)
        engine = GroupAnalysisEngine(db=group_db, session_manager=MagicMock())
        count = engine.enqueue_group_analysis("g1", pool_key="admin", billing=billing)
        assert count == 3


# ------------------------------------------------------------------
# Pre-charge on running, refund on error
# ------------------------------------------------------------------


class TestSchedulerChargeAndRefund:
    @pytest.mark.asyncio
    async def test_done_result_keeps_charge(
        self, dbs: tuple[GroupDatabase, Any], monkeypatch: Any
    ) -> None:
        from chatfilter.ai.billing import BillingService
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        group_db.set_cost_per_chat(0.1)
        _seed_group(group_db, uid, n_chats=1)
        chat = group_db.load_chats(group_id="g1")[0]
        group_db.enqueue_chat_task("g1", chat["id"], chat["chat_ref"], uid, "admin")

        async def fake_process_chat(chat: dict, *_a, **_kw):
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.GROUP.value,
                status=GroupChatStatus.DONE.value,
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)

        from tests.test_phase4_scheduler import _FakeSessionManager

        sm = _FakeSessionManager({"admin": ["acc"]})
        sm.get_client = AsyncMock(return_value=MagicMock())
        billing = BillingService(user_db, group_db=group_db)

        scheduler = AnalysisScheduler(
            db=group_db, session_manager=sm, billing=billing, user_limit=5
        )
        await scheduler.tick_once()
        for _ in range(3):
            await asyncio.sleep(0.02)

        # DONE → 0.10 charged (balance 4.90)
        assert pytest.approx(billing.get_balance(uid), abs=1e-6) == 4.9

    @pytest.mark.asyncio
    async def test_error_result_refunds_charge(
        self, dbs: tuple[GroupDatabase, Any], monkeypatch: Any
    ) -> None:
        from chatfilter.ai.billing import BillingService
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        group_db.set_cost_per_chat(0.1)
        _seed_group(group_db, uid, n_chats=1)
        chat = group_db.load_chats(group_id="g1")[0]
        group_db.enqueue_chat_task("g1", chat["id"], chat["chat_ref"], uid, "admin")

        async def fake_process_chat(chat: dict, *_a, **_kw):
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.PENDING.value,
                status=GroupChatStatus.ERROR.value,
                error="Network timeout",
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)

        from tests.test_phase4_scheduler import _FakeSessionManager

        sm = _FakeSessionManager({"admin": ["acc"]})
        sm.get_client = AsyncMock(return_value=MagicMock())
        billing = BillingService(user_db, group_db=group_db)

        scheduler = AnalysisScheduler(
            db=group_db, session_manager=sm, billing=billing, user_limit=5
        )
        await scheduler.tick_once()
        for _ in range(3):
            await asyncio.sleep(0.02)

        # ERROR → refund → balance back to 5.00
        assert pytest.approx(billing.get_balance(uid), abs=1e-6) == 5.0

    @pytest.mark.asyncio
    async def test_dead_result_is_billable(
        self, dbs: tuple[GroupDatabase, Any], monkeypatch: Any
    ) -> None:
        """DEAD counts as service delivered — do not refund."""
        from chatfilter.ai.billing import BillingService
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        group_db.set_cost_per_chat(0.1)
        _seed_group(group_db, uid, n_chats=1)
        chat = group_db.load_chats(group_id="g1")[0]
        group_db.enqueue_chat_task("g1", chat["id"], chat["chat_ref"], uid, "admin")

        async def fake_process_chat(chat: dict, *_a, **_kw):
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.DEAD.value,
                status=GroupChatStatus.DONE.value,
                error="UsernameNotOccupied",
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)

        from tests.test_phase4_scheduler import _FakeSessionManager

        sm = _FakeSessionManager({"admin": ["acc"]})
        sm.get_client = AsyncMock(return_value=MagicMock())
        billing = BillingService(user_db, group_db=group_db)

        scheduler = AnalysisScheduler(
            db=group_db, session_manager=sm, billing=billing, user_limit=5
        )
        await scheduler.tick_once()
        for _ in range(3):
            await asyncio.sleep(0.02)

        # DEAD + DONE → charge stays → balance 4.90
        assert pytest.approx(billing.get_balance(uid), abs=1e-6) == 4.9


class TestRefundRespectsCostMultiplier:
    """Regression for 0.40 audit Fix #1.

    When ``cost_multiplier != 1``, ``BillingService.charge`` multiplies
    the raw ``cost_per_chat`` on debit, but the pre-fix scheduler wrote
    the RAW cost onto the queue row. Refund then returned only the raw
    amount, silently keeping the multiplier diff in the product's pocket.
    """

    @pytest.mark.asyncio
    async def test_error_refund_returns_full_multiplied_amount(
        self, dbs: tuple[GroupDatabase, Any], monkeypatch: Any
    ) -> None:
        from chatfilter.ai.billing import BillingService
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        group_db.set_cost_per_chat(0.1)
        group_db.set_cost_multiplier(2.0)  # 2x — exposes the bug
        _seed_group(group_db, uid, n_chats=1)
        chat = group_db.load_chats(group_id="g1")[0]
        group_db.enqueue_chat_task("g1", chat["id"], chat["chat_ref"], uid, "admin")

        async def fake_process_chat(chat: dict, *_a, **_kw):
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.PENDING.value,
                status=GroupChatStatus.ERROR.value,
                error="Network timeout",
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)

        from tests.test_phase4_scheduler import _FakeSessionManager

        sm = _FakeSessionManager({"admin": ["acc"]})
        sm.get_client = AsyncMock(return_value=MagicMock())
        billing = BillingService(user_db, group_db=group_db)

        scheduler = AnalysisScheduler(
            db=group_db, session_manager=sm, billing=billing, user_limit=5
        )
        await scheduler.tick_once()
        for _ in range(3):
            await asyncio.sleep(0.02)

        # Before fix: balance 4.90 (refund gave back only raw 0.10 of the 0.20 debit).
        # After fix: refund returns the full multiplied 0.20 → balance 5.00.
        assert pytest.approx(billing.get_balance(uid), abs=1e-6) == 5.0

    @pytest.mark.asyncio
    async def test_done_with_multiplier_charges_multiplied(
        self, dbs: tuple[GroupDatabase, Any], monkeypatch: Any
    ) -> None:
        """Sanity: DONE under multiplier=2 keeps the full multiplied charge."""
        from chatfilter.ai.billing import BillingService
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        group_db, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        group_db.set_cost_per_chat(0.1)
        group_db.set_cost_multiplier(2.0)
        _seed_group(group_db, uid, n_chats=1)
        chat = group_db.load_chats(group_id="g1")[0]
        group_db.enqueue_chat_task("g1", chat["id"], chat["chat_ref"], uid, "admin")

        async def fake_process_chat(chat: dict, *_a, **_kw):
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.GROUP.value,
                status=GroupChatStatus.DONE.value,
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)

        from tests.test_phase4_scheduler import _FakeSessionManager

        sm = _FakeSessionManager({"admin": ["acc"]})
        sm.get_client = AsyncMock(return_value=MagicMock())
        billing = BillingService(user_db, group_db=group_db)

        scheduler = AnalysisScheduler(
            db=group_db, session_manager=sm, billing=billing, user_limit=5
        )
        await scheduler.tick_once()
        for _ in range(3):
            await asyncio.sleep(0.02)

        # DONE → 0.10 * 2.0 = 0.20 charged → balance 4.80
        assert pytest.approx(billing.get_balance(uid), abs=1e-6) == 4.8


class TestIdempotencyKeyPreventsDoubleCharge:
    """Regression for 0.40 audit Fix #2 — double-charge race.

    Pre-fix: ``billing.charge`` committed the balance debit in one SQLite
    connection; the scheduler then opened a second connection to set
    ``charged_amount`` on the queue row. A crash between the two left
    the user debited but the queue row at 0, so
    ``reset_running_tasks_to_queued`` at startup re-queued the task and
    the scheduler debited a second time.

    Post-fix: ``atomic_charge`` takes an ``idempotency_key`` written
    under a partial UNIQUE index on ``ai_transactions``. A second call
    with the same key is a no-op on balance.
    """

    def test_second_charge_with_same_key_is_noop(self, dbs: tuple[GroupDatabase, Any]) -> None:
        from chatfilter.ai.billing import BillingService

        _, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        billing = BillingService(user_db)

        key = "queue_task:42"
        after_first = billing.charge(
            uid,
            0.10,
            model="analysis",
            tokens_in=0,
            tokens_out=0,
            description="chat 1",
            idempotency_key=key,
        )
        assert pytest.approx(after_first, abs=1e-6) == 4.9

        # Simulate the scheduler's retry after a crash between charge-commit
        # and UPDATE charged_amount — SAME task_id → SAME key.
        after_retry = billing.charge(
            uid,
            0.10,
            model="analysis",
            tokens_in=0,
            tokens_out=0,
            description="chat 1",
            idempotency_key=key,
        )
        # Balance must NOT have moved: user charged exactly once.
        assert pytest.approx(after_retry, abs=1e-6) == 4.9
        assert pytest.approx(billing.get_balance(uid), abs=1e-6) == 4.9

        # And exactly one transaction row exists for the key.
        txs = user_db.get_transactions(uid, limit=10, offset=0)
        keyed = [t for t in txs if t.get("idempotency_key") == key]
        assert len(keyed) == 1, f"expected exactly 1 keyed tx, got {len(keyed)}"

    def test_different_keys_charge_independently(self, dbs: tuple[GroupDatabase, Any]) -> None:
        """Two different tasks with distinct keys both go through."""
        from chatfilter.ai.billing import BillingService

        _, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        billing = BillingService(user_db)

        billing.charge(
            uid,
            0.10,
            model="analysis",
            tokens_in=0,
            tokens_out=0,
            description="chat 1",
            idempotency_key="queue_task:1",
        )
        billing.charge(
            uid,
            0.10,
            model="analysis",
            tokens_in=0,
            tokens_out=0,
            description="chat 2",
            idempotency_key="queue_task:2",
        )
        # Both succeed — 2 × 0.10 debited.
        assert pytest.approx(billing.get_balance(uid), abs=1e-6) == 4.8

    def test_charge_without_key_keeps_legacy_behaviour(
        self, dbs: tuple[GroupDatabase, Any]
    ) -> None:
        """Non-scheduler calls (AI token charges) pass key=None and keep working."""
        from chatfilter.ai.billing import BillingService

        _, user_db = dbs
        uid = _seed_user(user_db, balance=5.0)
        billing = BillingService(user_db)

        billing.charge(
            uid,
            0.10,
            model="gpt-x",
            tokens_in=100,
            tokens_out=50,
            description="ai call",
        )
        billing.charge(
            uid,
            0.10,
            model="gpt-x",
            tokens_in=100,
            tokens_out=50,
            description="ai call",
        )
        # No key → no uniqueness — both go through.
        assert pytest.approx(billing.get_balance(uid), abs=1e-6) == 4.8

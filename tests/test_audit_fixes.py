"""Regression tests for issues found during the full Phase 0-6 audit.

1. ``enqueue_group_analysis`` must not create duplicate rows on a
   double-call (UI race, retry, operator error). The second call
   should no-op and return the current live count.

2. Scheduler pre-charge must be idempotent: if a crash left
   ``charged_amount > 0`` on the row, a fresh process that picks
   the task up again does NOT charge the user a second time.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from chatfilter.analyzer.worker import ChatResult
from chatfilter.models.group import ChatTypeEnum, GroupChatStatus, GroupSettings
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.storage.user_database import get_user_db


@pytest.fixture
def dbs(tmp_path: Path):
    db_path = tmp_path / "audit.db"
    return GroupDatabase(str(db_path)), get_user_db(f"sqlite:///{db_path}")


def _seed(group_db, user_db, balance=5.0, n_chats=3):
    from chatfilter.models.group import GroupStatus

    uid = user_db.create_user("audit_user", "pw12345678")
    with user_db._connection() as conn:
        conn.execute("UPDATE users SET ai_balance_usd=? WHERE id=?", (balance, uid))
    group_db.save_group(
        group_id="g1",
        name="G",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.IN_PROGRESS.value,
        user_id=uid,
    )
    for i in range(n_chats):
        group_db.save_chat(
            group_id="g1",
            chat_ref=f"@c{i}",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )
    return uid


# ------------------------------------------------------------------
# 1. Duplicate-enqueue protection
# ------------------------------------------------------------------


class TestEnqueueIsIdempotent:
    def test_second_call_does_not_duplicate_rows(self, dbs) -> None:
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        group_db, user_db = dbs
        _seed(group_db, user_db, n_chats=3)
        engine = GroupAnalysisEngine(db=group_db, session_manager=MagicMock())

        first = engine.enqueue_group_analysis("g1", pool_key="admin")
        second = engine.enqueue_group_analysis("g1", pool_key="admin")
        assert first == 3
        assert second == 3  # reports the existing live count, no new rows

        import sqlite3

        with sqlite3.connect(str(group_db._db_url).removeprefix("sqlite:///")) as conn:
            n = conn.execute("SELECT COUNT(*) FROM analysis_queue").fetchone()[0]
        assert n == 3, f"Duplicate enqueue created {n} rows (expected 3)"

    def test_enqueue_after_all_done_works(self, dbs) -> None:
        """Once every row reaches a terminal, non-live status (done /
        error / cancelled), a fresh enqueue should create new rows."""
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        group_db, user_db = dbs
        _seed(group_db, user_db, n_chats=2)
        engine = GroupAnalysisEngine(db=group_db, session_manager=MagicMock())
        engine.enqueue_group_analysis("g1", pool_key="admin")
        # Burn through them.
        import sqlite3

        with sqlite3.connect(str(group_db._db_url).removeprefix("sqlite:///")) as conn:
            conn.execute("UPDATE analysis_queue SET status='done'")
        # New enqueue should add fresh rows since chats are still PENDING
        # at the group_chats layer. For the test we flip them back.
        group_db.save_chat(
            group_id="g1",
            chat_ref="@c0",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
            chat_id=group_db.load_chats(group_id="g1")[0]["id"],
        )
        count = engine.enqueue_group_analysis("g1", pool_key="admin")
        assert count >= 1


# ------------------------------------------------------------------
# 2. Pre-charge idempotence on crash recovery
# ------------------------------------------------------------------


class TestPreChargeIdempotent:
    @pytest.mark.asyncio
    async def test_no_double_charge_after_recovery(self, dbs, monkeypatch) -> None:
        from chatfilter.ai.billing import BillingService
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        group_db, user_db = dbs
        uid = _seed(group_db, user_db, balance=5.0, n_chats=1)
        group_db.set_cost_per_chat(0.10)

        chat = group_db.load_chats(group_id="g1")[0]
        task_id = group_db.enqueue_chat_task("g1", chat["id"], chat["chat_ref"], uid, "admin")

        # Simulate a previous boot charging the user and then crashing.
        billing = BillingService(user_db, group_db=group_db)
        billing.charge(
            uid,
            0.10,
            model="analysis",
            tokens_in=0,
            tokens_out=0,
            description="previous boot",
        )
        import sqlite3

        with sqlite3.connect(str(group_db._db_url).removeprefix("sqlite:///")) as conn:
            conn.execute(
                "UPDATE analysis_queue SET status='running', charged_amount=0.10 WHERE id=?",
                (task_id,),
            )

        # Crash recovery → queued, charged_amount left intact.
        reset = group_db.reset_running_tasks_to_queued()
        assert reset == 1

        # Balance already debited once.
        balance_before = billing.get_balance(uid)
        assert pytest.approx(balance_before) == 4.90

        # Fresh scheduler picks the task up and runs it to DONE.
        async def fake_process_chat(chat, *_a, **_kw):
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.GROUP.value,
                status=GroupChatStatus.DONE.value,
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)
        from tests.test_phase4_scheduler import _FakeSessionManager

        sm = _FakeSessionManager({"admin": ["acc"]})
        sm.get_client = AsyncMock(return_value=MagicMock())

        scheduler = AnalysisScheduler(
            db=group_db, session_manager=sm, billing=billing, user_limit=5
        )
        await scheduler.tick_once()
        for _ in range(3):
            await asyncio.sleep(0.02)

        # Balance unchanged — no second charge.
        assert pytest.approx(billing.get_balance(uid)) == 4.90, (
            "Pre-charge was not idempotent — user double-charged on crash recovery"
        )

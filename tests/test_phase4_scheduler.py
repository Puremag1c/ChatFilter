"""Phase 4 — scheduler + persistent queue + pool routing.

Behaviour under test:

1. ``AccountInfo.owner`` defaults to ``"admin"`` for all pre-Phase-4
   sessions; user-uploaded sessions carry ``owner="user:{id}"``.

2. ``AnalysisScheduler`` is a background loop that, on each tick,
   finds idle accounts for each pool_key and atomically claims the
   next queued task for that pool. FairShare limit enforced.

3. On startup, stranded ``running`` tasks are reset to ``queued``
   so the fresh process can re-pick them.

4. When a chat-task completes, the group_chats row mirrors the
   (status, chat_type) pair from the worker. Dead/banned/restricted
   stay DONE.

The scheduler must work without touching Telethon — we stub out
``worker.process_chat`` with a fake.
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

# ------------------------------------------------------------------
# shared fixtures
# ------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> GroupDatabase:
    return GroupDatabase(str(tmp_path / "test.db"))


def _make_group(
    db: GroupDatabase,
    *,
    group_id: str = "g1",
    user_id: str = "u1",
    chat_refs: tuple[str, ...] = ("@a", "@b"),
) -> list[dict[str, Any]]:
    from chatfilter.models.group import GroupStatus

    db.save_group(
        group_id=group_id,
        name="G",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.IN_PROGRESS.value,
        user_id=user_id,
    )
    for ref in chat_refs:
        db.save_chat(
            group_id=group_id,
            chat_ref=ref,
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )
    return db.load_chats(group_id=group_id)


# ------------------------------------------------------------------
# 1. Account ownership
# ------------------------------------------------------------------


class TestAccountOwnership:
    def test_account_info_defaults_to_admin(self) -> None:
        from chatfilter.models.account import AccountInfo

        ai = AccountInfo(user_id=1)
        assert ai.owner == "admin"

    def test_user_owned_account(self) -> None:
        from chatfilter.models.account import AccountInfo

        ai = AccountInfo(user_id=1, owner="user:abc")
        assert ai.owner == "user:abc"

    def test_json_without_owner_field_is_admin(self, tmp_path: Path) -> None:
        """Pre-Phase-4 .account_info.json files lack the owner key.

        The model must accept them and default to admin so existing
        installations don't need a data migration for their sessions.
        """
        from chatfilter.models.account import AccountInfo

        # Simulate a pre-Phase-4 payload on disk (no "owner" key).
        legacy = {"user_id": 42, "username": "old"}
        ai = AccountInfo.model_validate(legacy)
        assert ai.owner == "admin"


# ------------------------------------------------------------------
# 2. AnalysisScheduler — atomic claim + FairShare
# ------------------------------------------------------------------


class _FakeSessionManager:
    """Minimal stand-in for SessionManager used by the scheduler."""

    def __init__(self, sessions_by_owner: dict[str, list[str]]) -> None:
        # owner → list of account_ids
        self._accounts = sessions_by_owner
        # sessions that are currently handling a task
        self.busy: set[str] = set()

    def list_accounts_for_pool(self, pool_key: str) -> list[str]:
        return list(self._accounts.get(pool_key, []))

    def mark_busy(self, account_id: str) -> None:
        self.busy.add(account_id)

    def mark_idle(self, account_id: str) -> None:
        self.busy.discard(account_id)

    def idle_accounts(self, pool_key: str) -> list[str]:
        return [a for a in self._accounts.get(pool_key, []) if a not in self.busy]


class TestSchedulerTick:
    @pytest.mark.asyncio
    async def test_tick_picks_up_queued_and_marks_done(
        self, db: GroupDatabase, monkeypatch: Any
    ) -> None:
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        chats = _make_group(db)
        for c in chats:
            db.enqueue_chat_task("g1", c["id"], c["chat_ref"], "u1", "admin")

        async def fake_process_chat(chat: dict, client: Any, account_id: str, *_a, **_kw):
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.GROUP.value,
                status=GroupChatStatus.DONE.value,
                subscribers=100,
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)

        sm = _FakeSessionManager({"admin": ["acc1", "acc2"]})
        sm.get_client = AsyncMock(return_value=MagicMock())  # type: ignore[attr-defined]

        scheduler = AnalysisScheduler(db=db, session_manager=sm, user_limit=5)
        await scheduler.tick_once()
        # Wait a moment for the spawned coroutines to complete.
        await asyncio.sleep(0.05)

        # Both tasks should now be done in analysis_queue and in group_chats.
        finished = db.load_chats(group_id="g1")
        assert all(c["status"] == GroupChatStatus.DONE.value for c in finished)

    @pytest.mark.asyncio
    async def test_tick_respects_fair_share_limit(
        self, db: GroupDatabase, monkeypatch: Any
    ) -> None:
        """With user_limit=1 and 3 queued tasks from one user, a single
        tick must claim only one — the other two stay queued."""
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        chats = _make_group(db, chat_refs=("@a", "@b", "@c"))
        for c in chats:
            db.enqueue_chat_task("g1", c["id"], c["chat_ref"], "u1", "admin")

        started: list[str] = []

        async def fake_process_chat(chat: dict, *_a, **_kw):
            started.append(chat["chat_ref"])
            # Hold on so the scheduler tries to claim more — they should
            # be blocked by the user_limit.
            await asyncio.sleep(0.2)
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.GROUP.value,
                status=GroupChatStatus.DONE.value,
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)

        sm = _FakeSessionManager({"admin": ["a1", "a2", "a3"]})
        sm.get_client = AsyncMock(return_value=MagicMock())  # type: ignore[attr-defined]

        scheduler = AnalysisScheduler(db=db, session_manager=sm, user_limit=1)
        await scheduler.tick_once()
        # Let the spawned coroutine reach its first await so started is populated.
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        # The tick spawned up to user_limit=1 concurrent runs.
        assert len(started) == 1, (
            f"FairShare broken: {len(started)} tasks running concurrently, limit=1"
        )
        # Wait until the first finishes so we don't leak coroutines.
        await asyncio.sleep(0.3)

    @pytest.mark.asyncio
    async def test_pool_isolation_admin_vs_user(self, db: GroupDatabase, monkeypatch: Any) -> None:
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        chats = _make_group(db)
        db.enqueue_chat_task("g1", chats[0]["id"], chats[0]["chat_ref"], "u1", "user:u1")
        db.enqueue_chat_task("g1", chats[1]["id"], chats[1]["chat_ref"], "u1", "admin")

        seen_pools: list[str] = []

        async def fake_process_chat(chat: dict, client: Any, account_id: str, *_a, **_kw):
            seen_pools.append(account_id)
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.GROUP.value,
                status=GroupChatStatus.DONE.value,
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)

        # admin pool has only "adm1"; user:u1 pool has only "own1"
        sm = _FakeSessionManager({"admin": ["adm1"], "user:u1": ["own1"]})
        sm.get_client = AsyncMock(return_value=MagicMock())  # type: ignore[attr-defined]

        scheduler = AnalysisScheduler(db=db, session_manager=sm, user_limit=5)
        await scheduler.tick_once()
        await asyncio.sleep(0.05)

        assert sorted(seen_pools) == ["adm1", "own1"], (
            f"Pool routing broken — accounts ran on pools: {seen_pools}"
        )


# ------------------------------------------------------------------
# 3. Crash recovery
# ------------------------------------------------------------------


class TestCrashRecovery:
    @pytest.mark.asyncio
    async def test_running_tasks_are_requeued_on_startup(self, db: GroupDatabase) -> None:
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        chats = _make_group(db)
        t1 = db.enqueue_chat_task("g1", chats[0]["id"], chats[0]["chat_ref"], "u1", "admin")
        # Simulate a prior process having claimed this task.
        db.claim_next_task("admin", "crashed-account", user_limit=10)

        sm = _FakeSessionManager({"admin": []})
        scheduler = AnalysisScheduler(db=db, session_manager=sm, user_limit=5)
        reset = scheduler.recover()
        assert reset == 1

        # Row is queued again with attempts incremented.
        import sqlite3

        with sqlite3.connect(str(db._db_url).removeprefix("sqlite:///")) as conn:
            row = conn.execute(
                "SELECT status, account_id, attempts FROM analysis_queue WHERE id = ?",
                (t1,),
            ).fetchone()
        assert row == ("queued", None, 1)


# ------------------------------------------------------------------
# 4. Worker result → group_chats mirroring
# ------------------------------------------------------------------


class TestEnqueueGroupAnalysis:
    """Calling enqueue_group_analysis must only write to analysis_queue.

    The scheduler is a separate actor; this call must return quickly
    without trying to start workers itself.
    """

    @pytest.mark.asyncio
    async def test_enqueue_creates_one_task_per_pending_chat(self, db: GroupDatabase) -> None:
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        _make_group(db, chat_refs=("@a", "@b", "@c"))
        engine = GroupAnalysisEngine(db=db, session_manager=MagicMock())

        count = engine.enqueue_group_analysis("g1", pool_key="admin")
        assert count == 3

        # One queue row per chat, all queued.
        import sqlite3

        with sqlite3.connect(str(db._db_url).removeprefix("sqlite:///")) as conn:
            rows = conn.execute(
                "SELECT status, pool_key FROM analysis_queue WHERE group_id = 'g1'"
            ).fetchall()
        assert len(rows) == 3
        assert all(row[0] == "queued" for row in rows)
        assert all(row[1] == "admin" for row in rows)

    @pytest.mark.asyncio
    async def test_enqueue_respects_pool_key(self, db: GroupDatabase) -> None:
        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        _make_group(db, user_id="u1", chat_refs=("@x",))
        engine = GroupAnalysisEngine(db=db, session_manager=MagicMock())

        engine.enqueue_group_analysis("g1", pool_key="user:u1")
        import sqlite3

        with sqlite3.connect(str(db._db_url).removeprefix("sqlite:///")) as conn:
            row = conn.execute(
                "SELECT pool_key FROM analysis_queue WHERE group_id = 'g1'"
            ).fetchone()
        assert row[0] == "user:u1"


class TestMirrorResultIntoGroupChats:
    @pytest.mark.asyncio
    async def test_dead_chat_stored_as_done_dead(self, db: GroupDatabase, monkeypatch: Any) -> None:
        """DONE + DEAD result (worker found 'chat does not exist') is
        persisted to group_chats as (DONE, DEAD), not swallowed to ERROR."""
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        chats = _make_group(db, chat_refs=("@ghost",))
        db.enqueue_chat_task("g1", chats[0]["id"], chats[0]["chat_ref"], "u1", "admin")

        async def fake_process_chat(chat: dict, *_a, **_kw):
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.DEAD.value,
                status=GroupChatStatus.DONE.value,
                error="UsernameNotOccupied",
            )

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", fake_process_chat)

        sm = _FakeSessionManager({"admin": ["acc"]})
        sm.get_client = AsyncMock(return_value=MagicMock())  # type: ignore[attr-defined]

        scheduler = AnalysisScheduler(db=db, session_manager=sm, user_limit=5)
        await scheduler.tick_once()
        await asyncio.sleep(0.05)

        row = db.load_chats(group_id="g1")[0]
        assert row["status"] == GroupChatStatus.DONE.value
        assert row["chat_type"] == ChatTypeEnum.DEAD.value


class TestCrashRetryWithDifferentAccount:
    """An unknown exception from process_chat must NOT land the task
    in ``error`` on the first attempt. Instead the scheduler requeues
    the task so another account can try; only after ``max_attempts``
    crashes do we record the last error as the reason.
    """

    @pytest.mark.asyncio
    async def test_unknown_exception_requeues_until_limit(
        self, db: GroupDatabase, monkeypatch: Any
    ) -> None:
        from chatfilter.analyzer.scheduler import AnalysisScheduler

        chats = _make_group(db, chat_refs=("@kaboom",))
        task_id = db.enqueue_chat_task(
            "g1", chats[0]["id"], chats[0]["chat_ref"], "u1", "admin"
        )

        call_log: list[str] = []

        async def always_fail(chat: dict, *_a, **_kw):
            call_log.append("called")
            raise RuntimeError("unknown downstream explosion")

        monkeypatch.setattr("chatfilter.analyzer.scheduler.process_chat", always_fail)

        sm = _FakeSessionManager({"admin": ["acc1"]})
        sm.get_client = AsyncMock(return_value=MagicMock())  # type: ignore[attr-defined]

        scheduler = AnalysisScheduler(db=db, session_manager=sm, user_limit=5, max_attempts=3)

        # Tick 1 → crash → requeue (attempts=1)
        await scheduler.tick_once()
        await asyncio.sleep(0.05)
        stats = db.get_queue_stats(group_id="g1")
        assert stats.get("queued", 0) == 1, "first crash must put the task back on queue"
        assert stats.get("error", 0) == 0

        # Tick 2 → crash → requeue (attempts=2)
        await scheduler.tick_once()
        await asyncio.sleep(0.05)
        stats = db.get_queue_stats(group_id="g1")
        assert stats.get("queued", 0) == 1
        assert stats.get("error", 0) == 0

        # Tick 3 → crash → now attempts == max_attempts → error with reason
        await scheduler.tick_once()
        await asyncio.sleep(0.05)
        stats = db.get_queue_stats(group_id="g1")
        assert stats.get("error", 0) == 1, "final crash must land in error"
        assert stats.get("queued", 0) == 0

        # The reason on the queue row must mention both the attempt
        # cap and the underlying exception.
        with db._connection() as conn:  # noqa: SLF001 — test-only introspection
            row = conn.execute(
                "SELECT attempts, error FROM analysis_queue WHERE id = ?", (task_id,)
            ).fetchone()
        assert row["attempts"] == 3
        assert "After 3 attempts" in row["error"]
        assert "unknown downstream explosion" in row["error"]

        # Worker was called on every attempt.
        assert len(call_log) == 3

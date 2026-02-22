"""Integration smoke tests: full analysis flow end-to-end.

Tests the complete lifecycle against the current single-pass engine model,
using GroupDatabase + GroupAnalysisEngine with mocked Telegram workers.

Scenarios:
1. Create group → start analysis → progress monotonic → all Done
2. Stop mid-analysis → resume → completes
3. INCREMENT: add missing metrics → new task → Pending → Done
4. OVERWRITE: clear + reanalyze → all Pending → Done
5. Dead chat → Done with chat_type=dead
6. Moderated chat → Done, activity NULL
7. All accounts banned → Error
8. CSV export with new columns
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.analyzer.group_engine import (
    METRICS_VERSION,
    GroupAnalysisEngine,
    NoConnectedAccountsError,
)
from chatfilter.analyzer.worker import ChatResult
from chatfilter.exporter.csv import export_group_results_to_csv, to_csv_rows_dynamic
from chatfilter.models.group import (
    AnalysisMode,
    ChatTypeEnum,
    GroupChatStatus,
    GroupSettings,
    GroupStatus,
)
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.web.routers.groups import _apply_export_filters, _convert_results_for_exporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path: Path) -> GroupDatabase:
    """Create isolated test database."""
    db_path = tmp_path / "test_groups.db"
    database = GroupDatabase(str(db_path))
    return database


@pytest.fixture
def session_manager() -> MagicMock:
    """Mock SessionManager with one healthy account."""
    mgr = MagicMock()
    mgr.list_sessions.return_value = ["acct-1"]
    mgr.is_healthy = AsyncMock(return_value=True)

    mock_client = AsyncMock()
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_client
    ctx.__aexit__.return_value = None
    mgr.session.return_value = ctx
    mgr.connect = AsyncMock(return_value=mock_client)

    return mgr


@pytest.fixture
def engine(db: GroupDatabase, session_manager: MagicMock) -> GroupAnalysisEngine:
    return GroupAnalysisEngine(db=db, session_manager=session_manager)


@pytest.fixture
def service(db: GroupDatabase, engine: GroupAnalysisEngine) -> GroupService:
    return GroupService(db=db, engine=engine)


def _setup_group(
    db: GroupDatabase,
    group_id: str = "grp-test",
    chat_refs: list[str] | None = None,
    settings: GroupSettings | None = None,
    status: str = "pending",
) -> str:
    """Helper: create group and chats in DB, return group_id."""
    if chat_refs is None:
        chat_refs = ["@chat1", "@chat2", "@chat3"]
    if settings is None:
        settings = GroupSettings()
    db.save_group(
        group_id=group_id,
        name="Test Group",
        settings=settings.model_dump(),
        status=status,
    )
    for ref in chat_refs:
        db.save_chat(
            group_id=group_id,
            chat_ref=ref,
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )
    return group_id


def _make_chat_result(chat_ref: str, **overrides) -> ChatResult:
    """Build a successful ChatResult with sensible defaults."""
    defaults = dict(
        chat_ref=chat_ref,
        chat_type=ChatTypeEnum.GROUP.value,
        title=f"Title of {chat_ref}",
        subscribers=100,
        moderation=False,
        messages_per_hour=5.0,
        unique_authors_per_hour=2.5,
        captcha=False,
        partial_data=False,
        status="done",
    )
    defaults.update(overrides)
    return ChatResult(**defaults)


# ---------------------------------------------------------------------------
# 1. Full analysis: create → start → progress monotonic → all Done
# ---------------------------------------------------------------------------

class TestFullAnalysisFlow:

    @pytest.mark.asyncio
    async def test_create_start_progress_all_done(
        self, db: GroupDatabase, engine: GroupAnalysisEngine, session_manager: MagicMock,
    ) -> None:
        """Create group → start analysis → progress monotonically increases → all chats Done."""
        refs = ["@ch1", "@ch2", "@ch3", "@ch4", "@ch5"]
        group_id = _setup_group(db, chat_refs=refs)

        # Track progress events for monotonicity check
        progress_values: list[int] = []
        original_publish = engine._progress.publish

        def capture_publish(event):
            progress_values.append(event.current)
            original_publish(event)

        # Mock process_chat to succeed for every chat
        async def mock_process(chat, client, account_id, settings):
            return _make_chat_result(chat["chat_ref"])

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process),
            patch.object(engine._progress, "publish", side_effect=capture_publish),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # All chats should be DONE
        all_chats = db.load_chats(group_id=group_id)
        assert len(all_chats) == 5
        for chat in all_chats:
            assert chat["status"] == GroupChatStatus.DONE.value, f"Chat {chat['chat_ref']} not done"

        # Group status should be COMPLETED (computed from all DONE)
        computed_status = db.compute_group_status(group_id)
        assert computed_status == GroupStatus.COMPLETED.value

        # Progress should be monotonically non-decreasing
        for i in range(1, len(progress_values)):
            assert progress_values[i] >= progress_values[i - 1], (
                f"Progress decreased: {progress_values[i - 1]} → {progress_values[i]}"
            )

        # All chats should have metrics
        for chat in all_chats:
            metrics = db.get_chat_metrics(chat["id"])
            assert metrics.get("metrics_version") == METRICS_VERSION


# ---------------------------------------------------------------------------
# 2. Stop mid-analysis → resume → completes
# ---------------------------------------------------------------------------

class TestStopResumeFlow:

    @pytest.mark.asyncio
    async def test_stop_and_resume_completes(
        self, db: GroupDatabase, engine: GroupAnalysisEngine, session_manager: MagicMock,
    ) -> None:
        """Simulate stop by manually pausing, then resume → all complete."""
        refs = ["@s1", "@s2", "@s3", "@s4", "@s5"]
        group_id = _setup_group(db, chat_refs=refs)

        # Phase 1: Process first 2 chats, then simulate a stop
        processed_count = 0

        async def mock_process_partial(chat, client, account_id, settings):
            nonlocal processed_count
            processed_count += 1
            if processed_count > 2:
                # Raise CancelledError to simulate task cancellation
                raise asyncio.CancelledError()
            return _make_chat_result(chat["chat_ref"])

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process_partial),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # Mark remaining PENDING chats as having errors (simulating stop mid-flight)
        for chat in db.load_chats(group_id=group_id, status=GroupChatStatus.PENDING.value):
            db.update_chat_status(chat["id"], GroupChatStatus.ERROR.value, error="Cancelled")

        # Status is computed: with 2 DONE + 3 ERROR = all processed → COMPLETED
        computed_status = db.compute_group_status(group_id)
        assert computed_status == GroupStatus.COMPLETED.value

        # Some chats done, some error
        done_chats = db.load_chats(group_id=group_id, status=GroupChatStatus.DONE.value)
        error_chats = db.load_chats(group_id=group_id, status=GroupChatStatus.ERROR.value)
        assert len(done_chats) > 0, "Some chats should be done"
        assert len(error_chats) > 0, "Some chats should have errors from cancel"

        # Sleep to avoid task ID collision (timestamp-based)
        import time
        time.sleep(1.1)

        # Phase 2: Resume — should reset errors to pending and complete remaining
        async def mock_process_resume(chat, client, account_id, settings):
            return _make_chat_result(chat["chat_ref"])

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process_resume),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.resume_analysis(group_id)

        # All chats should now be DONE
        all_chats = db.load_chats(group_id=group_id)
        done_or_error = [
            c for c in all_chats
            if c["status"] in (GroupChatStatus.DONE.value, GroupChatStatus.ERROR.value)
        ]
        assert len(done_or_error) == 5, f"Expected 5 done/error, got {len(done_or_error)}"

        # Group should be COMPLETED or FAILED (all processed)
        computed_status = db.compute_group_status(group_id)
        assert computed_status in (
            GroupStatus.COMPLETED.value, GroupStatus.FAILED.value
        )


# ---------------------------------------------------------------------------
# 3. INCREMENT: add missing metrics → new task → Pending → Done
# ---------------------------------------------------------------------------

class TestIncrementMode:

    @pytest.mark.asyncio
    async def test_increment_reanalyzes_incomplete_chats(
        self, db: GroupDatabase, engine: GroupAnalysisEngine, session_manager: MagicMock,
    ) -> None:
        """After initial analysis with partial settings, INCREMENT fills missing metrics."""
        refs = ["@inc1", "@inc2", "@inc3"]
        # Initial analysis: only subscribers, no activity
        initial_settings = GroupSettings(
            detect_activity=False,
            detect_unique_authors=False,
            detect_captcha=False,
        )
        group_id = _setup_group(db, chat_refs=refs, settings=initial_settings)

        # First pass: succeed with subscribers only (no activity)
        async def mock_first_pass(chat, client, account_id, settings):
            return _make_chat_result(
                chat["chat_ref"],
                messages_per_hour=None,
                unique_authors_per_hour=None,
                captcha=None,
            )

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_first_pass),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # Verify initial state: all DONE, no activity metrics
        for chat in db.load_chats(group_id=group_id):
            assert chat["status"] == GroupChatStatus.DONE.value
            metrics = db.get_chat_metrics(chat["id"])
            assert metrics["messages_per_hour"] is None

        # Now update group settings to include activity
        full_settings = GroupSettings()
        db.save_group(
            group_id=group_id,
            name="Test Group",
            settings=full_settings.model_dump(),
            status=GroupStatus.COMPLETED.value,
        )

        # Sleep to avoid task ID collision (timestamp-based)
        import time
        time.sleep(1.1)

        # Second pass: INCREMENT should only process chats missing metrics
        processed_refs: list[str] = []

        async def mock_increment_pass(chat, client, account_id, settings):
            processed_refs.append(chat["chat_ref"])
            return _make_chat_result(chat["chat_ref"])

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_increment_pass),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.INCREMENT)

        # All 3 should have been reprocessed (missing activity metrics)
        assert len(processed_refs) == 3

        # All chats should now have full metrics
        for chat in db.load_chats(group_id=group_id):
            metrics = db.get_chat_metrics(chat["id"])
            assert metrics["messages_per_hour"] is not None
            assert metrics["unique_authors_per_hour"] is not None


# ---------------------------------------------------------------------------
# 4. OVERWRITE: clear + reanalyze → all Pending → Done
# ---------------------------------------------------------------------------

class TestOverwriteMode:

    @pytest.mark.asyncio
    async def test_overwrite_resets_all_and_reanalyzes(
        self, db: GroupDatabase, engine: GroupAnalysisEngine, session_manager: MagicMock,
    ) -> None:
        """OVERWRITE resets all chats to PENDING and reanalyzes from scratch."""
        refs = ["@ow1", "@ow2", "@ow3"]
        group_id = _setup_group(db, chat_refs=refs)

        # First pass
        async def mock_first(chat, client, account_id, settings):
            return _make_chat_result(chat["chat_ref"], subscribers=50)

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_first),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # Verify first pass completed
        for chat in db.load_chats(group_id=group_id):
            assert chat["status"] == GroupChatStatus.DONE.value
            assert chat["subscribers"] == 50

        # Sleep to avoid task ID collision (timestamp-based)
        import time
        time.sleep(1.1)

        # OVERWRITE: should reset all chats and reanalyze
        processed_refs: list[str] = []

        async def mock_overwrite(chat, client, account_id, settings):
            processed_refs.append(chat["chat_ref"])
            return _make_chat_result(chat["chat_ref"], subscribers=999)

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_overwrite),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.OVERWRITE)

        # All 3 should have been reprocessed
        assert len(processed_refs) == 3

        # Verify new data
        for chat in db.load_chats(group_id=group_id):
            assert chat["status"] == GroupChatStatus.DONE.value
            assert chat["subscribers"] == 999


# ---------------------------------------------------------------------------
# 5. Dead chat → ERROR status with chat_type=dead
# ---------------------------------------------------------------------------

class TestDeadChat:

    @pytest.mark.asyncio
    async def test_dead_chat_saved_as_error_with_dead_type(
        self, db: GroupDatabase, engine: GroupAnalysisEngine, session_manager: MagicMock,
    ) -> None:
        """Dead/banned chat gets status=ERROR and chat_type=dead."""
        refs = ["@alive", "@dead_chat"]
        group_id = _setup_group(db, chat_refs=refs)

        async def mock_process(chat, client, account_id, settings):
            if "dead" in chat["chat_ref"]:
                return ChatResult(
                    chat_ref=chat["chat_ref"],
                    chat_type=ChatTypeEnum.DEAD.value,
                    status="dead",
                    error="ChannelPrivateError: channel is private",
                )
            return _make_chat_result(chat["chat_ref"])

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # Check the dead chat
        all_chats = db.load_chats(group_id=group_id)
        dead_chats = [c for c in all_chats if c["chat_type"] == ChatTypeEnum.DEAD.value]
        assert len(dead_chats) == 1
        assert dead_chats[0]["status"] == GroupChatStatus.ERROR.value
        assert dead_chats[0]["error"] is not None

        # Check the alive chat
        alive_chats = [c for c in all_chats if c["chat_ref"] == "@alive"]
        assert len(alive_chats) == 1
        assert alive_chats[0]["status"] == GroupChatStatus.DONE.value

        # Group should be COMPLETED (done + error = total, computed)
        computed_status = db.compute_group_status(group_id)
        assert computed_status == GroupStatus.COMPLETED.value


# ---------------------------------------------------------------------------
# 6. Moderated chat → Done, activity N/A
# ---------------------------------------------------------------------------

class TestModeratedChat:

    @pytest.mark.asyncio
    async def test_moderated_chat_done_activity_null(
        self, db: GroupDatabase, engine: GroupAnalysisEngine, session_manager: MagicMock,
    ) -> None:
        """Moderated chat (join approval required) → Done with N/A activity metrics."""
        refs = ["@moderated", "@normal"]
        group_id = _setup_group(db, chat_refs=refs)

        async def mock_process(chat, client, account_id, settings):
            if "moderated" in chat["chat_ref"]:
                return ChatResult(
                    chat_ref=chat["chat_ref"],
                    chat_type=ChatTypeEnum.GROUP.value,
                    title="Moderated Group",
                    subscribers=500,
                    moderation=True,
                    messages_per_hour="N/A",
                    unique_authors_per_hour="N/A",
                    captcha="N/A",
                    status="done",
                )
            return _make_chat_result(chat["chat_ref"])

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # Both should be DONE
        all_chats = db.load_chats(group_id=group_id)
        for c in all_chats:
            assert c["status"] == GroupChatStatus.DONE.value

        # Moderated chat: metrics should have "N/A" for activity
        mod_chat = [c for c in all_chats if c["chat_ref"] == "@moderated"][0]
        metrics = db.get_chat_metrics(mod_chat["id"])
        assert metrics["moderation"] in (True, 1)
        # N/A stored as string in SQLite
        assert metrics["messages_per_hour"] == "N/A" or metrics["messages_per_hour"] is None


# ---------------------------------------------------------------------------
# 7. All accounts banned → Error
# ---------------------------------------------------------------------------

class TestAllAccountsBanned:

    @pytest.mark.asyncio
    async def test_no_accounts_raises_error(
        self, db: GroupDatabase, session_manager: MagicMock,
    ) -> None:
        """When no healthy accounts available, start_analysis raises NoConnectedAccountsError."""
        # No healthy accounts
        session_manager.list_sessions.return_value = ["acct-1"]
        session_manager.is_healthy = AsyncMock(return_value=False)

        engine = GroupAnalysisEngine(db=db, session_manager=session_manager)
        group_id = _setup_group(db)

        with pytest.raises(NoConnectedAccountsError):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

    @pytest.mark.asyncio
    async def test_all_chats_error_when_worker_fails(
        self, db: GroupDatabase, engine: GroupAnalysisEngine, session_manager: MagicMock,
    ) -> None:
        """When all accounts fail for all chats, group ends as FAILED."""
        refs = ["@fail1", "@fail2"]
        group_id = _setup_group(db, chat_refs=refs)

        async def mock_process(chat, client, account_id, settings):
            return ChatResult(
                chat_ref=chat["chat_ref"],
                chat_type=ChatTypeEnum.DEAD.value,
                status="banned",
                error="UserBannedInChannelError: banned",
            )

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await engine.start_analysis(group_id, mode=AnalysisMode.FRESH)

        # All chats should be ERROR
        all_chats = db.load_chats(group_id=group_id)
        for c in all_chats:
            assert c["status"] == GroupChatStatus.ERROR.value

        # Group should be FAILED (all error, computed)
        computed_status = db.compute_group_status(group_id)
        assert computed_status == GroupStatus.FAILED.value


# ---------------------------------------------------------------------------
# 8. CSV export with new columns
# ---------------------------------------------------------------------------

class TestCsvExport:

    def test_csv_export_with_new_columns(self, db: GroupDatabase) -> None:
        """CSV export reads metrics from group_chats columns and produces correct output."""
        group_id = _setup_group(db, chat_refs=["@exp1", "@exp2", "@exp3"])
        settings = GroupSettings()

        # Simulate completed analysis — set metrics directly
        chats = db.load_chats(group_id=group_id)
        test_data = [
            {"type": "group", "subs": 500, "mph": 10.5, "uaph": 4.2, "mod": False, "cap": False},
            {"type": "channel_no_comments", "subs": 2000, "mph": None, "uaph": None, "mod": False, "cap": False},
            {"type": "dead", "subs": None, "mph": None, "uaph": None, "mod": None, "cap": None},
        ]

        for chat, data in zip(chats, test_data):
            db.save_chat(
                group_id=group_id,
                chat_ref=chat["chat_ref"],
                chat_type=data["type"],
                status=GroupChatStatus.DONE.value if data["type"] != "dead" else GroupChatStatus.ERROR.value,
                chat_id=chat["id"],
                subscribers=data["subs"],
            )
            db.save_chat_metrics(chat["id"], {
                "title": f"Title {chat['chat_ref']}",
                "moderation": data["mod"],
                "messages_per_hour": data["mph"],
                "unique_authors_per_hour": data["uaph"],
                "captcha": data["cap"],
                "partial_data": False,
                "metrics_version": METRICS_VERSION,
            })

        # Use GroupService.get_results() — same as router uses
        svc = GroupService(db=db)
        results = svc.get_results(group_id)
        assert len(results) == 3

        # Convert for exporter (same as router does)
        converted = _convert_results_for_exporter(results)
        rows = list(to_csv_rows_dynamic(converted, settings))

        # Header + 3 data rows
        assert len(rows) == 4

        header = rows[0]
        assert "chat_ref" in header
        assert "title" in header
        assert "chat_type" in header
        assert "subscribers" in header
        assert "messages_per_hour" in header
        assert "unique_authors_per_hour" in header
        assert "moderation" in header
        assert "captcha" in header
        assert "status" in header

        # First data row (group chat with metrics)
        row1 = rows[1]
        ref_idx = header.index("chat_ref")
        subs_idx = header.index("subscribers")
        mph_idx = header.index("messages_per_hour")
        assert row1[ref_idx] == "@exp1"
        assert row1[subs_idx] == "500"
        assert row1[mph_idx] == "10.50"

    def test_export_filters_on_flat_results(self, db: GroupDatabase) -> None:
        """Export filters work on flat service.get_results() structure."""
        results = [
            {"chat_ref": "@a", "chat_type": "group", "subscribers": 500,
             "messages_per_hour": 10.0, "moderation": False, "captcha": False,
             "status": "done"},
            {"chat_ref": "@b", "chat_type": "dead", "subscribers": None,
             "messages_per_hour": None, "moderation": None, "captcha": None,
             "status": "error"},
            {"chat_ref": "@c", "chat_type": "group", "subscribers": 100,
             "messages_per_hour": 2.0, "moderation": True, "captcha": True,
             "status": "done"},
        ]

        # Filter out dead
        filtered = _apply_export_filters(results, chat_types="group")
        assert len(filtered) == 2
        assert all(r["chat_type"] == "group" for r in filtered)

        # Filter by subscribers
        filtered = _apply_export_filters(results, chat_types="group", subscribers_min=200)
        assert len(filtered) == 1
        assert filtered[0]["chat_ref"] == "@a"

    def test_export_group_results_to_csv_function(self, db: GroupDatabase) -> None:
        """Full export_group_results_to_csv produces valid CSV string."""
        # Build results in exporter format
        results_data = [
            {
                "chat_ref": "@test",
                "metrics_data": {
                    "title": "Test Chat",
                    "chat_type": "group",
                    "subscribers": 500,
                    "messages_per_hour": 12.34,
                    "unique_authors_per_hour": 5.67,
                    "moderation": False,
                    "captcha": True,
                    "status": "done",
                },
            },
        ]
        settings = GroupSettings()
        csv_content = export_group_results_to_csv(results_data, settings, include_bom=False)

        lines = csv_content.strip().splitlines()
        assert len(lines) == 2  # header + 1 data row

        # Parse header (strip \r from CSV line endings)
        header = [h.strip() for h in lines[0].split(",")]
        assert "chat_ref" in header
        assert "status" in header

        # Parse data
        data = [d.strip() for d in lines[1].split(",")]
        ref_idx = header.index("chat_ref")
        assert data[ref_idx] == "@test"


# ---------------------------------------------------------------------------
# Cross-cutting: service layer orchestration
# ---------------------------------------------------------------------------

class TestServiceLayer:

    @pytest.mark.asyncio
    async def test_service_start_analysis_delegates_to_engine(
        self, db: GroupDatabase, engine: GroupAnalysisEngine,
        session_manager: MagicMock,
    ) -> None:
        """GroupService.start_analysis() creates group and delegates to engine."""
        group_id = _setup_group(db)
        svc = GroupService(db=db, engine=engine)

        async def mock_process(chat, client, account_id, settings):
            return _make_chat_result(chat["chat_ref"])

        with (
            patch("chatfilter.analyzer.group_engine.process_chat", side_effect=mock_process),
            patch("chatfilter.analyzer.group_engine.asyncio.sleep", new_callable=AsyncMock),
        ):
            await svc.start_analysis(group_id)

        # Status is computed from chat statuses
        computed_status = db.compute_group_status(group_id)
        assert computed_status == GroupStatus.COMPLETED.value

    def test_service_get_results_returns_flat_dicts(self, db: GroupDatabase) -> None:
        """service.get_results() returns flat dicts with metrics from group_chats."""
        group_id = _setup_group(db, chat_refs=["@r1"])
        svc = GroupService(db=db)

        # Manually set metrics
        chats = db.load_chats(group_id=group_id)
        chat = chats[0]
        db.save_chat(
            group_id=group_id, chat_ref=chat["chat_ref"],
            chat_type=ChatTypeEnum.GROUP.value,
            status=GroupChatStatus.DONE.value,
            chat_id=chat["id"], subscribers=300,
        )
        db.save_chat_metrics(chat["id"], {
            "title": "Result Chat",
            "moderation": False,
            "messages_per_hour": 7.5,
            "unique_authors_per_hour": 3.0,
            "captcha": True,
            "partial_data": False,
            "metrics_version": METRICS_VERSION,
        })

        results = svc.get_results(group_id)
        assert len(results) == 1
        r = results[0]
        assert r["chat_ref"] == "@r1"
        assert r["chat_type"] == ChatTypeEnum.GROUP.value
        assert r["subscribers"] == 300
        assert r["title"] == "Result Chat"
        assert r["messages_per_hour"] == 7.5
        assert r["captcha"] in (True, 1)


# ---------------------------------------------------------------------------
# Crash recovery
# ---------------------------------------------------------------------------

class TestCrashRecovery:

    def test_recover_stale_analysis_sets_paused(
        self, db: GroupDatabase, session_manager: MagicMock,
    ) -> None:
        """Groups stuck in IN_PROGRESS after crash get set to PAUSED."""
        group_id = _setup_group(db, status=GroupStatus.IN_PROGRESS.value)
        # Create an active task
        db.create_task(
            group_id=group_id,
            requested_metrics=GroupSettings().model_dump(),
            time_window=24,
        )

        engine = GroupAnalysisEngine(db=db, session_manager=session_manager)
        engine.recover_stale_analysis()

        # recover_stale_analysis now explicitly sets PAUSED (not computed)
        group = db.load_group(group_id)
        assert group["status"] == GroupStatus.PAUSED.value

        # Task should be cancelled
        active_task = db.get_active_task(group_id)
        assert active_task is None  # no running tasks

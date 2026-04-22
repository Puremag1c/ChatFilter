"""Phase 3 — analysis_queue schema + cost_per_chat tests.

Schema-only phase: no runtime behaviour changes. The scheduler is added
in Phase 4; billing uses cost_per_chat in Phase 5. Here we just assert
the DB has the shape the later phases will rely on.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


@pytest.fixture
def alembic_cfg_factory(tmp_path: Path):
    def _make(db_path: Path) -> Config:
        project_root = Path(__file__).resolve().parent.parent
        cfg = Config(str(project_root / "alembic.ini"))
        cfg.set_main_option("script_location", str(project_root / "src/chatfilter/migrations"))
        cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
        return cfg

    return _make


@pytest.fixture
def migrated_db(tmp_path: Path, alembic_cfg_factory) -> Path:
    db_path = tmp_path / "test.db"
    cfg = alembic_cfg_factory(db_path)
    command.upgrade(cfg, "head")
    return db_path


class TestAnalysisQueueTableExists:
    def test_table_has_required_columns(self, migrated_db: Path) -> None:
        with sqlite3.connect(migrated_db) as conn:
            cols = {
                row[1]
                for row in conn.execute("PRAGMA table_info(analysis_queue)").fetchall()
            }

        expected = {
            "id",
            "group_id",
            "group_chat_id",
            "chat_ref",
            "user_id",
            "pool_key",
            "status",
            "account_id",
            "attempts",
            "charged_amount",
            "created_at",
            "started_at",
            "finished_at",
            "error",
        }
        missing = expected - cols
        assert not missing, f"Missing columns in analysis_queue: {missing}"

    def test_table_has_fairshare_index(self, migrated_db: Path) -> None:
        with sqlite3.connect(migrated_db) as conn:
            indexes = {
                row[1]
                for row in conn.execute(
                    "SELECT * FROM sqlite_master WHERE type='index' AND tbl_name='analysis_queue'"
                ).fetchall()
            }
        # Index used by the FairShare SELECT (status + pool_key + created_at).
        assert any(
            "status" in idx.lower() and "pool" in idx.lower() for idx in indexes
        ), f"Expected a (status, pool_key, ...) index on analysis_queue — have: {indexes}"

    def test_table_has_user_status_index(self, migrated_db: Path) -> None:
        with sqlite3.connect(migrated_db) as conn:
            indexes = {
                row[1]
                for row in conn.execute(
                    "SELECT * FROM sqlite_master WHERE type='index' AND tbl_name='analysis_queue'"
                ).fetchall()
            }
        # Index used by the "how many running tasks does this user hold" query.
        assert any(
            "user" in idx.lower() and "status" in idx.lower() for idx in indexes
        ), f"Expected a (user_id, status) index on analysis_queue — have: {indexes}"


class TestAnalysisQueueDefaults:
    def test_insert_with_defaults(self, migrated_db: Path) -> None:
        with sqlite3.connect(migrated_db) as conn:
            conn.execute(
                "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at) "
                "VALUES ('g1', 'g', '{}', 'pending', '2026-01-01', '2026-01-01')"
            )
            conn.execute(
                "INSERT INTO group_chats (group_id, chat_ref, chat_type, status) "
                "VALUES ('g1', '@x', 'pending', 'pending')"
            )
            chat_id = conn.execute(
                "SELECT id FROM group_chats WHERE group_id = 'g1'"
            ).fetchone()[0]
            conn.execute(
                """
                INSERT INTO analysis_queue
                  (group_id, group_chat_id, chat_ref, user_id, pool_key, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                """,
                ("g1", chat_id, "@x", "u1", "admin", "queued"),
            )
            row = conn.execute(
                "SELECT attempts, charged_amount, account_id, started_at, finished_at, error "
                "FROM analysis_queue"
            ).fetchone()

        assert row[0] == 0, "attempts defaults to 0"
        assert row[1] == 0.0, "charged_amount defaults to 0.0"
        assert row[2] is None
        assert row[3] is None
        assert row[4] is None
        assert row[5] is None


class TestCostPerChatSetting:
    """cost_per_chat lives in the existing app_settings key/value table.

    Phase 5 will read it to compute pre-flight and per-chat charges.
    """

    def test_default_zero_when_unset(self, migrated_db: Path) -> None:
        from chatfilter.storage.group_database import GroupDatabase

        db = GroupDatabase(f"sqlite:///{migrated_db}")
        assert db.get_cost_per_chat() == 0.0

    def test_set_and_get(self, migrated_db: Path) -> None:
        from chatfilter.storage.group_database import GroupDatabase

        db = GroupDatabase(f"sqlite:///{migrated_db}")
        db.set_cost_per_chat(0.01)
        assert db.get_cost_per_chat() == 0.01

    def test_negative_rejected(self, migrated_db: Path) -> None:
        from chatfilter.storage.group_database import GroupDatabase

        db = GroupDatabase(f"sqlite:///{migrated_db}")
        with pytest.raises(ValueError):
            db.set_cost_per_chat(-0.01)


class TestEnqueueAndClaimHelpers:
    """Phase-4 scheduler relies on a handful of DB helpers — verify their
    atomic semantics here so the scheduler can assume they are safe.
    """

    def _seed(self, db_path: Path, user_id: str = "u1") -> None:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at, user_id) "
                "VALUES ('g1', 'g', '{}', 'pending', '2026-01-01', '2026-01-01', ?)",
                (user_id,),
            )
            conn.execute(
                "INSERT INTO group_chats (group_id, chat_ref, chat_type, status) "
                "VALUES ('g1', '@one', 'pending', 'pending'), "
                "       ('g1', '@two', 'pending', 'pending')"
            )

    def test_enqueue_chat_task_creates_queued_row(self, migrated_db: Path) -> None:
        from chatfilter.storage.group_database import GroupDatabase

        self._seed(migrated_db)
        db = GroupDatabase(f"sqlite:///{migrated_db}")
        chats = db.load_chats(group_id="g1")
        task_id = db.enqueue_chat_task(
            group_id="g1",
            group_chat_id=chats[0]["id"],
            chat_ref=chats[0]["chat_ref"],
            user_id="u1",
            pool_key="admin",
        )
        assert task_id is not None

        with sqlite3.connect(migrated_db) as conn:
            row = conn.execute(
                "SELECT status, pool_key, user_id, group_chat_id FROM analysis_queue "
                "WHERE id = ?",
                (task_id,),
            ).fetchone()
        assert row == ("queued", "admin", "u1", chats[0]["id"])

    def test_claim_next_respects_fairshare_limit(self, migrated_db: Path) -> None:
        """One user's existing running task blocks a second claim when limit=1."""
        from chatfilter.storage.group_database import GroupDatabase

        self._seed(migrated_db)
        db = GroupDatabase(f"sqlite:///{migrated_db}")
        chats = db.load_chats(group_id="g1")

        t1 = db.enqueue_chat_task("g1", chats[0]["id"], chats[0]["chat_ref"], "u1", "admin")
        db.enqueue_chat_task("g1", chats[1]["id"], chats[1]["chat_ref"], "u1", "admin")

        # First claim — succeeds, picks t1.
        claimed = db.claim_next_task(pool_key="admin", account_id="acc1", user_limit=1)
        assert claimed is not None
        assert claimed["id"] == t1

        # Second claim for the same user with limit=1 — returns None.
        second = db.claim_next_task(pool_key="admin", account_id="acc2", user_limit=1)
        assert second is None, (
            "FairShare limit must block a second claim for the same user"
        )

    def test_claim_next_isolates_pool_keys(self, migrated_db: Path) -> None:
        from chatfilter.storage.group_database import GroupDatabase

        self._seed(migrated_db)
        db = GroupDatabase(f"sqlite:///{migrated_db}")
        chats = db.load_chats(group_id="g1")

        db.enqueue_chat_task("g1", chats[0]["id"], chats[0]["chat_ref"], "u1", "user:u1")
        # admin pool is empty → no claim from admin pool
        assert db.claim_next_task("admin", "acc", user_limit=5) is None
        # but user's own pool yields the task
        picked = db.claim_next_task("user:u1", "acc", user_limit=5)
        assert picked is not None

    def test_mark_done_and_error(self, migrated_db: Path) -> None:
        from chatfilter.storage.group_database import GroupDatabase

        self._seed(migrated_db)
        db = GroupDatabase(f"sqlite:///{migrated_db}")
        chats = db.load_chats(group_id="g1")
        t1 = db.enqueue_chat_task("g1", chats[0]["id"], chats[0]["chat_ref"], "u1", "admin")
        t2 = db.enqueue_chat_task("g1", chats[1]["id"], chats[1]["chat_ref"], "u1", "admin")

        db.claim_next_task("admin", "acc1", user_limit=10)
        db.claim_next_task("admin", "acc2", user_limit=10)

        db.mark_task_done(t1)
        db.mark_task_error(t2, "Network timeout")

        with sqlite3.connect(migrated_db) as conn:
            done_row = conn.execute(
                "SELECT status, finished_at FROM analysis_queue WHERE id = ?", (t1,)
            ).fetchone()
            err_row = conn.execute(
                "SELECT status, error, finished_at FROM analysis_queue WHERE id = ?",
                (t2,),
            ).fetchone()

        assert done_row[0] == "done"
        assert done_row[1] is not None
        assert err_row[0] == "error"
        assert err_row[1] == "Network timeout"
        assert err_row[2] is not None

    def test_crash_recovery_resets_running_to_queued(
        self, migrated_db: Path
    ) -> None:
        """Phase 4 recovery: on startup, any running task goes back into the queue."""
        from chatfilter.storage.group_database import GroupDatabase

        self._seed(migrated_db)
        db = GroupDatabase(f"sqlite:///{migrated_db}")
        chats = db.load_chats(group_id="g1")
        t1 = db.enqueue_chat_task("g1", chats[0]["id"], chats[0]["chat_ref"], "u1", "admin")
        db.claim_next_task("admin", "acc1", user_limit=10)

        # Simulate crash recovery.
        reset = db.reset_running_tasks_to_queued()
        assert reset == 1

        with sqlite3.connect(migrated_db) as conn:
            row = conn.execute(
                "SELECT status, account_id, attempts FROM analysis_queue WHERE id = ?",
                (t1,),
            ).fetchone()
        assert row[0] == "queued"
        assert row[1] is None, "account_id cleared so a fresh account can pick it"
        assert row[2] == 1, "attempts incremented"

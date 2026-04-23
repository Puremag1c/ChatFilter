"""Phase 0 — data-migration 013 tests.

Historical rows with status='error' AND chat_type='dead' represent chats
where Telegram DID answer (saying "does not exist") but the old code
lumped them under status=ERROR.  The migration promotes them to
status='done' so billing at Phase 5 charges them and the UI shows them
under "Dead", not "Errors".
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config


@pytest.fixture
def alembic_cfg_factory(tmp_path: Path):
    """Build an Alembic Config pointing to a fresh SQLite DB."""

    def _make(db_path: Path) -> Config:
        project_root = Path(__file__).resolve().parent.parent
        cfg = Config(str(project_root / "alembic.ini"))
        cfg.set_main_option("script_location", str(project_root / "src/chatfilter/migrations"))
        cfg.set_main_option("sqlalchemy.url", f"sqlite:///{db_path}")
        return cfg

    return _make


def test_dead_chats_with_error_status_promoted_to_done(tmp_path: Path, alembic_cfg_factory) -> None:
    db_path = tmp_path / "test.db"
    cfg = alembic_cfg_factory(db_path)

    # Run all migrations up to (but not including) 013.
    command.upgrade(cfg, "012")

    # Seed historical data: three rows covering the interesting cases.
    with sqlite3.connect(db_path) as conn:
        # Need a parent group first (foreign-key target).
        conn.execute(
            "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at) "
            "VALUES ('g1', 'g', '{}', 'completed', '2026-01-01', '2026-01-01')"
        )
        # row A: dead chat mislabelled as error → should flip to done
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status, error) "
            "VALUES ('g1', '@dead', 'dead', 'error', 'Username not occupied')"
        )
        # row B: a real error unrelated to dead → stays error
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status, error) "
            "VALUES ('g1', '@err', 'pending', 'error', 'Network timeout')"
        )
        # row C: a normal done row — unchanged
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status) "
            "VALUES ('g1', '@grp', 'group', 'done')"
        )
        conn.commit()

    # Run the new migration.
    command.upgrade(cfg, "013")

    with sqlite3.connect(db_path) as conn:
        rows = dict(
            conn.execute("SELECT chat_ref, status FROM group_chats ORDER BY chat_ref").fetchall()
        )

    # Dead chat was promoted.
    assert rows["@dead"] == "done"
    # Real error left alone.
    assert rows["@err"] == "error"
    # Unrelated row unchanged.
    assert rows["@grp"] == "done"


def test_downgrade_reverts_dead_chats_to_error(tmp_path: Path, alembic_cfg_factory) -> None:
    db_path = tmp_path / "test.db"
    cfg = alembic_cfg_factory(db_path)

    command.upgrade(cfg, "013")

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at) "
            "VALUES ('g1', 'g', '{}', 'completed', '2026-01-01', '2026-01-01')"
        )
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status) "
            "VALUES ('g1', '@dead', 'dead', 'done')"
        )
        conn.commit()

    command.downgrade(cfg, "012")

    with sqlite3.connect(db_path) as conn:
        status = conn.execute("SELECT status FROM group_chats WHERE chat_ref = '@dead'").fetchone()[
            0
        ]

    assert status == "error"

"""Migration 017 — finish the Phase-0 terminal-chat-type backfill.

Migration 013 handled ``chat_type='dead'``; 017 extends the same fix
to banned/restricted/private. These are all rows where Telegram
answered and the chat is terminal — they should show as done and be
billable, not hide as pseudo-errors.
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


def test_banned_restricted_private_promoted_to_done(tmp_path: Path, alembic_cfg_factory) -> None:
    db_path = tmp_path / "test.db"
    cfg = alembic_cfg_factory(db_path)

    # Bring the DB up to 016 so 017 is the only pending revision.
    command.upgrade(cfg, "016")

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at) "
            "VALUES ('g1', 'g', '{}', 'completed', '2026-01-01', '2026-01-01')"
        )
        # A: banned stuck as error — should flip
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status, error) "
            "VALUES ('g1', '@banned', 'banned', 'error', 'ChannelBanned')"
        )
        # B: restricted stuck as error — should flip
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status, error) "
            "VALUES ('g1', '@restricted', 'restricted', 'error', 'ChannelRestricted')"
        )
        # C: private stuck as error — should flip
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status, error) "
            "VALUES ('g1', '@priv', 'private', 'error', 'ChannelPrivate')"
        )
        # D: unknown chat_type real error — must stay error
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status, error) "
            "VALUES ('g1', '@err', 'pending', 'error', 'Network timeout')"
        )
        # E: dead already promoted by 013 — unchanged
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status) "
            "VALUES ('g1', '@dead', 'dead', 'done')"
        )
        # F: normal done unaffected
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status) "
            "VALUES ('g1', '@grp', 'group', 'done')"
        )
        conn.commit()

    command.upgrade(cfg, "017")

    with sqlite3.connect(db_path) as conn:
        rows = dict(
            conn.execute("SELECT chat_ref, status FROM group_chats ORDER BY chat_ref").fetchall()
        )

    assert rows["@banned"] == "done", "banned chat must be promoted to done"
    assert rows["@restricted"] == "done", "restricted chat must be promoted to done"
    assert rows["@priv"] == "done", "private chat must be promoted to done"
    assert rows["@err"] == "error", "real error must stay error"
    assert rows["@dead"] == "done", "already-promoted dead chat unchanged"
    assert rows["@grp"] == "done", "normal done row unchanged"


def test_downgrade_reverts_only_rows_without_error(tmp_path: Path, alembic_cfg_factory) -> None:
    """Downgrade is intentionally conservative: it flips back only rows
    that carry no error text, so we don't smuggle a genuine error
    that was manually cleaned up later back into the wrong state."""
    db_path = tmp_path / "test.db"
    cfg = alembic_cfg_factory(db_path)

    command.upgrade(cfg, "017")

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at) "
            "VALUES ('g1', 'g', '{}', 'completed', '2026-01-01', '2026-01-01')"
        )
        # clean banned row — downgrade should revert
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status, error) "
            "VALUES ('g1', '@banned', 'banned', 'done', NULL)"
        )
        # done restricted row with an error note — downgrade skips
        conn.execute(
            "INSERT INTO group_chats (group_id, chat_ref, chat_type, status, error) "
            "VALUES ('g1', '@r', 'restricted', 'done', 'fyi: was a real issue too')"
        )
        conn.commit()

    command.downgrade(cfg, "016")

    with sqlite3.connect(db_path) as conn:
        rows = dict(
            conn.execute("SELECT chat_ref, status FROM group_chats ORDER BY chat_ref").fetchall()
        )

    assert rows["@banned"] == "error", "clean banned row reverted"
    assert rows["@r"] == "done", "restricted with error note preserved"

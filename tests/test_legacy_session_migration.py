"""One-shot migration: legacy ``sessions/<uuid>/<name>`` → ``sessions/<scope>/<name>``.

Before Phase 6 session dirs were stored under the uploader's raw user
UUID. After Phase 6 the canonical layout is ``sessions/admin/`` for
shared admin pool and ``sessions/user_<id>/`` for personal pools.
On start we migrate any pre-existing legacy dirs into the new layout
so delete/config/connect all find them at the expected path.

Also covered: user-owned legacy dirs and conflict handling.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def migrate_with_sessions_dir(tmp_path: Path, monkeypatch: Any):
    """Point ``helpers.get_settings().sessions_dir`` at a tmp tree."""
    from chatfilter.config import Settings
    from chatfilter.web.routers.sessions import helpers as session_helpers

    settings = Settings(data_dir=tmp_path / "data", api_id=1, api_hash="x")
    settings.ensure_data_dirs()
    monkeypatch.setattr(session_helpers, "get_settings", lambda: settings)

    from chatfilter.web.routers.sessions.io import migrate_legacy_session_dirs

    return migrate_legacy_session_dirs, settings.sessions_dir


def _seed_legacy(sessions_dir: Path, raw_user: str, name: str, owner: str | None) -> Path:
    d = sessions_dir / raw_user / name
    d.mkdir(parents=True)
    if owner is not None:
        (d / ".account_info.json").write_text(json.dumps({"owner": owner, "user_id": 1}))
    (d / "config.json").write_text("{}")
    return d


class TestMigrateLegacySessionDirs:
    def test_admin_owned_legacy_moves_to_admin_subdir(self, migrate_with_sessions_dir) -> None:
        migrate, sessions_dir = migrate_with_sessions_dir
        _seed_legacy(sessions_dir, "fake-admin-uuid-1", "ShivaBot", owner="admin")

        stats = migrate()

        assert stats["moved"] == 1
        assert (sessions_dir / "admin" / "ShivaBot").is_dir()
        assert not (sessions_dir / "fake-admin-uuid-1").exists(), (
            "Empty legacy dir should be cleaned up after migration"
        )

    def test_user_owned_legacy_moves_to_user_subdir(self, migrate_with_sessions_dir) -> None:
        migrate, sessions_dir = migrate_with_sessions_dir
        _seed_legacy(sessions_dir, "fake-user-uuid-2", "MyPersonal", owner="user:42")

        migrate()

        assert (sessions_dir / "user_42" / "MyPersonal").is_dir()
        assert not (sessions_dir / "fake-user-uuid-2").exists()

    def test_missing_owner_defaults_to_admin_pool(self, migrate_with_sessions_dir) -> None:
        """Pre-Phase-4 sessions without an owner field default to admin."""
        migrate, sessions_dir = migrate_with_sessions_dir
        _seed_legacy(sessions_dir, "very-old-uuid", "LegacyAcct", owner=None)

        migrate()

        assert (sessions_dir / "admin" / "LegacyAcct").is_dir()

    def test_already_canonical_untouched(self, migrate_with_sessions_dir) -> None:
        """A session already under sessions/admin/ is not moved or touched."""
        migrate, sessions_dir = migrate_with_sessions_dir
        target = sessions_dir / "admin" / "Already"
        target.mkdir(parents=True)
        (target / "config.json").write_text("{}")

        stats = migrate()

        assert stats["moved"] == 0
        assert target.is_dir()

    def test_conflict_leaves_legacy_in_place(self, migrate_with_sessions_dir) -> None:
        """If canonical path exists, legacy copy must not clobber it."""
        migrate, sessions_dir = migrate_with_sessions_dir
        # canonical
        (sessions_dir / "admin" / "Dup").mkdir(parents=True)
        (sessions_dir / "admin" / "Dup" / "config.json").write_text('{"canonical": true}')
        # legacy collision
        legacy = _seed_legacy(sessions_dir, "colliding-uuid", "Dup", owner="admin")

        stats = migrate()

        assert stats["conflicts"] == 1
        assert legacy.is_dir(), "Legacy dir must stay intact on conflict"
        assert json.loads((sessions_dir / "admin" / "Dup" / "config.json").read_text()) == {
            "canonical": True
        }

    def test_is_idempotent(self, migrate_with_sessions_dir) -> None:
        """Running the migration twice must be a no-op the second time."""
        migrate, sessions_dir = migrate_with_sessions_dir
        _seed_legacy(sessions_dir, "uuid-x", "Bot", owner="admin")

        first = migrate()
        second = migrate()

        assert first["moved"] == 1
        assert second["moved"] == 0
        assert second["conflicts"] == 0

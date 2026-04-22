"""Shared admin pool: all admins see the same accounts and proxies.

Regression prevention for the old per-user-directory behaviour where
each admin saw only the sessions they themselves uploaded.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest


# ------------------------------------------------------------------
# 1. get_pool_scope / get_owner_key
# ------------------------------------------------------------------


class TestScopeHelpers:
    def test_admin_session_returns_admin_scope(self) -> None:
        from chatfilter.web.dependencies import get_owner_key, get_pool_scope

        req = MagicMock()
        req.app.state = MagicMock()

        def fake_session(_req):
            s = MagicMock()
            s.get = lambda k, d=None: {
                "is_admin": True,
                "user_id": "42",
            }.get(k, d)
            return s

        import chatfilter.web.dependencies as deps

        orig = deps.get_session
        deps.get_session = fake_session
        try:
            assert get_pool_scope(req) == "admin"
            assert get_owner_key(req) == "admin"
        finally:
            deps.get_session = orig

    def test_user_session_returns_user_scope(self) -> None:
        from chatfilter.web.dependencies import get_owner_key, get_pool_scope

        req = MagicMock()

        def fake_session(_req):
            s = MagicMock()
            s.get = lambda k, d=None: {
                "is_admin": False,
                "user_id": "42",
            }.get(k, d)
            return s

        import chatfilter.web.dependencies as deps

        orig = deps.get_session
        deps.get_session = fake_session
        try:
            assert get_pool_scope(req) == "user_42"
            assert get_owner_key(req) == "user:42"
        finally:
            deps.get_session = orig


# ------------------------------------------------------------------
# 2. list_stored_sessions returns the full admin pool, not per-user
# ------------------------------------------------------------------


class TestAdminPoolIsShared:
    def test_all_admins_see_same_sessions(self, tmp_path: Path, monkeypatch: Any) -> None:
        """Two admins uploaded different accounts in their own moments.

        After the shared-pool fix both of them list exactly the same
        result when we call list_stored_sessions("admin").
        """
        from chatfilter.config import Settings

        # Build an isolated settings instance so we don't bleed into
        # whatever the current test suite uses.
        s = Settings(data_dir=tmp_path / "data")
        s.ensure_data_dirs()
        monkeypatch.setattr("chatfilter.config.get_settings", lambda: s)
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.helpers.get_settings", lambda: s
        )

        sessions_dir = s.sessions_dir

        # Admin #1 uploaded "Bot1" from their workstation — we simulate
        # the pre-fix layout where the uploader's user_id was used as
        # the subdir.
        (sessions_dir / "1" / "Bot1").mkdir(parents=True)
        (sessions_dir / "1" / "Bot1" / ".account_info.json").write_text(
            json.dumps({"user_id": 100, "owner": "admin"})
        )
        (sessions_dir / "1" / "Bot1" / "config.json").write_text("{}")

        # Admin #2 uploaded "Bot2" later — stored under their own
        # directory for some legacy reason.
        (sessions_dir / "2" / "Bot2").mkdir(parents=True)
        (sessions_dir / "2" / "Bot2" / ".account_info.json").write_text(
            json.dumps({"user_id": 200, "owner": "admin"})
        )
        (sessions_dir / "2" / "Bot2" / "config.json").write_text("{}")

        # A power-user also uploaded one account — it must NOT appear
        # in the admin view.
        (sessions_dir / "user_3" / "MyOwn").mkdir(parents=True)
        (sessions_dir / "user_3" / "MyOwn" / ".account_info.json").write_text(
            json.dumps({"user_id": 300, "owner": "user:3"})
        )
        (sessions_dir / "user_3" / "MyOwn" / "config.json").write_text("{}")

        from chatfilter.web.routers.sessions.listing import list_stored_sessions

        listed = list_stored_sessions(user_id="admin")
        ids = sorted(item.session_id for item in listed)
        assert ids == ["Bot1", "Bot2"], (
            f"Admin pool must include both bots and exclude user-owned — got {ids}"
        )

    def test_power_user_sees_only_their_own(
        self, tmp_path: Path, monkeypatch: Any
    ) -> None:
        from chatfilter.config import Settings

        s = Settings(data_dir=tmp_path / "data")
        s.ensure_data_dirs()
        monkeypatch.setattr("chatfilter.config.get_settings", lambda: s)
        monkeypatch.setattr(
            "chatfilter.web.routers.sessions.helpers.get_settings", lambda: s
        )

        sessions_dir = s.sessions_dir
        (sessions_dir / "admin" / "Shared").mkdir(parents=True)
        (sessions_dir / "admin" / "Shared" / ".account_info.json").write_text(
            json.dumps({"user_id": 1, "owner": "admin"})
        )
        (sessions_dir / "admin" / "Shared" / "config.json").write_text("{}")

        (sessions_dir / "user_7" / "Mine").mkdir(parents=True)
        (sessions_dir / "user_7" / "Mine" / ".account_info.json").write_text(
            json.dumps({"user_id": 7, "owner": "user:7"})
        )
        (sessions_dir / "user_7" / "Mine" / "config.json").write_text("{}")

        from chatfilter.web.routers.sessions.listing import list_stored_sessions

        listed = list_stored_sessions(user_id="user_7")
        ids = [item.session_id for item in listed]
        assert ids == ["Mine"], f"Power-user must see only their own — got {ids}"

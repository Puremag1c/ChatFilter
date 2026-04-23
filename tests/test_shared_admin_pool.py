"""Shared admin pool: all admins see the same accounts and proxies.

Regression prevention for the old per-user-directory behaviour where
each admin saw only the sessions they themselves uploaded.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

# ------------------------------------------------------------------
# 1. get_pool_scope / get_owner_key
# ------------------------------------------------------------------


class TestScopeHelpers:
    """Scope is chosen by URL path now: /admin/* → admin, everything
    else → the caller's personal scope. See test_admin_user_split for
    the exhaustive checks."""

    def test_admin_path_returns_admin_scope(self) -> None:
        from chatfilter.web.dependencies import get_owner_key, get_pool_scope

        req = MagicMock()
        req.url.path = "/admin/accounts"

        def fake_session(_req):
            s = MagicMock()
            s.get = lambda k, d=None: {"is_admin": True, "user_id": "42"}.get(k, d)
            return s

        import chatfilter.web.dependencies as deps

        orig = deps.get_session
        deps.get_session = fake_session
        try:
            assert get_pool_scope(req) == "admin"
            assert get_owner_key(req) == "admin"
        finally:
            deps.get_session = orig

    def test_non_admin_path_returns_user_scope(self) -> None:
        from chatfilter.web.dependencies import get_owner_key, get_pool_scope

        req = MagicMock()
        req.url.path = "/sessions"

        def fake_session(_req):
            s = MagicMock()
            s.get = lambda k, d=None: {"is_admin": False, "user_id": "42"}.get(k, d)
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
        monkeypatch.setattr("chatfilter.web.routers.sessions.helpers.get_settings", lambda: s)

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

    def test_power_user_sees_only_their_own(self, tmp_path: Path, monkeypatch: Any) -> None:
        from chatfilter.config import Settings

        s = Settings(data_dir=tmp_path / "data")
        s.ensure_data_dirs()
        monkeypatch.setattr("chatfilter.config.get_settings", lambda: s)
        monkeypatch.setattr("chatfilter.web.routers.sessions.helpers.get_settings", lambda: s)

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


# ------------------------------------------------------------------
# 3. DELETE /admin/api/sessions/{id} targets the shared admin dir
# ------------------------------------------------------------------
#
# Regression for v0.40 bug where delete_session / get_session_config /
# update_session_config all used `get_session(request).get("user_id")` —
# the caller's raw user id — instead of `get_pool_scope(request)`.
# For admin URLs the URL scope is "admin", so the files live under
# sessions/admin/<name>, not sessions/<admin_user_id>/<name>.


class TestAdminDeleteTargetsSharedDir:
    @staticmethod
    def _csrf(client: Any) -> dict[str, str]:
        """Grab a CSRF token out of /chats and format it as a request header."""
        from tests.test_groups_api import extract_csrf_token

        page = client.get("/chats")
        assert page.status_code == 200
        return {"X-CSRF-Token": extract_csrf_token(page.text)}

    @staticmethod
    def _effective_sessions_dir() -> Path:
        """Return the sessions_dir the handler actually sees.

        ``conftest._isolate_data_dir`` (autouse) patches get_settings to a
        per-test ``isolated_data`` dir — NOT ``test_settings.sessions_dir``.
        We must use the same getter the request handler uses.
        """
        from chatfilter.web.routers.sessions import helpers as session_helpers

        return session_helpers.get_settings().sessions_dir

    def test_admin_can_delete_from_shared_pool(self, admin_client: Any) -> None:
        """Fix #3: DELETE /admin/api/sessions/X must remove the file in
        ``sessions/admin/X``, not in ``sessions/<admin_id>/X``.

        Before the fix, delete_session derived the directory from the
        caller's raw user_id, so any admin-uploaded account (which
        always lives in sessions/admin/) returned 404 for every admin
        that didn't personally upload it.
        """
        sessions_dir = self._effective_sessions_dir()
        target = sessions_dir / "admin" / "SharedBot"
        target.mkdir(parents=True)
        (target / ".account_info.json").write_text(
            json.dumps({"user_id": 999, "owner": "admin", "phone": "+123"})
        )
        (target / "config.json").write_text(json.dumps({"proxy_id": None}))
        (target / "session.session").write_bytes(b"dummy")

        r = admin_client.delete(
            "/admin/api/sessions/SharedBot",
            headers=self._csrf(admin_client),
        )
        assert r.status_code == 200, f"expected 200, got {r.status_code}: {r.text}"
        assert not target.exists(), "shared-pool session directory must be gone"

    def test_admin_get_config_targets_shared_dir(self, admin_client: Any) -> None:
        """GET /admin/api/sessions/{id}/config must read sessions/admin/,
        not sessions/<admin_id>/."""
        sessions_dir = self._effective_sessions_dir()
        target = sessions_dir / "admin" / "CfgBot"
        target.mkdir(parents=True)
        (target / "config.json").write_text(json.dumps({"proxy_id": None}))

        r = admin_client.get("/admin/api/sessions/CfgBot/config")
        assert r.status_code == 200, (
            "Admin getting config of a shared-pool session must hit sessions/admin/"
        )

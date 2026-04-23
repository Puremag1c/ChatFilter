"""Rework: scheduler flow is default, feature flag gone, pool routing live.

Admin uploads accounts → analyses go through admin pool.
Power-user toggles use_own_accounts → /sessions and /proxies come back,
uploaded sessions get owner="user:{id}", their analyses route through
their private pool.
"""

from __future__ import annotations

from typing import Any

# ------------------------------------------------------------------
# 1. /sessions and /proxies access matches role
# ------------------------------------------------------------------


class TestSessionAccessDependency:
    """/sessions and /proxies are the personal pool — admins without the
    use_own_accounts toggle don't see them. See test_admin_user_split.py
    for the full access matrix."""

    def test_admin_sees_admin_accounts(self, admin_client: Any) -> None:
        r = admin_client.get("/admin/accounts")
        assert r.status_code < 400

    def test_admin_sees_admin_proxies(self, admin_client: Any) -> None:
        r = admin_client.get("/admin/proxies")
        assert r.status_code < 400

    def test_regular_user_without_toggle_is_blocked(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/sessions")
        assert r.status_code == 403
        r2 = fastapi_test_client.get("/proxies")
        assert r2.status_code == 403

    def test_regular_user_with_toggle_gets_access(
        self, fastapi_test_client: Any, test_settings: Any
    ) -> None:
        from chatfilter.storage.user_database import get_user_db

        user_db = get_user_db(test_settings.effective_database_url)
        user = user_db.get_user_by_username("testuser")
        assert user is not None
        user_db.set_use_own_accounts(user["id"], True)

        r = fastapi_test_client.get("/sessions")
        assert r.status_code == 200, "Power-user with use_own_accounts=True must see /sessions"
        r2 = fastapi_test_client.get("/proxies")
        assert r2.status_code == 200


# ------------------------------------------------------------------
# 2. Menu honours the toggle
# ------------------------------------------------------------------


class TestHeaderMenuRespectsToggle:
    def test_regular_user_with_toggle_sees_sessions_link(
        self, fastapi_test_client: Any, test_settings: Any
    ) -> None:
        from chatfilter.storage.user_database import get_user_db

        user_db = get_user_db(test_settings.effective_database_url)
        user_db.set_use_own_accounts(user_db.get_user_by_username("testuser")["id"], True)

        r = fastapi_test_client.get("/")
        assert r.status_code == 200
        body = r.text
        assert 'href="/sessions"' in body
        assert 'href="/proxies"' in body
        # Non-admin must still not see the Admin link.
        assert 'href="/admin"' not in body


# ------------------------------------------------------------------
# 3. /start always goes through the queue (no more flag)
# ------------------------------------------------------------------


class TestStartAlwaysEnqueues:
    """Feature flag is gone — engine.enqueue_group_analysis is called
    directly by the /start endpoint in every code path."""

    def test_start_endpoint_has_no_flag_check(self) -> None:
        """The flag-branching code is removed from the endpoint."""
        import inspect

        from chatfilter.web.routers.groups import analysis

        src = inspect.getsource(analysis.start_group_analysis)
        assert "get_use_scheduler_queue" not in src, (
            "Flag check still present — /start should always enqueue"
        )
        assert "enqueue_group_analysis" in src, "/start must call engine.enqueue_group_analysis"

    def test_reanalyze_endpoint_has_no_flag_check(self) -> None:
        import inspect

        from chatfilter.web.routers.groups import analysis

        src = inspect.getsource(analysis.reanalyze_group)
        assert "get_use_scheduler_queue" not in src
        assert "enqueue_group_analysis" in src


# ------------------------------------------------------------------
# 4. Power-user's pool_key is user:{id}
# ------------------------------------------------------------------


class TestPoolKeyPicksFromProfile:
    def test_engine_routes_power_user_to_user_pool(self, test_settings: Any) -> None:
        from unittest.mock import MagicMock

        from chatfilter.analyzer.group_engine import GroupAnalysisEngine
        from chatfilter.models.group import (
            ChatTypeEnum,
            GroupChatStatus,
            GroupSettings,
            GroupStatus,
        )
        from chatfilter.storage.group_database import GroupDatabase
        from chatfilter.storage.user_database import get_user_db

        user_db = get_user_db(test_settings.effective_database_url)
        uid = user_db.create_user("power", "pw12345678")

        db = GroupDatabase(test_settings.effective_database_url)
        db.save_group(
            group_id="g-pow",
            name="Pow",
            settings=GroupSettings().model_dump(),
            status=GroupStatus.PENDING.value,
            user_id=uid,
        )
        db.save_chat(
            group_id="g-pow",
            chat_ref="@p",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        engine = GroupAnalysisEngine(db=db, session_manager=MagicMock())
        engine.enqueue_group_analysis("g-pow", pool_key=f"user:{uid}")

        import sqlite3

        with sqlite3.connect(str(db._db_url).removeprefix("sqlite:///")) as conn:
            row = conn.execute(
                "SELECT pool_key FROM analysis_queue WHERE group_id = 'g-pow'"
            ).fetchone()
        assert row[0] == f"user:{uid}"


# ------------------------------------------------------------------
# 5. SessionManager.set_owner / get_info().owner
# ------------------------------------------------------------------


class TestSessionManagerOwner:
    def test_default_owner_is_admin(self) -> None:
        from chatfilter.telegram.session import SessionManager

        m = SessionManager()
        assert m.get_owner("someid") == "admin"

    def test_set_owner_round_trip(self) -> None:
        from chatfilter.telegram.session import SessionManager

        m = SessionManager()
        m.set_owner("abc", "user:42")
        assert m.get_owner("abc") == "user:42"

    def test_info_carries_owner(self) -> None:
        from chatfilter.telegram.session import SessionManager
        from chatfilter.telegram.session.manager import ClientFactory

        m = SessionManager()

        class _F(ClientFactory):
            def create_client(self) -> Any:
                return None

        m.register("abc", _F())
        m.set_owner("abc", "user:42")
        info = m.get_info("abc")
        assert info is not None
        assert info.owner == "user:42"

"""Tests that verify per-user data isolation for sessions, groups, and proxies."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from chatfilter.storage.user_database import get_user_db


@pytest.fixture
def two_user_ids(tmp_path: Path) -> tuple[str, str]:
    """Create two distinct users in an isolated DB, return their IDs."""
    db = get_user_db(tmp_path)
    uid_a = db.create_user("alice", "password123")
    uid_b = db.create_user("bob", "password456")
    return uid_a, uid_b


class TestSessionIsolation:
    """Session files are stored under sessions/<user_id>/ — each user has their own dir."""

    def test_session_dirs_are_separate(self, tmp_path: Path) -> None:
        sessions_dir = tmp_path / "sessions"
        uid_a, uid_b = "user-alice", "user-bob"

        # Simulate creating session files for both users
        dir_a = sessions_dir / uid_a / "my_session"
        dir_b = sessions_dir / uid_b / "my_session"
        dir_a.mkdir(parents=True)
        dir_b.mkdir(parents=True)
        (dir_a / "session.session").write_bytes(b"alice-data")
        (dir_b / "session.session").write_bytes(b"bob-data")

        assert (dir_a / "session.session").read_bytes() == b"alice-data"
        assert (dir_b / "session.session").read_bytes() == b"bob-data"

    def test_deleting_user_a_sessions_does_not_affect_user_b(self, tmp_path: Path) -> None:
        from chatfilter.storage.user_database import delete_user_files

        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        sessions_dir.mkdir()
        config_dir.mkdir()

        uid_a, uid_b = "user-alice", "user-bob"
        (sessions_dir / uid_a).mkdir()
        (sessions_dir / uid_b).mkdir()
        (sessions_dir / uid_b / "session.session").write_bytes(b"bob-data")

        delete_user_files(uid_a, sessions_dir, config_dir)

        assert not (sessions_dir / uid_a).exists()
        assert (sessions_dir / uid_b / "session.session").read_bytes() == b"bob-data"

    def test_ensure_data_dir_returns_user_scoped_path(self, tmp_path: Path) -> None:
        """ensure_data_dir(user_id) must use user_id as path component."""
        from unittest.mock import patch

        import chatfilter.config as cfg_module

        fake_settings = cfg_module.Settings(data_dir=tmp_path)

        with patch.object(cfg_module, "get_settings", return_value=fake_settings):
            from chatfilter.web.routers.sessions.helpers import ensure_data_dir

            path_a = ensure_data_dir("user-alice")
            path_b = ensure_data_dir("user-bob")

        assert path_a != path_b
        assert "user-alice" in str(path_a)
        assert "user-bob" in str(path_b)


class TestGroupIsolation:
    """Groups are tagged with user_id in chat_groups; each user sees only their own."""

    @pytest.fixture
    def group_db(self, tmp_path: Path):
        from chatfilter.storage.group_database import GroupDatabase

        return GroupDatabase(tmp_path / "groups.db")

    def _save(self, db, name: str, user_id: str) -> str:
        """Helper: save a group and return its ID."""
        import uuid

        from chatfilter.models.group import GroupStatus

        gid = str(uuid.uuid4())
        db.save_group(gid, name, {}, GroupStatus.PENDING.value, user_id=user_id)
        return gid

    def test_save_group_stores_user_id(self, group_db) -> None:
        self._save(group_db, "My Group", "user-alice")
        groups = group_db.load_all_groups_with_stats(user_id="user-alice")
        assert len(groups) == 1
        assert groups[0]["user_id"] == "user-alice"

    def test_user_a_groups_not_visible_to_user_b(self, group_db) -> None:
        self._save(group_db, "Alice's Group", "user-alice")
        self._save(group_db, "Bob's Group", "user-bob")

        alice_groups = group_db.load_all_groups_with_stats(user_id="user-alice")
        bob_groups = group_db.load_all_groups_with_stats(user_id="user-bob")

        alice_names = {g["name"] for g in alice_groups}
        bob_names = {g["name"] for g in bob_groups}

        assert "Alice's Group" in alice_names
        assert "Bob's Group" not in alice_names
        assert "Bob's Group" in bob_names
        assert "Alice's Group" not in bob_names

    def test_load_group_with_wrong_user_returns_none(self, group_db) -> None:
        group_id = self._save(group_db, "Alice's Group", "user-alice")
        result = group_db.load_group(group_id, user_id="user-bob")
        assert result is None

    def test_load_group_with_correct_user_returns_group(self, group_db) -> None:
        group_id = self._save(group_db, "Alice's Group", "user-alice")
        result = group_db.load_group(group_id, user_id="user-alice")
        assert result is not None
        assert result["name"] == "Alice's Group"

    def test_delete_group_scoped_to_user(self, group_db) -> None:
        """delete_group with wrong user_id must not remove the group."""
        group_id = self._save(group_db, "Alice's Group", "user-alice")

        # Bob tries to delete Alice's group
        group_db.delete_group(group_id, user_id="user-bob")

        result = group_db.load_group(group_id, user_id="user-alice")
        assert result is not None, "Alice's group should still exist after Bob's delete attempt"

    def test_api_list_groups_scoped_to_logged_in_user(
        self, fastapi_test_client, test_settings
    ) -> None:
        """GET /api/groups returns only the current user's groups."""
        import uuid

        from chatfilter.models.group import GroupStatus
        from chatfilter.storage.group_database import GroupDatabase

        db = GroupDatabase(test_settings.data_dir / "groups.db")
        gid = str(uuid.uuid4())
        db.save_group(
            gid, "Other User Group", {}, GroupStatus.PENDING.value, user_id="some-other-user-id"
        )

        resp = fastapi_test_client.get("/api/groups")
        assert resp.status_code == 200
        assert "Other User Group" not in resp.text


class TestProxyIsolation:
    """Proxies are stored in proxies_<user_id>.json — per user."""

    def _write_proxy_file(self, config_dir: Path, user_id: str, entries: list) -> None:
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / f"proxies_{user_id}.json").write_text(json.dumps(entries))

    def test_proxy_files_are_separate(self, tmp_path: Path) -> None:
        config_dir = tmp_path / "config"
        self._write_proxy_file(config_dir, "user-alice", [{"id": "pa1"}])
        self._write_proxy_file(config_dir, "user-bob", [{"id": "pb1"}])

        alice_data = json.loads((config_dir / "proxies_user-alice.json").read_text())
        bob_data = json.loads((config_dir / "proxies_user-bob.json").read_text())

        assert alice_data == [{"id": "pa1"}]
        assert bob_data == [{"id": "pb1"}]

    def test_load_proxy_pool_scoped_to_user(self, tmp_path: Path) -> None:
        from unittest.mock import patch

        import chatfilter.config as cfg_module
        import chatfilter.storage.proxy_pool as proxy_pool_module

        fake_settings = cfg_module.Settings(data_dir=tmp_path)
        fake_settings.data_dir.mkdir(parents=True, exist_ok=True)
        fake_settings.config_dir.mkdir(parents=True, exist_ok=True)

        alice_proxy = {
            "id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "name": "alice-proxy",
            "host": "1.2.3.4",
            "port": 1080,
            "type": "socks5",
            "username": "",
            "password": "",
            "status": "untested",
            "last_ping_at": None,
            "last_success_at": None,
            "consecutive_failures": 0,
        }
        (fake_settings.config_dir / "proxies_user-alice.json").write_text(json.dumps([alice_proxy]))
        (fake_settings.config_dir / "proxies_user-bob.json").write_text(json.dumps([]))

        # Patch get_settings at the proxy_pool module level (where it was imported)
        with patch.object(proxy_pool_module, "get_settings", return_value=fake_settings):
            alice_proxies = proxy_pool_module.load_proxy_pool("user-alice")
            bob_proxies = proxy_pool_module.load_proxy_pool("user-bob")

        assert len(alice_proxies) == 1
        assert str(alice_proxies[0].id) == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        assert len(bob_proxies) == 0

    def test_deleting_user_removes_proxy_file(self, tmp_path: Path) -> None:
        from chatfilter.storage.user_database import delete_user_files

        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        sessions_dir.mkdir()
        config_dir.mkdir()

        uid = "user-alice"
        proxy_file = config_dir / f"proxies_{uid}.json"
        proxy_file.write_text(json.dumps([{"id": "p1"}]))
        bob_proxy_file = config_dir / "proxies_user-bob.json"
        bob_proxy_file.write_text(json.dumps([{"id": "p2"}]))

        delete_user_files(uid, sessions_dir, config_dir)

        assert not proxy_file.exists()
        assert bob_proxy_file.exists()

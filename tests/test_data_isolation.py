"""Tests for user data isolation: sessions, groups, proxies per user."""

from __future__ import annotations

import json
from pathlib import Path

import pytest


class TestSessionIsolation:
    """Session files are stored per user under sessions_dir/user_id/."""

    def test_session_dirs_are_isolated(self, tmp_path):
        sessions_dir = tmp_path / "sessions"
        user_a_dir = sessions_dir / "user-a"
        user_b_dir = sessions_dir / "user-b"
        user_a_dir.mkdir(parents=True)
        user_b_dir.mkdir(parents=True)

        (user_a_dir / "session_a.session").write_bytes(b"session_data_a")
        (user_b_dir / "session_b.session").write_bytes(b"session_data_b")

        assert not (user_a_dir / "session_b.session").exists()
        assert not (user_b_dir / "session_a.session").exists()

    def test_delete_user_files_removes_session_dir(self, tmp_path):
        from chatfilter.storage.user_database import delete_user_files

        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        user_dir = sessions_dir / "user-a"
        user_dir.mkdir(parents=True)
        config_dir.mkdir(parents=True)
        (user_dir / "test.session").write_bytes(b"data")

        delete_user_files("user-a", sessions_dir, config_dir)

        assert not user_dir.exists()

    def test_delete_user_files_leaves_other_users(self, tmp_path):
        from chatfilter.storage.user_database import delete_user_files

        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        user_a_dir = sessions_dir / "user-a"
        user_b_dir = sessions_dir / "user-b"
        user_a_dir.mkdir(parents=True)
        user_b_dir.mkdir(parents=True)
        config_dir.mkdir(parents=True)
        (user_a_dir / "test.session").write_bytes(b"a_data")
        (user_b_dir / "test.session").write_bytes(b"b_data")

        delete_user_files("user-a", sessions_dir, config_dir)

        assert not user_a_dir.exists()
        assert user_b_dir.exists()


class TestProxyIsolation:
    """Proxy configs are stored as proxies_{user_id}.json."""

    def test_proxy_files_are_isolated(self, tmp_path):
        from chatfilter.storage.user_database import delete_user_files

        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        sessions_dir.mkdir()
        config_dir.mkdir()

        proxy_a = config_dir / "proxies_user-a.json"
        proxy_b = config_dir / "proxies_user-b.json"
        proxy_a.write_text(json.dumps([{"host": "proxy-a.example", "port": 1080}]))
        proxy_b.write_text(json.dumps([{"host": "proxy-b.example", "port": 1080}]))

        delete_user_files("user-a", sessions_dir, config_dir)

        assert not proxy_a.exists()
        assert proxy_b.exists()

    def test_delete_nonexistent_files_is_safe(self, tmp_path):
        from chatfilter.storage.user_database import delete_user_files

        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        sessions_dir.mkdir()
        config_dir.mkdir()

        # Should not raise even when files don't exist
        delete_user_files("nonexistent-user", sessions_dir, config_dir)


class TestGroupIsolation:
    """Groups (chat_groups table) have user_id column for isolation."""

    @pytest.fixture
    def group_db(self, tmp_path):
        from chatfilter.storage.group_database import GroupDatabase
        return GroupDatabase(tmp_path / "groups.db")

    def test_user_id_column_exists(self, group_db):
        import sqlite3
        conn = sqlite3.connect(group_db.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.execute("PRAGMA table_info(chat_groups)")
        columns = [row["name"] for row in cursor.fetchall()]
        conn.close()
        assert "user_id" in columns

    def test_groups_filtered_by_user_id(self, group_db):
        """Inserting groups for different users should be isolated by user_id."""
        import sqlite3
        conn = sqlite3.connect(group_db.db_path)
        conn.row_factory = sqlite3.Row

        now = "2026-01-01T00:00:00"
        settings_json = '{"chat_ids": []}'

        conn.execute(
            "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at, user_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("group-a", "Group A", settings_json, "idle", now, now, "user-a"),
        )
        conn.execute(
            "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at, user_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("group-b", "Group B", settings_json, "idle", now, now, "user-b"),
        )
        conn.commit()

        cursor = conn.execute("SELECT * FROM chat_groups WHERE user_id = ?", ("user-a",))
        user_a_groups = cursor.fetchall()
        assert len(user_a_groups) == 1
        assert user_a_groups[0]["id"] == "group-a"

        cursor = conn.execute("SELECT * FROM chat_groups WHERE user_id = ?", ("user-b",))
        user_b_groups = cursor.fetchall()
        assert len(user_b_groups) == 1
        assert user_b_groups[0]["id"] == "group-b"

        conn.close()

    def test_delete_user_groups_removes_only_their_groups(self, group_db):
        """Deleting user-a's groups should not affect user-b's groups."""
        import sqlite3
        conn = sqlite3.connect(group_db.db_path)
        conn.row_factory = sqlite3.Row

        now = "2026-01-01T00:00:00"
        settings_json = '{"chat_ids": []}'

        for uid, gid, name in [("user-a", "ga", "A"), ("user-b", "gb", "B")]:
            conn.execute(
                "INSERT INTO chat_groups (id, name, settings, status, created_at, updated_at, user_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (gid, name, settings_json, "idle", now, now, uid),
            )
        conn.commit()

        conn.execute("DELETE FROM chat_groups WHERE user_id = ?", ("user-a",))
        conn.commit()

        cursor = conn.execute("SELECT COUNT(*) as cnt FROM chat_groups WHERE user_id = ?", ("user-b",))
        assert cursor.fetchone()["cnt"] == 1

        cursor = conn.execute("SELECT COUNT(*) as cnt FROM chat_groups WHERE user_id = ?", ("user-a",))
        assert cursor.fetchone()["cnt"] == 0

        conn.close()


class TestUserDatabaseIsolation:
    """Users in UserDatabase are independent of each other."""

    def test_two_users_independent(self, tmp_path):
        from chatfilter.storage.user_database import UserDatabase

        db = UserDatabase(tmp_path / "users.db")
        db.create_user("alice", "passalice1")
        db.create_user("bob", "passbob123")

        assert db.verify_password("alice", "passalice1") is True
        assert db.verify_password("bob", "passbob123") is True
        assert db.verify_password("alice", "passbob123") is False
        assert db.verify_password("bob", "passalice1") is False

    def test_delete_user_a_keeps_user_b(self, tmp_path):
        from chatfilter.storage.user_database import UserDatabase

        db = UserDatabase(tmp_path / "users.db")
        uid_a = db.create_user("alice", "passalice1")
        db.create_user("bob", "passbob123")

        db.delete_user(uid_a)

        assert db.get_user_by_username("alice") is None
        assert db.get_user_by_username("bob") is not None

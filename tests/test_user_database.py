"""Tests for UserDatabase: CRUD, password hashing, and file cleanup."""

from __future__ import annotations

from pathlib import Path

import pytest

from chatfilter.storage.user_database import UserDatabase, delete_user_files, get_user_db


@pytest.fixture
def user_db(tmp_path: Path) -> UserDatabase:
    """Isolated UserDatabase instance backed by a temp directory."""
    return get_user_db(f"sqlite:///{tmp_path}/test.db")


class TestCreateUser:
    def test_returns_user_id(self, user_db: UserDatabase) -> None:
        uid = user_db.create_user("alice", "password123")
        assert isinstance(uid, str)
        assert len(uid) > 0

    def test_password_is_hashed(self, user_db: UserDatabase) -> None:
        user_db.create_user("alice", "password123")
        user = user_db.get_user_by_username("alice")
        assert user is not None
        assert user["password_hash"] != "password123"
        assert user["password_hash"].startswith("$2b$")

    def test_explicit_user_id(self, user_db: UserDatabase) -> None:
        uid = user_db.create_user("alice", "password123", user_id="fixed-id-123")
        assert uid == "fixed-id-123"

    def test_duplicate_username_raises(self, user_db: UserDatabase) -> None:
        user_db.create_user("alice", "password123")
        with pytest.raises(Exception):  # noqa: B017
            user_db.create_user("alice", "other_password")

    def test_is_admin_flag(self, user_db: UserDatabase) -> None:
        uid = user_db.create_user("admin", "password123", is_admin=True)
        user = user_db.get_user_by_id(uid)
        assert user is not None
        assert user["is_admin"] is True

    def test_default_not_admin(self, user_db: UserDatabase) -> None:
        uid = user_db.create_user("alice", "password123")
        user = user_db.get_user_by_id(uid)
        assert user is not None
        assert user["is_admin"] is False


class TestGetUser:
    def test_get_by_username_found(self, user_db: UserDatabase) -> None:
        uid = user_db.create_user("alice", "password123")
        user = user_db.get_user_by_username("alice")
        assert user is not None
        assert user["id"] == uid
        assert user["username"] == "alice"

    def test_get_by_username_not_found(self, user_db: UserDatabase) -> None:
        assert user_db.get_user_by_username("ghost") is None

    def test_get_by_id_found(self, user_db: UserDatabase) -> None:
        uid = user_db.create_user("alice", "password123")
        user = user_db.get_user_by_id(uid)
        assert user is not None
        assert user["username"] == "alice"

    def test_get_by_id_not_found(self, user_db: UserDatabase) -> None:
        assert user_db.get_user_by_id("nonexistent-id") is None


class TestListUsers:
    def test_empty_returns_empty_list(self, user_db: UserDatabase) -> None:
        users, total = user_db.list_users()
        assert users == []
        assert total == 0

    def test_returns_all_users(self, user_db: UserDatabase) -> None:
        user_db.create_user("alice", "password123")
        user_db.create_user("bob", "password456")
        users, total = user_db.list_users()
        assert len(users) == 2
        assert total == 2
        usernames = {u["username"] for u in users}
        assert usernames == {"alice", "bob"}

    def test_ordered_by_created_at(self, user_db: UserDatabase) -> None:
        user_db.create_user("first", "password123")
        user_db.create_user("second", "password123")
        users, _ = user_db.list_users()
        assert users[0]["username"] == "first"
        assert users[1]["username"] == "second"

    def test_pagination(self, user_db: UserDatabase) -> None:
        for i in range(5):
            user_db.create_user(f"user{i}", "password123")
        users, total = user_db.list_users(page=1, page_size=2)
        assert total == 5
        assert len(users) == 2
        users2, total2 = user_db.list_users(page=3, page_size=2)
        assert total2 == 5
        assert len(users2) == 1

    def test_search_by_username(self, user_db: UserDatabase) -> None:
        user_db.create_user("alice", "password123")
        user_db.create_user("bob", "password456")
        results, count = user_db.list_users(query="ali")
        assert count == 1
        assert results[0]["username"] == "alice"

    def test_search_cyrillic_case_insensitive(self, user_db: UserDatabase) -> None:
        user_db.create_user("Иван", "password123")
        results, count = user_db.list_users(query="иван")
        assert count == 1
        assert results[0]["username"] == "Иван"

    def test_search_by_email(self, user_db: UserDatabase) -> None:
        user_db.create_user("alice", "password123", email="alice@example.com")
        user_db.create_user("bob", "password456")
        results, count = user_db.list_users(query="alice@")
        assert count == 1
        assert results[0]["username"] == "alice"


class TestDeleteUser:
    def test_returns_true_when_deleted(self, user_db: UserDatabase) -> None:
        uid = user_db.create_user("alice", "password123")
        assert user_db.delete_user(uid) is True

    def test_user_gone_after_delete(self, user_db: UserDatabase) -> None:
        uid = user_db.create_user("alice", "password123")
        user_db.delete_user(uid)
        assert user_db.get_user_by_id(uid) is None

    def test_returns_false_for_nonexistent(self, user_db: UserDatabase) -> None:
        assert user_db.delete_user("no-such-id") is False


class TestPassword:
    def test_verify_correct_password(self, user_db: UserDatabase) -> None:
        user_db.create_user("alice", "password123")
        assert user_db.verify_password("alice", "password123") is True

    def test_verify_wrong_password(self, user_db: UserDatabase) -> None:
        user_db.create_user("alice", "password123")
        assert user_db.verify_password("alice", "wrongpassword") is False

    def test_verify_nonexistent_user(self, user_db: UserDatabase) -> None:
        assert user_db.verify_password("ghost", "password123") is False

    def test_update_password(self, user_db: UserDatabase) -> None:
        uid = user_db.create_user("alice", "oldpassword123")
        user_db.update_password(uid, "newpassword456")
        assert user_db.verify_password("alice", "newpassword456") is True
        assert user_db.verify_password("alice", "oldpassword123") is False

    def test_update_password_returns_false_for_nonexistent(self, user_db: UserDatabase) -> None:
        assert user_db.update_password("no-such-id", "newpassword456") is False


class TestUpsertUser:
    def test_creates_new_user(self, user_db: UserDatabase) -> None:
        uid = user_db.upsert_user("alice", "password123")
        assert user_db.get_user_by_id(uid) is not None

    def test_updates_existing_user_password(self, user_db: UserDatabase) -> None:
        uid1 = user_db.upsert_user("alice", "oldpassword123")
        uid2 = user_db.upsert_user("alice", "newpassword456")
        assert uid1 == uid2
        assert user_db.verify_password("alice", "newpassword456") is True

    def test_does_not_create_duplicate(self, user_db: UserDatabase) -> None:
        user_db.upsert_user("alice", "password123")
        user_db.upsert_user("alice", "password456")
        _, total = user_db.list_users()
        assert total == 1


class TestDeleteUserFiles:
    def test_deletes_session_directory(self, tmp_path: Path) -> None:
        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        sessions_dir.mkdir()
        config_dir.mkdir()

        user_id = "user-abc"
        user_session_dir = sessions_dir / user_id
        user_session_dir.mkdir()
        (user_session_dir / "session.session").write_bytes(b"data")

        delete_user_files(user_id, sessions_dir, config_dir)

        assert not user_session_dir.exists()

    def test_deletes_proxy_file(self, tmp_path: Path) -> None:
        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        sessions_dir.mkdir()
        config_dir.mkdir()

        user_id = "user-abc"
        proxy_file = config_dir / f"proxies_{user_id}.json"
        proxy_file.write_text("[]")

        delete_user_files(user_id, sessions_dir, config_dir)

        assert not proxy_file.exists()

    def test_noop_when_nothing_exists(self, tmp_path: Path) -> None:
        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        sessions_dir.mkdir()
        config_dir.mkdir()

        # Should not raise
        delete_user_files("nonexistent-user", sessions_dir, config_dir)

    def test_does_not_affect_other_users(self, tmp_path: Path) -> None:
        sessions_dir = tmp_path / "sessions"
        config_dir = tmp_path / "config"
        sessions_dir.mkdir()
        config_dir.mkdir()

        (sessions_dir / "user-a").mkdir()
        (sessions_dir / "user-b").mkdir()
        (config_dir / "proxies_user-b.json").write_text("[]")

        delete_user_files("user-a", sessions_dir, config_dir)

        assert not (sessions_dir / "user-a").exists()
        assert (sessions_dir / "user-b").exists()
        assert (config_dir / "proxies_user-b.json").exists()

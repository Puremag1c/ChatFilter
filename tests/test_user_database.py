"""Tests for UserDatabase: CRUD operations, password hashing, duplicate username."""

from __future__ import annotations

import pytest

from chatfilter.storage.user_database import UserDatabase


@pytest.fixture
def user_db(tmp_path):
    return UserDatabase(tmp_path / "users.db")


class TestCreateUser:
    def test_creates_user_and_returns_id(self, user_db):
        uid = user_db.create_user("alice", "password123")
        assert uid is not None
        assert len(uid) > 0

    def test_password_is_hashed(self, user_db):
        user_db.create_user("alice", "password123")
        user = user_db.get_user_by_username("alice")
        assert user["password_hash"] != "password123"
        assert user["password_hash"].startswith("$2b$")

    def test_duplicate_username_raises(self, user_db):
        user_db.create_user("alice", "password123")
        with pytest.raises(Exception):
            user_db.create_user("alice", "other_password")

    def test_admin_flag(self, user_db):
        user_db.create_user("admin", "adminpass1", is_admin=True)
        user = user_db.get_user_by_username("admin")
        assert user["is_admin"] is True

    def test_non_admin_by_default(self, user_db):
        user_db.create_user("alice", "password123")
        user = user_db.get_user_by_username("alice")
        assert user["is_admin"] is False

    def test_custom_user_id(self, user_db):
        uid = user_db.create_user("alice", "password123", user_id="custom-id-123")
        assert uid == "custom-id-123"


class TestGetUser:
    def test_get_by_username_returns_user(self, user_db):
        user_db.create_user("alice", "password123")
        user = user_db.get_user_by_username("alice")
        assert user is not None
        assert user["username"] == "alice"

    def test_get_by_username_missing_returns_none(self, user_db):
        assert user_db.get_user_by_username("nobody") is None

    def test_get_by_id_returns_user(self, user_db):
        uid = user_db.create_user("alice", "password123")
        user = user_db.get_user_by_id(uid)
        assert user is not None
        assert user["id"] == uid

    def test_get_by_id_missing_returns_none(self, user_db):
        assert user_db.get_user_by_id("nonexistent-id") is None


class TestListUsers:
    def test_list_returns_all_users(self, user_db):
        user_db.create_user("alice", "password123")
        user_db.create_user("bob", "password456")
        users = user_db.list_users()
        usernames = {u["username"] for u in users}
        assert usernames == {"alice", "bob"}

    def test_list_empty_returns_empty(self, user_db):
        assert user_db.list_users() == []


class TestDeleteUser:
    def test_delete_removes_user(self, user_db):
        uid = user_db.create_user("alice", "password123")
        result = user_db.delete_user(uid)
        assert result is True
        assert user_db.get_user_by_id(uid) is None

    def test_delete_nonexistent_returns_false(self, user_db):
        assert user_db.delete_user("nonexistent-id") is False


class TestVerifyPassword:
    def test_correct_password(self, user_db):
        user_db.create_user("alice", "password123")
        assert user_db.verify_password("alice", "password123") is True

    def test_wrong_password(self, user_db):
        user_db.create_user("alice", "password123")
        assert user_db.verify_password("alice", "wrongpass") is False

    def test_nonexistent_user(self, user_db):
        assert user_db.verify_password("nobody", "password") is False


class TestUpdatePassword:
    def test_updates_password(self, user_db):
        uid = user_db.create_user("alice", "oldpassword")
        user_db.update_password(uid, "newpassword")
        assert user_db.verify_password("alice", "newpassword") is True
        assert user_db.verify_password("alice", "oldpassword") is False

    def test_nonexistent_user_returns_false(self, user_db):
        assert user_db.update_password("nonexistent-id", "newpass") is False

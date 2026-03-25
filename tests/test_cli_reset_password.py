"""Tests for CLI reset-password command."""

from __future__ import annotations

import contextlib
import sys
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


class TestResetPasswordCLI:
    """Test suite for reset-password CLI subcommand."""

    def _run_reset_password(
        self, data_dir: Path, username: str, password: str
    ) -> tuple[int, str, str]:
        """Run reset-password command and return (exit_code, stdout, stderr)."""
        from chatfilter.main import _handle_reset_password

        # Capture stdout and stderr
        stdout_capture = StringIO()
        stderr_capture = StringIO()

        # Mock sys.argv and exit
        original_argv = sys.argv
        original_exit = sys.exit
        exit_code = 0

        def mock_exit(code: int = 0) -> None:
            nonlocal exit_code
            exit_code = code
            raise SystemExit(code)

        try:
            with (
                patch(
                    "sys.argv",
                    [
                        "chatfilter",
                        "reset-password",
                        username,
                        password,
                        "--data-dir",
                        str(data_dir),
                    ],
                ),
                patch("sys.stdout", stdout_capture),
                patch("sys.stderr", stderr_capture),
                patch("sys.exit", mock_exit),
                contextlib.suppress(SystemExit),
            ):
                _handle_reset_password()
        finally:
            sys.argv = original_argv
            sys.exit = original_exit

        return exit_code, stdout_capture.getvalue(), stderr_capture.getvalue()

    def test_successful_password_reset(self, test_settings: Any) -> None:
        """Test successful password reset for existing user."""
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)

        # Create a user
        db.create_user("testuser", "oldpassword123")

        # Verify old password works
        assert db.verify_password("testuser", "oldpassword123") is True

        # Reset password via CLI
        exit_code, stdout, stderr = self._run_reset_password(
            test_settings.data_dir, "testuser", "newpassword456"
        )

        # Should succeed
        assert exit_code == 0
        assert "password for 'testuser' has been reset successfully" in stdout.lower()
        assert stderr == ""

        # Verify new password works
        assert db.verify_password("testuser", "newpassword456") is True

    def test_unknown_user_returns_error(self, test_settings: Any) -> None:
        """Test that unknown user returns exit code 1 with error message."""
        test_settings.data_dir.mkdir(parents=True, exist_ok=True)

        exit_code, stdout, stderr = self._run_reset_password(
            test_settings.data_dir, "nonexistentuser", "password123"
        )

        # Should fail
        assert exit_code == 1
        assert "not found" in stderr.lower()
        assert "nonexistentuser" in stderr.lower()

    def test_password_too_short_returns_error(self, test_settings: Any) -> None:
        """Test that password less than 8 chars returns exit code 1."""
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)

        # Create a user
        db.create_user("testuser", "password123")

        # Try to reset with short password
        exit_code, stdout, stderr = self._run_reset_password(
            test_settings.data_dir, "testuser", "short"
        )

        # Should fail
        assert exit_code == 1
        assert "at least 8 characters" in stderr.lower() or "8 characters" in stderr.lower()

    def test_no_arguments_shows_help(self, test_settings: Any) -> None:
        """Test that running with no arguments shows help message."""
        from chatfilter.main import _handle_reset_password

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)

        # Run with no arguments (just "--data-dir")
        stdout_capture = StringIO()
        stderr_capture = StringIO()

        original_argv = sys.argv
        exit_code = 0

        def mock_exit(code: int = 0) -> None:
            nonlocal exit_code
            exit_code = code
            raise SystemExit(code)

        try:
            with (
                patch(
                    "sys.argv",
                    ["chatfilter", "reset-password", "--data-dir", str(test_settings.data_dir)],
                ),
                patch("sys.stdout", stdout_capture),
                patch("sys.stderr", stderr_capture),
                patch("sys.exit", mock_exit),
                contextlib.suppress(SystemExit),
            ):
                _handle_reset_password()
        finally:
            sys.argv = original_argv

        # Should show usage help (error exit code)
        assert exit_code != 0
        # Either stdout or stderr should contain usage/help text
        output = stdout_capture.getvalue() + stderr_capture.getvalue()
        assert "usage" in output.lower() or "required" in output.lower()

    def test_old_password_no_longer_works_after_reset(self, test_settings: Any) -> None:
        """Test that old password is invalidated after reset."""
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)

        # Create a user with old password
        old_pwd = "oldpassword123"
        db.create_user("testuser", old_pwd)

        # Verify old password works before reset
        assert db.verify_password("testuser", old_pwd) is True

        # Reset password via CLI
        new_pwd = "newpassword456"
        exit_code, _, _ = self._run_reset_password(test_settings.data_dir, "testuser", new_pwd)
        assert exit_code == 0

        # Verify old password no longer works
        assert db.verify_password("testuser", old_pwd) is False

    def test_new_password_works_after_reset(self, test_settings: Any) -> None:
        """Test that new password works after reset."""
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)

        # Create a user
        db.create_user("testuser", "oldpassword123")

        # Reset password via CLI
        new_pwd = "newpassword456"
        exit_code, _, _ = self._run_reset_password(test_settings.data_dir, "testuser", new_pwd)
        assert exit_code == 0

        # Verify new password works
        assert db.verify_password("testuser", new_pwd) is True

    def test_password_with_special_characters(self, test_settings: Any) -> None:
        """Test reset with password containing special characters."""
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)

        # Create a user
        db.create_user("testuser", "oldpassword123")

        # Reset with special characters
        special_pwd = "P@ss!word$123"
        exit_code, stdout, stderr = self._run_reset_password(
            test_settings.data_dir, "testuser", special_pwd
        )

        # Should succeed
        assert exit_code == 0
        assert db.verify_password("testuser", special_pwd) is True

    def test_password_exactly_8_chars_succeeds(self, test_settings: Any) -> None:
        """Test that password with exactly 8 characters is accepted."""
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)

        # Create a user
        db.create_user("testuser", "oldpassword123")

        # Reset with exactly 8 char password
        pwd_8_chars = "Pass1234"
        exit_code, stdout, stderr = self._run_reset_password(
            test_settings.data_dir, "testuser", pwd_8_chars
        )

        # Should succeed
        assert exit_code == 0
        assert "successfully" in stdout.lower()
        assert db.verify_password("testuser", pwd_8_chars) is True

    def test_password_7_chars_fails(self, test_settings: Any) -> None:
        """Test that password with only 7 characters is rejected."""
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)

        # Create a user
        db.create_user("testuser", "oldpassword123")

        # Try to reset with 7 char password
        pwd_7_chars = "Pass123"
        exit_code, stdout, stderr = self._run_reset_password(
            test_settings.data_dir, "testuser", pwd_7_chars
        )

        # Should fail
        assert exit_code == 1
        assert "8 characters" in stderr.lower()

    def test_database_locked_shows_clear_error(
        self, test_settings: Any, monkeypatch: Any, capsys: Any
    ) -> None:
        """Test that locked database shows clear error message and exits with code 1."""
        import sqlite3
        import sys
        from unittest.mock import MagicMock, patch

        from chatfilter.main import _handle_reset_password

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "chatfilter",
                "reset-password",
                "testuser",
                "newpassword456",
                "--data-dir",
                str(test_settings.data_dir),
            ],
        )

        with patch("chatfilter.storage.user_database.UserDatabase") as mock_db_class:
            mock_db = MagicMock()
            mock_db_class.return_value = mock_db
            mock_db.get_user_by_username.return_value = {"id": "user-id-1", "username": "testuser"}
            mock_db.update_password.side_effect = sqlite3.OperationalError("database is locked")

            with pytest.raises(SystemExit) as exc_info:
                _handle_reset_password()

        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        assert "locked" in captured.err.lower()
        assert "stop" in captured.err.lower()

    def test_reset_multiple_users_independently(self, test_settings: Any) -> None:
        """Test resetting passwords for multiple users doesn't affect others."""
        from chatfilter.storage.user_database import get_user_db

        test_settings.data_dir.mkdir(parents=True, exist_ok=True)
        db = get_user_db(test_settings.effective_database_url)

        # Create two users
        db.create_user("user1", "password1")
        db.create_user("user2", "password2")

        # Reset user1's password
        exit_code, _, _ = self._run_reset_password(test_settings.data_dir, "user1", "newpassword1")
        assert exit_code == 0

        # Verify user1 has new password
        assert db.verify_password("user1", "newpassword1") is True

        # Verify user2's password is unchanged
        assert db.verify_password("user2", "password2") is True

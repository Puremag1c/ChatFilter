"""Tests for automatic recovery from expired/corrupted session files.

Tests verify that _do_connect_in_background_v2 automatically handles:
- AuthKeyUnregisteredError → delete session.session → send_code → 'needs_code'
- SessionRevokedError → delete session.session → send_code → 'needs_code'
- SessionExpiredError → delete session.session → send_code → 'needs_code'
- Corrupted session file → delete session.session → send_code → 'needs_code'

User should NEVER see 'session_expired' or 'corrupted_session' state.

NOTE: session_manager.connect() wraps Telethon errors in SessionInvalidError/
SessionReauthRequiredError/SessionConnectError. Tests must use these wrappers
with __cause__ set to the original Telethon error.
"""

import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from chatfilter.telegram.session_manager import (
    SessionConnectError,
    SessionInvalidError,
    SessionReauthRequiredError,
)
from chatfilter.web.routers.sessions import _do_connect_in_background_v2


def _wrap_as_invalid(original: Exception) -> SessionInvalidError:
    """Wrap an exception as SessionInvalidError (mimics session_manager.connect)."""
    wrapped = SessionInvalidError(f"Session permanently invalid: {type(original).__name__}")
    wrapped.__cause__ = original
    return wrapped


def _wrap_as_reauth(original: Exception) -> SessionReauthRequiredError:
    """Wrap an exception as SessionReauthRequiredError (mimics session_manager.connect)."""
    wrapped = SessionReauthRequiredError(f"Reauth required: {type(original).__name__}")
    wrapped.__cause__ = original
    return wrapped


def _wrap_as_connect_error(original: Exception) -> SessionConnectError:
    """Wrap an exception as SessionConnectError (mimics session_manager.connect)."""
    wrapped = SessionConnectError(f"Connection failed: {type(original).__name__}")
    wrapped.__cause__ = original
    return wrapped


@pytest.fixture
def mock_session_dir(tmp_path: Path) -> Path:
    """Create a mock session directory with config.json and account_info.json."""
    session_dir = tmp_path / "test_session"
    session_dir.mkdir(parents=True)

    # Create config.json
    config = {
        "api_id": 12345,
        "api_hash": "test_hash",
        "proxy_id": "test_proxy",
    }
    (session_dir / "config.json").write_text(json.dumps(config))

    # Create account_info.json
    account_info = {
        "phone": "+1234567890",
    }
    (session_dir / "account_info.json").write_text(json.dumps(account_info))

    return session_dir


@pytest.fixture
def mock_session_file(mock_session_dir: Path) -> Path:
    """Create a mock session.session SQLite file."""
    session_path = mock_session_dir / "test_session.session"
    conn = sqlite3.connect(session_path)
    cursor = conn.cursor()

    # Telethon session schema
    cursor.execute("""
        CREATE TABLE sessions (
            dc_id INTEGER PRIMARY KEY,
            server_address TEXT,
            port INTEGER,
            auth_key BLOB
        )
    """)
    cursor.execute(
        "INSERT INTO sessions (dc_id, server_address, port, auth_key) VALUES (?, ?, ?, ?)",
        (2, "149.154.167.40", 443, b"fake_auth_key"),
    )
    conn.commit()
    conn.close()

    return session_path


@pytest.mark.asyncio
async def test_authkey_unregistered_triggers_recovery(
    mock_session_dir: Path, mock_session_file: Path
) -> None:
    """Test AuthKeyUnregisteredError triggers auto-recovery flow."""
    from telethon.errors import AuthKeyUnregisteredError

    session_id = "test_session"
    session_path = mock_session_file

    # Verify session file exists before test
    assert session_path.exists()

    # session_manager.connect() wraps in SessionInvalidError
    wrapped = _wrap_as_invalid(AuthKeyUnregisteredError(request=None))

    with (
        patch("chatfilter.web.dependencies.get_session_manager") as mock_get_sm,
        patch("chatfilter.web.events.get_event_bus") as mock_get_bus,
        patch(
            "chatfilter.web.routers.sessions._send_verification_code_with_timeout"
        ) as mock_send_code,
        patch("chatfilter.web.routers.sessions._get_session_lock") as mock_lock,
        patch("chatfilter.web.routers.sessions.background.secure_delete_file") as mock_secure_delete,
        patch("chatfilter.web.routers.sessions.load_account_info") as mock_load_account,
        patch("chatfilter.storage.proxy_pool.get_proxy_by_id"),
    ):
        # Setup mocks
        mock_sm = MagicMock()
        mock_factory = MagicMock()
        mock_factory.session_path = session_path
        mock_sm._factories = {session_id: mock_factory}
        mock_sm.connect = AsyncMock(side_effect=wrapped)
        mock_get_sm.return_value = mock_sm

        mock_bus = MagicMock()
        mock_bus.publish = AsyncMock()
        mock_get_bus.return_value = mock_bus

        mock_lock_ctx = AsyncMock()
        mock_lock_ctx.__aenter__ = AsyncMock()
        mock_lock_ctx.__aexit__ = AsyncMock()
        mock_lock.return_value = mock_lock_ctx

        mock_load_account.return_value = {"phone": "+1234567890"}
        mock_send_code.return_value = None

        # Execute
        await _do_connect_in_background_v2(session_id)

        # Verify session file was deleted
        mock_secure_delete.assert_called_once_with(session_path)

        # Verify send_code was called
        mock_send_code.assert_called_once()
        call_args = mock_send_code.call_args
        assert call_args[0][0] == session_id  # session_id
        assert call_args[0][1] == session_path  # session_path
        assert call_args[0][3] == "+1234567890"  # phone

        # Verify NO 'session_expired' event was published
        for call in mock_bus.publish.call_args_list:
            assert call[0][1] != "session_expired"


@pytest.mark.asyncio
async def test_session_revoked_triggers_recovery(
    mock_session_dir: Path, mock_session_file: Path
) -> None:
    """Test SessionRevokedError triggers auto-recovery flow."""
    from telethon.errors import SessionRevokedError

    session_id = "test_session"
    session_path = mock_session_file

    assert session_path.exists()

    # session_manager.connect() wraps in SessionInvalidError
    wrapped = _wrap_as_invalid(SessionRevokedError(request=None))

    with (
        patch("chatfilter.web.dependencies.get_session_manager") as mock_get_sm,
        patch("chatfilter.web.events.get_event_bus") as mock_get_bus,
        patch(
            "chatfilter.web.routers.sessions._send_verification_code_with_timeout"
        ) as mock_send_code,
        patch("chatfilter.web.routers.sessions._get_session_lock") as mock_lock,
        patch("chatfilter.web.routers.sessions.background.secure_delete_file") as mock_secure_delete,
        patch("chatfilter.web.routers.sessions.load_account_info") as mock_load_account,
        patch("chatfilter.storage.proxy_pool.get_proxy_by_id"),
    ):
        # Setup mocks
        mock_sm = MagicMock()
        mock_factory = MagicMock()
        mock_factory.session_path = session_path
        mock_sm._factories = {session_id: mock_factory}
        mock_sm.connect = AsyncMock(side_effect=wrapped)
        mock_get_sm.return_value = mock_sm

        mock_bus = MagicMock()
        mock_bus.publish = AsyncMock()
        mock_get_bus.return_value = mock_bus

        mock_lock_ctx = AsyncMock()
        mock_lock_ctx.__aenter__ = AsyncMock()
        mock_lock_ctx.__aexit__ = AsyncMock()
        mock_lock.return_value = mock_lock_ctx

        mock_load_account.return_value = {"phone": "+1234567890"}
        mock_send_code.return_value = None

        # Execute
        await _do_connect_in_background_v2(session_id)

        # Verify session file was deleted
        mock_secure_delete.assert_called_once_with(session_path)

        # Verify send_code was called
        mock_send_code.assert_called_once()

        # Verify NO 'session_expired' event was published
        for call in mock_bus.publish.call_args_list:
            assert call[0][1] != "session_expired"


@pytest.mark.asyncio
async def test_session_expired_triggers_recovery(
    mock_session_dir: Path, mock_session_file: Path
) -> None:
    """Test SessionExpiredError triggers auto-recovery flow."""
    from telethon.errors import SessionExpiredError

    session_id = "test_session"
    session_path = mock_session_file

    assert session_path.exists()

    # session_manager.connect() wraps SessionExpiredError in SessionReauthRequiredError
    wrapped = _wrap_as_reauth(SessionExpiredError(request=None))

    with (
        patch("chatfilter.web.dependencies.get_session_manager") as mock_get_sm,
        patch("chatfilter.web.events.get_event_bus") as mock_get_bus,
        patch(
            "chatfilter.web.routers.sessions._send_verification_code_with_timeout"
        ) as mock_send_code,
        patch("chatfilter.web.routers.sessions._get_session_lock") as mock_lock,
        patch("chatfilter.web.routers.sessions.background.secure_delete_file") as mock_secure_delete,
        patch("chatfilter.web.routers.sessions.load_account_info") as mock_load_account,
        patch("chatfilter.storage.proxy_pool.get_proxy_by_id"),
    ):
        # Setup mocks
        mock_sm = MagicMock()
        mock_factory = MagicMock()
        mock_factory.session_path = session_path
        mock_sm._factories = {session_id: mock_factory}
        mock_sm.connect = AsyncMock(side_effect=wrapped)
        mock_get_sm.return_value = mock_sm

        mock_bus = MagicMock()
        mock_bus.publish = AsyncMock()
        mock_get_bus.return_value = mock_bus

        mock_lock_ctx = AsyncMock()
        mock_lock_ctx.__aenter__ = AsyncMock()
        mock_lock_ctx.__aexit__ = AsyncMock()
        mock_lock.return_value = mock_lock_ctx

        mock_load_account.return_value = {"phone": "+1234567890"}
        mock_send_code.return_value = None

        # Execute
        await _do_connect_in_background_v2(session_id)

        # Verify session file was deleted
        mock_secure_delete.assert_called_once_with(session_path)

        # Verify send_code was called
        mock_send_code.assert_called_once()

        # Verify NO 'session_expired' event was published
        for call in mock_bus.publish.call_args_list:
            assert call[0][1] != "session_expired"


@pytest.mark.asyncio
async def test_corrupted_session_file_triggers_recovery(
    mock_session_dir: Path, mock_session_file: Path
) -> None:
    """Test corrupted session.session file triggers auto-recovery flow.

    When session.session SQLite file is corrupted (e.g., struct.error during connect),
    the system should:
    1. Delete the corrupted file
    2. Trigger send_code flow
    3. NOT publish 'corrupted_session' event

    This verifies SPEC.md Must Have #3: auto-recovery without exposing 'corrupted_session' to user.
    """
    import struct

    session_id = "test_session"
    session_path = mock_session_file

    assert session_path.exists()

    # session_manager.connect() wraps struct.error in SessionConnectError
    wrapped = _wrap_as_connect_error(struct.error("invalid session file format"))

    with (
        patch("chatfilter.web.dependencies.get_session_manager") as mock_get_sm,
        patch("chatfilter.web.events.get_event_bus") as mock_get_bus,
        patch(
            "chatfilter.web.routers.sessions._send_verification_code_with_timeout"
        ) as mock_send_code,
        patch("chatfilter.web.routers.sessions._get_session_lock") as mock_lock,
        patch("chatfilter.web.routers.sessions.background.secure_delete_file") as mock_secure_delete,
        patch("chatfilter.web.routers.sessions.load_account_info") as mock_load_account,
        patch("chatfilter.storage.proxy_pool.get_proxy_by_id"),
    ):
        # Setup mocks
        mock_sm = MagicMock()
        mock_factory = MagicMock()
        mock_factory.session_path = session_path
        mock_sm._factories = {session_id: mock_factory}
        mock_sm.connect = AsyncMock(side_effect=wrapped)
        mock_get_sm.return_value = mock_sm

        mock_bus = MagicMock()
        mock_bus.publish = AsyncMock()
        mock_get_bus.return_value = mock_bus

        mock_lock_ctx = AsyncMock()
        mock_lock_ctx.__aenter__ = AsyncMock()
        mock_lock_ctx.__aexit__ = AsyncMock()
        mock_lock.return_value = mock_lock_ctx

        mock_load_account.return_value = {"phone": "+1234567890"}
        mock_send_code.return_value = None

        # Execute
        await _do_connect_in_background_v2(session_id)

        # Verify session file was deleted (auto-recovery)
        mock_secure_delete.assert_called_once_with(session_path)

        # Verify send_code was called (triggers needs_code flow)
        mock_send_code.assert_called_once()
        call_args = mock_send_code.call_args
        assert call_args[0][0] == session_id
        assert call_args[0][1] == session_path
        assert call_args[0][3] == "+1234567890"

        # Verify NO 'corrupted_session' event was published (SPEC.md Must Have #3)
        for call in mock_bus.publish.call_args_list:
            assert call[0][1] != "corrupted_session"


@pytest.mark.asyncio
async def test_recovery_without_phone_publishes_error(
    mock_session_dir: Path, mock_session_file: Path
) -> None:
    """Test recovery fails gracefully if phone number is missing."""
    from telethon.errors import AuthKeyUnregisteredError

    session_id = "test_session"
    session_path = mock_session_file

    # session_manager.connect() wraps in SessionInvalidError
    wrapped = _wrap_as_invalid(AuthKeyUnregisteredError(request=None))

    with (
        patch("chatfilter.web.dependencies.get_session_manager") as mock_get_sm,
        patch("chatfilter.web.events.get_event_bus") as mock_get_bus,
        patch("chatfilter.web.routers.sessions._get_session_lock") as mock_lock,
        patch("chatfilter.web.routers.sessions.background.secure_delete_file") as mock_secure_delete,
        patch("chatfilter.web.routers.sessions.load_account_info") as mock_load_account,
        patch("chatfilter.web.routers.sessions._save_error_to_config") as mock_save_error,
        patch("chatfilter.storage.proxy_pool.get_proxy_by_id"),
    ):
        # Setup mocks
        mock_sm = MagicMock()
        mock_factory = MagicMock()
        mock_factory.session_path = session_path
        mock_sm._factories = {session_id: mock_factory}
        mock_sm.connect = AsyncMock(side_effect=wrapped)
        mock_get_sm.return_value = mock_sm

        mock_bus = MagicMock()
        mock_bus.publish = AsyncMock()
        mock_get_bus.return_value = mock_bus

        mock_lock_ctx = AsyncMock()
        mock_lock_ctx.__aenter__ = AsyncMock()
        mock_lock_ctx.__aexit__ = AsyncMock()
        mock_lock.return_value = mock_lock_ctx

        mock_load_account.return_value = {}  # No phone number
        mock_secure_delete.return_value = None

        # Execute
        await _do_connect_in_background_v2(session_id)

        # Verify session file was deleted
        mock_secure_delete.assert_called_once()

        # Verify needs_config event was published per SPEC.md 4.1
        mock_bus.publish.assert_called_once_with(session_id, "needs_config")

        # Verify error was saved to config
        mock_save_error.assert_called_once()

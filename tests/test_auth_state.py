"""Tests for auth state manager.

Tests cover:
- AuthState: creation, expiration, touch
- AuthStateManager: create, get, update, remove, cleanup
- Singleton pattern
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from chatfilter.web.auth_state import (
    AUTH_LOCK_DURATION_SECONDS,
    AUTH_STATE_EXPIRY_SECONDS,
    MAX_AUTH_ATTEMPTS,
    AuthState,
    AuthStateManager,
    AuthStep,
    get_auth_state_manager,
)


class TestAuthState:
    """Tests for AuthState dataclass."""

    def test_creation(self) -> None:
        """AuthState should initialize with correct values."""
        state = AuthState(
            auth_id="test-123",
            session_name="my_session",
            api_id=12345,
            api_hash="abcdef",
            proxy_id="proxy-1",
            phone="+1234567890",
            step=AuthStep.PHONE_SENT,
        )

        assert state.auth_id == "test-123"
        assert state.session_name == "my_session"
        assert state.api_id == 12345
        assert state.step == AuthStep.PHONE_SENT
        assert state.phone_code_hash == ""
        assert state.error_message == ""
        assert state.client is None
        assert state.created_at > 0
        assert state.updated_at > 0

    def test_is_expired_false(self) -> None:
        """Fresh state should not be expired."""
        state = AuthState(
            auth_id="test",
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            step=AuthStep.PHONE_SENT,
        )

        assert state.is_expired() is False

    def test_is_expired_true(self) -> None:
        """Old state should be expired."""
        state = AuthState(
            auth_id="test",
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            step=AuthStep.PHONE_SENT,
            created_at=time.time() - AUTH_STATE_EXPIRY_SECONDS - 1,
        )

        assert state.is_expired() is True

    def test_touch(self) -> None:
        """touch() should update updated_at."""
        state = AuthState(
            auth_id="test",
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            step=AuthStep.PHONE_SENT,
        )
        old_updated = state.updated_at

        time.sleep(0.01)
        state.touch()

        assert state.updated_at > old_updated

    def test_is_locked_false(self) -> None:
        """Fresh state should not be locked."""
        state = AuthState(
            auth_id="test",
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            step=AuthStep.PHONE_SENT,
        )

        assert state.is_locked() is False

    def test_is_locked_true(self) -> None:
        """State with future locked_until should be locked."""
        state = AuthState(
            auth_id="test",
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            step=AuthStep.PHONE_SENT,
            locked_until=time.time() + 100,
        )

        assert state.is_locked() is True

    def test_is_locked_expired(self) -> None:
        """State with past locked_until should not be locked."""
        state = AuthState(
            auth_id="test",
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            step=AuthStep.PHONE_SENT,
            locked_until=time.time() - 1,
        )

        assert state.is_locked() is False

    def test_get_lock_remaining_seconds(self) -> None:
        """get_lock_remaining_seconds should return correct value."""
        state = AuthState(
            auth_id="test",
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            step=AuthStep.PHONE_SENT,
            locked_until=time.time() + 100,
        )

        remaining = state.get_lock_remaining_seconds()
        assert 95 <= remaining <= 100  # Allow for small time drift

    def test_get_lock_remaining_seconds_not_locked(self) -> None:
        """get_lock_remaining_seconds should return 0 when not locked."""
        state = AuthState(
            auth_id="test",
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            step=AuthStep.PHONE_SENT,
        )

        assert state.get_lock_remaining_seconds() == 0


class TestAuthStep:
    """Tests for AuthStep enum."""

    def test_values(self) -> None:
        """AuthStep should have expected values."""
        assert AuthStep.PHONE_SENT.value == "phone_sent"
        assert AuthStep.CODE_INVALID.value == "code_invalid"
        assert AuthStep.NEED_2FA.value == "need_2fa"
        assert AuthStep.COMPLETED.value == "completed"
        assert AuthStep.FAILED.value == "failed"


class TestAuthStateManager:
    """Tests for AuthStateManager class."""

    @pytest.fixture
    def manager(self) -> AuthStateManager:
        """Create a fresh manager instance for testing."""
        # Reset singleton for testing
        AuthStateManager._instance = None
        return AuthStateManager()

    @pytest.fixture
    def mock_client(self) -> MagicMock:
        """Create a mock Telegram client."""
        client = MagicMock()
        client.is_connected = MagicMock(return_value=True)
        client.disconnect = AsyncMock()
        return client

    @pytest.mark.asyncio
    async def test_create_auth_state(
        self, manager: AuthStateManager, mock_client: MagicMock
    ) -> None:
        """create_auth_state should create and store state."""
        state = await manager.create_auth_state(
            session_name="test_session",
            api_id=12345,
            api_hash="hash123",
            proxy_id="proxy-1",
            phone="+1234567890",
            phone_code_hash="code_hash",
            client=mock_client,
        )

        assert state is not None
        assert state.session_name == "test_session"
        assert state.api_id == 12345
        assert state.step == AuthStep.PHONE_SENT
        assert state.client is mock_client
        assert len(state.auth_id) > 0

    @pytest.mark.asyncio
    async def test_get_auth_state(self, manager: AuthStateManager, mock_client: MagicMock) -> None:
        """get_auth_state should return existing state."""
        created = await manager.create_auth_state(
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )

        retrieved = await manager.get_auth_state(created.auth_id)

        assert retrieved is not None
        assert retrieved.auth_id == created.auth_id

    @pytest.mark.asyncio
    async def test_get_auth_state_missing(self, manager: AuthStateManager) -> None:
        """get_auth_state should return None for missing ID."""
        result = await manager.get_auth_state("nonexistent-id")

        assert result is None

    @pytest.mark.asyncio
    async def test_get_auth_state_expired(
        self, manager: AuthStateManager, mock_client: MagicMock
    ) -> None:
        """get_auth_state should return None for expired state."""
        created = await manager.create_auth_state(
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )
        # Make it expired
        created.created_at = time.time() - AUTH_STATE_EXPIRY_SECONDS - 1

        result = await manager.get_auth_state(created.auth_id)

        assert result is None

    @pytest.mark.asyncio
    async def test_update_auth_state(
        self, manager: AuthStateManager, mock_client: MagicMock
    ) -> None:
        """update_auth_state should update state fields."""
        created = await manager.create_auth_state(
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )

        updated = await manager.update_auth_state(
            created.auth_id,
            step=AuthStep.NEED_2FA,
            error_message="2FA required",
        )

        assert updated is not None
        assert updated.step == AuthStep.NEED_2FA
        assert updated.error_message == "2FA required"

    @pytest.mark.asyncio
    async def test_update_auth_state_missing(self, manager: AuthStateManager) -> None:
        """update_auth_state should return None for missing state."""
        result = await manager.update_auth_state(
            "nonexistent-id",
            step=AuthStep.COMPLETED,
        )

        assert result is None

    @pytest.mark.asyncio
    async def test_remove_auth_state(
        self, manager: AuthStateManager, mock_client: MagicMock
    ) -> None:
        """remove_auth_state should remove state and disconnect client."""
        created = await manager.create_auth_state(
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )

        await manager.remove_auth_state(created.auth_id)

        assert await manager.get_auth_state(created.auth_id) is None
        mock_client.disconnect.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_all(self, manager: AuthStateManager, mock_client: MagicMock) -> None:
        """cleanup_all should remove all states."""
        await manager.create_auth_state(
            session_name="session1",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )
        await manager.create_auth_state(
            session_name="session2",
            api_id=2,
            api_hash="hash2",
            proxy_id="proxy",
            phone="+2",
            phone_code_hash="code2",
            client=mock_client,
        )

        await manager.cleanup_all()

        # Both should be removed
        assert len(manager._states) == 0

    @pytest.mark.asyncio
    async def test_increment_failed_attempts(
        self, manager: AuthStateManager, mock_client: MagicMock
    ) -> None:
        """increment_failed_attempts should increment counter."""
        created = await manager.create_auth_state(
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )

        updated = await manager.increment_failed_attempts(created.auth_id)

        assert updated is not None
        assert updated.failed_attempts == 1
        assert updated.is_locked() is False

    @pytest.mark.asyncio
    async def test_increment_failed_attempts_locks_at_max(
        self, manager: AuthStateManager, mock_client: MagicMock
    ) -> None:
        """increment_failed_attempts should lock when reaching MAX_AUTH_ATTEMPTS."""
        created = await manager.create_auth_state(
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )

        # Increment to MAX_AUTH_ATTEMPTS
        for _ in range(MAX_AUTH_ATTEMPTS):
            await manager.increment_failed_attempts(created.auth_id)

        state = await manager.get_auth_state(created.auth_id)
        assert state is not None
        assert state.failed_attempts == MAX_AUTH_ATTEMPTS
        assert state.is_locked() is True
        assert state.get_lock_remaining_seconds() > 0

    @pytest.mark.asyncio
    async def test_check_auth_lock_not_locked(
        self, manager: AuthStateManager, mock_client: MagicMock
    ) -> None:
        """check_auth_lock should return False for unlocked state."""
        created = await manager.create_auth_state(
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )

        is_locked, remaining = await manager.check_auth_lock(created.auth_id)

        assert is_locked is False
        assert remaining == 0

    @pytest.mark.asyncio
    async def test_check_auth_lock_locked(
        self, manager: AuthStateManager, mock_client: MagicMock
    ) -> None:
        """check_auth_lock should return True for locked state."""
        created = await manager.create_auth_state(
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )

        # Lock the state
        for _ in range(MAX_AUTH_ATTEMPTS):
            await manager.increment_failed_attempts(created.auth_id)

        is_locked, remaining = await manager.check_auth_lock(created.auth_id)

        assert is_locked is True
        assert remaining > 0
        # Should be approximately AUTH_LOCK_DURATION_SECONDS
        assert AUTH_LOCK_DURATION_SECONDS - 10 <= remaining <= AUTH_LOCK_DURATION_SECONDS

    @pytest.mark.asyncio
    async def test_check_auth_lock_missing_state(self, manager: AuthStateManager) -> None:
        """check_auth_lock should return False for missing state."""
        is_locked, remaining = await manager.check_auth_lock("nonexistent-id")

        assert is_locked is False
        assert remaining == 0

    @pytest.mark.asyncio
    async def test_reset_failed_attempts(
        self, manager: AuthStateManager, mock_client: MagicMock
    ) -> None:
        """reset_failed_attempts should reset counter and unlock state."""
        created = await manager.create_auth_state(
            session_name="session",
            api_id=1,
            api_hash="hash",
            proxy_id="proxy",
            phone="+1",
            phone_code_hash="code",
            client=mock_client,
        )

        # Lock the state
        for _ in range(MAX_AUTH_ATTEMPTS):
            await manager.increment_failed_attempts(created.auth_id)

        # Verify locked
        state = await manager.get_auth_state(created.auth_id)
        assert state is not None
        assert state.is_locked() is True

        # Reset
        reset_state = await manager.reset_failed_attempts(created.auth_id)

        assert reset_state is not None
        assert reset_state.failed_attempts == 0
        assert reset_state.is_locked() is False

    @pytest.mark.asyncio
    async def test_reset_failed_attempts_missing_state(
        self, manager: AuthStateManager
    ) -> None:
        """reset_failed_attempts should return None for missing state."""
        result = await manager.reset_failed_attempts("nonexistent-id")

        assert result is None


class TestGetAuthStateManager:
    """Tests for get_auth_state_manager function."""

    def test_returns_manager(self) -> None:
        """Should return AuthStateManager instance."""
        # Reset singleton
        AuthStateManager._instance = None

        manager = get_auth_state_manager()

        assert isinstance(manager, AuthStateManager)

    def test_singleton(self) -> None:
        """Should return same instance (singleton)."""
        # Reset singleton
        AuthStateManager._instance = None

        manager1 = get_auth_state_manager()
        manager2 = get_auth_state_manager()

        assert manager1 is manager2

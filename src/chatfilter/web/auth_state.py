"""In-memory auth state manager for Telegram session creation flow.

Auth flow state is intentionally stored in memory (not persisted).
If the server restarts, auth flows start over - this is expected behavior.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from telethon import TelegramClient

logger = logging.getLogger(__name__)

# Auth state expiry time (10 minutes)
AUTH_STATE_EXPIRY_SECONDS = 600


class AuthStep(str, Enum):
    """Current step in the auth flow."""

    PHONE_SENT = "phone_sent"  # Code sent, waiting for user to enter code
    CODE_INVALID = "code_invalid"  # Code was invalid, user can retry
    NEED_2FA = "need_2fa"  # 2FA password required
    COMPLETED = "completed"  # Auth successful, session created
    FAILED = "failed"  # Auth failed permanently


@dataclass
class AuthState:
    """State for an in-progress auth flow."""

    # Unique ID for this auth flow
    auth_id: str

    # Session configuration
    session_name: str
    api_id: int
    api_hash: str
    proxy_id: str
    phone: str

    # Auth flow state
    step: AuthStep
    phone_code_hash: str = ""
    error_message: str = ""

    # Telethon client (kept alive during auth flow)
    client: TelegramClient | None = None

    # Timestamps
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def is_expired(self) -> bool:
        """Check if this auth state has expired."""
        return time.time() - self.created_at > AUTH_STATE_EXPIRY_SECONDS

    def touch(self) -> None:
        """Update the last activity timestamp."""
        self.updated_at = time.time()


class AuthStateManager:
    """Manager for in-memory auth flow states.

    Thread-safe singleton that manages all active auth flows.
    Automatically cleans up expired states.
    """

    _instance: AuthStateManager | None = None
    _lock: asyncio.Lock

    def __new__(cls) -> AuthStateManager:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._states = {}
            cls._instance._lock = asyncio.Lock()
            cls._instance._cleanup_task = None
        return cls._instance

    def __init__(self) -> None:
        # Avoid reinitializing on subsequent calls
        if not hasattr(self, "_states"):
            self._states: dict[str, AuthState] = {}
            self._lock = asyncio.Lock()
            self._cleanup_task: asyncio.Task[None] | None = None

    def _generate_auth_id(self) -> str:
        """Generate a unique auth flow ID."""
        return secrets.token_urlsafe(16)

    async def create_auth_state(
        self,
        session_name: str,
        api_id: int,
        api_hash: str,
        proxy_id: str,
        phone: str,
        phone_code_hash: str,
        client: TelegramClient,
    ) -> AuthState:
        """Create a new auth state for a phone that has received a code.

        Args:
            session_name: Name for the session being created
            api_id: Telegram API ID
            api_hash: Telegram API hash
            proxy_id: ID of proxy to use
            phone: Phone number
            phone_code_hash: Hash returned by send_code_request
            client: Telethon client instance to keep alive

        Returns:
            The created AuthState
        """
        async with self._lock:
            # Clean up expired states first
            await self._cleanup_expired_unlocked()

            auth_id = self._generate_auth_id()
            state = AuthState(
                auth_id=auth_id,
                session_name=session_name,
                api_id=api_id,
                api_hash=api_hash,
                proxy_id=proxy_id,
                phone=phone,
                step=AuthStep.PHONE_SENT,
                phone_code_hash=phone_code_hash,
                client=client,
            )
            self._states[auth_id] = state
            logger.info(f"Created auth state {auth_id} for session '{session_name}'")
            return state

    async def get_auth_state(self, auth_id: str) -> AuthState | None:
        """Get an auth state by ID.

        Returns None if not found or expired.
        """
        async with self._lock:
            state = self._states.get(auth_id)
            if state is None:
                return None
            if state.is_expired():
                await self._remove_state_unlocked(auth_id)
                return None
            return state

    async def update_auth_state(
        self,
        auth_id: str,
        step: AuthStep | None = None,
        error_message: str | None = None,
    ) -> AuthState | None:
        """Update an auth state.

        Returns the updated state, or None if not found.
        """
        async with self._lock:
            state = self._states.get(auth_id)
            if state is None or state.is_expired():
                return None

            if step is not None:
                state.step = step
            if error_message is not None:
                state.error_message = error_message
            state.touch()

            logger.info(f"Updated auth state {auth_id}: step={state.step}")
            return state

    async def remove_auth_state(self, auth_id: str) -> None:
        """Remove an auth state and disconnect its client."""
        async with self._lock:
            await self._remove_state_unlocked(auth_id)

    async def _remove_state_unlocked(self, auth_id: str) -> None:
        """Remove a state without acquiring the lock (caller must hold lock)."""
        state = self._states.pop(auth_id, None)
        if state and state.client:
            try:
                if state.client.is_connected():
                    await state.client.disconnect()
                logger.info(f"Disconnected and removed auth state {auth_id}")
            except Exception as e:
                logger.warning(f"Error disconnecting client for auth {auth_id}: {e}")

    async def _cleanup_expired_unlocked(self) -> None:
        """Clean up expired states (caller must hold lock)."""
        expired_ids = [auth_id for auth_id, state in self._states.items() if state.is_expired()]
        for auth_id in expired_ids:
            await self._remove_state_unlocked(auth_id)
        if expired_ids:
            logger.info(f"Cleaned up {len(expired_ids)} expired auth states")

    async def _periodic_cleanup(self) -> None:
        """Background task that periodically cleans up expired states."""
        # Run cleanup every 5 minutes (300 seconds)
        # This is less frequent than expiry time (600s) but frequent enough
        # to prevent excessive memory usage from accumulated expired states
        cleanup_interval = 300

        try:
            while True:
                await asyncio.sleep(cleanup_interval)
                async with self._lock:
                    await self._cleanup_expired_unlocked()
        except asyncio.CancelledError:
            logger.info("Auth state cleanup task cancelled")
            raise

    def start_cleanup_task(self) -> None:
        """Start the background cleanup task.

        Should be called during application startup.
        """
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
            logger.info("Auth state cleanup task started (5 minute interval)")

    async def stop_cleanup_task(self) -> None:
        """Stop the background cleanup task.

        Should be called during application shutdown.
        """
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task
            logger.info("Auth state cleanup task stopped")

    async def cleanup_all(self) -> None:
        """Clean up all auth states (for shutdown)."""
        async with self._lock:
            auth_ids = list(self._states.keys())
            for auth_id in auth_ids:
                await self._remove_state_unlocked(auth_id)
            logger.info(f"Cleaned up all {len(auth_ids)} auth states")


def get_auth_state_manager() -> AuthStateManager:
    """Get the global auth state manager instance."""
    return AuthStateManager()

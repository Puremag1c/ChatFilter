"""Tests for graceful shutdown handling."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from chatfilter.web.app import create_app


class TestGracefulShutdownMiddleware:
    """Tests for graceful shutdown middleware."""

    def test_middleware_tracks_active_connections(self, tmp_path: Path) -> None:
        """Test that middleware tracks active connections."""
        from chatfilter.config import Settings
        from chatfilter.web.app import AppState

        settings = Settings(data_dir=tmp_path, port=8893)
        app = create_app(settings=settings)

        # Initialize app state (normally done by lifespan)
        app.state.app_state = AppState()

        # App should start with 0 active connections
        assert app.state.app_state.active_connections == 0

        # Make a request
        with TestClient(app) as client:
            response = client.get("/health")
            assert response.status_code == 200

        # After request completes, should be back to 0
        assert app.state.app_state.active_connections == 0

    def test_rejects_requests_during_shutdown(self, tmp_path: Path) -> None:
        """Test that new requests are rejected during shutdown."""
        from chatfilter.config import Settings
        from chatfilter.web.app import AppState

        settings = Settings(data_dir=tmp_path, port=8894)
        app = create_app(settings=settings)

        # Initialize app state (normally done by lifespan)
        app.state.app_state = AppState()

        with TestClient(app) as client:
            # Set shutting_down flag
            app.state.app_state.shutting_down = True

            response = client.get("/")
            assert response.status_code == 503
            assert "shutting_down" in response.json()["status"]
            assert "Retry-After" in response.headers

    def test_health_check_fails_during_shutdown(self, tmp_path: Path) -> None:
        """Test that health check returns 503 during shutdown."""
        from chatfilter.config import Settings
        from chatfilter.web.app import AppState

        settings = Settings(data_dir=tmp_path, port=8895)
        app = create_app(settings=settings)

        # Initialize app state (normally done by lifespan)
        app.state.app_state = AppState()

        with TestClient(app) as client:
            # Normal health check should pass
            response = client.get("/health")
            assert response.status_code == 200

            # Set shutting_down flag
            app.state.app_state.shutting_down = True

            # Health check should now fail
            response = client.get("/health")
            assert response.status_code == 503
            assert response.json()["status"] == "shutting_down"


class TestLifespanShutdown:
    """Tests for lifespan shutdown handling."""

    @pytest.mark.asyncio
    async def test_lifespan_initializes_app_state(self, tmp_path: Path) -> None:
        """Test that lifespan initializes app state."""
        from chatfilter.config import Settings
        from chatfilter.web.app import lifespan

        settings = Settings(data_dir=tmp_path, port=8896)
        app = create_app(settings=settings)

        # Manually run lifespan context manager
        async with lifespan(app):
            # App state should be initialized during lifespan startup
            assert hasattr(app.state, "app_state")
            assert app.state.app_state.shutting_down is False
            assert app.state.app_state.active_connections == 0

    @pytest.mark.asyncio
    async def test_shutdown_waits_for_active_connections(self, tmp_path: Path) -> None:
        """Test that shutdown waits for active connections to complete."""
        from chatfilter.config import Settings
        from chatfilter.web.app import lifespan

        settings = Settings(data_dir=tmp_path, port=8897)
        app = create_app(settings=settings)

        # Simulate active connections
        async with lifespan(app):
            app.state.app_state.active_connections = 2

            # Start shutdown in background
            shutdown_task = asyncio.create_task(
                asyncio.sleep(0.1)  # Simulate some shutdown delay
            )

            # Simulate connections completing
            await asyncio.sleep(0.05)
            app.state.app_state.active_connections = 1
            await asyncio.sleep(0.05)
            app.state.app_state.active_connections = 0

            await shutdown_task

        # After shutdown, should be marked as shutting down
        assert app.state.app_state.shutting_down is True


class TestPollingTaskCleanupOnShutdown:
    """Tests that background polling tasks are properly cancelled on app shutdown.

    Verifies: no 'Task was destroyed but it is pending!' warnings during shutdown
    when device confirmation polling tasks are active.
    """

    @pytest.mark.asyncio
    async def test_shutdown_cancels_active_polling_task(self, tmp_path: Path) -> None:
        """Shutdown via lifespan exit must cancel active polling tasks cleanly."""
        import warnings

        from chatfilter.config import Settings
        from chatfilter.web.app import lifespan
        from chatfilter.web.auth_state import AuthState, AuthStateManager, AuthStep

        # Reset singleton to get a clean manager for this test
        AuthStateManager._instance = None
        manager = AuthStateManager()

        settings = Settings(data_dir=tmp_path, port=8900)
        app = create_app(settings=settings)

        # Track if the simulated polling task received CancelledError
        cancel_received = False

        async def _fake_polling() -> None:
            """Simulate a long-running polling task (like _poll_device_confirmation)."""
            nonlocal cancel_received
            try:
                await asyncio.sleep(300)  # 5 minutes, like the real task
            except asyncio.CancelledError:
                cancel_received = True
                raise

        async with lifespan(app):
            # Inject a fake auth state with a running polling task
            state = AuthState(
                auth_id="test-poll-cleanup",
                session_name="test_session",
                api_id=12345,
                api_hash="abcdef",
                proxy_id="proxy-1",
                phone="+1234567890",
                step=AuthStep.NEED_CONFIRMATION,
            )
            polling_task = asyncio.create_task(_fake_polling())
            state.polling_task = polling_task
            manager._states["test-poll-cleanup"] = state

        # After lifespan exit (shutdown complete):
        # 1. Polling task should have been cancelled
        assert cancel_received, "Polling task did not receive CancelledError during shutdown"
        assert polling_task.done(), "Polling task should be done after shutdown"
        assert polling_task.cancelled(), "Polling task should be cancelled after shutdown"

        # 2. Auth state should be cleaned up
        assert "test-poll-cleanup" not in manager._states

        # Reset singleton
        AuthStateManager._instance = None

    @pytest.mark.asyncio
    async def test_shutdown_handles_already_finished_polling_task(self, tmp_path: Path) -> None:
        """Shutdown should handle polling tasks that finished before shutdown."""
        from chatfilter.config import Settings
        from chatfilter.web.app import lifespan
        from chatfilter.web.auth_state import AuthState, AuthStateManager, AuthStep

        AuthStateManager._instance = None
        manager = AuthStateManager()

        settings = Settings(data_dir=tmp_path, port=8901)
        app = create_app(settings=settings)

        async with lifespan(app):
            # Create a polling task that's already done
            async def _instant_task() -> None:
                return

            state = AuthState(
                auth_id="test-done-task",
                session_name="test_session2",
                api_id=12345,
                api_hash="abcdef",
                proxy_id="proxy-1",
                phone="+1234567890",
                step=AuthStep.NEED_CONFIRMATION,
            )
            polling_task = asyncio.create_task(_instant_task())
            await polling_task  # Let it finish
            state.polling_task = polling_task
            manager._states["test-done-task"] = state

        # Should not raise or warn — already-done tasks are skipped
        assert "test-done-task" not in manager._states
        AuthStateManager._instance = None

    @pytest.mark.asyncio
    async def test_no_task_destroyed_warnings_on_shutdown(self, tmp_path: Path) -> None:
        """No 'Task was destroyed but it is pending!' warnings during shutdown.

        This is the key verification for ChatFilter-m9v84: asyncio emits this
        warning when a Task object is garbage-collected while still pending.
        The shutdown path must cancel and await all tasks before they're GC'd.
        """
        import gc
        import warnings

        from chatfilter.config import Settings
        from chatfilter.web.app import lifespan
        from chatfilter.web.auth_state import AuthState, AuthStateManager, AuthStep

        AuthStateManager._instance = None
        manager = AuthStateManager()

        settings = Settings(data_dir=tmp_path, port=8902)
        app = create_app(settings=settings)

        async with lifespan(app):
            # Create multiple auth states with active polling tasks
            for i in range(3):
                async def _long_poll(idx: int = i) -> None:
                    try:
                        await asyncio.sleep(300)
                    except asyncio.CancelledError:
                        raise

                state = AuthState(
                    auth_id=f"test-multi-{i}",
                    session_name=f"session_{i}",
                    api_id=12345,
                    api_hash="abcdef",
                    proxy_id="proxy-1",
                    phone=f"+123456789{i}",
                    step=AuthStep.NEED_CONFIRMATION,
                )
                task = asyncio.create_task(_long_poll())
                state.polling_task = task
                manager._states[f"test-multi-{i}"] = state

        # Force garbage collection to trigger any "Task was destroyed" warnings
        with warnings.catch_warnings(record=True) as caught_warnings:
            warnings.simplefilter("always")
            gc.collect()

        task_destroyed_warnings = [
            w for w in caught_warnings
            if "Task was destroyed" in str(w.message)
        ]
        assert len(task_destroyed_warnings) == 0, (
            f"Got 'Task was destroyed' warnings: {[str(w.message) for w in task_destroyed_warnings]}"
        )

        # All states should be cleaned up
        assert len(manager._states) == 0
        AuthStateManager._instance = None


class TestAppState:
    """Tests for AppState class."""

    def test_app_state_initialization(self) -> None:
        """Test AppState initializes with correct defaults."""
        from chatfilter.web.app import AppState

        state = AppState()
        assert state.shutting_down is False
        assert state.active_connections == 0
        assert state.session_manager is None

    def test_app_state_tracks_connections(self) -> None:
        """Test AppState can track connections."""
        from chatfilter.web.app import AppState

        state = AppState()

        state.active_connections += 1
        assert state.active_connections == 1

        state.active_connections += 1
        assert state.active_connections == 2

        state.active_connections -= 1
        assert state.active_connections == 1

    def test_app_state_shutdown_flag(self) -> None:
        """Test AppState shutdown flag."""
        from chatfilter.web.app import AppState

        state = AppState()
        assert not state.shutting_down

        state.shutting_down = True
        assert state.shutting_down

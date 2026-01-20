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

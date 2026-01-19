"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.cors import CORSMiddleware

from chatfilter.web.middleware import RequestIDMiddleware, RequestLoggingMiddleware
from chatfilter.web.routers.analysis import router as analysis_router
from chatfilter.web.routers.chats import router as chats_router
from chatfilter.web.routers.export import router as export_router
from chatfilter.web.routers.health import router as health_router
from chatfilter.web.routers.pages import router as pages_router
from chatfilter.web.routers.sessions import router as sessions_router

logger = logging.getLogger(__name__)

# Paths for static files and templates
PACKAGE_DIR = Path(__file__).parent.parent
STATIC_DIR = PACKAGE_DIR / "static"
TEMPLATES_DIR = PACKAGE_DIR / "templates"


class AppState:
    """Application state container for graceful shutdown."""

    def __init__(self) -> None:
        self.shutting_down = False


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan handler for startup/shutdown.

    Handles:
    - Startup: Initialize resources
    - Shutdown: Graceful cleanup with signal to active connections
    """
    # Startup
    logger.info("ChatFilter application starting up")
    app.state.app_state = AppState()

    yield

    # Shutdown
    logger.info("ChatFilter application shutting down")
    app.state.app_state.shutting_down = True
    # Give active connections a moment to complete
    # In production, you might want to track and wait for active SSE connections
    logger.info("Shutdown complete")


def create_app(
    *,
    debug: bool = False,
    cors_origins: list[str] | None = None,
) -> FastAPI:
    """Create and configure FastAPI application.

    This factory pattern allows creating isolated app instances for testing
    and configuring different environments.

    Args:
        debug: Enable debug mode (more verbose errors)
        cors_origins: List of allowed CORS origins. Defaults to localhost.

    Returns:
        Configured FastAPI application instance

    Example:
        ```python
        app = create_app(debug=True)
        # Run with: uvicorn chatfilter.web.app:app
        ```
    """
    from chatfilter import __version__

    app = FastAPI(
        title="ChatFilter",
        description="Telegram chat filtering and analysis tool",
        version=__version__,
        debug=debug,
        lifespan=lifespan,
    )

    # Add middlewares (order matters: first added = last executed)
    # RequestLogging should run after RequestID is set
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestIDMiddleware)

    # CORS configuration
    if cors_origins is None:
        cors_origins = [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:3000",  # For potential dev frontend
        ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount static files if directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # Include routers
    app.include_router(health_router)
    app.include_router(export_router)
    app.include_router(sessions_router)
    app.include_router(chats_router)
    app.include_router(analysis_router)
    app.include_router(pages_router)

    return app


def get_templates() -> Jinja2Templates:
    """Get Jinja2 templates instance.

    Returns:
        Configured Jinja2Templates for rendering HTML

    Raises:
        FileNotFoundError: If templates directory doesn't exist
    """
    if not TEMPLATES_DIR.exists():
        raise FileNotFoundError(f"Templates directory not found: {TEMPLATES_DIR}")
    return Jinja2Templates(directory=str(TEMPLATES_DIR))


# Default app instance for uvicorn
app = create_app()

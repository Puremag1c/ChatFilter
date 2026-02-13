"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.cors import CORSMiddleware

from chatfilter.config import Settings, get_settings
from chatfilter.utils.paths import get_base_path
from chatfilter.web.exception_handlers import register_exception_handlers
from chatfilter.web.middleware import (
    CSRFProtectionMiddleware,
    GracefulShutdownMiddleware,
    RequestIDMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    SessionMiddleware,
)
from chatfilter.web.routers.analysis import router as analysis_router
from chatfilter.web.routers.chatlist import router as chatlist_router
from chatfilter.web.routers.chats import router as chats_router
from chatfilter.web.routers.export import router as export_router
from chatfilter.web.routers.health import router as health_router
from chatfilter.web.routers.history import router as history_router
from chatfilter.web.routers.monitoring import router as monitoring_router
from chatfilter.web.routers.pages import router as pages_router
from chatfilter.web.routers.proxy_pool import router as proxy_pool_router
from chatfilter.web.routers.groups import router as groups_router
from chatfilter.web.routers.sessions import router as sessions_router

logger = logging.getLogger(__name__)

# Paths for static files and templates (PyInstaller-safe)
PACKAGE_DIR = get_base_path()
STATIC_DIR = PACKAGE_DIR / "static"
TEMPLATES_DIR = PACKAGE_DIR / "templates"


class AppState:
    """Application state container for graceful shutdown."""

    def __init__(self) -> None:
        from typing import TYPE_CHECKING

        if TYPE_CHECKING:
            from chatfilter.service.proxy_health import ProxyHealthMonitor
            from chatfilter.telegram.session_manager import SessionManager

        self.shutting_down = False
        self.active_connections = 0
        self.session_manager: SessionManager | None = None  # Will be set during startup
        self.proxy_health_monitor: ProxyHealthMonitor | None = None  # Will be set during startup


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan handler for startup/shutdown.

    Handles:
    - Startup: Initialize resources and recover incomplete tasks
    - Shutdown: Graceful cleanup with signal to active connections
    """
    import asyncio

    # Startup
    import platform

    from chatfilter import __version__
    from chatfilter.analyzer.task_queue import get_task_queue
    from chatfilter.storage.database import TaskDatabase
    from chatfilter.utils import cleanup_orphaned_resources

    logger.info("=" * 60)
    logger.info(f"ChatFilter v{__version__} starting up")
    logger.info(
        f"Python: {platform.python_version()}, OS: {platform.system()} {platform.release()}"
    )
    logger.info("=" * 60)
    app.state.app_state = AppState()

    # Initialize task database and queue
    settings = app.state.settings

    # Log configuration paths
    logger.info(f"Configuration: host={settings.host}, port={settings.port}")
    logger.info(f"Data directory: {settings.data_dir}")
    logger.info(f"Sessions directory: {settings.sessions_dir}")
    logger.info(f"Exports directory: {settings.exports_dir}")

    # Warn if debug mode is enabled (potential security risk)
    if settings.debug:
        logger.warning(
            "⚠️  DEBUG MODE ENABLED - Not recommended for production! "
            "This exposes detailed error messages including stack traces, "
            "exception types, and internal details. Set CHATFILTER_DEBUG=false "
            "for production deployments."
        )

    db_path = settings.data_dir / "tasks.db"
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    # Clean up orphaned resources from SIGKILL/crashes
    cleanup_orphaned_resources(
        data_dir=settings.data_dir,
        sessions_dir=settings.sessions_dir,
        session_cleanup_days=settings.session_cleanup_days,
    )

    # Migrate legacy sessions (v0.4 -> v0.5 per-session config)
    from chatfilter.web.routers.sessions import migrate_legacy_sessions

    migrated_sessions = migrate_legacy_sessions()
    if migrated_sessions:
        logger.info(f"Migrated {len(migrated_sessions)} legacy sessions to new config format")

    task_db = TaskDatabase(db_path)
    task_queue = get_task_queue(
        db=task_db,
        stale_task_threshold_hours=settings.stale_task_threshold_hours,
    )
    logger.info(f"Task database initialized at {db_path}")

    # Initialize session manager and start connection monitor
    from chatfilter.web.dependencies import get_session_manager

    session_manager = get_session_manager()
    app.state.app_state.session_manager = session_manager
    session_manager.start_monitor()
    logger.info("Telegram session manager initialized with connection monitoring")

    # Start proxy health monitor
    from chatfilter.service.proxy_health import get_proxy_health_monitor

    proxy_health_monitor = get_proxy_health_monitor()
    proxy_health_monitor.start()
    app.state.app_state.proxy_health_monitor = proxy_health_monitor
    logger.info("Proxy health monitor started")

    # Start auth state cleanup task
    from chatfilter.web.auth_state import get_auth_state_manager

    auth_state_manager = get_auth_state_manager()
    auth_state_manager.start_cleanup_task()
    logger.info("Auth state cleanup task started")

    logger.info("Application startup complete")

    yield

    # Graceful shutdown
    logger.info("Initiating graceful shutdown")
    app.state.app_state.shutting_down = True

    # 1. Stop accepting new requests (handled by middleware)
    logger.info("Rejecting new requests")

    # 2. Wait for active connections to complete (with timeout)
    shutdown_timeout = 30.0  # seconds
    start_time = asyncio.get_event_loop().time()

    while app.state.app_state.active_connections > 0:
        elapsed = asyncio.get_event_loop().time() - start_time
        if elapsed > shutdown_timeout:
            logger.warning(
                f"Shutdown timeout reached with {app.state.app_state.active_connections} "
                "active connections still running. Forcing shutdown."
            )
            break

        logger.info(
            f"Waiting for {app.state.app_state.active_connections} active connections "
            f"to complete ({elapsed:.1f}s / {shutdown_timeout}s)"
        )
        await asyncio.sleep(0.5)

    # 3. Clear completed tasks to free memory
    try:
        logger.info("Cleaning up completed tasks")
        cleared = task_queue.clear_completed()
        orphaned = await task_queue.cleanup_orphaned_subscribers()
        logger.info(f"Cleared {cleared} tasks and {orphaned} orphaned subscriber lists")
    except Exception as e:
        logger.error(f"Error clearing tasks during shutdown: {e}")

    # 4. Stop proxy health monitor
    if app.state.app_state.proxy_health_monitor:
        logger.info("Stopping proxy health monitor")
        try:
            await app.state.app_state.proxy_health_monitor.stop()
            logger.info("Proxy health monitor stopped")
        except Exception as e:
            logger.error(f"Error stopping proxy health monitor: {e}")

    # 5. Stop connection monitor and disconnect all Telegram sessions
    if app.state.app_state.session_manager:
        logger.info("Stopping connection monitor")
        try:
            await app.state.app_state.session_manager.stop_monitor()
            logger.info("Connection monitor stopped")
        except Exception as e:
            logger.error(f"Error stopping connection monitor during shutdown: {e}")

        logger.info("Disconnecting Telegram sessions")
        try:
            await app.state.app_state.session_manager.disconnect_all()
            logger.info("All Telegram sessions disconnected")
        except Exception as e:
            logger.error(f"Error disconnecting sessions during shutdown: {e}")

    # 6. Stop auth state cleanup task and clean up all states
    try:
        from chatfilter.web.auth_state import get_auth_state_manager

        auth_state_manager = get_auth_state_manager()
        await auth_state_manager.stop_cleanup_task()
        await auth_state_manager.cleanup_all()
        logger.info("Auth state manager shutdown complete")
    except Exception as e:
        logger.error(f"Error stopping auth state manager during shutdown: {e}")

    # 7. Clear service caches to free memory
    try:
        from chatfilter.web.dependencies import get_chat_analysis_service

        service = get_chat_analysis_service()
        service.clear_cache()
        logger.info("Cleared service caches")
    except Exception as e:
        logger.error(f"Error clearing service caches during shutdown: {e}")

    logger.info("Graceful shutdown complete")


def create_app(
    *,
    debug: bool | None = None,
    cors_origins: list[str] | None = None,
    settings: Settings | None = None,
) -> FastAPI:
    """Create and configure FastAPI application.

    This factory pattern allows creating isolated app instances for testing
    and configuring different environments.

    Args:
        debug: Enable debug mode (more verbose errors). If None, uses settings.
        cors_origins: List of allowed CORS origins. If None, uses settings.
        settings: Settings instance. If None, uses get_settings().

    Returns:
        Configured FastAPI application instance

    Example:
        ```python
        app = create_app(debug=True)
        # Run with: uvicorn chatfilter.web.app:app
        ```
    """
    from chatfilter import __version__

    # Use provided settings or get from cache
    if settings is None:
        settings = get_settings()

    # Use explicit values or fall back to settings
    effective_debug = debug if debug is not None else settings.debug
    effective_cors = cors_origins if cors_origins is not None else settings.cors_origins

    app = FastAPI(
        title="ChatFilter",
        description="Telegram chat filtering and analysis tool",
        version=__version__,
        debug=effective_debug,
        lifespan=lifespan,
    )

    # Store settings in app state for access in routes
    app.state.settings = settings

    # Register custom exception handlers for secure error responses
    register_exception_handlers(app)

    # Add middlewares (order matters: first added = last executed)
    # GracefulShutdown runs first to reject requests during shutdown
    # RequestLogging should run after RequestID is set
    # Session middleware manages session cookies (must run before CSRF)
    # CSRF protection validates tokens (must run after Session)
    # SecurityHeaders adds security headers to all responses
    # LocaleMiddleware detects and sets user's preferred language
    from chatfilter.i18n.middleware import LocaleMiddleware

    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CSRFProtectionMiddleware)
    # Enable body logging in verbose mode (sanitized for security)
    app.add_middleware(RequestLoggingMiddleware, log_bodies=settings.verbose)
    app.add_middleware(LocaleMiddleware)
    app.add_middleware(SessionMiddleware)
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(GracefulShutdownMiddleware)

    # CORS configuration for separated frontend/backend
    # Restrict to only the methods and headers actually used by the API
    app.add_middleware(
        CORSMiddleware,
        allow_origins=effective_cors,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],  # Explicit methods used by API
        allow_headers=[  # Only allow headers needed for the application
            "Content-Type",
            "Accept",
            "Accept-Language",
            "Content-Language",
            "X-CSRF-Token",  # CSRF protection header
        ],
    )

    # Mount static files if directory exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    # Include routers
    app.include_router(health_router)
    app.include_router(export_router)
    app.include_router(history_router)
    app.include_router(sessions_router)
    app.include_router(chatlist_router)
    app.include_router(chats_router)
    app.include_router(groups_router)
    app.include_router(analysis_router)
    app.include_router(monitoring_router)
    app.include_router(proxy_pool_router)
    app.include_router(pages_router)

    return app


# Singleton for Jinja2Templates instance
_templates_instance: Jinja2Templates | None = None


def get_templates() -> Jinja2Templates:
    """Get Jinja2 templates instance with i18n support (singleton).

    Returns:
        Configured Jinja2Templates for rendering HTML with translations

    Raises:
        FileNotFoundError: If templates directory doesn't exist
    """
    global _templates_instance

    if _templates_instance is not None:
        return _templates_instance

    if not TEMPLATES_DIR.exists():
        raise FileNotFoundError(f"Templates directory not found: {TEMPLATES_DIR}")

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # Configure Jinja2 i18n extension
    templates.env.add_extension("jinja2.ext.i18n")

    # Install translation functions
    # These will be updated per-request with the correct locale
    from chatfilter.i18n.translations import get_current_locale, get_translations

    def install_translations() -> None:
        """Install translations for current locale into Jinja2 environment."""
        locale = get_current_locale()
        translations = get_translations(locale)
        templates.env.install_gettext_translations(translations)  # type: ignore[attr-defined]

    # Install default translations (will be overridden per request)
    install_translations()

    # Store the installer function for use in template context
    templates.env.globals["install_translations"] = install_translations

    _templates_instance = templates
    return templates


# Default app instance for uvicorn
app = create_app()

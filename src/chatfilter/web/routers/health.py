"""Health check endpoint router."""

from __future__ import annotations

import logging
import shutil
import time
from datetime import datetime
from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from chatfilter.utils.network import get_network_monitor

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

# Track application start time
_start_time = time.time()

# Cache for update check results (to avoid excessive API calls)
_update_check_cache: dict[str, tuple[datetime, dict[str, Any]]] = {}


class TelegramStatus(BaseModel):
    """Telegram connection status."""

    connected: bool
    sessions_count: int
    error: str | None = None


class TelegramUser(BaseModel):
    """Telegram user information."""

    id: int
    username: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    phone: str | None = None
    error: str | None = None


class DiskSpace(BaseModel):
    """Disk space information."""

    total_gb: float = Field(description="Total disk space in GB")
    used_gb: float = Field(description="Used disk space in GB")
    free_gb: float = Field(description="Free disk space in GB")
    percent_used: float = Field(description="Percentage of disk space used")


class NetworkHealth(BaseModel):
    """Network connectivity health information."""

    online: bool = Field(description="Whether network is currently reachable")
    check_duration_ms: float | None = Field(description="Time taken for connectivity check")
    error: str | None = Field(description="Error message if offline", default=None)


class UpdateStatus(BaseModel):
    """Application update status."""

    update_available: bool = Field(description="Whether an update is available")
    current_version: str = Field(description="Current application version")
    latest_version: str | None = Field(description="Latest available version", default=None)
    release_url: str | None = Field(description="URL to release page", default=None)
    published_at: str | None = Field(description="Release publication date", default=None)
    error: str | None = Field(description="Error message if check failed", default=None)


class HealthResponse(BaseModel):
    """Health check response model."""

    status: Literal["ok", "degraded", "unhealthy"]
    version: str
    uptime_seconds: float
    telegram: TelegramStatus | None = None
    disk: DiskSpace
    network: NetworkHealth
    update: UpdateStatus | None = None


class ReadyResponse(BaseModel):
    """Readiness check response model."""

    ready: bool
    message: str | None = None


def get_disk_space(path: str = "/") -> DiskSpace:
    """Get disk space information for a path.

    Args:
        path: Path to check disk space for

    Returns:
        DiskSpace with disk usage information
    """
    usage = shutil.disk_usage(path)
    total_gb = usage.total / (1024**3)
    used_gb = usage.used / (1024**3)
    free_gb = usage.free / (1024**3)
    percent_used = (usage.used / usage.total) * 100 if usage.total > 0 else 0

    return DiskSpace(
        total_gb=round(total_gb, 2),
        used_gb=round(used_gb, 2),
        free_gb=round(free_gb, 2),
        percent_used=round(percent_used, 2),
    )


async def _check_for_updates(settings: Any) -> UpdateStatus | None:
    """Check for application updates with caching.

    Args:
        settings: Application settings

    Returns:
        UpdateStatus or None if update checking is disabled
    """
    from datetime import UTC, datetime

    from chatfilter import __version__
    from chatfilter.service.version_checker import VersionChecker

    if not settings.update_check_enabled:
        return None

    # Check cache first
    cache_key = "update_check"
    if cache_key in _update_check_cache:
        cached_time, cached_result = _update_check_cache[cache_key]
        cache_age_hours = (datetime.now(UTC) - cached_time).total_seconds() / 3600

        # Use cached result if within check interval
        if cache_age_hours < settings.update_check_interval:
            return UpdateStatus.model_validate(cached_result)

    # Perform update check
    try:
        checker = VersionChecker(
            github_repo="Puremag1c/ChatFilter",
            current_version=__version__,
            timeout=settings.update_check_timeout,
        )

        result = await checker.check_for_updates(
            include_prereleases=settings.update_check_include_prereleases,
        )

        # Build update status
        update_status = UpdateStatus(
            update_available=result.update_available,
            current_version=result.current_version,
            latest_version=result.latest_version.version if result.latest_version else None,
            release_url=result.latest_version.html_url if result.latest_version else None,
            published_at=(
                result.latest_version.published_at.isoformat() if result.latest_version else None
            ),
            error=result.error,
        )

        # Cache the result (store dict for serialization)
        update_status_dict: dict[str, Any] = {
            "update_available": result.update_available,
            "current_version": result.current_version,
            "latest_version": result.latest_version.version if result.latest_version else None,
            "release_url": result.latest_version.html_url if result.latest_version else None,
            "published_at": (
                result.latest_version.published_at.isoformat() if result.latest_version else None
            ),
            "error": result.error,
        }
        _update_check_cache[cache_key] = (datetime.now(UTC), update_status_dict)

        return update_status

    except Exception as e:
        logger.error(f"Failed to check for updates: {e}")
        return UpdateStatus(
            update_available=False,
            current_version=__version__,
            error=str(e),
        )


@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request) -> HealthResponse:
    """Health check endpoint for monitoring.

    Returns application status including:
    - Overall health status (ok/degraded/unhealthy)
    - Application version
    - Uptime since startup
    - Network connectivity status
    - Telegram connection status (if available)
    - Disk space availability
    - Update availability (if enabled)

    The status is determined by:
    - ok: All systems operational, network online, disk space > 10%
    - degraded: Minor issues (network offline, no telegram connections, disk space 5-10%)
    - unhealthy: Critical issues (disk space < 5%)

    Returns:
        HealthResponse with comprehensive status information
    """
    from chatfilter import __version__
    from chatfilter.config import get_settings

    settings = get_settings()

    # Calculate uptime
    uptime = time.time() - _start_time

    # Check disk space
    disk = get_disk_space(str(settings.data_dir))

    # Check network connectivity
    network_monitor = get_network_monitor()
    network_status = await network_monitor.get_status(force_check=True)
    network_health = NetworkHealth(
        online=network_status.is_online,
        check_duration_ms=network_status.check_duration_ms,
        error=network_status.error_message if not network_status.is_online else None,
    )

    # Check for updates (if enabled and network is online)
    update_status: UpdateStatus | None = None
    if network_health.online:
        update_status = await _check_for_updates(settings)

    # Check Telegram connection status
    telegram_status: TelegramStatus | None = None
    try:
        # Access session manager if available
        if hasattr(request.app.state, "app_state") and hasattr(
            request.app.state.app_state, "session_manager"
        ):
            session_manager = request.app.state.app_state.session_manager
            if session_manager:
                sessions = session_manager.list_sessions()
                connected_count = 0
                for sid in sessions:
                    if await session_manager.is_healthy(sid):
                        connected_count += 1
                telegram_status = TelegramStatus(
                    connected=connected_count > 0,
                    sessions_count=connected_count,
                )
            else:
                telegram_status = TelegramStatus(
                    connected=False,
                    sessions_count=0,
                    error="Session manager not initialized",
                )
        else:
            telegram_status = TelegramStatus(
                connected=False,
                sessions_count=0,
                error="Session manager not available",
            )
    except Exception as e:
        telegram_status = TelegramStatus(
            connected=False,
            sessions_count=0,
            error=str(e),
        )

    # Determine overall status
    status: Literal["ok", "degraded", "unhealthy"]
    if disk.percent_used >= 95:
        status = "unhealthy"
    elif (
        disk.percent_used >= 90
        or (telegram_status and not telegram_status.connected)
        or not network_health.online
    ):
        status = "degraded"
    else:
        status = "ok"

    return HealthResponse(
        status=status,
        version=__version__,
        uptime_seconds=round(uptime, 2),
        telegram=telegram_status,
        disk=disk,
        network=network_health,
        update=update_status,
    )


@router.get("/api/telegram/status", response_model=TelegramStatus)
async def telegram_status(request: Request) -> TelegramStatus:
    """Get current Telegram connection status.

    Returns lightweight status information suitable for polling:
    - Whether any sessions are connected
    - Count of connected sessions
    - Error message if connection failed

    This endpoint is optimized for frequent polling by the UI status indicator.

    Returns:
        TelegramStatus with current connection state
    """
    try:
        # Access session manager if available
        if hasattr(request.app.state, "app_state") and hasattr(
            request.app.state.app_state, "session_manager"
        ):
            session_manager = request.app.state.app_state.session_manager
            if session_manager:
                sessions = session_manager.list_sessions()
                connected_count = 0
                for sid in sessions:
                    if await session_manager.is_healthy(sid):
                        connected_count += 1
                return TelegramStatus(
                    connected=connected_count > 0,
                    sessions_count=connected_count,
                )
            else:
                return TelegramStatus(
                    connected=False,
                    sessions_count=0,
                    error="Session manager not initialized",
                )
        else:
            return TelegramStatus(
                connected=False,
                sessions_count=0,
                error="Session manager not available",
            )
    except Exception as e:
        return TelegramStatus(
            connected=False,
            sessions_count=0,
            error=str(e),
        )


@router.get("/api/telegram/user", response_model=TelegramUser)
async def telegram_user(request: Request, session_id: str | None = None) -> TelegramUser:
    """Get current Telegram user information for a session.

    Args:
        request: FastAPI request object
        session_id: Optional session ID. If not provided, uses selected session from web session.

    Returns:
        TelegramUser with user information or error
    """
    from chatfilter.web.dependencies import get_web_session

    # If no session_id provided, try to get it from web session
    if not session_id:
        try:
            web_session = get_web_session(request)
            session_id = web_session.get("selected_telegram_session")
        except Exception:
            pass

    if not session_id:
        return TelegramUser(id=0, error="No session selected")

    try:
        # Access session manager if available
        if hasattr(request.app.state, "app_state") and hasattr(
            request.app.state.app_state, "session_manager"
        ):
            session_manager = request.app.state.app_state.session_manager
            if not session_manager:
                return TelegramUser(id=0, error="Session manager not initialized")

            # Get the client for this session
            sessions = session_manager.list_sessions()
            if session_id not in sessions:
                return TelegramUser(id=0, error=f"Session '{session_id}' not found")

            # Check if session is healthy first
            if not await session_manager.is_healthy(session_id):
                return TelegramUser(id=0, error="Session not connected or unhealthy")

            # Get user info from the session
            async with session_manager.get_session(session_id) as client:
                me = await client.get_me()
                return TelegramUser(
                    id=me.id,
                    username=me.username,
                    first_name=me.first_name,
                    last_name=me.last_name,
                    phone=me.phone,
                )
        else:
            return TelegramUser(id=0, error="Session manager not available")
    except Exception as e:
        logger.exception(f"Failed to fetch user info for session '{session_id}'")
        return TelegramUser(id=0, error=str(e))


@router.get("/api/version/check-updates", response_model=UpdateStatus)
async def check_updates(force: bool = False) -> UpdateStatus:
    """Check for application updates.

    This endpoint checks if a new version of the application is available
    on GitHub releases. Results are cached based on the configured check interval.

    Args:
        force: If True, bypass cache and force a fresh check

    Returns:
        UpdateStatus with information about available updates
    """
    from chatfilter import __version__
    from chatfilter.config import get_settings

    settings = get_settings()

    # Force cache clear if requested
    if force:
        _update_check_cache.clear()

    # Use the cached check helper
    update_status = await _check_for_updates(settings)

    if update_status is None:
        # Update checking is disabled
        return UpdateStatus(
            update_available=False,
            current_version=__version__,
            error="Update checking is disabled in configuration",
        )

    return update_status


@router.get("/ready", response_model=ReadyResponse)
async def readiness_check(request: Request) -> ReadyResponse:
    """Readiness check endpoint for Kubernetes-style health probes.

    Returns whether the application is ready to accept traffic.
    This checks if the application is in a shutting down state.

    Returns:
        ReadyResponse indicating if application is ready
    """
    # Check if app is shutting down
    if hasattr(request.app.state, "app_state"):
        app_state = request.app.state.app_state
        if app_state.shutting_down:
            return ReadyResponse(
                ready=False,
                message="Application is shutting down",
            )

    return ReadyResponse(ready=True)

"""Health check endpoint router."""

from __future__ import annotations

import shutil
import time
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

router = APIRouter(tags=["health"])

# Track application start time
_start_time = time.time()


class TelegramStatus(BaseModel):
    """Telegram connection status."""

    connected: bool
    sessions_count: int
    error: str | None = None


class DiskSpace(BaseModel):
    """Disk space information."""

    total_gb: float = Field(description="Total disk space in GB")
    used_gb: float = Field(description="Used disk space in GB")
    free_gb: float = Field(description="Free disk space in GB")
    percent_used: float = Field(description="Percentage of disk space used")


class HealthResponse(BaseModel):
    """Health check response model."""

    status: Literal["ok", "degraded", "unhealthy"]
    version: str
    uptime_seconds: float
    telegram: TelegramStatus | None = None
    disk: DiskSpace


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


@router.get("/health", response_model=HealthResponse)
async def health_check(request: Request) -> HealthResponse:
    """Health check endpoint for monitoring.

    Returns application status including:
    - Overall health status (ok/degraded/unhealthy)
    - Application version
    - Uptime since startup
    - Telegram connection status (if available)
    - Disk space availability

    The status is determined by:
    - ok: All systems operational, disk space > 10%
    - degraded: Minor issues (no telegram connections, disk space 5-10%)
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
    elif disk.percent_used >= 90 or (telegram_status and not telegram_status.connected):
        status = "degraded"
    else:
        status = "ok"

    return HealthResponse(
        status=status,
        version=__version__,
        uptime_seconds=round(uptime, 2),
        telegram=telegram_status,
        disk=disk,
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

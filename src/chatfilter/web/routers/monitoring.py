"""Monitoring router for continuous chat analysis.

Provides API endpoints for:
- Enable/disable continuous monitoring for chats
- Trigger delta sync to fetch new messages
- View monitoring status and growth metrics
- Track activity trends over time
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Query, status
from pydantic import BaseModel

from chatfilter.service.monitoring import (
    MonitoringError,
    MonitoringService,
    MonitorNotFoundError,
    get_monitoring_service,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])


def _get_monitoring_service() -> MonitoringService:
    """Get monitoring service, initializing if needed."""
    from pathlib import Path

    from chatfilter.config import get_settings
    from chatfilter.web.dependencies import get_session_manager

    settings = get_settings()
    data_dir = Path(settings.data_dir) / "sessions"

    # Get or create session manager
    session_manager = get_session_manager()

    return get_monitoring_service(
        session_manager=session_manager,
        data_dir=data_dir,
    )


class MonitoringStatusResponse(BaseModel):
    """Response for monitoring status."""

    session_id: str
    chat_id: int
    is_enabled: bool
    is_monitoring: bool
    message_count: int
    unique_authors: int
    messages_per_hour: float
    history_hours: float
    last_sync_at: datetime | None
    sync_count: int


class SyncResultResponse(BaseModel):
    """Response for sync operation."""

    chat_id: int
    new_messages: int
    new_authors: int
    total_messages: int
    total_authors: int
    sync_duration_seconds: float | None


class GrowthMetricsResponse(BaseModel):
    """Response for growth metrics."""

    chat_id: int
    period_hours: float
    total_new_messages: int
    total_new_authors: int
    messages_per_hour: float
    author_growth_rate: float


class EnableMonitoringResponse(BaseModel):
    """Response for enable monitoring."""

    session_id: str
    chat_id: int
    message_count: int
    unique_authors: int
    messages_per_hour: float


class MonitorListItem(BaseModel):
    """Item in monitor list response."""

    chat_id: int
    is_enabled: bool
    message_count: int
    unique_authors: int
    last_sync_at: datetime | None


@router.post("/enable")
async def enable_monitoring(
    session_id: Annotated[str, Form(min_length=1)],
    chat_id: Annotated[int, Form(gt=0)],
    initial_message_limit: Annotated[int, Form(gt=0)] = 1000,
) -> EnableMonitoringResponse:
    """Enable continuous monitoring for a chat.

    Performs an initial sync to establish baseline metrics.

    Args:
        session_id: Telegram session identifier
        chat_id: Chat ID to monitor
        initial_message_limit: Max messages for initial sync (default: 1000)

    Returns:
        EnableMonitoringResponse with initial metrics
    """
    service = _get_monitoring_service()

    try:
        state = await service.enable_monitoring(
            session_id=session_id,
            chat_id=chat_id,
            initial_message_limit=initial_message_limit,
        )

        return EnableMonitoringResponse(
            session_id=session_id,
            chat_id=chat_id,
            message_count=state.message_count,
            unique_authors=state.unique_authors,
            messages_per_hour=state.messages_per_hour,
        )

    except MonitoringError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.exception(f"Failed to enable monitoring for chat {chat_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enable monitoring: {e}",
        ) from e


@router.post("/disable")
async def disable_monitoring(
    session_id: Annotated[str, Form(min_length=1)],
    chat_id: Annotated[int, Form(gt=0)],
    delete_data: Annotated[bool, Form()] = False,
) -> dict[str, bool]:
    """Disable monitoring for a chat.

    Args:
        session_id: Telegram session identifier
        chat_id: Chat ID to stop monitoring
        delete_data: If true, delete all monitoring data

    Returns:
        Success status
    """
    service = _get_monitoring_service()

    try:
        success = await service.disable_monitoring(
            session_id=session_id,
            chat_id=chat_id,
            delete_data=delete_data,
        )

        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Chat {chat_id} is not being monitored",
            )

        return {"success": True, "deleted_data": delete_data}

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to disable monitoring for chat {chat_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to disable monitoring: {e}",
        ) from e


@router.post("/sync")
async def sync_chat(
    session_id: Annotated[str, Form(min_length=1)],
    chat_id: Annotated[int, Form(gt=0)],
    max_messages: Annotated[int | None, Form(gt=0)] = None,
) -> SyncResultResponse:
    """Trigger delta sync for a monitored chat.

    Fetches only new messages since the last sync.

    Args:
        session_id: Telegram session identifier
        chat_id: Chat ID to sync
        max_messages: Maximum new messages to fetch (uses settings.max_messages_limit if not provided)

    Returns:
        SyncResultResponse with sync results
    """
    from chatfilter.config import get_settings

    settings = get_settings()
    effective_max = max_messages if max_messages is not None else settings.max_messages_limit
    service = _get_monitoring_service()

    try:
        snapshot = await service.sync_chat(
            session_id=session_id,
            chat_id=chat_id,
            max_messages=effective_max,
        )

        return SyncResultResponse(
            chat_id=chat_id,
            new_messages=snapshot.new_messages,
            new_authors=snapshot.new_authors,
            total_messages=snapshot.message_count,
            total_authors=snapshot.unique_authors,
            sync_duration_seconds=snapshot.sync_duration_seconds,
        )

    except MonitorNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        ) from e
    except MonitoringError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        ) from e
    except Exception as e:
        logger.exception(f"Failed to sync chat {chat_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync chat: {e}",
        ) from e


@router.post("/sync-all")
async def sync_all_monitors(
    session_id: Annotated[str, Form(min_length=1)],
    max_messages_per_chat: Annotated[int | None, Form(gt=0)] = None,
) -> list[SyncResultResponse]:
    """Sync all enabled monitors for a session.

    Args:
        session_id: Telegram session identifier
        max_messages_per_chat: Max new messages per chat (uses settings.max_messages_limit if not provided)

    Returns:
        List of SyncResultResponse for each synced chat
    """
    from chatfilter.config import get_settings

    settings = get_settings()
    effective_max = (
        max_messages_per_chat if max_messages_per_chat is not None else settings.max_messages_limit
    )
    service = _get_monitoring_service()

    try:
        snapshots = await service.sync_all_enabled(
            session_id=session_id,
            max_messages_per_chat=effective_max,
        )

        return [
            SyncResultResponse(
                chat_id=s.chat_id,
                new_messages=s.new_messages,
                new_authors=s.new_authors,
                total_messages=s.message_count,
                total_authors=s.unique_authors,
                sync_duration_seconds=s.sync_duration_seconds,
            )
            for s in snapshots
        ]

    except Exception as e:
        logger.exception(f"Failed to sync all monitors for session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to sync monitors: {e}",
        ) from e


@router.get("/status")
async def get_monitoring_status(
    session_id: Annotated[str, Query(min_length=1)],
    chat_id: Annotated[int, Query(ge=1)],
) -> MonitoringStatusResponse:
    """Get monitoring status for a chat.

    Args:
        session_id: Telegram session identifier
        chat_id: Chat ID

    Returns:
        MonitoringStatusResponse with current status

    Raises:
        HTTPException: 500 if database operation fails
    """
    try:
        service = _get_monitoring_service()

        state = service.get_monitor_state(session_id, chat_id)

        if state is None:
            # Return status indicating not monitored
            return MonitoringStatusResponse(
                session_id=session_id,
                chat_id=chat_id,
                is_enabled=False,
                is_monitoring=False,
                message_count=0,
                unique_authors=0,
                messages_per_hour=0.0,
                history_hours=0.0,
                last_sync_at=None,
                sync_count=0,
            )

        from pathlib import Path

        from chatfilter.config import get_settings
        from chatfilter.storage.database import MonitoringDatabase

        settings = get_settings()
        data_dir = Path(settings.data_dir) / "sessions"
        db = MonitoringDatabase(data_dir / "monitoring.db")
        sync_count = db.count_snapshots(session_id, chat_id)

        return MonitoringStatusResponse(
            session_id=session_id,
            chat_id=chat_id,
            is_enabled=state.is_enabled,
            is_monitoring=True,
            message_count=state.message_count,
            unique_authors=state.unique_authors,
            messages_per_hour=state.messages_per_hour,
            history_hours=state.history_hours,
            last_sync_at=state.last_sync_at,
            sync_count=sync_count,
        )
    except Exception as e:
        logger.exception(f"Failed to get monitoring status for chat {chat_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get monitoring status: {e}",
        ) from e


@router.get("/list")
async def list_monitors(
    session_id: Annotated[str, Query(min_length=1)],
    enabled_only: Annotated[bool, Query()] = False,
) -> list[MonitorListItem]:
    """List all monitored chats for a session.

    Args:
        session_id: Telegram session identifier
        enabled_only: If true, only return enabled monitors

    Returns:
        List of MonitorListItem

    Raises:
        HTTPException: 500 if operation fails
    """
    try:
        service = _get_monitoring_service()

        monitors = service.list_monitors(session_id, enabled_only=enabled_only)

        return [
            MonitorListItem(
                chat_id=m.chat_id,
                is_enabled=m.is_enabled,
                message_count=m.message_count,
                unique_authors=m.unique_authors,
                last_sync_at=m.last_sync_at,
            )
            for m in monitors
        ]
    except Exception as e:
        logger.exception(f"Failed to list monitors for session {session_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list monitors: {e}",
        ) from e


@router.get("/growth")
async def get_growth_metrics(
    session_id: Annotated[str, Query(min_length=1)],
    chat_id: Annotated[int, Query(ge=1)],
    hours: Annotated[float, Query(gt=0)] = 24.0,
) -> GrowthMetricsResponse:
    """Get growth metrics for a chat over a time period.

    Args:
        session_id: Telegram session identifier
        chat_id: Chat ID
        hours: Number of hours to analyze (default: 24)

    Returns:
        GrowthMetricsResponse with growth metrics

    Raises:
        HTTPException: 404 if no growth data available, 500 if operation fails
    """
    try:
        service = _get_monitoring_service()

        growth = service.get_growth_metrics(session_id, chat_id, hours=hours)

        if growth is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No growth data available for chat {chat_id}",
            )

        return GrowthMetricsResponse(
            chat_id=growth.chat_id,
            period_hours=growth.period_hours,
            total_new_messages=growth.total_new_messages,
            total_new_authors=growth.total_new_authors,
            messages_per_hour=growth.messages_per_hour,
            author_growth_rate=growth.author_growth_rate,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to get growth metrics for chat {chat_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get growth metrics: {e}",
        ) from e


class SnapshotResponse(BaseModel):
    """Response for a sync snapshot."""

    sync_at: datetime
    message_count: int
    unique_authors: int
    new_messages: int
    new_authors: int
    sync_duration_seconds: float | None


@router.get("/snapshots")
async def get_snapshots(
    session_id: Annotated[str, Query(min_length=1)],
    chat_id: Annotated[int, Query(ge=1)],
    limit: Annotated[int, Query(ge=1, le=1000)] = 100,
) -> list[SnapshotResponse]:
    """Get sync snapshots for a chat.

    Args:
        session_id: Telegram session identifier
        chat_id: Chat ID
        limit: Maximum number of snapshots to return (default: 100)

    Returns:
        List of SnapshotResponse (newest first)

    Raises:
        HTTPException: 500 if operation fails
    """
    try:
        service = _get_monitoring_service()

        snapshots = service.get_snapshots(session_id, chat_id, limit=limit)

        return [
            SnapshotResponse(
                sync_at=s.sync_at,
                message_count=s.message_count,
                unique_authors=s.unique_authors,
                new_messages=s.new_messages,
                new_authors=s.new_authors,
                sync_duration_seconds=s.sync_duration_seconds,
            )
            for s in snapshots
        ]
    except Exception as e:
        logger.exception(f"Failed to get snapshots for chat {chat_id}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get snapshots: {e}",
        ) from e

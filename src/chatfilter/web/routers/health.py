"""Health check endpoint router."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    version: str


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Health check endpoint for monitoring.

    Returns:
        HealthResponse with status and version info
    """
    from chatfilter import __version__

    return HealthResponse(status="healthy", version=__version__)

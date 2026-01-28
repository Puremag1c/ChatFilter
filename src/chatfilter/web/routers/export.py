"""Export endpoints for downloading analysis results and diagnostics."""

from __future__ import annotations

import math
import secrets
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated

from fastapi import APIRouter, Body, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator, model_validator

from chatfilter.exporter import export_to_csv
from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType


class DiagnosticsFormat(str, Enum):
    """Supported formats for diagnostics export."""

    TEXT = "text"
    JSON = "json"


router = APIRouter(prefix="/api/export", tags=["export"])


def _generate_unique_filename(base_filename: str) -> str:
    """Generate a unique filename with timestamp and random suffix.

    Prevents concurrent download conflicts by ensuring each request
    gets a unique filename, even if requests are made simultaneously.

    Args:
        base_filename: Base name for the file (e.g., "results.csv")

    Returns:
        Unique filename with timestamp and random suffix
        (e.g., "results_20260120_143052_a3f2.csv")

    Example:
        >>> _generate_unique_filename("results.csv")
        'results_20260120_143052_a3f2.csv'
    """
    # Split filename and extension
    if "." in base_filename:
        name, ext = base_filename.rsplit(".", 1)
    else:
        name, ext = base_filename, "csv"

    # Generate timestamp
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")

    # Generate short random suffix (4 chars)
    suffix = secrets.token_hex(2)

    return f"{name}_{timestamp}_{suffix}.{ext}"


class AnalysisResultInput(BaseModel):
    """Input model for analysis result in API requests."""

    chat_id: int = Field(gt=0)
    chat_title: str
    chat_type: ChatType
    chat_username: str | None = None
    message_count: int = Field(ge=0)
    unique_authors: int = Field(ge=0)
    history_hours: float = Field(ge=0)
    first_message_at: datetime | None = None
    last_message_at: datetime | None = None
    analyzed_at: datetime | None = None

    @field_validator("history_hours")
    @classmethod
    def validate_history_hours(cls, v: float) -> float:
        """Validate that history_hours is not NaN or Inf."""
        if math.isnan(v):
            raise ValueError("history_hours cannot be NaN")
        if math.isinf(v):
            raise ValueError("history_hours cannot be infinite")
        return v

    @model_validator(mode="after")
    def validate_consistency(self) -> AnalysisResultInput:
        """Validate logical consistency of input data.

        Checks:
        - unique_authors cannot exceed message_count
        - Non-empty chats must have at least one author
        - first_message_at must be before or equal to last_message_at
        - Dates cannot be in the future
        - analyzed_at should be after last_message_at
        """
        # unique_authors cannot exceed message_count
        if self.unique_authors > self.message_count:
            raise ValueError(
                f"unique_authors ({self.unique_authors}) cannot exceed "
                f"message_count ({self.message_count})"
            )

        # Non-empty chats must have at least one author
        if self.message_count > 0 and self.unique_authors == 0:
            raise ValueError("message_count > 0 requires at least one unique_author")

        # Validate date ordering
        if (
            self.first_message_at is not None
            and self.last_message_at is not None
            and self.first_message_at > self.last_message_at
        ):
            raise ValueError("first_message_at cannot be after last_message_at")

        # Dates cannot be in the future
        now = datetime.now(UTC)
        if self.first_message_at is not None and self.first_message_at > now:
            raise ValueError("first_message_at cannot be in the future")
        if self.last_message_at is not None and self.last_message_at > now:
            raise ValueError("last_message_at cannot be in the future")

        # analyzed_at validation
        if self.analyzed_at is not None:
            # Cannot be significantly in the future (allow 1 minute for clock skew)
            if self.analyzed_at > now + timedelta(minutes=1):
                raise ValueError("analyzed_at cannot be in the future")

            # Should be after last message (with tolerance)
            if (
                self.last_message_at is not None
                and self.analyzed_at < self.last_message_at - timedelta(minutes=5)
            ):
                raise ValueError("analyzed_at cannot be before last_message_at")

        return self

    def to_analysis_result(self) -> AnalysisResult:
        """Convert to internal AnalysisResult model."""
        return AnalysisResult(
            chat=Chat(
                id=self.chat_id,
                title=self.chat_title,
                chat_type=self.chat_type,
                username=self.chat_username,
            ),
            metrics=ChatMetrics(
                message_count=self.message_count,
                unique_authors=self.unique_authors,
                history_hours=self.history_hours,
                first_message_at=self.first_message_at,
                last_message_at=self.last_message_at,
            ),
            analyzed_at=self.analyzed_at or datetime.now(UTC),
        )


class ExportRequest(BaseModel):
    """Request body for CSV export."""

    results: list[AnalysisResultInput]


@router.post("/csv")
async def export_csv(
    request: Annotated[ExportRequest, Body()],
    filename: Annotated[str, Query()] = "chatfilter_results.csv",
    include_bom: Annotated[bool, Query()] = True,
) -> Response:
    """Export analysis results to CSV format.

    Accepts analysis results in the request body and returns
    a downloadable CSV file with a unique filename to prevent
    concurrent download conflicts.

    Args:
        request: Analysis results to export
        filename: Base name for the downloaded file (will have timestamp added)
        include_bom: Include UTF-8 BOM for Excel compatibility

    Returns:
        CSV file with Content-Disposition: attachment header
        and unique filename with timestamp

    Raises:
        HTTPException: If there's insufficient disk space or other errors
    """

    # Convert input models to internal models
    results = [r.to_analysis_result() for r in request.results]

    try:
        # Generate CSV content (in-memory, no disk space check needed here)
        csv_content = export_to_csv(results, include_bom=include_bom)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate CSV: {e}",
        ) from e

    # Generate unique filename to prevent concurrent request conflicts
    unique_filename = _generate_unique_filename(filename)

    # Return as downloadable file
    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{unique_filename}"',
        },
    )


@router.get("/diagnostics")
async def export_diagnostics(
    request: Request,
    format: Annotated[DiagnosticsFormat, Query()] = DiagnosticsFormat.TEXT,
) -> Response:
    """Export diagnostic information for troubleshooting and support.

    Collects system information, configuration, logs, and disk space
    in a single file for easy sharing with support.

    Args:
        request: FastAPI request object (for accessing app settings)
        format: Export format - "text" (human-readable) or "json" (default: text)

    Returns:
        Downloadable file containing diagnostic information

    Example:
        GET /api/export/diagnostics?format=text
        GET /api/export/diagnostics?format=json
    """
    from chatfilter.diagnostics import export_diagnostics_to_json, export_diagnostics_to_text

    settings = request.app.state.settings

    if format == DiagnosticsFormat.JSON:
        content = export_diagnostics_to_json(settings)
        media_type = "application/json; charset=utf-8"
        extension = "json"
    else:
        content = export_diagnostics_to_text(settings)
        media_type = "text/plain; charset=utf-8"
        extension = "txt"

    # Generate unique filename
    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    filename = f"chatfilter_diagnostics_{timestamp}.{extension}"

    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )

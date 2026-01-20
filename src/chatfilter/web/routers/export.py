"""Export endpoints for downloading analysis results."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Body, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field

from chatfilter.exporter import export_to_csv
from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType

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
    """
    # Convert input models to internal models
    results = [r.to_analysis_result() for r in request.results]

    # Generate CSV content
    csv_content = export_to_csv(results, include_bom=include_bom)

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

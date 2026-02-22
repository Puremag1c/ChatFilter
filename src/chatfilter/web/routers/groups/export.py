"""Export functionality for groups router.

This module handles CSV export with filtering and dynamic columns.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime
from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

from chatfilter.exporter.csv import export_group_results_to_csv

from .helpers import (
    _get_group_service,
    parse_optional_float,
    parse_optional_int,
)

router = APIRouter()


def _convert_results_for_exporter(results: list[dict]) -> list[dict]:
    """Convert flat results structure to exporter-compatible format.

    Converts service.get_results() flat structure to old nested structure
    expected by to_csv_rows_dynamic.

    Args:
        results: List of flat result dicts from service.get_results()

    Returns:
        List of dicts with metrics_data nested structure
    """
    converted = []
    for result in results:
        # Extract all fields into metrics_data dict
        metrics_data = {
            "title": result.get("title", ""),
            "chat_type": result.get("chat_type"),
            "subscribers": result.get("subscribers"),
            "messages_per_hour": result.get("messages_per_hour"),
            "unique_authors_per_hour": result.get("unique_authors_per_hour"),
            "moderation": result.get("moderation"),
            "captcha": result.get("captcha"),
            "status": result.get("status"),
        }
        converted.append({
            "chat_ref": result["chat_ref"],
            "metrics_data": metrics_data,
        })
    return converted


def _apply_export_filters(
    results_data: list[dict],
    *,
    chat_types: str | None = None,
    subscribers_min: int | None = None,
    subscribers_max: int | None = None,
    activity_min: float | None = None,
    activity_max: float | None = None,
    authors_min: float | None = None,
    authors_max: float | None = None,
    moderation: str = "all",
    captcha: str = "all",
) -> list[dict]:
    """Apply export filters to results data.

    Accepts results from service.get_results() which has flat structure.
    """
    allowed_chat_types = None
    if chat_types:
        allowed_chat_types = set(t.strip() for t in chat_types.split(",") if t.strip())

    filtered = []

    for result in results_data:
        # New model: flat structure from service.get_results()
        if allowed_chat_types:
            if result.get("chat_type") not in allowed_chat_types:
                continue

        if subscribers_min is not None or subscribers_max is not None:
            subscribers = result.get("subscribers")
            # When min=0, include chats with NULL subscribers (treat as "no lower bound")
            # Only exclude NULL if min > 0 or max is set (requires actual value for comparison)
            if subscribers is None:
                if (subscribers_min is not None and subscribers_min > 0) or subscribers_max is not None:
                    continue
            else:
                if subscribers_min is not None and subscribers < subscribers_min:
                    continue
                if subscribers_max is not None and subscribers > subscribers_max:
                    continue

        if activity_min is not None or activity_max is not None:
            activity = result.get("messages_per_hour")
            if activity is None:
                continue
            if activity_min is not None and activity < activity_min:
                continue
            if activity_max is not None and activity > activity_max:
                continue

        if authors_min is not None or authors_max is not None:
            authors = result.get("unique_authors_per_hour")
            if authors is None:
                continue
            if authors_min is not None and authors < authors_min:
                continue
            if authors_max is not None and authors > authors_max:
                continue

        if moderation != "all":
            mod_value = result.get("moderation")
            # Handle both bool (True/False) and int (1/0) from SQLite
            # Use truthiness: 1/True are truthy, 0/False are falsy
            if moderation == "yes" and not mod_value:
                continue
            if moderation == "no" and mod_value:
                continue

        if captcha != "all":
            captcha_value = result.get("captcha")
            # Handle both bool (True/False) and int (1/0) from SQLite
            # Use truthiness: 1/True are truthy, 0/False are falsy
            if captcha == "yes" and not captcha_value:
                continue
            if captcha == "no" and captcha_value:
                continue

        filtered.append(result)

    return filtered


@router.get("/api/groups/{group_id}/export/preview", response_class=HTMLResponse)
async def preview_export_count(
    group_id: str,
    chat_types: list[str] | None = Query(None),
    subscribers_min: str | None = None,
    subscribers_max: str | None = None,
    activity_min: str | None = None,
    activity_max: str | None = None,
    authors_min: str | None = None,
    authors_max: str | None = None,
    moderation: str = "all",
    captcha: str = "all",
) -> HTMLResponse:
    """Preview export count with filters applied.

    Returns HTML fragment showing how many chats match the current filters.
    Used by HTMX to update preview count in export modal.

    Args:
        group_id: Group identifier
        chat_types: Comma-separated list of chat types to include
        subscribers_min: Minimum subscribers count (string from query param, empty = None)
        subscribers_max: Maximum subscribers count (string from query param, empty = None)
        activity_min: Minimum messages per hour (string from query param, empty = None)
        activity_max: Maximum messages per hour (string from query param, empty = None)
        authors_min: Minimum unique authors per hour (string from query param, empty = None)
        authors_max: Maximum unique authors per hour (string from query param, empty = None)
        moderation: Filter by moderation (all/yes/no)
        captcha: Filter by captcha (all/yes/no)

    Returns:
        HTML fragment with count: '<span>Подходит: X из Y чатов</span>'

    Raises:
        HTTPException: If group not found
    """
    # Parse query params: empty string → None
    parsed_subscribers_min = parse_optional_int(subscribers_min)
    parsed_subscribers_max = parse_optional_int(subscribers_max)
    parsed_activity_min = parse_optional_float(activity_min)
    parsed_activity_max = parse_optional_float(activity_max)
    parsed_authors_min = parse_optional_float(authors_min)
    parsed_authors_max = parse_optional_float(authors_max)

    # Verify group exists
    service = _get_group_service()
    group = service.get_group(group_id)

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Load results from service (reads from group_chats columns)
    results_data = service.get_results(group_id)
    total_count = len(results_data)

    # Convert chat_types list to comma-separated string
    chat_types_str = ",".join(chat_types) if chat_types else None

    # Apply filters
    filtered_results = _apply_export_filters(
        results_data,
        chat_types=chat_types_str,
        subscribers_min=parsed_subscribers_min,
        subscribers_max=parsed_subscribers_max,
        activity_min=parsed_activity_min,
        activity_max=parsed_activity_max,
        authors_min=parsed_authors_min,
        authors_max=parsed_authors_max,
        moderation=moderation,
        captcha=captcha,
    )

    matching_count = len(filtered_results)

    # Return HTML fragment for HTMX swap with data attribute
    return HTMLResponse(
        content=f'<span data-count="{matching_count}">Подходит: {matching_count} из {total_count} чатов</span>',
        status_code=200,
    )


@router.get("/api/groups/{group_id}/export")
async def export_group_results(
    group_id: str,
    chat_types: list[str] | None = Query(None),
    subscribers_min: str | None = None,
    subscribers_max: str | None = None,
    activity_min: str | None = None,
    activity_max: str | None = None,
    authors_min: str | None = None,
    authors_max: str | None = None,
    moderation: str = "all",
    captcha: str = "all",
) -> Response:
    """Export group analysis results as CSV with dynamic columns and filtering.

    Columns are determined by the group's settings - only selected
    metrics are included in the CSV output.

    Args:
        group_id: Group identifier
        chat_types: Comma-separated list of chat types to include
        subscribers_min: Minimum subscribers count (string from query param, empty = None)
        subscribers_max: Maximum subscribers count (string from query param, empty = None)
        activity_min: Minimum messages per hour (string from query param, empty = None)
        activity_max: Maximum messages per hour (string from query param, empty = None)
        authors_min: Minimum unique authors per hour (string from query param, empty = None)
        authors_max: Maximum unique authors per hour (string from query param, empty = None)
        moderation: Filter by moderation (all/yes/no)
        captcha: Filter by captcha (all/yes/no)

    Returns:
        CSV file with filtered analysis results

    Raises:
        HTTPException: If group not found or no results available
    """
    # Parse query params: empty string → None
    parsed_subscribers_min = parse_optional_int(subscribers_min)
    parsed_subscribers_max = parse_optional_int(subscribers_max)
    parsed_activity_min = parse_optional_float(activity_min)
    parsed_activity_max = parse_optional_float(activity_max)
    parsed_authors_min = parse_optional_float(authors_min)
    parsed_authors_max = parse_optional_float(authors_max)

    # Verify group exists and load settings
    service = _get_group_service()
    group = service.get_group(group_id)

    if not group:
        raise HTTPException(status_code=404, detail="Group not found")

    # Load results from service (reads from group_chats columns)
    results_data = service.get_results(group_id)

    # Convert chat_types list to comma-separated string
    chat_types_str = ",".join(chat_types) if chat_types else None

    # Apply filters
    filtered_results = _apply_export_filters(
        results_data,
        chat_types=chat_types_str,
        subscribers_min=parsed_subscribers_min,
        subscribers_max=parsed_subscribers_max,
        activity_min=parsed_activity_min,
        activity_max=parsed_activity_max,
        authors_min=parsed_authors_min,
        authors_max=parsed_authors_max,
        moderation=moderation,
        captcha=captcha,
    )

    # Always return CSV with headers, even if no results yet
    # This prevents browser from saving JSON error as a file
    # Convert flat results to exporter-compatible format (nested metrics_data)
    exporter_format = _convert_results_for_exporter(filtered_results or [])
    csv_content = export_group_results_to_csv(
        exporter_format,
        settings=group.settings,
        include_bom=True,
    )

    # Generate filename from group name
    # Sanitize group name for filename (security: prevent path traversal + header injection)
    sanitized_name = group.name if group.name else ""
    # Normalize unicode characters
    sanitized_name = unicodedata.normalize("NFKD", sanitized_name)
    # Strip path separators and parent dir sequences
    sanitized_name = sanitized_name.replace("/", "").replace("\\", "").replace("..", "")
    # Remove control characters (prevent HTTP Response Splitting)
    sanitized_name = re.sub(r"[\x00-\x1f\x7f]", "", sanitized_name)
    # Remove dangerous chars but PRESERVE non-ASCII (Cyrillic, etc.)
    sanitized_name = re.sub(r'[^\w\s-]', '', sanitized_name)
    # Replace spaces with underscores
    sanitized_name = sanitized_name.replace(" ", "_")
    # Limit length (filesystem limits)
    sanitized_name = sanitized_name[:255]

    # Fallback if empty after sanitization
    if not sanitized_name:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_name = f"sanitized_export_{timestamp}"

    # Create ASCII fallback for old browsers (transliterate or timestamp)
    ascii_fallback = sanitized_name.encode('ascii', 'ignore').decode('ascii')
    if not ascii_fallback:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ascii_fallback = f"export_{timestamp}"

    # RFC 5987 encoding: filename for old browsers, filename* for modern ones
    filename_ascii = f"{ascii_fallback}.csv"
    filename_utf8 = f"{sanitized_name}.csv"
    filename_encoded = quote(filename_utf8.encode('utf-8'))

    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{filename_ascii}"; filename*=UTF-8\'\'{filename_encoded}',
        },
    )

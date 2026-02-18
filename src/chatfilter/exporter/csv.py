"""CSV export for analysis results.

This module provides robust CSV export with proper handling of:
- Unicode characters including emoji (🎉), RTL text (العربية), and complex emoji sequences
- Zero-width characters (zero-width space, joiner, non-joiner)
- Special CSV characters (quotes, commas, newlines) with proper escaping
- UTF-8 BOM for Excel compatibility
- Disk space checking before writes to prevent "No space left on device" errors
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

from chatfilter.storage.helpers import atomic_write

if TYPE_CHECKING:
    from chatfilter.models import AnalysisResult
    from chatfilter.models.group import GroupSettings

# UTF-8 BOM for Excel compatibility
UTF8_BOM = "\ufeff"

# CSV column headers
CSV_HEADERS = [
    "chat_link",
    "chat_title",
    "chat_type",
    "slowmode_seconds",
    "message_count",
    "unique_authors",
    "history_hours",
    "messages_per_hour",
    "first_message_at",
    "last_message_at",
    "analyzed_at",
]


def _generate_chat_link(result: AnalysisResult) -> str:
    """Generate Telegram link for the chat.

    Args:
        result: Analysis result containing chat info

    Returns:
        Telegram link (t.me/username) or chat ID if no username
    """
    if result.chat.username:
        return f"https://t.me/{result.chat.username}"
    return f"tg://chat?id={result.chat.id}"


def _format_datetime(dt: object) -> str:
    """Format datetime for CSV export.

    Args:
        dt: datetime object or None

    Returns:
        ISO format string or empty string if None
    """
    if dt is None:
        return ""
    return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)


def to_csv_rows_dynamic(
    results_data: list[dict],
    settings: GroupSettings | None = None,
) -> Iterator[list[str]]:
    """Convert group analysis results to CSV rows with dynamic columns.

    Columns included:
    - Always: chat_ref, title, status
    - Conditional (based on settings):
      - chat_type (if detect_chat_type enabled)
      - subscribers (if detect_subscribers enabled)
      - messages_per_hour (if detect_activity enabled)
      - unique_authors_per_hour (if detect_unique_authors enabled)
      - moderation (if detect_moderation enabled)
      - captcha (if detect_captcha enabled)

    Args:
        results_data: List of result dicts from GroupDatabase.load_results()
            Each dict has: {chat_ref, metrics_data: {...}, analyzed_at}
        settings: Group settings to determine which columns to include.
            If None, includes all columns (backward compatibility).

    Yields:
        List of string values for each CSV row

    Example:
        ```python
        from chatfilter.exporter import to_csv_rows_dynamic
        from chatfilter.models.group import GroupSettings

        settings = GroupSettings(detect_chat_type=True, detect_subscribers=False)
        results = db.load_results(group_id)
        for row in to_csv_rows_dynamic(results, settings):
            print(",".join(row))
        ```
    """
    # Build dynamic headers
    headers = ["chat_ref", "title"]

    # Add conditional columns
    if settings is None or settings.detect_chat_type:
        headers.append("chat_type")
    if settings is None or settings.detect_subscribers:
        headers.append("subscribers")
    if settings is None or settings.detect_activity:
        headers.append("messages_per_hour")
    if settings is None or settings.detect_unique_authors:
        headers.append("unique_authors_per_hour")
    if settings is None or settings.detect_moderation:
        headers.append("moderation")
    if settings is None or settings.detect_captcha:
        headers.append("captcha")

    # Always include status last
    headers.append("status")

    # Yield header row
    yield headers

    # Yield data rows
    for result in results_data:
        metrics = result["metrics_data"]

        row = [
            result["chat_ref"],
            metrics.get("title", ""),
        ]

        # Add conditional data columns
        if settings is None or settings.detect_chat_type:
            row.append(metrics.get("chat_type", ""))
        if settings is None or settings.detect_subscribers:
            subscribers = metrics.get("subscribers")
            row.append(str(subscribers) if subscribers is not None else "")
        if settings is None or settings.detect_activity:
            messages_per_hour = metrics.get("messages_per_hour")
            if messages_per_hour is not None:
                # Handle special "N/A" value for chats with moderation
                if messages_per_hour == "N/A":
                    row.append("N/A")
                else:
                    # Safe type coercion: handle both float and string numeric values
                    try:
                        row.append(f"{float(messages_per_hour):.2f}")
                    except (ValueError, TypeError):
                        row.append(str(messages_per_hour))
            else:
                row.append("")
        if settings is None or settings.detect_unique_authors:
            unique_authors_per_hour = metrics.get("unique_authors_per_hour")
            if unique_authors_per_hour is not None:
                # Handle special "N/A" value for chats with moderation
                if unique_authors_per_hour == "N/A":
                    row.append("N/A")
                else:
                    # Safe type coercion: handle both float and string numeric values
                    try:
                        row.append(f"{float(unique_authors_per_hour):.2f}")
                    except (ValueError, TypeError):
                        row.append(str(unique_authors_per_hour))
            else:
                row.append("")
        if settings is None or settings.detect_moderation:
            moderation = metrics.get("moderation")
            row.append("yes" if moderation is True else "no" if moderation is False else "")
        if settings is None or settings.detect_captcha:
            captcha = metrics.get("captcha")
            row.append("yes" if captcha is True else "no" if captcha is False else "")

        # Always include status
        row.append(metrics.get("status", ""))

        yield row


def to_csv_rows(results: list[AnalysisResult]) -> Iterator[list[str]]:
    """Convert analysis results to CSV rows.

    Yields header row first, then data rows.

    Args:
        results: List of analysis results to convert

    Yields:
        List of string values for each CSV row

    Example:
        ```python
        from chatfilter.exporter import to_csv_rows

        for row in to_csv_rows(results):
            print(",".join(row))
        ```
    """
    # Yield header row
    yield CSV_HEADERS

    # Yield data rows
    for result in results:
        yield [
            _generate_chat_link(result),
            result.chat.title,
            result.chat.chat_type.value,
            str(result.chat.slowmode_seconds) if result.chat.slowmode_seconds else "",
            str(result.metrics.message_count),
            str(result.metrics.unique_authors),
            f"{result.metrics.history_hours:.2f}",
            f"{float(result.metrics.messages_per_hour):.2f}",
            _format_datetime(result.metrics.first_message_at),
            _format_datetime(result.metrics.last_message_at),
            _format_datetime(result.analyzed_at),
        ]


def export_group_results_to_csv(
    results_data: list[dict],
    settings: GroupSettings | None = None,
    output: Path | None = None,
    *,
    include_bom: bool = True,
) -> str:
    """Export group analysis results to CSV with dynamic columns.

    Columns are determined by GroupSettings - only selected metrics
    are included in the output.

    Args:
        results_data: List of result dicts from GroupDatabase.load_results()
        settings: Group settings to determine columns. If None, all columns included.
        output: Optional file path to write CSV to.
        include_bom: Whether to include UTF-8 BOM for Excel. Default True.

    Returns:
        CSV content as string

    Raises:
        DiskSpaceError: If insufficient disk space for writing

    Example:
        ```python
        from chatfilter.exporter import export_group_results_to_csv

        results = db.load_results(group_id)
        csv_content = export_group_results_to_csv(results, group.settings)
        ```
    """
    # Build CSV in memory
    buffer = io.StringIO()

    if include_bom:
        buffer.write(UTF8_BOM)

    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)

    for row in to_csv_rows_dynamic(results_data, settings):
        writer.writerow(row)

    content = buffer.getvalue()

    # Write to file if path provided
    if output is not None:
        # Check disk space before writing
        from chatfilter.utils.disk import ensure_space_available

        content_bytes = content.encode("utf-8")
        ensure_space_available(output, len(content_bytes))

        # Atomic write to prevent corruption on crash
        atomic_write(output, content)

    return content


def export_to_csv(
    results: list[AnalysisResult],
    output: Path | None = None,
    *,
    include_bom: bool = True,
) -> str:
    """Export analysis results to CSV format.

    Properly handles Unicode characters including emoji, RTL text,
    zero-width characters, and special CSV characters (quotes, commas,
    newlines). Output is UTF-8 encoded with optional BOM for Excel.

    Checks available disk space before writing to prevent
    "No space left on device" errors with clear error messages.

    Args:
        results: List of analysis results to export
        output: Optional file path to write CSV to.
            If None, returns CSV as string.
        include_bom: Whether to include UTF-8 BOM for Excel
            compatibility. Default True.

    Returns:
        CSV content as string (always returned, even when
        writing to file)

    Raises:
        DiskSpaceError: If insufficient disk space is available
            for writing the file

    Example:
        ```python
        from chatfilter.exporter import export_to_csv

        # Get CSV as string
        csv_content = export_to_csv(results)

        # Write to file
        export_to_csv(results, Path("results.csv"))
        ```
    """
    # Build CSV in memory
    buffer = io.StringIO()

    if include_bom:
        buffer.write(UTF8_BOM)

    writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)

    for row in to_csv_rows(results):
        writer.writerow(row)

    content = buffer.getvalue()

    # Write to file if path provided
    if output is not None:
        # Check disk space before writing
        from chatfilter.utils.disk import ensure_space_available

        content_bytes = content.encode("utf-8")
        ensure_space_available(output, len(content_bytes))

        # Atomic write to prevent corruption on crash
        atomic_write(output, content)

    return content

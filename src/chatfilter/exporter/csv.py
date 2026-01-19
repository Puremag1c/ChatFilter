"""CSV export for analysis results."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

if TYPE_CHECKING:
    from chatfilter.models import AnalysisResult

# UTF-8 BOM for Excel compatibility
UTF8_BOM = "\ufeff"

# CSV column headers
CSV_HEADERS = [
    "chat_link",
    "chat_title",
    "chat_type",
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
            str(result.metrics.message_count),
            str(result.metrics.unique_authors),
            f"{result.metrics.history_hours:.2f}",
            f"{result.metrics.messages_per_hour:.2f}",
            _format_datetime(result.metrics.first_message_at),
            _format_datetime(result.metrics.last_message_at),
            _format_datetime(result.analyzed_at),
        ]


def export_to_csv(
    results: list[AnalysisResult],
    output: Path | None = None,
    *,
    include_bom: bool = True,
) -> str:
    """Export analysis results to CSV format.

    Args:
        results: List of analysis results to export
        output: Optional file path to write CSV to.
            If None, returns CSV as string.
        include_bom: Whether to include UTF-8 BOM for Excel
            compatibility. Default True.

    Returns:
        CSV content as string (always returned, even when
        writing to file)

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
        output.write_text(content, encoding="utf-8")

    return content

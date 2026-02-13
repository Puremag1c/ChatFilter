"""Google Sheets fetching for chat lists."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

import httpx

from chatfilter.importer.parser import ChatListEntry, ParseError, parse_csv
from chatfilter.security.url_validator import URLValidationError, validate_url

# Regex patterns for Google Sheets URLs
SHEETS_URL_PATTERNS = [
    # Full URL: https://docs.google.com/spreadsheets/d/{id}/edit#gid={gid}
    re.compile(
        r"(?:https?://)?docs\.google\.com/spreadsheets/d/([a-zA-Z0-9_-]+)",
        re.IGNORECASE,
    ),
    # Short URL: https://docs.google.com/spreadsheets/d/{id}
    re.compile(
        r"(?:https?://)?docs\.google\.com/spreadsheets/d/([a-zA-Z0-9_-]+)",
        re.IGNORECASE,
    ),
]


class GoogleSheetsError(Exception):
    """Error during Google Sheets operations."""


def extract_sheet_id(url: str) -> str:
    """Extract the spreadsheet ID from a Google Sheets URL.

    Args:
        url: Google Sheets URL.

    Returns:
        Spreadsheet ID.

    Raises:
        GoogleSheetsError: If URL is not a valid Google Sheets URL.
    """
    for pattern in SHEETS_URL_PATTERNS:
        match = pattern.search(url)
        if match:
            return match.group(1)

    raise GoogleSheetsError(
        "Invalid Google Sheets URL. Expected format: "
        "https://docs.google.com/spreadsheets/d/{spreadsheet_id}/..."
    )


def extract_gid(url: str) -> str | None:
    """Extract the sheet GID from a Google Sheets URL.

    Args:
        url: Google Sheets URL.

    Returns:
        Sheet GID or None if not specified.
    """
    parsed = urlparse(url)

    # Check fragment (e.g., #gid=123)
    if parsed.fragment:
        fragment_params = parse_qs(parsed.fragment)
        if "gid" in fragment_params:
            return fragment_params["gid"][0]

    # Check query params
    if parsed.query:
        query_params = parse_qs(parsed.query)
        if "gid" in query_params:
            return query_params["gid"][0]

    return None


def build_csv_export_url(sheet_id: str, gid: str | None = None) -> str:
    """Build the CSV export URL for a Google Sheets spreadsheet.

    Args:
        sheet_id: The spreadsheet ID.
        gid: Optional sheet GID (defaults to first sheet).

    Returns:
        URL for CSV export.
    """
    base_url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export"
    params = "format=csv"
    if gid:
        params += f"&gid={gid}"
    return f"{base_url}?{params}"


async def fetch_google_sheet(
    url: str,
    timeout: float = 30.0,
    max_size_bytes: int = 10 * 1024 * 1024,  # 10MB default
) -> list[ChatListEntry]:
    """Fetch and parse a Google Sheets document.

    The spreadsheet must be publicly accessible (view permissions for anyone with link).

    Args:
        url: Google Sheets URL.
        timeout: Request timeout in seconds.
        max_size_bytes: Maximum response size in bytes (default: 10MB).

    Returns:
        List of parsed chat entries.

    Raises:
        GoogleSheetsError: If fetching or parsing fails.
    """
    # Validate URL security before processing
    try:
        validate_url(url)
    except URLValidationError as e:
        raise GoogleSheetsError(f"URL validation failed: {e}") from e

    try:
        sheet_id = extract_sheet_id(url)
    except GoogleSheetsError:
        raise

    gid = extract_gid(url)
    export_url = build_csv_export_url(sheet_id, gid)

    # Validate export URL as well (defense in depth)
    try:
        validate_url(export_url)
    except URLValidationError as e:
        raise GoogleSheetsError(f"Export URL validation failed: {e}") from e

    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
    ) as client:
        try:
            # Stream the response to enforce size limit
            async with client.stream("GET", export_url) as response:
                response.raise_for_status()

                # Check content type early
                content_type = response.headers.get("content-type", "")
                if "text/html" in content_type:
                    raise GoogleSheetsError(
                        "Received HTML instead of CSV. Make sure the spreadsheet is publicly accessible."
                    )

                # Read response in chunks while enforcing size limit
                accumulated_size = 0
                chunks: list[bytes] = []

                async for chunk in response.aiter_bytes():
                    accumulated_size += len(chunk)
                    if accumulated_size > max_size_bytes:
                        raise GoogleSheetsError(
                            f"Response too large (>{max_size_bytes / (1024 * 1024):.1f}MB). "
                            "Please reduce the spreadsheet size or use a smaller sheet."
                        )
                    chunks.append(chunk)

                # Combine chunks into final response
                content_bytes = b"".join(chunks)

        except httpx.TimeoutException as e:
            raise GoogleSheetsError(f"Request timed out: {e}") from e
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                raise GoogleSheetsError(
                    "Spreadsheet not found. Check the URL and ensure the sheet is publicly accessible."
                ) from e
            elif e.response.status_code == 403:
                raise GoogleSheetsError(
                    "Access denied. Make sure the spreadsheet is shared with 'Anyone with the link'."
                ) from e
            else:
                raise GoogleSheetsError(f"HTTP error: {e}") from e
        except httpx.RequestError as e:
            raise GoogleSheetsError(f"Request failed: {e}") from e

    try:
        content = content_bytes.decode("utf-8")
        return parse_csv(content)
    except ParseError as e:
        raise GoogleSheetsError(f"Failed to parse sheet data: {e}") from e


def is_google_sheets_url(url: str) -> bool:
    """Check if a URL is a Google Sheets URL.

    Args:
        url: URL to check.

    Returns:
        True if the URL is a Google Sheets URL.
    """
    return "docs.google.com/spreadsheets" in url.lower()

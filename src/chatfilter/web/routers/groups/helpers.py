"""Helper functions and utilities for groups router.

This module contains parsing functions, file validation, factories,
and constants used across the groups router.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx
from fastapi import Request, UploadFile

from chatfilter.analyzer.group_engine import GroupAnalysisEngine
from chatfilter.analyzer.progress import ProgressTracker
from chatfilter.security.url_validator import URLValidationError, validate_url
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

# Constants
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
READ_CHUNK_SIZE = 8192  # 8 KB chunks

ALLOWED_EXTENSIONS = {".csv", ".xlsx", ".xls", ".txt"}

ALLOWED_MIME_TYPES = {
    ".csv": {"text/csv", "text/plain", "application/csv"},
    ".xlsx": {
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/zip",  # XLSX is a ZIP archive
    },
    ".xls": {
        "application/vnd.ms-excel",
        "application/octet-stream",  # Legacy binary format
    },
    ".txt": {"text/plain"},
}

# Singletons
_group_engine: GroupAnalysisEngine | None = None
_progress_tracker: ProgressTracker | None = None


def parse_optional_int(value: str | None) -> int | None:
    """Convert query param to int, treating empty string as None.

    Args:
        value: Query parameter value (can be empty string from HTMX forms)

    Returns:
        Parsed integer or None if empty/None
    """
    if value is None or value == "":
        return None
    return int(value)


def parse_optional_float(value: str | None) -> float | None:
    """Convert query param to float, treating empty string as None.

    Args:
        value: Query parameter value (can be empty string from HTMX forms)

    Returns:
        Parsed float or None if empty/None
    """
    if value is None or value == "":
        return None
    return float(value)


def _detect_mime_type(content: bytes) -> str:
    """Detect MIME type from file content using magic bytes.

    Args:
        content: File content bytes

    Returns:
        Detected MIME type string
    """
    if not content:
        return "application/octet-stream"

    # Check for XLSX (ZIP archive with specific structure)
    if content[:2] == b"PK":
        # XLSX files are ZIP archives starting with PK
        return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    # Check for XLS (old binary format)
    if content[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "application/vnd.ms-excel"

    # Check if it's text (CSV or TXT)
    try:
        # Try to decode as UTF-8
        content[:1024].decode("utf-8")
        # Check if it looks like CSV (contains common delimiters)
        sample = content[:2048].decode("utf-8", errors="ignore")
        if any(delimiter in sample for delimiter in [",", ";", "\t"]):
            return "text/csv"
        return "text/plain"
    except (UnicodeDecodeError, AttributeError):
        pass

    return "application/octet-stream"


def _validate_file_type(file_ext: str, content: bytes) -> None:
    """Validate that file content matches the declared extension.

    Args:
        file_ext: File extension (e.g., '.csv', '.xlsx')
        content: File content bytes

    Raises:
        ValueError: If MIME type doesn't match extension
    """
    detected_mime = _detect_mime_type(content)
    allowed_mimes = ALLOWED_MIME_TYPES.get(file_ext, set())

    if detected_mime not in allowed_mimes:
        raise ValueError(
            f"File content type ({detected_mime}) does not match "
            f"extension ({file_ext}). Expected one of: {', '.join(allowed_mimes)}"
        )


async def read_upload_with_size_limit(
    upload_file: UploadFile, max_size: int, file_type: str = "file"
) -> bytes:
    """Read uploaded file with size limit enforcement.

    Reads file in chunks to prevent loading large files into memory.
    Raises ValueError if file exceeds size limit.

    Args:
        upload_file: FastAPI UploadFile object
        max_size: Maximum allowed file size in bytes
        file_type: Description of file type for error messages

    Returns:
        File content as bytes

    Raises:
        ValueError: If file exceeds size limit
    """
    content = bytearray()
    bytes_read = 0

    while True:
        chunk = await upload_file.read(READ_CHUNK_SIZE)
        if not chunk:
            break

        bytes_read += len(chunk)
        if bytes_read > max_size:
            raise ValueError(
                f"{file_type.capitalize()} size exceeds maximum allowed "
                f"size of {max_size / 1024 / 1024:.1f} MB"
            )

        content.extend(chunk)

    return bytes(content)


async def fetch_file_from_url(url: str, max_size: int, timeout: float = 30.0) -> bytes:
    """Fetch file from direct URL with security validation.

    Args:
        url: Direct file URL
        max_size: Maximum allowed file size in bytes
        timeout: Request timeout in seconds

    Returns:
        File content as bytes

    Raises:
        ValueError: If URL validation fails or file exceeds size limit
    """
    # Validate URL for security (SSRF prevention)
    try:
        validate_url(url)
    except URLValidationError as e:
        raise ValueError(f"URL validation failed: {e}") from e

    async with (
        httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client,
        client.stream("GET", url) as response,
    ):
        response.raise_for_status()

        # Stream response with size limit
        chunks = []
        total_size = 0

        async for chunk in response.iter_bytes():
            total_size += len(chunk)
            if total_size > max_size:
                raise ValueError(
                    f"File size exceeds maximum allowed size of {max_size / 1024 / 1024:.1f} MB"
                )
            chunks.append(chunk)

        return b"".join(chunks)


def _get_group_service(request: Request | None = None) -> GroupService:
    """Get or create GroupService instance.

    Args:
        request: Optional FastAPI request for engine initialization

    Returns:
        GroupService instance
    """
    from chatfilter.config import get_settings

    # Use settings from app state if available (for test isolation)
    # Otherwise fall back to global settings
    if request is not None and hasattr(request.app.state, "settings"):
        settings = request.app.state.settings
    else:
        settings = get_settings()

    db_path = settings.data_dir / "groups.db"
    settings.data_dir.mkdir(parents=True, exist_ok=True)

    db = GroupDatabase(db_path)

    # If request provided, wire up engine
    engine = None
    if request is not None:
        engine = _get_group_engine(request)

    return GroupService(db, engine=engine)


def _get_group_engine(request: Request) -> GroupAnalysisEngine:
    """Get or create GroupAnalysisEngine instance (singleton).

    Args:
        request: FastAPI request to access app state

    Returns:
        GroupAnalysisEngine instance

    Raises:
        RuntimeError: If required app state components are not initialized
    """
    global _group_engine

    if _group_engine is not None:
        return _group_engine

    # Get dependencies from app state
    session_manager = request.app.state.app_state.session_manager
    if session_manager is None:
        raise RuntimeError("SessionManager not initialized in app state")

    # Get GroupDatabase from service
    service = _get_group_service()
    db = service._db

    # Create and cache engine — inject shared ProgressTracker
    _group_engine = GroupAnalysisEngine(
        db=db,
        session_manager=session_manager,
        progress=_get_progress_tracker(),
    )

    return _group_engine


def _get_progress_tracker() -> ProgressTracker:
    """Get or create ProgressTracker instance (singleton).

    Returns:
        ProgressTracker instance
    """
    global _progress_tracker

    if _progress_tracker is not None:
        return _progress_tracker

    # Get GroupDatabase from service
    service = _get_group_service()
    db = service._db

    # Create and cache tracker
    _progress_tracker = ProgressTracker(db)

    return _progress_tracker

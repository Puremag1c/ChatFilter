"""Groups router module.

This module provides FastAPI routes for chat group operations.
Previously a single 1720-line file, now split into focused modules:

- helpers.py: parsing functions, file validation, factories, constants
- crud.py: CRUD operations (create, list, get, update, delete, settings)
- progress.py: SSE progress tracking
- export.py: CSV export with filtering
- analysis.py: start, stop, resume, reanalyze operations
- modals.py: modal rendering endpoints

All routes are re-exported through this module for backward compatibility.
"""

from __future__ import annotations

from fastapi import APIRouter

from . import analysis, crud, export, modals, progress

# Create main router
router = APIRouter()

# Include all sub-routers
router.include_router(progress.router, tags=["groups"])
router.include_router(crud.router, tags=["groups"])
router.include_router(export.router, tags=["groups"])
router.include_router(analysis.router, tags=["groups"])
router.include_router(modals.router, tags=["groups"])

# Re-export functions for backward compatibility with tests
from .helpers import (
    ALLOWED_EXTENSIONS,
    ALLOWED_MIME_TYPES,
    MAX_FILE_SIZE,
    READ_CHUNK_SIZE,
    _get_group_engine,
    _get_group_service,
    _get_progress_tracker,
    fetch_file_from_url,
    parse_optional_float,
    parse_optional_int,
    read_upload_with_size_limit,
)
from .export import (
    _apply_export_filters,
    _convert_results_for_exporter,
)
from .progress import (
    _generate_unified_sse_events,
    get_unified_group_events,
)
from .analysis import (
    start_group_analysis,
    stop_group_analysis,
    reanalyze_group,
    resume_group_analysis,
)

__all__ = [
    "router",
    "ALLOWED_EXTENSIONS",
    "ALLOWED_MIME_TYPES",
    "MAX_FILE_SIZE",
    "READ_CHUNK_SIZE",
    "_get_group_engine",
    "_get_group_service",
    "_get_progress_tracker",
    "fetch_file_from_url",
    "parse_optional_float",
    "parse_optional_int",
    "read_upload_with_size_limit",
    "_apply_export_filters",
    "_convert_results_for_exporter",
    "_generate_group_sse_events",
    "get_group_progress",
    "start_group_analysis",
    "stop_group_analysis",
    "reanalyze_group",
    "resume_group_analysis",
]

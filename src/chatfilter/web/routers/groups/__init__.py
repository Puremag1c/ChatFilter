"""FastAPI router for chat group operations.

This package splits the groups router into focused modules:
- crud: CRUD endpoints (create, list, get, update, delete, settings)
- progress: SSE progress streaming
- export: CSV export with filters
- analysis: start, stop, resume, reanalyze
- modals: modal HTML endpoints
- helpers: shared utilities, constants, factories
"""

from fastapi import APIRouter

from .analysis import router as analysis_router
from .analysis import reanalyze_group, resume_group_analysis, start_group_analysis, stop_group_analysis
from .crud import router as crud_router
from .crud import create_group, delete_group, get_group, list_groups, update_group, update_group_settings
from .export import _apply_export_filters, _convert_results_for_exporter
from .export import router as export_router
from .export import export_group_results, preview_export_count
from .helpers import (
    _get_group_engine,
    _get_group_service,
    _get_progress_tracker,
    _detect_mime_type,
    _validate_file_type,
    fetch_file_from_url,
    parse_optional_float,
    parse_optional_int,
    read_upload_with_size_limit,
    ALLOWED_EXTENSIONS,
    ALLOWED_MIME_TYPES,
    MAX_FILE_SIZE,
    READ_CHUNK_SIZE,
)
from .modals import router as modals_router
from .modals import get_create_group_modal, get_export_modal, get_reanalyze_confirm_modal, get_settings_modal
from .progress import _generate_group_sse_events, get_group_progress
from .progress import router as progress_router

# Combined router — includes all sub-module routes
router = APIRouter()
router.include_router(crud_router)
router.include_router(progress_router)
router.include_router(export_router)
router.include_router(analysis_router)
router.include_router(modals_router)

__all__ = [
    "router",
    # crud
    "create_group",
    "list_groups",
    "get_group",
    "update_group",
    "delete_group",
    "update_group_settings",
    # progress
    "get_group_progress",
    "_generate_group_sse_events",
    # export
    "export_group_results",
    "preview_export_count",
    "_apply_export_filters",
    "_convert_results_for_exporter",
    # analysis
    "start_group_analysis",
    "reanalyze_group",
    "stop_group_analysis",
    "resume_group_analysis",
    # modals
    "get_create_group_modal",
    "get_settings_modal",
    "get_reanalyze_confirm_modal",
    "get_export_modal",
    # helpers
    "_get_group_service",
    "_get_group_engine",
    "_get_progress_tracker",
    "parse_optional_int",
    "parse_optional_float",
    "_detect_mime_type",
    "_validate_file_type",
    "read_upload_with_size_limit",
    "fetch_file_from_url",
    "MAX_FILE_SIZE",
    "READ_CHUNK_SIZE",
    "ALLOWED_EXTENSIONS",
    "ALLOWED_MIME_TYPES",
]

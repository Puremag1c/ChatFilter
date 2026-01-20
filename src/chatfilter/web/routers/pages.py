"""Pages router for serving full HTML pages."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

from chatfilter.web.template_helpers import get_template_context

router = APIRouter(tags=["pages"])


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Home page - session upload."""
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    templates = get_templates()
    return templates.TemplateResponse(
        "upload.html",
        get_template_context(request, version=__version__),
    )


@router.get("/chats", response_class=HTMLResponse)
async def chats_page(request: Request) -> HTMLResponse:
    """Chats selection page."""
    from chatfilter import __version__
    from chatfilter.web.app import get_templates
    from chatfilter.web.routers.sessions import list_stored_sessions

    templates = get_templates()
    sessions = list_stored_sessions()

    return templates.TemplateResponse(
        "chats.html",
        get_template_context(request, version=__version__, sessions=sessions),
    )


@router.get("/chatlist", response_class=HTMLResponse)
async def chatlist_page(request: Request) -> HTMLResponse:
    """Chat list import page."""
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    templates = get_templates()

    return templates.TemplateResponse(
        "chatlist.html",
        get_template_context(request, version=__version__),
    )


@router.get("/proxy", response_class=HTMLResponse)
async def proxy_page(request: Request) -> HTMLResponse:
    """Proxy settings page."""
    from chatfilter import __version__
    from chatfilter.config import load_proxy_config
    from chatfilter.web.app import get_templates

    templates = get_templates()
    config = load_proxy_config()

    return templates.TemplateResponse(
        "proxy.html",
        get_template_context(request, version=__version__, config=config),
    )


@router.get("/results", response_class=HTMLResponse)
async def results_page(
    request: Request,
    task_id: str | None = None,
) -> HTMLResponse:
    """Analysis results page.

    Args:
        request: FastAPI request
        task_id: Optional task ID to load results from

    Returns:
        HTML page with results table
    """
    from uuid import UUID

    from chatfilter import __version__
    from chatfilter.analyzer.task_queue import TaskStatus, get_task_queue
    from chatfilter.web.app import get_templates

    templates = get_templates()
    results = []
    error = None

    if task_id:
        try:
            uuid_task_id = UUID(task_id)
            queue = get_task_queue()
            task = queue.get_task(uuid_task_id)

            if task is None:
                error = "Task not found"
            elif task.status == TaskStatus.IN_PROGRESS:
                error = "Analysis still in progress"
            elif task.status == TaskStatus.FAILED:
                error = task.error or "Analysis failed"
            else:
                results = task.results
        except ValueError:
            error = "Invalid task ID format"

    return templates.TemplateResponse(
        "results.html",
        get_template_context(
            request,
            version=__version__,
            results=results,
            error=error,
            task_id=task_id,
        ),
    )

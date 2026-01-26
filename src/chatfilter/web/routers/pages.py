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
    from chatfilter.storage.proxy_pool import load_proxy_pool
    from chatfilter.web.app import get_templates

    templates = get_templates()
    proxies = load_proxy_pool()

    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context=get_template_context(request, version=__version__, proxies=proxies),
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
        request=request,
        name="chats.html",
        context=get_template_context(request, version=__version__, sessions=sessions),
    )


@router.get("/chatlist", response_class=HTMLResponse)
async def chatlist_page(request: Request) -> HTMLResponse:
    """Chat list import page."""
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    templates = get_templates()

    return templates.TemplateResponse(
        request=request,
        name="chatlist.html",
        context=get_template_context(request, version=__version__),
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
        request=request,
        name="proxy.html",
        context=get_template_context(request, version=__version__, config=config),
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
    from chatfilter.web.session import get_session

    templates = get_templates()
    results = []
    error = None

    # Clear orphaned task notification if viewing results for that task
    if task_id:
        session = get_session(request)
        current_task_id = session.get("current_task_id")
        if current_task_id == task_id:
            session.delete("current_task_id")

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
        request=request,
        name="results.html",
        context=get_template_context(
            request,
            version=__version__,
            results=results,
            error=error,
            task_id=task_id,
        ),
    )


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request) -> HTMLResponse:
    """Analysis history page.

    Args:
        request: FastAPI request

    Returns:
        HTML page with historical analyses list
    """
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    templates = get_templates()

    return templates.TemplateResponse(
        request=request,
        name="history.html",
        context=get_template_context(request, version=__version__),
    )


@router.get("/proxies", response_class=HTMLResponse)
async def proxies_page(request: Request) -> HTMLResponse:
    """Proxy pool management page.

    Args:
        request: FastAPI request

    Returns:
        HTML page with proxy pool list and management form
    """
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    templates = get_templates()

    return templates.TemplateResponse(
        request=request,
        name="proxies.html",
        context=get_template_context(request, version=__version__),
    )

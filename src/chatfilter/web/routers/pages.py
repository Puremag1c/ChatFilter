"""Pages router for serving full HTML pages."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse

from chatfilter.utils.paths import get_base_path
from chatfilter.web.template_helpers import get_template_context

router = APIRouter(tags=["pages"])


@router.get("/favicon.ico", include_in_schema=False)
async def favicon() -> FileResponse:
    """Serve favicon from static images."""
    favicon_path = get_base_path() / "static" / "images" / "logo.ico"
    return FileResponse(favicon_path, media_type="image/x-icon")


@router.get("/", response_class=HTMLResponse)
@router.get("/sessions", response_class=HTMLResponse)
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

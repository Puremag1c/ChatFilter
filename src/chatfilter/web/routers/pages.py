"""Pages router for serving full HTML pages."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, HTMLResponse

from chatfilter.utils.paths import get_base_path
from chatfilter.web.dependencies import require_session_access
from chatfilter.web.template_helpers import get_template_context

router = APIRouter(tags=["pages"])


@router.get("/favicon.ico", include_in_schema=False)
async def favicon() -> FileResponse:
    """Serve favicon from static images."""
    favicon_path = get_base_path() / "static" / "images" / "logo.ico"
    return FileResponse(favicon_path, media_type="image/x-icon")


def _render_groups_page(request: Request) -> HTMLResponse:
    """Render the user's groups list — the new home page (Phase 2)."""
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


@router.get("/", response_class=HTMLResponse)
async def home(request: Request) -> HTMLResponse:
    """Home page: the user's groups list."""
    return _render_groups_page(request)


@router.get("/chats", response_class=HTMLResponse)
async def chats_page(request: Request) -> HTMLResponse:
    """Back-compat alias for the groups page — same content as `/`."""
    return _render_groups_page(request)


@router.get(
    "/sessions",
    response_class=HTMLResponse,
    dependencies=[Depends(require_session_access)],
)
async def sessions_page(request: Request) -> HTMLResponse:
    """Sessions management — admin only (Phase 2)."""
    from chatfilter import __version__
    from chatfilter.storage.proxy_pool import load_proxy_pool
    from chatfilter.web.app import get_templates
    from chatfilter.web.session import get_session

    templates = get_templates()
    user_id = get_session(request).get("user_id", "default")
    proxies = load_proxy_pool(user_id)
    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context=get_template_context(request, version=__version__, proxies=proxies),
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


@router.get(
    "/proxies",
    response_class=HTMLResponse,
    dependencies=[Depends(require_session_access)],
)
async def proxies_page(request: Request) -> HTMLResponse:
    """Proxy pool management — admin only (Phase 2)."""
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    templates = get_templates()

    return templates.TemplateResponse(
        request=request,
        name="proxies.html",
        context=get_template_context(request, version=__version__),
    )

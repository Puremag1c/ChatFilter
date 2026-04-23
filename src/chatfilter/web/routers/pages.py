"""Pages router for serving full HTML pages."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, HTMLResponse

from chatfilter.utils.paths import get_base_path
from chatfilter.web.dependencies import require_admin, require_own_accounts
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


def _render_sessions_page(request: Request) -> HTMLResponse:
    """Shared renderer for both personal /sessions and admin /admin/accounts."""
    from chatfilter import __version__
    from chatfilter.storage.proxy_pool import load_proxy_pool
    from chatfilter.web.app import get_templates
    from chatfilter.web.dependencies import get_pool_scope

    templates = get_templates()
    scope = get_pool_scope(request)
    proxies = load_proxy_pool(scope)
    return templates.TemplateResponse(
        request=request,
        name="upload.html",
        context=get_template_context(request, version=__version__, proxies=proxies),
    )


def _render_proxies_page(request: Request) -> HTMLResponse:
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="proxies.html",
        context=get_template_context(request, version=__version__),
    )


@router.get(
    "/sessions",
    response_class=HTMLResponse,
    dependencies=[Depends(require_own_accounts)],
)
async def sessions_page(request: Request) -> HTMLResponse:
    """Personal sessions — only power-users with use_own_accounts=True."""
    return _render_sessions_page(request)


@router.get(
    "/proxies",
    response_class=HTMLResponse,
    dependencies=[Depends(require_own_accounts)],
)
async def proxies_page(request: Request) -> HTMLResponse:
    """Personal proxies — only power-users with use_own_accounts=True."""
    return _render_proxies_page(request)


@router.get(
    "/admin/accounts",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin)],
)
async def admin_accounts_page(request: Request) -> HTMLResponse:
    """Shared admin pool of Telegram accounts — admins only.

    Backed by the same template as the personal /sessions page; the
    URL prefix drives get_pool_scope to "admin" so this page reads and
    writes the shared account pool instead of a personal one.
    """
    return _render_sessions_page(request)


@router.get(
    "/admin/proxies",
    response_class=HTMLResponse,
    dependencies=[Depends(require_admin)],
)
async def admin_proxies_page(request: Request) -> HTMLResponse:
    """Shared admin pool of proxies — admins only."""
    return _render_proxies_page(request)


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

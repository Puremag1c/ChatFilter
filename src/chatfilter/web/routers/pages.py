"""Pages router for serving full HTML pages."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["pages"])


@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Home page - session upload."""
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    templates = get_templates()
    return templates.TemplateResponse(
        "upload.html",
        {"request": request, "version": __version__},
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
        {"request": request, "version": __version__, "sessions": sessions},
    )


@router.get("/results", response_class=HTMLResponse)
async def results_page(request: Request) -> HTMLResponse:
    """Analysis results page (placeholder)."""
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    templates = get_templates()
    # TODO: Implement results page template
    return templates.TemplateResponse(
        "base.html",
        {"request": request, "version": __version__},
    )

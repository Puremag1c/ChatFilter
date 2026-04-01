"""Catalog router: public chat catalog with filters."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from pydantic import BeforeValidator

from chatfilter.web.session import get_session

if TYPE_CHECKING:
    from chatfilter.storage.group_database import GroupDatabase


def _empty_str_to_none(v: object) -> object:
    """Convert empty string to None for optional query params."""
    if v == "":
        return None
    return v


OptionalInt = Annotated[int | None, BeforeValidator(_empty_str_to_none)]
OptionalFloat = Annotated[float | None, BeforeValidator(_empty_str_to_none)]

logger = logging.getLogger(__name__)

router = APIRouter(tags=["catalog"])


def _get_catalog_db() -> GroupDatabase:
    """Get GroupDatabase instance (includes CatalogMixin)."""
    from chatfilter.web.dependencies import get_group_engine

    engine = get_group_engine()
    return engine.db


@router.get("/catalog", response_class=HTMLResponse)
async def catalog_page(request: Request) -> Response:
    """Catalog page — requires login."""
    from chatfilter import __version__
    from chatfilter.web.app import get_templates
    from chatfilter.web.template_helpers import get_template_context

    session = get_session(request)
    if not session.get("user_id"):
        return RedirectResponse(url="/login", status_code=302)

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="catalog.html",
        context=get_template_context(request, version=__version__),
    )


_DEFAULT_PAGE_SIZE = 100


@router.get("/api/catalog", response_class=HTMLResponse)
async def catalog_table(
    request: Request,
    chat_type: str | None = None,
    min_subscribers: OptionalInt = None,
    max_subscribers: OptionalInt = None,
    has_moderation: str | None = None,
    has_captcha: str | None = None,
    min_activity: OptionalFloat = None,
    max_activity: OptionalFloat = None,
    fresh_only: OptionalInt = None,
    search: str | None = None,
    sort_by: str | None = None,
    sort_dir: str | None = None,
    page: OptionalInt = None,
) -> Response:
    """HTMX partial: filtered/sorted/paginated catalog table."""
    from chatfilter.web.app import get_templates
    from chatfilter.web.template_helpers import get_template_context

    session = get_session(request)
    if not session.get("user_id"):
        return RedirectResponse(url="/login", status_code=302)

    templates = get_templates()

    filters: dict[str, Any] = {}
    if chat_type:
        filters["chat_type"] = chat_type
    if min_subscribers is not None:
        filters["min_subscribers"] = min_subscribers
    if max_subscribers is not None:
        filters["max_subscribers"] = max_subscribers
    if has_moderation is not None and has_moderation != "":
        filters["has_moderation"] = has_moderation.lower() in ("1", "true", "yes")
    if has_captcha is not None and has_captcha != "":
        filters["has_captcha"] = has_captcha.lower() in ("1", "true", "yes")
    if min_activity is not None:
        filters["min_activity"] = min_activity
    if max_activity is not None:
        filters["max_activity"] = max_activity
    if fresh_only is not None:
        filters["fresh_only"] = fresh_only
    if search:
        filters["search"] = search
    if sort_by:
        filters["sort_by"] = sort_by
    if sort_dir:
        filters["sort_dir"] = sort_dir

    current_page = max(1, page or 1)

    try:
        db = _get_catalog_db()
        page_size_str = db.get_setting("catalog_page_size")
        page_size = int(page_size_str) if page_size_str else _DEFAULT_PAGE_SIZE
        chats, total_count = db.list_catalog_chats(filters, page=current_page, page_size=page_size)
    except Exception:
        logger.exception("Failed to fetch catalog chats")
        chats = []
        total_count = 0
        page_size = _DEFAULT_PAGE_SIZE

    total_pages = max(1, (total_count + page_size - 1) // page_size)

    return templates.TemplateResponse(
        request=request,
        name="partials/catalog_table.html",
        context=get_template_context(
            request,
            chats=chats,
            total_count=total_count,
            page=current_page,
            page_size=page_size,
            total_pages=total_pages,
        ),
    )

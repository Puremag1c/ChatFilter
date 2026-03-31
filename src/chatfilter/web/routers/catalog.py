"""Catalog router: public chat catalog with filters."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse

if TYPE_CHECKING:
    from chatfilter.db.group_database import GroupDatabase

logger = logging.getLogger(__name__)

router = APIRouter(tags=["catalog"])


def _get_catalog_db() -> GroupDatabase:
    """Get GroupDatabase instance (includes CatalogMixin)."""
    from chatfilter.web.dependencies import get_group_engine

    engine = get_group_engine()
    return engine._db


@router.get("/catalog", response_class=HTMLResponse)
async def catalog_page(request: Request) -> HTMLResponse:
    """Catalog page — requires login."""
    from chatfilter import __version__
    from chatfilter.web.app import get_templates
    from chatfilter.web.template_helpers import get_template_context

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="catalog.html",
        context=get_template_context(request, version=__version__),
    )


@router.get("/api/catalog", response_class=HTMLResponse)
async def catalog_table(
    request: Request,
    chat_type: str | None = None,
    min_subscribers: int | None = None,
    max_subscribers: int | None = None,
    has_moderation: str | None = None,
    has_captcha: str | None = None,
    min_activity: float | None = None,
    max_activity: float | None = None,
    fresh_only: int | None = None,
    search: str | None = None,
    sort_by: str | None = None,
    sort_dir: str | None = None,
) -> HTMLResponse:
    """HTMX partial: filtered/sorted catalog table."""
    from chatfilter.web.app import get_templates
    from chatfilter.web.template_helpers import get_template_context

    templates = get_templates()

    filters: dict[str, Any] = {}
    if chat_type:
        filters["chat_type"] = chat_type
    if min_subscribers is not None:
        filters["min_subscribers"] = min_subscribers
    if max_subscribers is not None:
        filters["max_subscribers"] = max_subscribers
    if has_moderation is not None:
        filters["has_moderation"] = has_moderation.lower() in ("1", "true", "yes")
    if has_captcha is not None:
        filters["has_captcha"] = has_captcha.lower() in ("1", "true", "yes")
    if min_activity is not None:
        filters["min_activity"] = min_activity
    if max_activity is not None:
        filters["max_activity"] = max_activity
    if fresh_only is not None:
        filters["fresh_only"] = fresh_only

    try:
        db = _get_catalog_db()
        chats = db.list_catalog_chats(filters)
    except Exception:
        logger.exception("Failed to fetch catalog chats")
        chats = []

    # Client-side search by title substring
    if search:
        search_lower = search.lower()
        chats = [c for c in chats if search_lower in c.title.lower() or search_lower in c.id.lower()]

    # Sorting
    valid_sort_fields = {
        "title": lambda c: c.title.lower(),
        "subscribers": lambda c: c.subscribers,
        "activity": lambda c: c.messages_per_hour,
        "authors": lambda c: c.unique_authors_per_hour,
        "last_check": lambda c: c.last_check or "",
    }
    if sort_by and sort_by in valid_sort_fields:
        reverse = sort_dir == "desc"
        chats = sorted(chats, key=valid_sort_fields[sort_by], reverse=reverse)

    return templates.TemplateResponse(
        request=request,
        name="partials/catalog_table.html",
        context=get_template_context(request, chats=chats),
    )

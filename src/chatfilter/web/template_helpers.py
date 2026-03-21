"""Template helper functions for rendering."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from chatfilter.web.csrf import get_csrf_token
from chatfilter.web.session import get_session

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from starlette.requests import Request


def _safe_get_js_translations(locale: str) -> dict:
    """Return JS translations dict, falling back to {} on any error."""
    from chatfilter.i18n.js_translations import get_js_translations

    try:
        return get_js_translations(locale)
    except Exception:
        logger.exception("Failed to load JS translations for locale %r; falling back to {}", locale)
        return {}


def get_template_context(request: Request, **kwargs: Any) -> dict[str, Any]:
    """Get template context with CSRF token, i18n support, and other common data.

    This helper ensures CSRF tokens and i18n functions are available in all templates.

    Args:
        request: FastAPI request object
        **kwargs: Additional context variables

    Returns:
        Context dictionary with request, csrf_token, locale, and any provided kwargs
    """
    from chatfilter.i18n.translations import get_current_locale, get_translations

    session = get_session(request)
    csrf_token = get_csrf_token(session)

    # Get current locale for this request
    locale = get_current_locale()
    translations = get_translations(locale)

    # Create translation function for this request's locale
    def _(message: str) -> str:
        return translations.gettext(message)

    # Get CSS version from app state (computed at startup for cache-busting)
    css_version = getattr(request.app.state, "app_state", None)
    if css_version and hasattr(css_version, "css_version"):
        css_version = css_version.css_version
    else:
        # Fallback to __version__ if app_state not initialized
        from chatfilter import __version__

        css_version = __version__

    return {
        "request": request,
        "csrf_token": csrf_token,
        "locale": locale,
        "_": _,  # Pass translation function directly to override Jinja2 i18n
        "gettext": translations.gettext,
        "ngettext": translations.ngettext,
        "css_version": css_version,  # CSS file hash for cache-busting
        "js_translations": _safe_get_js_translations(locale),
        **kwargs,
    }

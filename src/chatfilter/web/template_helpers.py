"""Template helper functions for rendering."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from chatfilter.web.csrf import get_csrf_token
from chatfilter.web.session import get_session

if TYPE_CHECKING:
    from starlette.requests import Request


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
    from chatfilter.web.app import get_templates

    session = get_session(request)
    csrf_token = get_csrf_token(session)

    # Get current locale for this request
    locale = get_current_locale()
    translations = get_translations(locale)

    # Install translations for Jinja2 _() function
    # This must be done before each render to use the correct locale
    # Note: install_gettext_translations is added by jinja2.ext.i18n extension
    templates = get_templates()
    env = cast(Any, templates.env)
    env.install_gettext_translations(translations)

    return {
        "request": request,
        "csrf_token": csrf_token,
        "locale": locale,
        "gettext": translations.gettext,
        "ngettext": translations.ngettext,
        **kwargs,
    }

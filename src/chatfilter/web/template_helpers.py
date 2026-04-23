"""Template helper functions for rendering."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

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
    from chatfilter.i18n.js_translations import get_js_translations
    from chatfilter.i18n.translations import get_current_locale, get_translations

    def _js_translations_json(locale: str) -> str:
        """Return HTML-safe JSON for inline <script> use.

        json.dumps() alone does not escape '<', '>', or '&', so a translation
        value containing '</script>' would break out of the script block.  We
        apply the standard three replacements used by Jinja2's tojson /
        Flask's htmlsafe_json_dumps, making the guarantee explicit in Python.
        """
        data: dict[str, Any]
        try:
            data = get_js_translations(locale)
        except Exception:
            data = {}
        serialized = json.dumps(data, ensure_ascii=False)
        return serialized.replace("&", r"\u0026").replace("<", r"\u003c").replace(">", r"\u003e")

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

    current_username = session.get("username")

    ai_balance: float | None = None
    current_use_own_accounts = False
    if current_username:
        try:
            from chatfilter.storage.user_database import get_user_db

            settings = getattr(request.app.state, "settings", None)
            if settings is not None:
                db = get_user_db(settings.effective_database_url)
                user = db.get_user_by_username(current_username)
                if user is not None:
                    ai_balance = user.get("ai_balance_usd")
                    current_use_own_accounts = bool(user.get("use_own_accounts"))
        except Exception:
            pass

    is_admin = session.get("is_admin", False)

    return {
        "request": request,
        "csrf_token": csrf_token,
        "locale": locale,
        "_": _,  # Pass translation function directly to override Jinja2 i18n
        "gettext": translations.gettext,
        "ngettext": translations.ngettext,
        "css_version": css_version,  # CSS file hash for cache-busting
        "js_translations_json": _js_translations_json(locale),
        "current_username": current_username,
        "current_is_admin": is_admin,
        # Personal pool is a user feature (admin ticks the toggle too
        # if they want their own accounts alongside the shared pool).
        "current_use_own_accounts": current_use_own_accounts,
        "ai_balance": ai_balance,
        **kwargs,
    }

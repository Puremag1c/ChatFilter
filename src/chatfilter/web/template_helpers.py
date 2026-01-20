"""Template helper functions for rendering."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from chatfilter.web.csrf import get_csrf_token
from chatfilter.web.session import get_session

if TYPE_CHECKING:
    from starlette.requests import Request


def get_template_context(request: Request, **kwargs: Any) -> dict[str, Any]:
    """Get template context with CSRF token and other common data.

    This helper ensures CSRF tokens are available in all templates.

    Args:
        request: FastAPI request object
        **kwargs: Additional context variables

    Returns:
        Context dictionary with request, csrf_token, and any provided kwargs
    """
    session = get_session(request)
    csrf_token = get_csrf_token(session)

    return {
        "request": request,
        "csrf_token": csrf_token,
        **kwargs,
    }

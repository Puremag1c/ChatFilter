"""Error handling helpers for authentication flows.

Extracts common error response patterns from auth_reconnect.py to reduce duplication.
"""

from typing import Any, Optional

from starlette.requests import Request
from starlette.responses import HTMLResponse


def auth_error_response(
    request: Request,
    templates: Any,
    error: str,
    status_code: int = 400,
) -> HTMLResponse:
    """Return generic auth error partial."""
    return templates.TemplateResponse(
        request=request,
        name="partials/auth_result.html",
        context={"success": False, "error": error},
        status_code=status_code,
    )


def auth_code_form_error(
    request: Request,
    templates: Any,
    auth_id: str,
    phone: str,
    session_name: str,
    session_id: str,
    error: str,
    status_code: int = 400,
) -> HTMLResponse:
    """Return auth code form with error message (reconnect flow)."""
    return templates.TemplateResponse(
        request=request,
        name="partials/auth_code_form_reconnect.html",
        context={
            "auth_id": auth_id,
            "phone": phone,
            "session_name": session_name,
            "session_id": session_id,
            "error": error,
        },
        status_code=status_code,
    )


def auth_2fa_form_error(
    request: Request,
    templates: Any,
    auth_id: str,
    phone: str,
    session_name: str,
    session_id: str,
    error: str,
    status_code: int = 400,
) -> HTMLResponse:
    """Return 2FA form with error message (reconnect flow)."""
    return templates.TemplateResponse(
        request=request,
        name="partials/auth_2fa_form_reconnect.html",
        context={
            "auth_id": auth_id,
            "phone": phone,
            "session_name": session_name,
            "session_id": session_id,
            "error": error,
        },
        status_code=status_code,
    )


def auth_success_response(
    request: Request,
    templates: Any,
    message: str,
    next_url: Optional[str] = None,
) -> HTMLResponse:
    """Return auth success partial."""
    context: dict[str, Any] = {"success": True, "message": message}
    if next_url:
        context["next_url"] = next_url
    return templates.TemplateResponse(
        request=request,
        name="partials/auth_result.html",
        context=context,
        status_code=200,
    )

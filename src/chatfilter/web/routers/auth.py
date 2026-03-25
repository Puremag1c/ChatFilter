"""Authentication routes: login and logout."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from chatfilter.i18n import _
from chatfilter.web.session import get_session
from chatfilter.web.template_helpers import get_template_context

if TYPE_CHECKING:
    from chatfilter.storage.user_database import UserDatabase

router = APIRouter(tags=["auth"])


def _get_user_db(request: Request) -> UserDatabase:
    from chatfilter.storage.user_database import get_user_db

    return get_user_db(request.app.state.settings.effective_database_url)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request) -> Response:
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    # Already logged in → redirect to home
    session = get_session(request)
    if session.get("user_id"):
        return RedirectResponse(url="/", status_code=302)

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context=get_template_context(request, version=__version__),
    )


@router.post("/login", response_model=None)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse | HTMLResponse:
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    db = _get_user_db(request)
    user = db.get_user_by_username(username)

    if user and db.verify_password(username, password):
        session = get_session(request)
        session.set("user_id", user["id"])
        session.set("username", user["username"])
        session.set("is_admin", user["is_admin"])
        return RedirectResponse(url="/", status_code=303)

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context=get_template_context(
            request,
            version=__version__,
            error=_("Invalid username or password"),
            login_username=username,
        ),
        status_code=401,
    )


@router.post("/logout")
async def logout(request: Request) -> RedirectResponse:
    session = get_session(request)
    session.clear()
    return RedirectResponse(url="/login", status_code=303)

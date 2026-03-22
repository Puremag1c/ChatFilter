"""Admin routes: user management."""

from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from chatfilter.web.session import get_session
from chatfilter.web.template_helpers import get_template_context

router = APIRouter(tags=["admin"])


def _get_user_db(request: Request):
    from chatfilter.storage.user_database import get_user_db

    return get_user_db(request.app.state.settings.data_dir)


def _require_admin(request: Request) -> bool:
    session = get_session(request)
    return bool(session.get("is_admin"))


@router.get("/admin", response_class=HTMLResponse, response_model=None)
async def admin_page(request: Request) -> HTMLResponse | Response:
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)
    users = db.list_users()

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context=get_template_context(request, version=__version__, users=users),
    )


@router.post("/admin/users", response_model=None)
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse | HTMLResponse | Response:
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)

    existing = db.get_user_by_username(username)
    if existing:
        users = db.list_users()
        templates = get_templates()
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context=get_template_context(
                request,
                version=__version__,
                users=users,
                error=f"Пользователь '{username}' уже существует",
            ),
            status_code=409,
        )

    db.create_user(username, password)
    return RedirectResponse(url="/admin", status_code=303)


@router.delete("/admin/users/{user_id}", response_model=None)
async def delete_user(request: Request, user_id: str) -> Response:
    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)
    db.delete_user(user_id)
    return Response(status_code=200)


@router.post("/admin/users/{user_id}/password", response_model=None)
async def change_password(
    request: Request,
    user_id: str,
    password: str = Form(...),
) -> RedirectResponse | Response:
    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)
    db.update_password(user_id, password)
    return RedirectResponse(url="/admin", status_code=303)

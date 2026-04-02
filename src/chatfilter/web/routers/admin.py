"""Admin routes: user management."""

from __future__ import annotations

import html
from typing import TYPE_CHECKING
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from chatfilter.web.session import get_session
from chatfilter.web.template_helpers import get_template_context

if TYPE_CHECKING:
    from chatfilter.storage.group_database import GroupDatabase
    from chatfilter.storage.user_database import UserDatabase

router = APIRouter(tags=["admin"])

_SENSITIVE_SETTINGS = {"openrouter_api_key"}


def _mask_api_key(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return value[:3] + "..." + value[-4:]


def _safe_app_settings(settings: dict[str, str]) -> dict[str, str]:
    """Return app_settings with sensitive keys masked for display."""
    result = dict(settings)
    for key in _SENSITIVE_SETTINGS:
        if key in result:
            result[key] = _mask_api_key(result[key])
    return result


def _get_user_db(request: Request) -> UserDatabase:
    from chatfilter.storage.user_database import get_user_db

    return get_user_db(request.app.state.settings.effective_database_url)


def _get_group_db(request: Request) -> GroupDatabase:
    from chatfilter.storage.group_database import GroupDatabase

    return GroupDatabase(request.app.state.settings.effective_database_url)


def _require_admin(request: Request) -> bool:
    session = get_session(request)
    user_id = session.get("user_id")
    if not user_id:
        return False
    db = _get_user_db(request)
    user = db.get_user_by_id(user_id)
    return bool(user and user.get("is_admin"))


@router.get("/admin", response_class=HTMLResponse, response_model=None)
async def admin_page(
    request: Request,
    flash: str | None = Query(None),
    flash_type: str | None = Query(None),
) -> HTMLResponse | Response:
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)
    users = db.list_users()
    current_user_id = get_session(request).get("user_id")

    group_db = _get_group_db(request)
    app_settings = _safe_app_settings(group_db.get_all_settings())

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context=get_template_context(
            request,
            version=__version__,
            users=users,
            flash=flash,
            flash_type=flash_type or "success",
            current_user_id=current_user_id,
            app_settings=app_settings,
        ),
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

    if len(password) < 8:
        users = db.list_users()
        group_db = _get_group_db(request)
        app_settings = _safe_app_settings(group_db.get_all_settings())
        templates = get_templates()
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context=get_template_context(
                request,
                version=__version__,
                users=users,
                app_settings=app_settings,
                error="Пароль должен содержать минимум 8 символов",
            ),
            status_code=422,
        )

    existing = db.get_user_by_username(username)
    if existing:
        users = db.list_users()
        group_db = _get_group_db(request)
        app_settings = _safe_app_settings(group_db.get_all_settings())
        templates = get_templates()
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context=get_template_context(
                request,
                version=__version__,
                users=users,
                app_settings=app_settings,
                error=f"Пользователь '{username}' уже существует",
            ),
            status_code=409,
        )

    db.create_user(username, password)
    qs = urlencode({"flash": f"Пользователь '{username}' создан", "flash_type": "success"})
    return RedirectResponse(url=f"/admin?{qs}", status_code=303)


@router.delete("/admin/users/{user_id}", response_model=None)
async def delete_user(request: Request, user_id: str) -> Response:
    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    from chatfilter.storage.group_database import GroupDatabase
    from chatfilter.storage.user_database import delete_user_files
    from chatfilter.web.routers.sessions.client_registry import disconnect_user_clients

    settings = request.app.state.settings

    db = _get_user_db(request)
    user = db.get_user_by_id(user_id)
    username = html.escape(user["username"]) if user else "?"

    # 1. Disconnect any active Telegram sessions
    await disconnect_user_clients(user_id)

    # 2. Remove session files and proxy config
    delete_user_files(user_id, settings.sessions_dir, settings.config_dir)

    # 3. Delete user's groups from the database
    group_db = GroupDatabase(settings.effective_database_url)
    with group_db._connection() as conn:
        conn.execute("DELETE FROM chat_groups WHERE user_id = ?", (user_id,))

    # 4. Delete user record
    db.delete_user(user_id)

    flash_html = (
        '<div id="flash-container" hx-swap-oob="innerHTML">'
        '<div class="alert alert-success" role="alert">'
        f"Пользователь &#39;{username}&#39; удалён</div></div>"
    )
    return HTMLResponse(content=flash_html, status_code=200)


@router.post("/admin/users/{user_id}/password", response_model=None)
async def change_password(
    request: Request,
    user_id: str,
    password: str = Form(...),
) -> RedirectResponse | Response:
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)

    if len(password) < 8:
        users = db.list_users()
        group_db = _get_group_db(request)
        app_settings = _safe_app_settings(group_db.get_all_settings())
        templates = get_templates()
        return templates.TemplateResponse(
            request=request,
            name="admin.html",
            context=get_template_context(
                request,
                version=__version__,
                users=users,
                app_settings=app_settings,
                error="Пароль должен содержать минимум 8 символов",
            ),
            status_code=422,
        )

    db.update_password(user_id, password)
    qs = urlencode({"flash": "Пароль изменён", "flash_type": "success"})
    return RedirectResponse(url=f"/admin?{qs}", status_code=303)


@router.post("/admin/users/{user_id}/toggle-admin", response_model=None)
async def toggle_admin(request: Request, user_id: str) -> Response:
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    current_user_id = get_session(request).get("user_id")
    if current_user_id == user_id:
        return Response(status_code=400, content="Cannot remove own admin rights")

    db = _get_user_db(request)
    user = db.get_user_by_id(user_id)
    if not user:
        return Response(status_code=404, content="User not found")

    db.set_admin(user_id, not user["is_admin"])
    updated_user = db.get_user_by_id(user_id)

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="partials/admin_user_row.html",
        context=get_template_context(
            request,
            user=updated_user,
            current_user_id=current_user_id,
        ),
    )


@router.post("/admin/ai-settings", response_model=None)
async def update_ai_settings(
    request: Request,
    openrouter_api_key: str = Form(""),
    ai_model: str = Form(""),
    ai_fallback_models: str = Form(""),
) -> RedirectResponse | Response:
    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    group_db = _get_group_db(request)
    if openrouter_api_key.strip():
        group_db.set_setting("openrouter_api_key", openrouter_api_key.strip())
    if ai_model.strip():
        group_db.set_setting("ai_model", ai_model.strip())
    group_db.set_setting("ai_fallback_models", ai_fallback_models.strip())

    qs = urlencode({"flash": "AI настройки сохранены", "flash_type": "success"})
    return RedirectResponse(url=f"/admin?{qs}", status_code=303)


@router.post("/admin/settings", response_model=None)
async def update_settings(
    request: Request,
    max_chats_per_account: int = Form(...),
    analysis_freshness_days: int = Form(...),
) -> RedirectResponse | Response:
    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    if not (1 <= max_chats_per_account <= 1000):
        qs = urlencode(
            {"flash": "max_chats_per_account должен быть от 1 до 1000", "flash_type": "error"}
        )
        return RedirectResponse(url=f"/admin?{qs}", status_code=303)

    if not (1 <= analysis_freshness_days <= 30):
        qs = urlencode(
            {"flash": "analysis_freshness_days должен быть от 1 до 30", "flash_type": "error"}
        )
        return RedirectResponse(url=f"/admin?{qs}", status_code=303)

    group_db = _get_group_db(request)
    group_db.set_setting("max_chats_per_account", str(max_chats_per_account))
    group_db.set_setting("analysis_freshness_days", str(analysis_freshness_days))

    qs = urlencode({"flash": "Настройки сохранены", "flash_type": "success"})
    return RedirectResponse(url=f"/admin?{qs}", status_code=303)

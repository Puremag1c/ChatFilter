"""Admin routes: user management."""

from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, Response

from chatfilter import __version__
from chatfilter.web.session import get_session
from chatfilter.web.template_helpers import get_template_context

if TYPE_CHECKING:
    from chatfilter.storage.group_database import GroupDatabase
    from chatfilter.storage.user_database import UserDatabase

router = APIRouter(tags=["admin"])


def _toast_response(
    message: str,
    toast_type: str = "success",
    redirect: str | None = None,
    status_code: int = 200,
) -> Response:
    """Return a response that triggers a toast notification via HX-Trigger."""
    headers: dict[str, str] = {
        "HX-Trigger": json.dumps({"showToast": {"type": toast_type, "message": message}}),
    }
    if redirect:
        if status_code == 303:
            headers["Location"] = redirect
        else:
            headers["HX-Redirect"] = redirect
    return Response(status_code=status_code, headers=headers)


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
) -> HTMLResponse | Response:
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context=get_template_context(request, version=__version__),
    )


@router.get("/admin/tab/users", response_class=HTMLResponse, response_model=None)
async def admin_tab_users(
    request: Request,
    page: int = 1,
    q: str = "",
) -> HTMLResponse | Response:
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)
    page_size = 20
    users, total_count = db.list_users(page=page, page_size=page_size, query=q or None)
    total_pages = max(1, (total_count + page_size - 1) // page_size)
    current_user_id = get_session(request).get("user_id")

    hx_target = request.headers.get("HX-Target", "")
    if hx_target == "users-table-container":
        template_name = "partials/admin_users.html"
    else:
        template_name = "partials/admin_tab_users.html"

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name=template_name,
        context=get_template_context(
            request,
            version=__version__,
            users=users,
            current_user_id=current_user_id,
            page=page,
            total_pages=total_pages,
            total_count=total_count,
            q=q,
        ),
    )


@router.get("/admin/tab/platforms", response_class=HTMLResponse, response_model=None)
async def admin_tab_platforms(request: Request) -> HTMLResponse | Response:
    from chatfilter.scraper.registry import registry
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    group_db = _get_group_db(request)
    all_platform_settings = {s["id"]: s for s in group_db.get_all_platform_settings()}
    platforms_data = []
    for platform in registry.get_all():
        db_settings = all_platform_settings.get(platform.id, {})
        api_key_raw = db_settings.get("api_key") or ""
        platforms_data.append(
            {
                "id": platform.id,
                "name": platform.name,
                "needs_api_key": platform.needs_api_key,
                "api_key_display": _mask_api_key(api_key_raw) if api_key_raw else "",
                "api_key_set": bool(api_key_raw),
                "cost_per_request_usd": db_settings.get("cost_per_request_usd", 0.0),
                "enabled": db_settings.get("enabled", True),
            }
        )

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="partials/admin_tab_platforms.html",
        context=get_template_context(
            request,
            version=__version__,
            platforms_data=platforms_data,
        ),
    )


@router.get("/admin/tab/system", response_class=HTMLResponse, response_model=None)
async def admin_tab_system(request: Request) -> HTMLResponse | Response:
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    group_db = _get_group_db(request)
    app_settings = _safe_app_settings(group_db.get_all_settings())
    cost_multiplier = group_db.get_cost_multiplier()
    cost_per_chat = group_db.get_cost_per_chat()

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="partials/admin_tab_system.html",
        context=get_template_context(
            request,
            version=__version__,
            app_settings=app_settings,
            cost_multiplier=cost_multiplier,
            cost_per_chat=cost_per_chat,
        ),
    )


@router.get("/admin/queue", response_class=HTMLResponse, response_model=None)
async def admin_queue_dashboard(request: Request) -> HTMLResponse | Response:
    """Persistent-queue dashboard — counts by status and per-user depth."""
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    group_db = _get_group_db(request)
    queue_stats = group_db.get_queue_stats()

    # Per-user queue depth (queued + running). Cheap enough to read inline.
    with group_db._connection() as conn:  # noqa: SLF001
        rows = conn.execute(
            "SELECT user_id, status, COUNT(*) AS n FROM analysis_queue "
            "WHERE status IN ('queued', 'running') "
            "GROUP BY user_id, status ORDER BY user_id"
        ).fetchall()
    per_user: dict[str, dict[str, int]] = {}
    for row in rows:
        per_user.setdefault(row["user_id"], {})[row["status"]] = int(row["n"])

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="partials/admin_queue_dashboard.html",
        context=get_template_context(
            request,
            version=__version__,
            queue_stats=queue_stats,
            per_user=per_user,
        ),
    )


@router.get("/admin/monitor", response_class=HTMLResponse, response_model=None)
async def admin_monitor_dashboard(request: Request) -> HTMLResponse | Response:
    """Admin-pool health monitor: account state counts, proxy state
    counts, external balances. HTMX-polls /admin/api/monitor/summary
    every 30s to refresh the numbers without a full page reload.
    """
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="partials/admin_monitor_dashboard.html",
        context=get_template_context(request, version=__version__),
    )


@router.get("/admin/api/monitor/summary", response_class=HTMLResponse, response_model=None)
async def admin_monitor_summary(request: Request) -> HTMLResponse | Response:
    """HTMX partial with current admin-pool health snapshot."""
    from chatfilter.service.monitor import get_monitor_service
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    snapshot = get_monitor_service().gather()
    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="partials/admin_monitor_summary.html",
        context=get_template_context(request, snapshot=snapshot),
    )


@router.get("/admin/users", response_class=HTMLResponse, response_model=None)
@router.get("/admin/platforms", response_class=HTMLResponse, response_model=None)
@router.get("/admin/system", response_class=HTMLResponse, response_model=None)
async def admin_tab_page(request: Request) -> HTMLResponse | Response:
    """Serve admin shell for direct tab URL access (e.g. /admin/users on refresh)."""
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context=get_template_context(request, version=__version__),
    )


@router.post("/admin/users", response_model=None)
async def create_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    email: str = Form(""),
) -> Response:
    import re

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)

    if len(password) < 8:
        return _toast_response(
            "Пароль должен содержать минимум 8 символов", toast_type="error", status_code=422
        )

    existing = db.get_user_by_username(username)
    if existing:
        return _toast_response(
            f"Пользователь '{username}' уже существует", toast_type="error", status_code=409
        )

    email_value: str | None = email.strip() or None
    if email_value:
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email_value):
            return _toast_response("Неверный формат email", toast_type="error", status_code=422)
        existing_email = db.get_user_by_email(email_value)
        if existing_email:
            return _toast_response(
                f"Email '{email_value}' уже используется", toast_type="error", status_code=409
            )

    db.create_user(username, password, email=email_value)
    return _toast_response(f"Пользователь '{username}' создан", redirect="/admin", status_code=303)


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

    return _toast_response(f"Пользователь '{username}' удалён")


@router.post("/admin/users/{user_id}/password", response_model=None)
async def change_password(
    request: Request,
    user_id: str,
    password: str = Form(...),
) -> Response:
    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)

    if len(password) < 8:
        return _toast_response(
            "Пароль должен содержать минимум 8 символов", toast_type="error", status_code=422
        )

    db.update_password(user_id, password)
    return _toast_response("Пароль изменён", redirect="/admin", status_code=303)


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

    new_is_admin = not user["is_admin"]
    db.set_admin(user_id, new_is_admin)
    updated_user = db.get_user_by_id(user_id)

    templates = get_templates()
    response = templates.TemplateResponse(
        request=request,
        name="partials/admin_user_row.html",
        context=get_template_context(
            request,
            version=__version__,
            user=updated_user,
            current_user_id=current_user_id,
        ),
    )
    username = user["username"]
    action = "назначен администратором" if new_is_admin else "снят с должности администратора"
    response.headers["HX-Trigger"] = json.dumps(
        {"showToast": {"type": "success", "message": f"Пользователь '{username}' {action}"}}
    )
    return response


@router.post("/admin/users/{user_id}/topup", response_model=None)
async def topup_balance(
    request: Request,
    user_id: str,
    amount: float = Form(...),
) -> Response:
    from chatfilter.ai.billing import BillingService
    from chatfilter.web.app import get_templates

    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    db = _get_user_db(request)
    user = db.get_user_by_id(user_id)
    if not user:
        return Response(status_code=404, content="User not found")

    if amount <= 0:
        return Response(status_code=400, content="Amount must be positive")

    billing = BillingService(db)
    new_balance = billing.topup(
        user_id=user_id,
        amount_usd=amount,
        admin_description=f"Admin topup ${amount:.2f}",
    )
    templates = get_templates()
    response = templates.TemplateResponse(
        request=request,
        name="partials/balance_td.html",
        context=get_template_context(
            request,
            version=__version__,
            user_id=user_id,
            new_balance=new_balance,
        ),
    )
    response.headers["HX-Trigger"] = json.dumps(
        {"showToast": {"type": "success", "message": f"Баланс пополнен на ${amount:.2f}"}}
    )
    return response


@router.post("/admin/ai-settings", response_model=None)
async def update_ai_settings(
    request: Request,
    cost_multiplier: float = Form(1.0),
    cost_per_chat: float = Form(0.0),
    openrouter_api_key: str = Form(""),
    ai_model: str = Form(""),
    ai_model_query: str = Form(""),
    ai_model_parse: str = Form(""),
    ai_model_filter: str = Form(""),
    ai_fallback_models: str = Form(""),
) -> Response:
    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    group_db = _get_group_db(request)
    if cost_multiplier > 0:
        group_db.set_cost_multiplier(cost_multiplier)
    # cost_per_chat accepts 0 (the deployment default meaning "no charge").
    if cost_per_chat >= 0:
        group_db.set_cost_per_chat(cost_per_chat)
    if openrouter_api_key.strip():
        group_db.set_setting("openrouter_api_key", openrouter_api_key.strip())
    if ai_model.strip():
        group_db.set_setting("ai_model", ai_model.strip())
    # Per-stage models: empty = use default
    group_db.set_setting("ai_model_query", ai_model_query.strip())
    group_db.set_setting("ai_model_parse", ai_model_parse.strip())
    group_db.set_setting("ai_model_filter", ai_model_filter.strip())
    group_db.set_setting("ai_fallback_models", ai_fallback_models.strip())

    return _toast_response("AI настройки сохранены", redirect="/admin")


@router.post("/admin/settings", response_model=None)
async def update_settings(
    request: Request,
    max_chats_per_account: int = Form(...),
    analysis_freshness_days: int = Form(...),
) -> Response:
    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    if not (1 <= max_chats_per_account <= 1000):
        return _toast_response("max_chats_per_account должен быть от 1 до 1000", toast_type="error")

    if not (1 <= analysis_freshness_days <= 30):
        return _toast_response("analysis_freshness_days должен быть от 1 до 30", toast_type="error")

    group_db = _get_group_db(request)
    group_db.set_setting("max_chats_per_account", str(max_chats_per_account))
    group_db.set_setting("analysis_freshness_days", str(analysis_freshness_days))

    return _toast_response("Настройки сохранены", redirect="/admin")


@router.post("/admin/platform-settings", response_model=None)
async def update_platform_settings(
    request: Request,
) -> Response:
    if not _require_admin(request):
        return Response(status_code=403, content="Forbidden")

    from chatfilter.scraper.registry import registry

    form = await request.form()
    group_db = _get_group_db(request)

    for platform in registry.get_all():
        pid = platform.id
        api_key: str | None = str(form.get(f"platform_{pid}_api_key", "")).strip()
        cost_str = str(form.get(f"platform_{pid}_cost", "0")).strip()
        enabled = f"platform_{pid}_enabled" in form

        try:
            cost = float(cost_str) if cost_str else 0.0
        except ValueError:
            cost = 0.0

        # Preserve existing api_key if field left blank
        if not api_key:
            existing = group_db.get_platform_setting(pid)
            api_key = existing["api_key"] if existing and existing.get("api_key") else None

        group_db.save_platform_setting(
            platform_id=pid,
            api_key=api_key or None,
            cost=cost,
            enabled=enabled,
        )

    return _toast_response("Настройки площадок сохранены", redirect="/admin")

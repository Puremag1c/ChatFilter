"""Profile routes: view profile and change password."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from chatfilter.i18n import _
from chatfilter.web.session import get_session
from chatfilter.web.template_helpers import get_template_context

if TYPE_CHECKING:
    from chatfilter.storage.user_database import UserDatabase

router = APIRouter(tags=["profile"])


def _get_user_db(request: Request) -> UserDatabase:
    from chatfilter.storage.user_database import get_user_db

    return get_user_db(request.app.state.settings.effective_database_url)


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
) -> Response:
    from chatfilter import __version__
    from chatfilter.ai.billing import BillingService
    from chatfilter.web.app import get_templates

    session = get_session(request)
    user_id = session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    db = _get_user_db(request)
    user = db.get_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    billing = BillingService(db)
    ai_balance = billing.get_balance(user_id)
    transactions = billing.get_transactions(user_id)

    templates = get_templates()
    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context=get_template_context(
            request,
            version=__version__,
            user=user,
            ai_balance=ai_balance,
            transactions=transactions,
        ),
    )


@router.post("/profile/password", response_model=None)
async def change_password(
    request: Request,
    old_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
) -> Response:
    session = get_session(request)
    user_id = session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    db = _get_user_db(request)
    user = db.get_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    username = user["username"]

    def toast_error(message: str) -> Response:
        trigger = json.dumps({"showToast": {"message": message, "type": "error"}})
        return HTMLResponse(content="", status_code=400, headers={"HX-Trigger": trigger})

    if not db.verify_password(username, old_password):
        return toast_error(_("Current password is incorrect"))

    if len(new_password) < 8:
        return toast_error(_("New password must be at least 8 characters"))

    if new_password != confirm_password:
        return toast_error(_("New password and confirmation do not match"))

    db.update_password(user_id, new_password)

    trigger = json.dumps(
        {"showToast": {"message": _("Password changed successfully"), "type": "success"}}
    )
    return HTMLResponse(content="", status_code=200, headers={"HX-Trigger": trigger})

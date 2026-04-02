"""Profile routes: view profile and change password."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlencode

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
    flash: str | None = None,
    flash_type: str = "success",
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
            flash=flash,
            flash_type=flash_type,
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
    from chatfilter import __version__
    from chatfilter.web.app import get_templates

    session = get_session(request)
    user_id = session.get("user_id")
    if not user_id:
        return RedirectResponse(url="/login", status_code=302)

    db = _get_user_db(request)
    user = db.get_user_by_id(user_id)
    if not user:
        return RedirectResponse(url="/login", status_code=302)

    username = user["username"]

    from chatfilter.ai.billing import BillingService

    billing = BillingService(db)
    ai_balance = billing.get_balance(user_id)
    transactions = billing.get_transactions(user_id)

    def render_error(error: str) -> Response:
        templates = get_templates()
        return templates.TemplateResponse(
            request=request,
            name="profile.html",
            context=get_template_context(
                request,
                version=__version__,
                user=user,
                flash=error,
                flash_type="error",
                ai_balance=ai_balance,
                transactions=transactions,
            ),
            status_code=400,
        )

    if not db.verify_password(username, old_password):
        return render_error(_("Current password is incorrect"))

    if len(new_password) < 8:
        return render_error(_("New password must be at least 8 characters"))

    if new_password != confirm_password:
        return render_error(_("New password and confirmation do not match"))

    db.update_password(user_id, new_password)

    params = urlencode({"flash": _("Password changed successfully"), "flash_type": "success"})
    return RedirectResponse(url=f"/profile?{params}", status_code=303)

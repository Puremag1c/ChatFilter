"""Boot recovery status endpoint — consumed by the banner JS poll.

Any logged-in user can read the shared boot-recovery counters. These
are just totals (how many sessions pinged / connected / skipped); not
user-scoped, not secret. We deliberately don't split per-user because
(a) the counters are the same facts the banner shows to everyone and
(b) per-user filtering would require linking each session to its
owning user at startup, which we already do elsewhere and don't want
to duplicate here.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from chatfilter.service.boot_recovery import get_boot_recovery_holder
from chatfilter.web.session import get_session

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/admin/api/boot-status", response_model=None)
async def boot_status(request: Request) -> JSONResponse:
    session = get_session(request)
    if not session.get("user_id"):
        return JSONResponse({"error": "login required"}, status_code=401)

    holder = get_boot_recovery_holder()
    if holder is None:
        return JSONResponse({"in_progress": False, "phase": "done"})
    return JSONResponse(holder.snapshot().to_dict())

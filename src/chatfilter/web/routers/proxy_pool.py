"""REST API endpoints for proxy pool management.

Provides CRUD operations for managing multiple proxy configurations:
- GET /api/proxies - list all proxies
- POST /api/proxies - create a new proxy
- DELETE /api/proxies/{proxy_id} - delete a proxy (with in-use validation)
"""

from __future__ import annotations

import json
import logging
from typing import Annotated

from fastapi import APIRouter, HTTPException, Path, Request, status
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from chatfilter.config import ProxyType, get_settings
from chatfilter.models.proxy import ProxyEntry
from chatfilter.storage.errors import StorageNotFoundError
from chatfilter.storage.proxy_pool import (
    add_proxy,
    get_proxy_by_id,
    load_proxy_pool,
    remove_proxy,
    update_proxy,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["proxy_pool"])


class ProxyResponse(BaseModel):
    """Proxy entry response model."""

    id: str
    name: str
    type: str
    host: str
    port: int
    username: str = ""
    has_auth: bool
    # Health monitoring fields
    status: str
    last_ping_at: str | None = None
    last_success_at: str | None = None
    consecutive_failures: int = 0
    is_available: bool = True


class ProxyListResponse(BaseModel):
    """Response model for listing proxies."""

    proxies: list[ProxyResponse]
    count: int


class ProxyCreateRequest(BaseModel):
    """Request model for creating a new proxy."""

    name: str = Field(..., min_length=1, max_length=100)
    type: str = Field(..., description="Proxy type: socks5 or http")
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    username: str = ""
    password: str = ""


class ProxyUpdateRequest(BaseModel):
    """Request model for updating an existing proxy."""

    name: str = Field(..., min_length=1, max_length=100)
    type: str = Field(..., description="Proxy type: socks5 or http")
    host: str = Field(..., min_length=1, max_length=255)
    port: int = Field(..., ge=1, le=65535)
    username: str = ""
    password: str | None = None  # None means keep existing password


class ProxyCreateResponse(BaseModel):
    """Response model for proxy creation."""

    success: bool
    proxy: ProxyResponse | None = None
    error: str | None = None


class ProxyDeleteResponse(BaseModel):
    """Response model for proxy deletion."""

    success: bool
    message: str | None = None
    error: str | None = None
    sessions_using_proxy: list[str] | None = None


class ProxyRetestResponse(BaseModel):
    """Response model for proxy retest."""

    success: bool
    proxy: ProxyResponse | None = None
    error: str | None = None


def _proxy_to_response(proxy: ProxyEntry) -> ProxyResponse:
    """Convert ProxyEntry to ProxyResponse."""
    return ProxyResponse(
        id=proxy.id,
        name=proxy.name,
        type=proxy.type.value,
        host=proxy.host,
        port=proxy.port,
        username=proxy.username,
        has_auth=proxy.has_auth,
        status=proxy.status.value,
        last_ping_at=proxy.last_ping_at.isoformat() if proxy.last_ping_at else None,
        last_success_at=proxy.last_success_at.isoformat() if proxy.last_success_at else None,
        consecutive_failures=proxy.consecutive_failures,
        is_available=proxy.is_available,
    )


def _get_sessions_using_proxy(proxy_id: str) -> list[str]:
    """Find all sessions that are using a specific proxy.

    Args:
        proxy_id: UUID of the proxy to check.

    Returns:
        List of session IDs that have this proxy configured.
    """
    sessions_using = []
    sessions_dir = get_settings().sessions_dir

    if not sessions_dir.exists():
        return []

    for session_dir in sessions_dir.iterdir():
        if not session_dir.is_dir():
            continue

        config_file = session_dir / "config.json"
        if not config_file.exists():
            continue

        try:
            with config_file.open("r", encoding="utf-8") as f:
                config = json.load(f)

            if config.get("proxy_id") == proxy_id:
                sessions_using.append(session_dir.name)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read config for session {session_dir.name}: {e}")
            continue

    return sessions_using


@router.get("/api/proxies", response_model=ProxyListResponse)
async def list_proxies() -> ProxyListResponse:
    """List all proxies in the pool.

    Returns:
        ProxyListResponse with all proxies and count.
    """
    try:
        proxies = load_proxy_pool()
        proxy_responses = [_proxy_to_response(p) for p in proxies]

        return ProxyListResponse(
            proxies=proxy_responses,
            count=len(proxy_responses),
        )
    except Exception as e:
        logger.exception("Failed to load proxy pool")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to load proxies: {e}",
        ) from e


@router.post("/api/proxies", response_model=ProxyCreateResponse)
async def create_proxy(request: ProxyCreateRequest) -> ProxyCreateResponse:
    """Create a new proxy in the pool.

    Args:
        request: Proxy creation request with name, type, host, port, and optional auth.

    Returns:
        ProxyCreateResponse with created proxy or error.
    """
    try:
        # Validate proxy type
        try:
            proxy_type = ProxyType(request.type.lower())
        except ValueError:
            return ProxyCreateResponse(
                success=False,
                error=f"Invalid proxy type: {request.type}. Must be 'socks5' or 'http'.",
            )

        # Create proxy entry
        proxy = ProxyEntry(
            name=request.name,
            type=proxy_type,
            host=request.host,
            port=request.port,
            username=request.username,
            password=request.password,
        )

        # Add to pool
        added_proxy = add_proxy(proxy)

        logger.info(f"Created new proxy: {added_proxy.name} ({added_proxy.id})")

        return ProxyCreateResponse(
            success=True,
            proxy=_proxy_to_response(added_proxy),
        )

    except ValueError as e:
        return ProxyCreateResponse(
            success=False,
            error=str(e),
        )
    except Exception as e:
        logger.exception("Failed to create proxy")
        return ProxyCreateResponse(
            success=False,
            error=f"Failed to create proxy: {e}",
        )


@router.put("/api/proxies/{proxy_id}", response_model=ProxyCreateResponse)
async def update_proxy_endpoint(
    proxy_id: Annotated[
        str, Path(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    ],
    request: ProxyUpdateRequest,
) -> ProxyCreateResponse:
    """Update an existing proxy in the pool.

    Args:
        proxy_id: UUID of the proxy to update.
        request: Proxy update request with name, type, host, port, and optional auth.

    Returns:
        ProxyCreateResponse with updated proxy or error.
    """
    try:
        # Validate proxy type
        try:
            proxy_type = ProxyType(request.type.lower())
        except ValueError:
            return ProxyCreateResponse(
                success=False,
                error=f"Invalid proxy type: {request.type}. Must be 'socks5' or 'http'.",
            )

        # Get existing proxy to preserve password if not provided
        existing_proxy = get_proxy_by_id(proxy_id)

        # Use existing password if new one not provided
        password = request.password if request.password is not None else existing_proxy.password

        # Create updated proxy entry
        updated_proxy = ProxyEntry(
            id=proxy_id,
            name=request.name,
            type=proxy_type,
            host=request.host,
            port=request.port,
            username=request.username,
            password=password,
        )

        # Update in pool
        result = update_proxy(proxy_id, updated_proxy)

        logger.info(f"Updated proxy: {result.name} ({result.id})")

        return ProxyCreateResponse(
            success=True,
            proxy=_proxy_to_response(result),
        )

    except StorageNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proxy not found: {proxy_id}",
        ) from None
    except ValueError as e:
        return ProxyCreateResponse(
            success=False,
            error=str(e),
        )
    except Exception as e:
        logger.exception(f"Failed to update proxy {proxy_id}")
        return ProxyCreateResponse(
            success=False,
            error=f"Failed to update proxy: {e}",
        )


@router.delete("/api/proxies/{proxy_id}", response_model=ProxyDeleteResponse)
async def delete_proxy(
    proxy_id: Annotated[
        str, Path(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    ],
) -> ProxyDeleteResponse:
    """Delete a proxy from the pool.

    If the proxy is in use by sessions, they will lose their proxy configuration.
    The frontend should warn the user before deletion if sessions are affected.

    Args:
        proxy_id: UUID of the proxy to delete.

    Returns:
        ProxyDeleteResponse with success status or error.
    """
    try:
        # Log if proxy is in use (sessions will be affected)
        sessions_using = _get_sessions_using_proxy(proxy_id)
        if sessions_using:
            logger.warning(
                f"Deleting proxy {proxy_id} that is in use by {len(sessions_using)} sessions: {sessions_using}"
            )

        # Remove from pool
        remove_proxy(proxy_id)

        logger.info(f"Deleted proxy: {proxy_id}")

        return ProxyDeleteResponse(
            success=True,
            message=f"Proxy {proxy_id} deleted successfully",
        )

    except StorageNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Proxy not found: {proxy_id}",
        ) from None
    except Exception as e:
        logger.exception(f"Failed to delete proxy {proxy_id}")
        return ProxyDeleteResponse(
            success=False,
            error=f"Failed to delete proxy: {e}",
        )


@router.post("/api/proxies/{proxy_id}/retest", response_class=HTMLResponse)
async def retest_proxy_endpoint(
    request: Request,
    proxy_id: Annotated[
        str, Path(pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    ],
) -> HTMLResponse:
    """Retest a proxy's health and update its status.

    Resets the failure counter, then performs a health check.
    Used to re-enable a disabled proxy after fixing connection issues.

    Args:
        request: FastAPI request object for template rendering.
        proxy_id: UUID of the proxy to retest.

    Returns:
        HTMLResponse with single <tr> fragment for HTMX swap or error.
    """
    from chatfilter.service.proxy_health import retest_proxy
    from chatfilter.web.app import get_templates
    from chatfilter.web.template_helpers import get_template_context

    try:
        updated_proxy = await retest_proxy(proxy_id)

        if updated_proxy is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Proxy not found: {proxy_id}",
            )

        logger.info(f"Retested proxy: {updated_proxy.name} - status: {updated_proxy.status.value}")

        # Get usage count for the proxy
        usage_count = len(_get_sessions_using_proxy(proxy_id))

        # Build proxy data for template
        proxy_data = {
            "id": updated_proxy.id,
            "name": updated_proxy.name,
            "type": updated_proxy.type.value,
            "host": updated_proxy.host,
            "port": updated_proxy.port,
            "username": updated_proxy.username,
            "has_auth": updated_proxy.has_auth,
            "usage_count": usage_count,
            "status": updated_proxy.status.value,
            "last_ping_at": updated_proxy.last_ping_at,
            "last_success_at": updated_proxy.last_success_at,
            "consecutive_failures": updated_proxy.consecutive_failures,
            "is_available": updated_proxy.is_available,
        }

        # Render single row using macro
        templates = get_templates()
        template = templates.env.from_string(
            "{% from 'partials/proxy_pool_list.html' import proxy_row %}"
            "{{ proxy_row(proxy) }}"
        )
        html = template.render(**get_template_context(request, proxy=proxy_data))

        return HTMLResponse(content=html, status_code=200)

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Failed to retest proxy {proxy_id}")
        # Return HTTP 500 with HX-Trigger for toast notification
        # Frontend will show error toast via showToast event listener
        trigger_data = json.dumps({
            "showToast": {
                "type": "error",
                "title": "Test Failed",
                "message": "An error occurred while testing the proxy. Please try again.",
            }
        })
        return HTMLResponse(
            content="",
            status_code=500,
            headers={"HX-Trigger": trigger_data},
        )


@router.get("/api/proxies/list", response_class=HTMLResponse)
async def list_proxies_html(request: Request) -> HTMLResponse:
    """List all proxies as HTML partial for HTMX.

    Returns:
        HTML fragment with proxy table.
    """
    from chatfilter.web.app import get_templates
    from chatfilter.web.template_helpers import get_template_context

    try:
        proxies = load_proxy_pool()

        # Build response with usage count and health status for each proxy
        proxies_with_usage = []
        for proxy in proxies:
            usage_count = len(_get_sessions_using_proxy(proxy.id))
            proxies_with_usage.append(
                {
                    "id": proxy.id,
                    "name": proxy.name,
                    "type": proxy.type.value,
                    "host": proxy.host,
                    "port": proxy.port,
                    "username": proxy.username,
                    "has_auth": proxy.has_auth,
                    "usage_count": usage_count,
                    # Health status fields
                    "status": proxy.status.value,
                    "last_ping_at": proxy.last_ping_at,
                    "last_success_at": proxy.last_success_at,
                    "consecutive_failures": proxy.consecutive_failures,
                    "is_available": proxy.is_available,
                }
            )

        templates = get_templates()
        return templates.TemplateResponse(
            request=request,
            name="partials/proxy_pool_list.html",
            context=get_template_context(request, proxies=proxies_with_usage),
        )
    except Exception as e:
        logger.exception("Failed to load proxy pool for HTML")
        return HTMLResponse(
            content=f'<div class="alert alert-error">'
            f"<strong>Error:</strong> Failed to load proxies: {e}"
            f"</div>",
            status_code=500,
        )

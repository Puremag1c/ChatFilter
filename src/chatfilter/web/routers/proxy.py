"""Proxy settings router."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse

from chatfilter.config import ProxyConfig, ProxyType, load_proxy_config, save_proxy_config

logger = logging.getLogger(__name__)

router = APIRouter(tags=["proxy"])


@router.get("/api/proxy", response_class=HTMLResponse)
async def get_proxy_config(request: Request) -> HTMLResponse:
    """Get current proxy configuration as HTML partial."""
    from chatfilter.web.app import get_templates

    templates = get_templates()
    config = load_proxy_config()

    return templates.TemplateResponse(
        "partials/proxy_form.html",
        {"request": request, "config": config, "proxy_types": list(ProxyType)},
    )


@router.post("/api/proxy", response_class=HTMLResponse)
async def save_proxy(
    request: Request,
    enabled: Annotated[bool, Form()] = False,
    proxy_type: Annotated[str, Form()] = "socks5",
    host: Annotated[str, Form()] = "",
    port: Annotated[int, Form()] = 1080,
    username: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
) -> HTMLResponse:
    """Save proxy configuration.

    Returns HTML partial for HTMX to display result.
    """
    from chatfilter.web.app import get_templates

    templates = get_templates()

    try:
        # Validate proxy type
        try:
            validated_type = ProxyType(proxy_type.lower())
        except ValueError:
            return templates.TemplateResponse(
                "partials/proxy_result.html",
                {
                    "request": request,
                    "success": False,
                    "error": f"Invalid proxy type: {proxy_type}",
                },
            )

        # Validate port range
        if port < 1 or port > 65535:
            return templates.TemplateResponse(
                "partials/proxy_result.html",
                {
                    "request": request,
                    "success": False,
                    "error": "Port must be between 1 and 65535",
                },
            )

        # Create and save config
        config = ProxyConfig(
            enabled=enabled,
            proxy_type=validated_type,
            host=host.strip(),
            port=port,
            username=username.strip(),
            password=password,
        )

        save_proxy_config(config)

        return templates.TemplateResponse(
            "partials/proxy_result.html",
            {
                "request": request,
                "success": True,
                "message": "Proxy settings saved successfully",
            },
        )

    except Exception as e:
        logger.exception("Failed to save proxy config")
        return templates.TemplateResponse(
            "partials/proxy_result.html",
            {
                "request": request,
                "success": False,
                "error": f"Failed to save settings: {e}",
            },
        )

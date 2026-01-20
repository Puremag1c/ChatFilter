"""Custom exception handlers for secure error responses."""

from __future__ import annotations

import logging
import traceback
from typing import TYPE_CHECKING

from fastapi import Request, status
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)


def _get_error_id(request: Request) -> str:
    """Get request ID for error tracking."""
    return getattr(request.state, "request_id", "unknown")


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle HTTPException with consistent formatting.

    Args:
        request: FastAPI request object
        exc: HTTPException instance

    Returns:
        JSONResponse with error details
    """
    error_id = _get_error_id(request)

    # Log the error with request context
    logger.warning(
        f"HTTP {exc.status_code} error: {exc.detail} "
        f"(request_id={error_id}, path={request.url.path})"
    )

    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle validation errors with sanitized output.

    Args:
        request: FastAPI request object
        exc: RequestValidationError instance

    Returns:
        JSONResponse with validation error details
    """
    error_id = _get_error_id(request)

    # Log validation errors for debugging
    logger.warning(
        f"Validation error on {request.url.path}: {exc.errors()} "
        f"(request_id={error_id})"
    )

    # In production, we still return validation details as they're safe
    # (they don't expose server internals, just input validation issues)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Invalid input data",
            "errors": exc.errors(),
        },
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle all unhandled exceptions with production-safe error messages.

    In debug mode: Returns detailed error information including exception type
    In production: Returns generic error message, logs full details server-side

    Args:
        request: FastAPI request object
        exc: Exception instance

    Returns:
        JSONResponse with error details (sanitized in production)
    """
    error_id = _get_error_id(request)

    # Always log the full exception with stack trace for debugging
    logger.exception(
        f"Unhandled exception in {request.method} {request.url.path} "
        f"(request_id={error_id}): {exc}"
    )

    # Get debug mode from app settings
    debug_mode = getattr(request.app.state, "settings", None)
    debug_mode = getattr(debug_mode, "debug", False) if debug_mode else False

    if debug_mode:
        # In debug mode, return detailed error information
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "Internal server error",
                "error_type": type(exc).__name__,
                "error_message": str(exc),
                "request_id": error_id,
                "traceback": traceback.format_exc().split("\n"),
            },
        )
    else:
        # In production, return sanitized generic error
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An internal error occurred. Please try again later.",
                "request_id": error_id,
            },
        )


def register_exception_handlers(app: FastAPI) -> None:
    """Register all custom exception handlers.

    Args:
        app: FastAPI application instance
    """
    # Handle FastAPI HTTPExceptions
    app.add_exception_handler(HTTPException, http_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)

    # Handle validation errors
    app.add_exception_handler(RequestValidationError, validation_exception_handler)

    # Catch-all for any unhandled exceptions
    app.add_exception_handler(Exception, general_exception_handler)

    logger.info("Registered custom exception handlers")

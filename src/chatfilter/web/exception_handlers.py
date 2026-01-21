"""Custom exception handlers for secure error responses."""

from __future__ import annotations

import asyncio
import logging
import socket
import traceback
from typing import TYPE_CHECKING

from fastapi import Request, status
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from chatfilter.utils.network import NetworkOfflineError, detect_network_error

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)


def _get_error_id(request: Request) -> str:
    """Get request ID for error tracking."""
    return getattr(request.state, "request_id", "unknown")


async def http_exception_handler(request: Request, exc: HTTPException | Exception) -> JSONResponse:
    """Handle HTTPException with consistent formatting.

    Args:
        request: FastAPI request object
        exc: HTTPException instance (FastAPI or Starlette)

    Returns:
        JSONResponse with error details
    """
    error_id = _get_error_id(request)

    # Handle both FastAPI and Starlette HTTPExceptions
    if not isinstance(exc, HTTPException | StarletteHTTPException):
        exc = HTTPException(status_code=500, detail=str(exc))

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
    request: Request, exc: RequestValidationError | Exception
) -> JSONResponse:
    """Handle validation errors with sanitized output.

    Args:
        request: FastAPI request object
        exc: RequestValidationError instance

    Returns:
        JSONResponse with validation error details
    """
    error_id = _get_error_id(request)

    # Cast to RequestValidationError for type checking
    if not isinstance(exc, RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Invalid input data",
                "errors": [{"msg": str(exc)}],
            },
        )

    # Log validation errors for debugging
    logger.warning(
        f"Validation error on {request.url.path}: {exc.errors()} (request_id={error_id})"
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


async def network_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle network-related errors with user-friendly messages.

    This handler detects network connectivity issues and provides clear
    guidance to users about offline state.

    Args:
        request: FastAPI request object
        exc: Exception instance (network-related)

    Returns:
        JSONResponse with network error details
    """
    error_id = _get_error_id(request)

    # Log network error
    logger.warning(
        f"Network error in {request.method} {request.url.path} "
        f"(request_id={error_id}): {type(exc).__name__}: {exc}"
    )

    # Determine user-friendly message
    if isinstance(exc, NetworkOfflineError):
        error_message = str(exc)
        error_hint = "Please check your internet connection and try again."
    elif isinstance(exc, TimeoutError | asyncio.TimeoutError):
        error_message = "Request timed out. The server may be unreachable."
        error_hint = "Check your internet connection or try again later."
    elif isinstance(exc, ConnectionError | socket.error):
        error_message = "Connection failed. Unable to reach the server."
        error_hint = "Please check your internet connection and try again."
    else:
        error_message = "Network error occurred."
        error_hint = "Please check your internet connection and try again."

    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "detail": error_message,
            "hint": error_hint,
            "error_type": "network_error",
            "request_id": error_id,
            "retry_suggested": True,
        },
    )


async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle all unhandled exceptions with production-safe error messages.

    In debug mode: Returns detailed error information including exception type
    In production: Returns generic error message, logs full details server-side

    This handler also detects network errors and provides appropriate responses.

    Args:
        request: FastAPI request object
        exc: Exception instance

    Returns:
        JSONResponse with error details (sanitized in production)
    """
    error_id = _get_error_id(request)

    # Check if this is a network error
    if detect_network_error(exc):
        return await network_error_handler(request, exc)

    # Always log the full exception with stack trace for debugging
    logger.exception(
        f"Unhandled exception in {request.method} {request.url.path} (request_id={error_id}): {exc}"
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

    # Handle network errors specifically
    app.add_exception_handler(NetworkOfflineError, network_error_handler)
    app.add_exception_handler(TimeoutError, network_error_handler)
    app.add_exception_handler(asyncio.TimeoutError, network_error_handler)
    app.add_exception_handler(ConnectionError, network_error_handler)
    app.add_exception_handler(socket.error, network_error_handler)

    # Catch-all for any unhandled exceptions
    app.add_exception_handler(Exception, general_exception_handler)

    logger.info("Registered custom exception handlers (including network error handlers)")

"""FastAPI middleware for request tracking and logging."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Callable
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)

# Context variable for request ID (thread-safe)
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> str | None:
    """Get current request ID from context."""
    return request_id_var.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware that assigns a unique ID to each request.

    The request ID is:
    - Generated as UUID4 if not provided
    - Read from X-Request-ID header if present
    - Stored in request.state.request_id
    - Added to response as X-Request-ID header
    - Available via get_request_id() context function
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        # Use existing request ID or generate new one
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Store in request state and context var
        request.state.request_id = request_id
        token = request_id_var.set(request_id)

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            request_id_var.reset(token)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs request/response info without body content.

    Logs:
    - Request: method, path, client IP, request ID
    - Response: status code, duration
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        start_time = time.perf_counter()

        # Get request ID (set by RequestIDMiddleware)
        request_id = getattr(request.state, "request_id", None) or get_request_id()

        # Log request (without body for privacy/security)
        client_ip = request.client.host if request.client else "unknown"
        logger.info(
            "Request started",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
            },
        )

        response = await call_next(request)

        # Calculate duration
        duration_ms = (time.perf_counter() - start_time) * 1000

        # Log response
        logger.info(
            "Request completed",
            extra={
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "duration_ms": round(duration_ms, 2),
            },
        )

        return response


class GracefulShutdownMiddleware(BaseHTTPMiddleware):
    """Middleware for graceful shutdown handling.

    Features:
    - Rejects new requests when shutting down (503 Service Unavailable)
    - Tracks active connections for graceful drain
    - Allows health checks even during shutdown

    During shutdown:
    - Health check endpoint returns 503 (load balancers will remove from pool)
    - All other requests get 503 with Retry-After header
    - Active requests are allowed to complete
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Response]
    ) -> Response:
        from starlette.responses import JSONResponse

        # Get app state
        app_state = getattr(request.app.state, "app_state", None)
        if not app_state:
            # No app state, proceed normally
            return await call_next(request)

        # Check if shutting down
        if app_state.shutting_down:
            # Allow health checks to fail (for load balancer detection)
            if request.url.path == "/health":
                return JSONResponse(
                    status_code=503,
                    content={"status": "shutting_down"},
                )

            # Reject new requests
            logger.warning(
                f"Rejecting request during shutdown: {request.method} {request.url.path}",
                extra={"request_id": get_request_id()},
            )
            return JSONResponse(
                status_code=503,
                content={
                    "detail": "Server is shutting down. Please retry.",
                    "status": "shutting_down",
                },
                headers={"Retry-After": "10"},  # Suggest retry in 10 seconds
            )

        # Track active connection
        app_state.active_connections += 1

        try:
            response = await call_next(request)
            return response
        finally:
            app_state.active_connections -= 1

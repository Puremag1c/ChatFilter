"""FastAPI middleware for request tracking, logging, session management, and CSRF protection."""

from __future__ import annotations

import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from chatfilter.web.csrf import CSRF_FORM_FIELD, CSRF_HEADER_NAME, validate_csrf_token
from chatfilter.web.session import get_session, set_session_cookie

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
    - Used as correlation ID for logging
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Use existing request ID or generate new one
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Store in request state and context var
        request.state.request_id = request_id
        token = request_id_var.set(request_id)

        # Set correlation ID for logging (use first 16 chars of request ID)
        from chatfilter.utils.logging import set_correlation_id

        correlation_id = request_id[:16] if len(request_id) >= 16 else request_id
        set_correlation_id(correlation_id)

        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = request_id
            return response
        finally:
            request_id_var.reset(token)
            # Clear correlation ID after request
            from chatfilter.utils.logging import clear_correlation_id

            clear_correlation_id()


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware that logs request/response info without body content.

    Logs:
    - Request: method, path, client IP, request ID
    - Response: status code, duration
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
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


class SessionMiddleware(BaseHTTPMiddleware):
    """Middleware for automatic session management.

    Features:
    - Automatically creates sessions for new visitors
    - Manages session cookies on all responses
    - Provides session data via request.state.session
    - Performs periodic cleanup of expired sessions

    Session data is accessible in route handlers via:
        session = get_session(request)
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Get or create session
        session = get_session(request)

        # Process request
        response = await call_next(request)

        # Set session cookie on response (if not already set)
        if session:
            set_session_cookie(response, session)

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
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that adds security headers to all responses.

    Headers added:
    - X-Content-Type-Options: nosniff (prevent MIME type sniffing)
    - X-Frame-Options: DENY (prevent clickjacking)
    - X-XSS-Protection: 1; mode=block (enable XSS protection)
    - Referrer-Policy: strict-origin-when-cross-origin (control referrer info)
    - Content-Security-Policy: Restrictive policy to prevent XSS

    These headers help prevent information disclosure and common web attacks.
    """

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        response = await call_next(request)

        # Prevent MIME type sniffing (information disclosure)
        response.headers["X-Content-Type-Options"] = "nosniff"

        # Prevent clickjacking attacks
        response.headers["X-Frame-Options"] = "DENY"

        # Enable XSS protection in older browsers
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Control referrer information sent to external sites
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy - allows inline styles/scripts for HTMX
        # Note: This is permissive for HTMX functionality but still provides protection
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )

        return response


class CSRFProtectionMiddleware(BaseHTTPMiddleware):
    """Middleware for CSRF protection on state-changing requests.

    Validates CSRF tokens on POST/DELETE requests to prevent Cross-Site
    Request Forgery attacks. Token can be provided via:
    - X-CSRF-Token header (recommended for AJAX/HTMX)
    - csrf_token form field (for traditional forms)

    Features:
    - Validates all POST/DELETE requests (except exempt paths)
    - Supports both header and form-based tokens
    - Constant-time comparison to prevent timing attacks
    - Clear error messages for debugging

    Exempt paths (no CSRF check):
    - /health - Health check endpoint
    - /api/export/* - Export endpoints (read-only operations)
    """

    # Paths exempt from CSRF validation
    EXEMPT_PATHS = {
        "/health",
    }

    # Path prefixes exempt from CSRF validation
    EXEMPT_PREFIXES = (
        "/api/export/",  # Export endpoints are read-only despite POST
    )

    def _is_exempt(self, path: str) -> bool:
        """Check if path is exempt from CSRF validation."""
        if path in self.EXEMPT_PATHS:
            return True

        return any(path.startswith(prefix) for prefix in self.EXEMPT_PREFIXES)

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Only check state-changing methods
        if request.method not in ("POST", "DELETE"):
            return await call_next(request)

        # Skip CSRF check for exempt paths
        if self._is_exempt(request.url.path):
            logger.debug(f"CSRF check skipped for exempt path: {request.url.path}")
            return await call_next(request)

        # Get session (created by SessionMiddleware)
        session = get_session(request)
        if not session:
            logger.error("No session found for CSRF validation")
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "CSRF validation failed: No session",
                    "error": "csrf_no_session",
                },
            )

        # Try to get token from header first (preferred for AJAX/HTMX)
        csrf_token = request.headers.get(CSRF_HEADER_NAME)

        # If not in header, try form data
        if not csrf_token:
            try:
                form_data = await request.form()
                token_value = form_data.get(CSRF_FORM_FIELD)
                # Ensure we only accept string tokens, not file uploads
                csrf_token = token_value if isinstance(token_value, str) else None
            except Exception:
                # Not a form request or error parsing form
                pass

        # Validate token
        if not csrf_token:
            logger.warning(
                f"CSRF token missing for {request.method} {request.url.path}",
                extra={"request_id": get_request_id()},
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "CSRF validation failed: Token missing",
                    "error": "csrf_token_missing",
                },
            )

        if not validate_csrf_token(session, csrf_token):
            logger.warning(
                f"CSRF token invalid for {request.method} {request.url.path}",
                extra={"request_id": get_request_id()},
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "CSRF validation failed: Invalid token",
                    "error": "csrf_token_invalid",
                },
            )

        # Token valid, proceed with request
        logger.debug(f"CSRF token validated for {request.method} {request.url.path}")
        return await call_next(request)

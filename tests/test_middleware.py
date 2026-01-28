"""Tests for web middleware.

Tests cover:
- RequestIDMiddleware: request ID generation and propagation
- RequestLoggingMiddleware: request/response logging
- SessionMiddleware: session management
- GracefulShutdownMiddleware: shutdown handling
- SecurityHeadersMiddleware: security headers
- NetworkStatusMiddleware: network status
- CSRFProtectionMiddleware: CSRF validation
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from chatfilter.web.middleware import (
    CSRFProtectionMiddleware,
    GracefulShutdownMiddleware,
    NetworkStatusMiddleware,
    RequestIDMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    SessionMiddleware,
    get_request_id,
    request_id_var,
)


class TestRequestIDMiddleware:
    """Tests for RequestIDMiddleware."""

    @pytest.fixture
    def app(self) -> MagicMock:
        """Create a mock ASGI app."""
        return MagicMock()

    @pytest.fixture
    def middleware(self, app: MagicMock) -> RequestIDMiddleware:
        """Create middleware instance."""
        return RequestIDMiddleware(app)

    @pytest.mark.asyncio
    async def test_generates_request_id(self, middleware: RequestIDMiddleware) -> None:
        """Should generate UUID4 if no X-Request-ID header."""
        request = MagicMock(spec=Request)
        request.headers = {}
        request.state = MagicMock()

        response = Response(content="test")
        call_next = AsyncMock(return_value=response)

        result = await middleware.dispatch(request, call_next)

        # Check request ID was set in state
        assert hasattr(request.state, "request_id")
        # Check response has header
        assert "X-Request-ID" in result.headers

    @pytest.mark.asyncio
    async def test_uses_existing_request_id(self, middleware: RequestIDMiddleware) -> None:
        """Should use X-Request-ID header if provided."""
        existing_id = "custom-request-id-123"
        request = MagicMock(spec=Request)
        request.headers = {"X-Request-ID": existing_id}
        request.state = MagicMock()

        response = Response(content="test")
        call_next = AsyncMock(return_value=response)

        result = await middleware.dispatch(request, call_next)

        assert request.state.request_id == existing_id
        assert result.headers["X-Request-ID"] == existing_id


class TestGetRequestId:
    """Tests for get_request_id function."""

    def test_returns_none_when_not_set(self) -> None:
        """Should return None when no request ID in context."""
        token = request_id_var.set(None)
        try:
            assert get_request_id() is None
        finally:
            request_id_var.reset(token)

    def test_returns_value_when_set(self) -> None:
        """Should return request ID when set."""
        test_id = "test-id-456"
        token = request_id_var.set(test_id)
        try:
            assert get_request_id() == test_id
        finally:
            request_id_var.reset(token)


class TestRequestLoggingMiddleware:
    """Tests for RequestLoggingMiddleware."""

    @pytest.fixture
    def app(self) -> MagicMock:
        """Create a mock ASGI app."""
        return MagicMock()

    @pytest.fixture
    def middleware(self, app: MagicMock) -> RequestLoggingMiddleware:
        """Create middleware instance."""
        return RequestLoggingMiddleware(app)

    @pytest.mark.asyncio
    async def test_logs_request(self, middleware: RequestLoggingMiddleware) -> None:
        """Should log request start and completion."""
        request = MagicMock(spec=Request)
        request.method = "GET"
        request.url = MagicMock()
        request.url.path = "/test"
        request.client = MagicMock()
        request.client.host = "127.0.0.1"
        request.state = MagicMock()
        request.state.request_id = "test-123"

        response = Response(content="test", status_code=200)
        call_next = AsyncMock(return_value=response)

        with patch("chatfilter.web.middleware.logger") as mock_logger:
            result = await middleware.dispatch(request, call_next)

            # Check request was logged
            assert mock_logger.info.call_count >= 2  # Start and complete
            assert result.status_code == 200


class TestSessionMiddleware:
    """Tests for SessionMiddleware."""

    @pytest.fixture
    def app(self) -> MagicMock:
        """Create a mock ASGI app."""
        return MagicMock()

    @pytest.fixture
    def middleware(self, app: MagicMock) -> SessionMiddleware:
        """Create middleware instance."""
        return SessionMiddleware(app)

    @pytest.mark.asyncio
    async def test_creates_session(self, middleware: SessionMiddleware) -> None:
        """Should create session and set cookie."""
        request = MagicMock(spec=Request)
        request.cookies = {}
        request.state = MagicMock(spec=[])

        response = MagicMock(spec=Response)
        call_next = AsyncMock(return_value=response)

        with patch("chatfilter.web.middleware.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_get_session.return_value = mock_session

            await middleware.dispatch(request, call_next)

            mock_get_session.assert_called_once_with(request)


class TestSecurityHeadersMiddleware:
    """Tests for SecurityHeadersMiddleware."""

    @pytest.fixture
    def app(self) -> MagicMock:
        """Create a mock ASGI app."""
        return MagicMock()

    @pytest.fixture
    def middleware(self, app: MagicMock) -> SecurityHeadersMiddleware:
        """Create middleware instance."""
        return SecurityHeadersMiddleware(app)

    @pytest.mark.asyncio
    async def test_adds_security_headers(self, middleware: SecurityHeadersMiddleware) -> None:
        """Should add all security headers to response."""
        request = MagicMock(spec=Request)
        response = Response(content="test")
        call_next = AsyncMock(return_value=response)

        result = await middleware.dispatch(request, call_next)

        assert result.headers["X-Content-Type-Options"] == "nosniff"
        assert result.headers["X-Frame-Options"] == "DENY"
        assert result.headers["X-XSS-Protection"] == "1; mode=block"
        assert result.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "Content-Security-Policy" in result.headers


class TestGracefulShutdownMiddleware:
    """Tests for GracefulShutdownMiddleware."""

    @pytest.fixture
    def app(self) -> MagicMock:
        """Create a mock ASGI app."""
        return MagicMock()

    @pytest.fixture
    def middleware(self, app: MagicMock) -> GracefulShutdownMiddleware:
        """Create middleware instance."""
        return GracefulShutdownMiddleware(app)

    @pytest.mark.asyncio
    async def test_normal_request(self, middleware: GracefulShutdownMiddleware) -> None:
        """Should process request normally when not shutting down."""
        request = MagicMock(spec=Request)
        request.app.state = MagicMock()
        request.app.state.app_state = None  # No app state

        response = Response(content="test")
        call_next = AsyncMock(return_value=response)

        result = await middleware.dispatch(request, call_next)

        assert result is response

    @pytest.mark.asyncio
    async def test_rejects_during_shutdown(self, middleware: GracefulShutdownMiddleware) -> None:
        """Should return 503 during shutdown."""
        request = MagicMock(spec=Request)
        request.method = "GET"
        request.url = MagicMock()
        request.url.path = "/api/test"

        app_state = MagicMock()
        app_state.shutting_down = True
        request.app.state.app_state = app_state

        call_next = AsyncMock()

        result = await middleware.dispatch(request, call_next)

        assert result.status_code == 503
        call_next.assert_not_called()

    @pytest.mark.asyncio
    async def test_health_check_during_shutdown(
        self, middleware: GracefulShutdownMiddleware
    ) -> None:
        """Health check should also return 503 during shutdown."""
        request = MagicMock(spec=Request)
        request.url = MagicMock()
        request.url.path = "/health"

        app_state = MagicMock()
        app_state.shutting_down = True
        request.app.state.app_state = app_state

        call_next = AsyncMock()

        result = await middleware.dispatch(request, call_next)

        assert result.status_code == 503


class TestCSRFProtectionMiddleware:
    """Tests for CSRFProtectionMiddleware."""

    @pytest.fixture
    def app(self) -> MagicMock:
        """Create a mock ASGI app."""
        return MagicMock()

    @pytest.fixture
    def middleware(self, app: MagicMock) -> CSRFProtectionMiddleware:
        """Create middleware instance."""
        return CSRFProtectionMiddleware(app)

    def test_is_exempt_health(self, middleware: CSRFProtectionMiddleware) -> None:
        """Health endpoint should be exempt."""
        assert middleware._is_exempt("/health") is True

    def test_is_exempt_export(self, middleware: CSRFProtectionMiddleware) -> None:
        """Export endpoints should be exempt."""
        assert middleware._is_exempt("/api/export/data") is True

    def test_is_not_exempt(self, middleware: CSRFProtectionMiddleware) -> None:
        """Normal endpoints should not be exempt."""
        assert middleware._is_exempt("/api/sessions") is False

    @pytest.mark.asyncio
    async def test_skips_get_requests(self, middleware: CSRFProtectionMiddleware) -> None:
        """GET requests should not require CSRF."""
        request = MagicMock(spec=Request)
        request.method = "GET"

        response = Response(content="test")
        call_next = AsyncMock(return_value=response)

        result = await middleware.dispatch(request, call_next)

        assert result is response

    @pytest.mark.asyncio
    async def test_rejects_missing_token(self, middleware: CSRFProtectionMiddleware) -> None:
        """POST without CSRF token should be rejected."""
        request = MagicMock(spec=Request)
        request.method = "POST"
        request.url = MagicMock()
        request.url.path = "/api/sessions"
        request.headers = {}
        request.cookies = {}
        request.state = MagicMock(spec=[])

        async def no_form():
            return {}

        request.form = no_form

        with patch("chatfilter.web.middleware.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_get_session.return_value = mock_session

            result = await middleware.dispatch(request, AsyncMock())

            assert result.status_code == 403

    @pytest.mark.asyncio
    async def test_accepts_valid_token(self, middleware: CSRFProtectionMiddleware) -> None:
        """POST with valid CSRF token should be accepted."""
        valid_token = "valid-csrf-token"
        request = MagicMock(spec=Request)
        request.method = "POST"
        request.url = MagicMock()
        request.url.path = "/api/sessions"
        request.headers = {"X-CSRF-Token": valid_token}
        request.cookies = {}
        request.state = MagicMock(spec=[])

        response = Response(content="test")
        call_next = AsyncMock(return_value=response)

        with patch("chatfilter.web.middleware.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_get_session.return_value = mock_session

            with patch("chatfilter.web.middleware.validate_csrf_token") as mock_validate:
                mock_validate.return_value = True

                result = await middleware.dispatch(request, call_next)

                assert result is response
                mock_validate.assert_called_once_with(mock_session, valid_token)


class TestNetworkStatusMiddleware:
    """Tests for NetworkStatusMiddleware."""

    @pytest.fixture
    def app(self) -> MagicMock:
        """Create a mock ASGI app."""
        return MagicMock()

    @pytest.mark.asyncio
    async def test_adds_network_status_header(self, app: MagicMock) -> None:
        """Should add X-Network-Status header."""
        middleware = NetworkStatusMiddleware(app)

        request = MagicMock(spec=Request)
        request.url = MagicMock()
        request.url.path = "/api/test"
        request.state = MagicMock()

        response = Response(content="test")
        call_next = AsyncMock(return_value=response)

        with patch.object(middleware, "network_monitor") as mock_monitor:
            mock_status = MagicMock()
            mock_status.is_online = True
            mock_monitor.get_status = AsyncMock(return_value=mock_status)

            result = await middleware.dispatch(request, call_next)

            assert result.headers["X-Network-Status"] == "online"

    def test_is_exempt(self, app: MagicMock) -> None:
        """Health and static paths should be exempt."""
        middleware = NetworkStatusMiddleware(app)

        assert middleware._is_exempt("/health") is True
        assert middleware._is_exempt("/static/js/app.js") is True
        assert middleware._is_exempt("/api/sessions") is False

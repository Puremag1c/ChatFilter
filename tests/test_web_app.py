"""Tests for FastAPI web application."""

from fastapi.testclient import TestClient

from chatfilter.web.app import create_app


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    def test_health_returns_200(self) -> None:
        """Test health endpoint returns 200 OK."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/health")

        assert response.status_code == 200

    def test_health_returns_status_healthy(self) -> None:
        """Test health endpoint returns healthy status."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/health")
        data = response.json()

        assert data["status"] == "healthy"

    def test_health_returns_version(self) -> None:
        """Test health endpoint returns application version."""
        from chatfilter import __version__

        app = create_app()
        client = TestClient(app)

        response = client.get("/health")
        data = response.json()

        assert data["version"] == __version__


class TestRequestIDMiddleware:
    """Tests for request ID middleware."""

    def test_response_has_request_id_header(self) -> None:
        """Test that responses include X-Request-ID header."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/health")

        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) > 0

    def test_request_id_is_uuid_format(self) -> None:
        """Test that generated request ID is UUID format."""
        import uuid

        app = create_app()
        client = TestClient(app)

        response = client.get("/health")
        request_id = response.headers["X-Request-ID"]

        # Should be valid UUID
        uuid.UUID(request_id)  # Raises if invalid

    def test_client_provided_request_id_is_preserved(self) -> None:
        """Test that client-provided X-Request-ID is preserved."""
        app = create_app()
        client = TestClient(app)

        custom_id = "test-request-123"
        response = client.get("/health", headers={"X-Request-ID": custom_id})

        assert response.headers["X-Request-ID"] == custom_id


class TestCORSConfiguration:
    """Tests for CORS middleware."""

    def test_cors_headers_present_for_allowed_origin(self) -> None:
        """Test CORS headers are present for allowed origins."""
        app = create_app(cors_origins=["http://localhost:3000"])
        client = TestClient(app)

        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )

        assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"

    def test_default_cors_allows_localhost(self) -> None:
        """Test default CORS configuration allows localhost."""
        app = create_app()
        client = TestClient(app)

        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:8000",
                "Access-Control-Request-Method": "GET",
            },
        )

        assert response.headers.get("access-control-allow-origin") == "http://localhost:8000"


class TestAppFactory:
    """Tests for app factory pattern."""

    def test_create_app_returns_fastapi_instance(self) -> None:
        """Test that create_app returns FastAPI instance."""
        from fastapi import FastAPI

        app = create_app()

        assert isinstance(app, FastAPI)

    def test_create_app_with_debug_mode(self) -> None:
        """Test creating app with debug mode enabled."""
        app = create_app(debug=True)

        assert app.debug is True

    def test_create_app_default_not_debug(self) -> None:
        """Test that debug mode is off by default."""
        app = create_app()

        assert app.debug is False

    def test_multiple_app_instances_are_independent(self) -> None:
        """Test that multiple app instances don't share state."""
        app1 = create_app(debug=True)
        app2 = create_app(debug=False)

        assert app1.debug is True
        assert app2.debug is False


class TestStaticFiles:
    """Tests for static file serving."""

    def test_static_css_served(self) -> None:
        """Test that static CSS file is served."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/static/css/style.css")

        assert response.status_code == 200
        assert "text/css" in response.headers.get("content-type", "")

    def test_static_404_for_missing_file(self) -> None:
        """Test 404 for missing static files."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/static/nonexistent.js")

        assert response.status_code == 404

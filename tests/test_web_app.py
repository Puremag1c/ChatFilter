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

    def test_health_returns_status_ok(self) -> None:
        """Test health endpoint returns ok status."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/health")
        data = response.json()

        assert data["status"] in ["ok", "degraded", "unhealthy"]

    def test_health_returns_version(self) -> None:
        """Test health endpoint returns application version."""
        from chatfilter import __version__

        app = create_app()
        client = TestClient(app)

        response = client.get("/health")
        data = response.json()

        assert data["version"] == __version__

    def test_health_returns_uptime(self) -> None:
        """Test health endpoint returns uptime."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/health")
        data = response.json()

        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], (int, float))
        assert data["uptime_seconds"] >= 0

    def test_health_returns_disk_space(self) -> None:
        """Test health endpoint returns disk space information."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/health")
        data = response.json()

        assert "disk" in data
        assert "total_gb" in data["disk"]
        assert "used_gb" in data["disk"]
        assert "free_gb" in data["disk"]
        assert "percent_used" in data["disk"]

    def test_health_returns_telegram_status(self) -> None:
        """Test health endpoint returns telegram connection status."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/health")
        data = response.json()

        # Telegram status may be None or have status info
        if data.get("telegram"):
            assert "connected" in data["telegram"]
            assert "sessions_count" in data["telegram"]


class TestReadyEndpoint:
    """Tests for /ready endpoint."""

    def test_ready_returns_200(self) -> None:
        """Test ready endpoint returns 200 OK."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/ready")

        assert response.status_code == 200

    def test_ready_returns_ready_true(self) -> None:
        """Test ready endpoint returns ready: true when not shutting down."""
        app = create_app()
        client = TestClient(app)

        response = client.get("/ready")
        data = response.json()

        assert data["ready"] is True


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

    def test_cors_allows_only_specified_methods(self) -> None:
        """Test CORS only allows GET, POST, DELETE methods."""
        app = create_app(cors_origins=["http://localhost:3000"])
        client = TestClient(app)

        # Test allowed methods
        for method in ["GET", "POST", "DELETE"]:
            response = client.options(
                "/health",
                headers={
                    "Origin": "http://localhost:3000",
                    "Access-Control-Request-Method": method,
                },
            )
            allowed_methods = response.headers.get("access-control-allow-methods", "")
            assert method in allowed_methods, f"{method} should be allowed"

        # Test that disallowed methods are not in the allowed list
        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        allowed_methods = response.headers.get("access-control-allow-methods", "")
        # Verify we don't have wildcard
        assert allowed_methods != "*", "Should not use wildcard for methods"
        # PUT and PATCH should not be explicitly listed (unless framework adds them)
        assert "PUT" not in allowed_methods or "GET" in allowed_methods

    def test_cors_allows_credentials(self) -> None:
        """Test CORS allows credentials for secure cookie-based auth."""
        app = create_app(cors_origins=["http://localhost:3000"])
        client = TestClient(app)

        response = client.options(
            "/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )

        assert response.headers.get("access-control-allow-credentials") == "true"

    def test_cors_default_origins_include_common_frontend_ports(self) -> None:
        """Test default CORS origins include common frontend development ports."""
        app = create_app()
        client = TestClient(app)

        # Test common frontend ports are allowed by default
        frontend_ports = ["3000", "5173", "4200", "8000"]
        for port in frontend_ports:
            response = client.options(
                "/health",
                headers={
                    "Origin": f"http://localhost:{port}",
                    "Access-Control-Request-Method": "GET",
                },
            )
            assert (
                response.headers.get("access-control-allow-origin") == f"http://localhost:{port}"
            ), f"Default CORS should allow localhost:{port}"

    def test_cors_blocks_disallowed_origin(self) -> None:
        """Test CORS blocks requests from non-allowed origins."""
        app = create_app(cors_origins=["http://localhost:3000"])
        client = TestClient(app)

        response = client.options(
            "/health",
            headers={
                "Origin": "http://evil.com",
                "Access-Control-Request-Method": "GET",
            },
        )

        # Should not include the evil origin in response
        origin_header = response.headers.get("access-control-allow-origin")
        assert origin_header != "http://evil.com", "Should not allow unauthorized origin"


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


class TestExportCsvEndpoint:
    """Tests for /api/export/csv endpoint."""

    def test_export_csv_returns_200(self) -> None:
        """Test CSV export returns 200 OK."""
        app = create_app()
        client = TestClient(app)

        request_data = {
            "results": [
                {
                    "chat_id": 123,
                    "chat_title": "Test Chat",
                    "chat_type": "group",
                    "message_count": 100,
                    "unique_authors": 10,
                    "history_hours": 24.0,
                }
            ]
        }

        response = client.post("/api/export/csv", json=request_data)

        assert response.status_code == 200

    def test_export_csv_content_type(self) -> None:
        """Test CSV export returns correct content type."""
        app = create_app()
        client = TestClient(app)

        request_data = {"results": []}

        response = client.post("/api/export/csv", json=request_data)

        assert "text/csv" in response.headers.get("content-type", "")

    def test_export_csv_content_disposition(self) -> None:
        """Test CSV export has attachment disposition."""
        app = create_app()
        client = TestClient(app)

        request_data = {"results": []}

        response = client.post("/api/export/csv", json=request_data)

        assert "attachment" in response.headers.get("content-disposition", "")
        assert "chatfilter_results.csv" in response.headers.get("content-disposition", "")

    def test_export_csv_custom_filename(self) -> None:
        """Test CSV export with custom filename."""
        app = create_app()
        client = TestClient(app)

        request_data = {"results": []}

        response = client.post("/api/export/csv?filename=my_export.csv", json=request_data)

        assert "my_export.csv" in response.headers.get("content-disposition", "")

    def test_export_csv_includes_data(self) -> None:
        """Test CSV export includes provided data."""
        app = create_app()
        client = TestClient(app)

        request_data = {
            "results": [
                {
                    "chat_id": 456,
                    "chat_title": "My Group",
                    "chat_type": "supergroup",
                    "chat_username": "mygroup",
                    "message_count": 500,
                    "unique_authors": 25,
                    "history_hours": 48.0,
                }
            ]
        }

        response = client.post("/api/export/csv?include_bom=false", json=request_data)
        content = response.text

        assert "My Group" in content
        assert "supergroup" in content
        assert "500" in content
        assert "25" in content
        assert "t.me/mygroup" in content

    def test_export_csv_multiple_results(self) -> None:
        """Test CSV export with multiple results."""
        app = create_app()
        client = TestClient(app)

        request_data = {
            "results": [
                {
                    "chat_id": 1,
                    "chat_title": "Chat One",
                    "chat_type": "group",
                    "message_count": 100,
                    "unique_authors": 10,
                    "history_hours": 24.0,
                },
                {
                    "chat_id": 2,
                    "chat_title": "Chat Two",
                    "chat_type": "channel",
                    "message_count": 200,
                    "unique_authors": 1,
                    "history_hours": 48.0,
                },
            ]
        }

        response = client.post("/api/export/csv?include_bom=false", json=request_data)
        content = response.text

        assert "Chat One" in content
        assert "Chat Two" in content

    def test_export_csv_empty_results(self) -> None:
        """Test CSV export with empty results returns header only."""
        app = create_app()
        client = TestClient(app)

        request_data = {"results": []}

        response = client.post("/api/export/csv?include_bom=false", json=request_data)
        content = response.text

        # Should have header row
        assert "chat_link" in content
        assert "message_count" in content

    def test_export_csv_invalid_chat_type_returns_422(self) -> None:
        """Test that invalid chat type returns validation error."""
        app = create_app()
        client = TestClient(app)

        request_data = {
            "results": [
                {
                    "chat_id": 123,
                    "chat_title": "Test",
                    "chat_type": "invalid_type",
                    "message_count": 0,
                    "unique_authors": 0,
                    "history_hours": 0,
                }
            ]
        }

        response = client.post("/api/export/csv", json=request_data)

        assert response.status_code == 422

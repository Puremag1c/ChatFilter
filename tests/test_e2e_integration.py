"""E2E integration tests for complete workflow: session load → analysis → export.

Tests the full application flow with mocked Telegram API to ensure
components work together correctly.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from chatfilter.config import Settings, reset_settings
from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType
from chatfilter.web.app import create_app


def extract_csrf_token(html: str) -> str | None:
    """Extract CSRF token from HTML meta tag.

    Args:
        html: HTML content containing meta tag with csrf-token

    Returns:
        CSRF token string or None if not found
    """
    match = re.search(r'<meta name="csrf-token" content="([^"]+)"', html)
    return match.group(1) if match else None


@pytest.fixture
def e2e_settings(isolated_tmp_dir: Path) -> Settings:
    """Create isolated settings for E2E tests.

    Returns:
        Settings instance with isolated data directory
    """
    reset_settings()
    settings = Settings(
        data_dir=isolated_tmp_dir,
        debug=True,
    )
    errors = settings.ensure_data_dirs()
    assert errors == []
    return settings


@pytest.fixture
def e2e_app(e2e_settings: Settings) -> TestClient:
    """Create FastAPI test client with isolated settings.

    Returns:
        TestClient configured for E2E testing
    """
    app = create_app(settings=e2e_settings)
    return TestClient(app)


@pytest.fixture
def mock_telegram_data() -> dict[str, Any]:
    """Provide mock Telegram API responses for E2E tests.

    Returns:
        Dictionary with mock dialogs and messages
    """
    now = datetime.now(UTC)

    # Mock dialogs (chats)
    dialogs = []
    for i in range(3):
        dialog = MagicMock()
        dialog.id = 1000 + i
        dialog.name = f"Test Chat {i + 1}"
        dialog.title = f"Test Chat {i + 1}"

        entity = MagicMock()
        entity.id = 1000 + i
        entity.username = f"testchat{i + 1}"
        entity.participants_count = 100 + i * 50

        # Create Channel entity
        from telethon.tl.types import Channel

        entity.__class__ = Channel
        entity.megagroup = True
        entity.forum = False
        entity.title = f"Test Chat {i + 1}"

        dialog.entity = entity
        dialogs.append(dialog)

    # Mock messages for each chat
    messages_by_chat = {}
    for i in range(3):
        chat_id = 1000 + i
        messages = []
        for j in range(10):  # 10 messages per chat
            msg = MagicMock()
            msg.id = j + 1
            msg.message = f"Test message {j + 1} in chat {chat_id}"
            msg.sender_id = 2000 + (j % 3)  # 3 different authors
            msg.from_id = None
            msg.date = now - timedelta(hours=10 - j)
            msg.media = None
            messages.append(msg)
        messages_by_chat[chat_id] = messages

    return {
        "dialogs": dialogs,
        "messages_by_chat": messages_by_chat,
    }


@pytest.fixture
def mock_telegram_client(mock_telegram_data: dict[str, Any]) -> MagicMock:
    """Create mock TelegramClient that returns pre-configured data.

    Args:
        mock_telegram_data: Mock Telegram responses

    Returns:
        Mock TelegramClient with async methods configured
    """
    client = MagicMock()

    # Configure async methods
    client.connect = AsyncMock()
    client.disconnect = AsyncMock()
    client.is_connected = MagicMock(return_value=True)
    client.get_me = AsyncMock(return_value=MagicMock(id=12345, username="testuser"))

    # Mock iter_dialogs to return test chats
    async def mock_iter_dialogs(**kwargs: Any) -> Any:
        for dialog in mock_telegram_data["dialogs"]:
            yield dialog

    client.iter_dialogs = mock_iter_dialogs

    # Mock iter_messages to return test messages
    def mock_iter_messages(chat_id: int, **kwargs: Any) -> Any:
        async def _iter() -> Any:
            messages = mock_telegram_data["messages_by_chat"].get(chat_id, [])
            for msg in messages:
                yield msg

        return _iter()

    client.iter_messages = mock_iter_messages
    client.get_entity = AsyncMock()

    return client


class TestE2EIntegration:
    """E2E integration tests for complete workflow."""

    def test_csv_export_flow(self) -> None:
        """Test CSV export with mock analysis results.

        This test ensures the export flow works:
        1. Create mock analysis results
        2. Export to CSV format
        3. Verify CSV content

        Note: This is a simplified E2E test focusing on the export component
        since the full flow requires complex HTMX/HTML handling.
        """
        # Create test app
        app = create_app()
        client = TestClient(app)

        # Create mock analysis results
        now = datetime.now(UTC)
        mock_results = []
        for i in range(2):
            result = AnalysisResult(
                chat=Chat(
                    id=1000 + i,
                    title=f"Test Chat {i + 1}",
                    chat_type=ChatType.SUPERGROUP,
                    username=f"testchat{i + 1}",
                ),
                metrics=ChatMetrics(
                    message_count=10,
                    unique_authors=3,
                    history_hours=10.0,
                    first_message_at=now - timedelta(hours=10),
                    last_message_at=now,
                ),
                analyzed_at=now,
            )
            mock_results.append(result)

        # Export to CSV
        export_data = {
            "results": [
                {
                    "chat_id": r.chat.id,
                    "chat_title": r.chat.title,
                    "chat_type": r.chat.chat_type.value,
                    "chat_username": r.chat.username,
                    "message_count": r.metrics.message_count,
                    "unique_authors": r.metrics.unique_authors,
                    "history_hours": r.metrics.history_hours,
                    "first_message_at": r.metrics.first_message_at.isoformat()
                    if r.metrics.first_message_at
                    else None,
                    "last_message_at": r.metrics.last_message_at.isoformat()
                    if r.metrics.last_message_at
                    else None,
                    "analyzed_at": r.analyzed_at.isoformat(),
                }
                for r in mock_results
            ]
        }

        response = client.post(
            "/api/export/csv?filename=test_results.csv",
            json=export_data,
        )

        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv; charset=utf-8"
        disposition = response.headers["content-disposition"]
        assert "attachment" in disposition
        # Filename now includes timestamp for uniqueness
        assert "test_results_" in disposition
        assert ".csv" in disposition

        # Verify CSV content
        csv_content = response.content.decode("utf-8-sig")  # Handle BOM
        assert "chat_link" in csv_content  # CSV uses chat_link, not chat_id
        assert "chat_title" in csv_content
        assert "Test Chat 1" in csv_content
        assert "Test Chat 2" in csv_content
        assert "https://t.me/testchat1" in csv_content  # Chat link format

    def test_session_upload_with_invalid_file(
        self,
        e2e_app: TestClient,
        isolated_tmp_dir: Path,
        telegram_config_file: Path,
    ) -> None:
        """Test that invalid session file shows error in HTML response.

        Args:
            e2e_app: Test client
            isolated_tmp_dir: Isolated temp directory
            telegram_config_file: Config file fixture
        """
        # Get CSRF token from home page
        home_response = e2e_app.get("/")
        csrf_token = extract_csrf_token(home_response.text)
        assert csrf_token is not None, "CSRF token not found in home page"

        # Create invalid session file (not SQLite)
        invalid_session = isolated_tmp_dir / "invalid.session"
        invalid_session.write_text("This is not a valid SQLite file")

        with invalid_session.open("rb") as session_f, telegram_config_file.open("rb") as config_f:
            response = e2e_app.post(
                "/api/sessions/upload",
                data={"session_name": "invalid_session"},
                files={
                    "session_file": ("invalid.session", session_f, "application/octet-stream"),
                    "config_file": ("config.json", config_f, "application/json"),
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        # The endpoint returns HTML (HTMX), check for error in response
        assert response.status_code == 200  # HTMX returns 200 with error HTML
        html_content = response.text
        # Should contain error message in the HTML
        assert (
            "error" in html_content.lower()
            or "invalid" in html_content.lower()
            or "not a valid" in html_content.lower()
        )

    def test_export_csv_with_empty_results(
        self,
        e2e_app: TestClient,
    ) -> None:
        """Test CSV export with empty results list.

        Args:
            e2e_app: Test client
        """
        export_data: dict[str, list[Any]] = {"results": []}

        response = e2e_app.post(
            "/api/export/csv?filename=empty.csv",
            json=export_data,
        )

        assert response.status_code == 200
        csv_content = response.content.decode("utf-8-sig")
        # Should have headers but no data rows
        assert "chat_link" in csv_content  # CSV uses chat_link, not chat_id
        assert "chat_title" in csv_content
        lines = csv_content.strip().split("\n")
        assert len(lines) == 1  # Only header row

    def test_export_csv_with_unicode_content(
        self,
        e2e_app: TestClient,
    ) -> None:
        """Test CSV export handles Unicode characters correctly.

        Args:
            e2e_app: Test client
        """
        now = datetime.now(UTC)
        export_data = {
            "results": [
                {
                    "chat_id": 12345,
                    "chat_title": "🎉 Тестовая группа 中文测试 🚀",
                    "chat_type": "supergroup",
                    "chat_username": "unicode_test",
                    "message_count": 100,
                    "unique_authors": 10,
                    "history_hours": 24.5,
                    "first_message_at": now.isoformat(),
                    "last_message_at": now.isoformat(),
                    "analyzed_at": now.isoformat(),
                }
            ]
        }

        response = e2e_app.post(
            "/api/export/csv?filename=unicode.csv",
            json=export_data,
        )

        assert response.status_code == 200
        csv_content = response.content.decode("utf-8-sig")
        assert "🎉 Тестовая группа 中文测试 🚀" in csv_content

    def test_export_preserves_data_integrity(self) -> None:
        """Test that CSV export preserves all data from analysis results.

        This ensures no data loss during the export process.
        """
        app = create_app()
        client = TestClient(app)

        now = datetime.now(UTC)
        export_data = {
            "results": [
                {
                    "chat_id": 12345,
                    "chat_title": "Test Chat",
                    "chat_type": "supergroup",
                    "chat_username": "testchat",
                    "message_count": 100,
                    "unique_authors": 10,
                    "history_hours": 24.5,
                    "first_message_at": now.isoformat(),
                    "last_message_at": now.isoformat(),
                    "analyzed_at": now.isoformat(),
                }
            ]
        }

        response = client.post(
            "/api/export/csv",
            json=export_data,
        )

        assert response.status_code == 200
        csv_content = response.content.decode("utf-8-sig")

        # Verify all key data is preserved
        assert "Test Chat" in csv_content
        assert "100" in csv_content  # message_count
        assert "10" in csv_content  # unique_authors
        assert "24.5" in csv_content or "24.50" in csv_content  # history_hours

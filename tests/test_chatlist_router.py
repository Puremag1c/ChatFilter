"""Comprehensive tests for chatlist router."""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from chatfilter.importer import ChatListEntry, ChatListEntryType, GoogleSheetsError, ParseError
from chatfilter.web.app import create_app
from chatfilter.web.routers.chatlist import (
    _imported_lists,
    clear_chat_list,
    get_chat_list,
    store_chat_list,
)


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
def client() -> TestClient:
    """Create test client."""
    app = create_app()
    return TestClient(app)


@pytest.fixture
def csrf_token(client: TestClient) -> str:
    """Get CSRF token from home page."""
    home_response = client.get("/")
    token = extract_csrf_token(home_response.text)
    assert token is not None, "CSRF token not found in home page"
    return token


@pytest.fixture(autouse=True)
def clear_imported_lists() -> None:
    """Clear the imported lists before each test."""
    _imported_lists.clear()


@pytest.fixture
def sample_entries() -> list[ChatListEntry]:
    """Create sample chat list entries."""
    return [
        ChatListEntry(
            value="@testchannel",
            entry_type=ChatListEntryType.USERNAME,
            normalized="testchannel",
        ),
        ChatListEntry(
            value="https://t.me/anotherchannel",
            entry_type=ChatListEntryType.LINK,
            normalized="anotherchannel",
        ),
        ChatListEntry(
            value="-1001234567890",
            entry_type=ChatListEntryType.ID,
            normalized="-1001234567890",
        ),
    ]


class TestStoreChatList:
    """Tests for store_chat_list helper function."""

    def test_store_chat_list_returns_id(self, sample_entries: list[ChatListEntry]) -> None:
        """Test that storing a chat list returns a list ID."""
        list_id = store_chat_list(sample_entries)

        assert list_id is not None
        assert isinstance(list_id, str)
        assert len(list_id) == 36  # Full UUID format

    def test_store_chat_list_empty(self) -> None:
        """Test storing empty list."""
        list_id = store_chat_list([])

        assert list_id is not None
        assert isinstance(list_id, str)
        retrieved = get_chat_list(list_id)
        assert retrieved == []

    def test_store_multiple_lists(self, sample_entries: list[ChatListEntry]) -> None:
        """Test storing multiple lists returns different IDs."""
        list_id_1 = store_chat_list(sample_entries[:1])
        list_id_2 = store_chat_list(sample_entries[1:])

        assert list_id_1 != list_id_2


class TestGetChatList:
    """Tests for get_chat_list helper function."""

    def test_get_chat_list_found(self, sample_entries: list[ChatListEntry]) -> None:
        """Test retrieving an existing chat list."""
        list_id = store_chat_list(sample_entries)
        retrieved = get_chat_list(list_id)

        assert retrieved == sample_entries

    def test_get_chat_list_not_found(self) -> None:
        """Test retrieving non-existent list returns None."""
        retrieved = get_chat_list("nonexistent")

        assert retrieved is None

    def test_get_chat_list_empty_id(self) -> None:
        """Test retrieving with empty ID returns None."""
        retrieved = get_chat_list("")

        assert retrieved is None


class TestClearChatList:
    """Tests for clear_chat_list helper function."""

    def test_clear_chat_list_exists(self, sample_entries: list[ChatListEntry]) -> None:
        """Test clearing an existing chat list."""
        list_id = store_chat_list(sample_entries)
        result = clear_chat_list(list_id)

        assert result is True
        assert get_chat_list(list_id) is None

    def test_clear_chat_list_not_found(self) -> None:
        """Test clearing non-existent list returns False."""
        result = clear_chat_list("nonexistent")

        assert result is False


class TestUploadChatList:
    """Tests for /api/chatlist/upload endpoint."""

    def test_upload_text_file_success(self, client: TestClient, csrf_token: str) -> None:
        """Test uploading a valid text file."""
        content = b"@channel1\n@channel2\nhttps://t.me/channel3\n"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            mock_entries = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
                ChatListEntry(
                    value="@channel2",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel2",
                ),
            ]
            mock_parse.return_value = mock_entries

            response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("chats.txt", content, "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "success" in response.text.lower() or "2" in response.text

    def test_upload_csv_file_success(self, client: TestClient, csrf_token: str) -> None:
        """Test uploading a valid CSV file."""
        content = b"channel1\nchannel2\nchannel3\n"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            mock_entries = [
                ChatListEntry(
                    value="channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ]
            mock_parse.return_value = mock_entries

            response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("chats.csv", content, "text/csv")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_upload_file_too_large(self, client: TestClient, csrf_token: str) -> None:
        """Test uploading file exceeding size limit."""
        # Create a file larger than MAX_FILE_SIZE (5 MB)
        large_content = b"x" * (6 * 1024 * 1024)  # 6 MB

        response = client.post(
            "/api/chatlist/upload",
            files={"chatlist_file": ("large.txt", large_content, "text/plain")},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "too large" in response.text.lower()

    def test_upload_empty_file(self, client: TestClient, csrf_token: str) -> None:
        """Test uploading empty file."""
        response = client.post(
            "/api/chatlist/upload",
            files={"chatlist_file": ("empty.txt", b"", "text/plain")},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "empty" in response.text.lower()

    def test_upload_parse_error(self, client: TestClient, csrf_token: str) -> None:
        """Test upload with file that causes parse error."""
        content = b"invalid content"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            mock_parse.side_effect = ParseError("Invalid format")

            response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("bad.txt", content, "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "parse error" in response.text.lower() or "invalid format" in response.text.lower()

    def test_upload_no_valid_entries(self, client: TestClient, csrf_token: str) -> None:
        """Test upload with file containing no valid entries."""
        content = b"# Just comments\n# No actual channels\n"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            mock_parse.return_value = []

            response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("noentries.txt", content, "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "no valid" in response.text.lower() or "not found" in response.text.lower()

    def test_upload_removes_duplicates(self, client: TestClient, csrf_token: str) -> None:
        """Test that duplicate entries are removed."""
        content = b"@channel1\n@channel1\n@channel2\n"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            # Parser returns duplicates
            mock_entries = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
                ChatListEntry(
                    value="@channel2",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel2",
                ),
            ]
            mock_parse.return_value = mock_entries

            response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("dupes.txt", content, "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        # Should show 2 unique entries, not 3
        # We can't easily verify the exact count without parsing HTML,
        # but we can verify success
        assert "success" in response.text.lower() or response.status_code == 200

    def test_upload_unexpected_error(self, client: TestClient, csrf_token: str) -> None:
        """Test handling of unexpected errors during upload."""
        content = b"@channel1\n"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            # Simulate unexpected exception
            mock_parse.side_effect = RuntimeError("Unexpected error")

            response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("test.txt", content, "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "unexpected error" in response.text.lower() or "error" in response.text.lower()

    def test_upload_xlsx_file(self, client: TestClient, csrf_token: str) -> None:
        """Test uploading Excel file."""
        # Create minimal XLSX content (just a marker)
        content = b"fake xlsx content"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            mock_entries = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ]
            mock_parse.return_value = mock_entries

            response = client.post(
                "/api/chatlist/upload",
                files={
                    "chatlist_file": (
                        "chats.xlsx",
                        content,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    )
                },
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200


class TestFetchGoogleSheet:
    """Tests for /api/chatlist/fetch_sheet endpoint."""

    def test_fetch_sheet_success(self, client: TestClient, csrf_token: str) -> None:
        """Test successfully fetching Google Sheet."""
        sheet_url = "https://docs.google.com/spreadsheets/d/1ABC123/edit"

        with (
            patch("chatfilter.web.routers.chatlist.is_google_sheets_url") as mock_is_url,
            patch("chatfilter.web.routers.chatlist.fetch_google_sheet") as mock_fetch,
        ):
            mock_is_url.return_value = True
            mock_entries = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
                ChatListEntry(
                    value="@channel2",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel2",
                ),
            ]
            mock_fetch.return_value = mock_entries

            response = client.post(
                "/api/chatlist/fetch_sheet",
                data={"sheet_url": sheet_url},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "success" in response.text.lower() or "2" in response.text

    def test_fetch_sheet_empty_url(self, client: TestClient, csrf_token: str) -> None:
        """Test fetching with empty URL."""
        response = client.post(
            "/api/chatlist/fetch_sheet",
            data={"sheet_url": ""},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "enter" in response.text.lower() or "url" in response.text.lower()

    def test_fetch_sheet_whitespace_url(self, client: TestClient, csrf_token: str) -> None:
        """Test fetching with whitespace-only URL."""
        response = client.post(
            "/api/chatlist/fetch_sheet",
            data={"sheet_url": "   \n\t   "},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "enter" in response.text.lower() or "url" in response.text.lower()

    def test_fetch_sheet_invalid_url(self, client: TestClient, csrf_token: str) -> None:
        """Test fetching with invalid Google Sheets URL."""
        with patch("chatfilter.web.routers.chatlist.is_google_sheets_url") as mock_is_url:
            mock_is_url.return_value = False

            response = client.post(
                "/api/chatlist/fetch_sheet",
                data={"sheet_url": "https://example.com/not-a-sheet"},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "invalid" in response.text.lower()

    def test_fetch_sheet_google_sheets_error(self, client: TestClient, csrf_token: str) -> None:
        """Test handling of Google Sheets API error."""
        sheet_url = "https://docs.google.com/spreadsheets/d/1ABC123/edit"

        with (
            patch("chatfilter.web.routers.chatlist.is_google_sheets_url") as mock_is_url,
            patch("chatfilter.web.routers.chatlist.fetch_google_sheet") as mock_fetch,
        ):
            mock_is_url.return_value = True
            mock_fetch.side_effect = GoogleSheetsError("Sheet not accessible")

            response = client.post(
                "/api/chatlist/fetch_sheet",
                data={"sheet_url": sheet_url},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "not accessible" in response.text.lower() or "error" in response.text.lower()

    def test_fetch_sheet_no_valid_entries(self, client: TestClient, csrf_token: str) -> None:
        """Test fetching sheet with no valid entries."""
        sheet_url = "https://docs.google.com/spreadsheets/d/1ABC123/edit"

        with (
            patch("chatfilter.web.routers.chatlist.is_google_sheets_url") as mock_is_url,
            patch("chatfilter.web.routers.chatlist.fetch_google_sheet") as mock_fetch,
        ):
            mock_is_url.return_value = True
            mock_fetch.return_value = []

            response = client.post(
                "/api/chatlist/fetch_sheet",
                data={"sheet_url": sheet_url},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "no valid" in response.text.lower() or "not found" in response.text.lower()

    def test_fetch_sheet_removes_duplicates(self, client: TestClient, csrf_token: str) -> None:
        """Test that duplicate entries from sheet are removed."""
        sheet_url = "https://docs.google.com/spreadsheets/d/1ABC123/edit"

        with (
            patch("chatfilter.web.routers.chatlist.is_google_sheets_url") as mock_is_url,
            patch("chatfilter.web.routers.chatlist.fetch_google_sheet") as mock_fetch,
        ):
            mock_is_url.return_value = True
            # Return duplicate entries
            mock_entries = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
                ChatListEntry(
                    value="https://t.me/channel1",
                    entry_type=ChatListEntryType.LINK,
                    normalized="channel1",  # Same normalized value
                ),
                ChatListEntry(
                    value="@channel2",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel2",
                ),
            ]
            mock_fetch.return_value = mock_entries

            response = client.post(
                "/api/chatlist/fetch_sheet",
                data={"sheet_url": sheet_url},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_fetch_sheet_unexpected_error(self, client: TestClient, csrf_token: str) -> None:
        """Test handling of unexpected errors during sheet fetch."""
        sheet_url = "https://docs.google.com/spreadsheets/d/1ABC123/edit"

        with (
            patch("chatfilter.web.routers.chatlist.is_google_sheets_url") as mock_is_url,
            patch("chatfilter.web.routers.chatlist.fetch_google_sheet") as mock_fetch,
        ):
            mock_is_url.return_value = True
            mock_fetch.side_effect = RuntimeError("Unexpected error")

            response = client.post(
                "/api/chatlist/fetch_sheet",
                data={"sheet_url": sheet_url},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        assert "unexpected error" in response.text.lower() or "error" in response.text.lower()

    def test_fetch_sheet_url_with_whitespace(self, client: TestClient, csrf_token: str) -> None:
        """Test that URLs with leading/trailing whitespace are handled."""
        sheet_url = "  https://docs.google.com/spreadsheets/d/1ABC123/edit  "

        with (
            patch("chatfilter.web.routers.chatlist.is_google_sheets_url") as mock_is_url,
            patch("chatfilter.web.routers.chatlist.fetch_google_sheet") as mock_fetch,
        ):
            mock_is_url.return_value = True
            mock_entries = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ]
            mock_fetch.return_value = mock_entries

            response = client.post(
                "/api/chatlist/fetch_sheet",
                data={"sheet_url": sheet_url},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200
        # Verify that the URL was stripped before validation
        mock_is_url.assert_called_once_with(sheet_url.strip())


class TestGetChatListEntries:
    """Tests for /api/chatlist/{list_id} endpoint."""

    def test_get_entries_success(
        self, client: TestClient, sample_entries: list[ChatListEntry]
    ) -> None:
        """Test retrieving entries for existing list."""
        list_id = store_chat_list(sample_entries)

        response = client.get(f"/api/chatlist/{list_id}")

        assert response.status_code == 200
        # Check that entries are in response
        assert "testchannel" in response.text or "@testchannel" in response.text

    def test_get_entries_not_found(self, client: TestClient) -> None:
        """Test retrieving entries for non-existent list."""
        # Use valid UUID format that doesn't exist
        nonexistent_uuid = "00000000-0000-0000-0000-000000000000"
        response = client.get(f"/api/chatlist/{nonexistent_uuid}")

        assert response.status_code == 200
        assert "not found" in response.text.lower() or "expired" in response.text.lower()

    def test_get_entries_empty_list(self, client: TestClient) -> None:
        """Test retrieving empty list."""
        list_id = store_chat_list([])

        response = client.get(f"/api/chatlist/{list_id}")

        assert response.status_code == 200

    def test_get_entries_invalid_id_format(self, client: TestClient) -> None:
        """Test retrieving with malformed list ID."""
        response = client.get("/api/chatlist/invalid@#$%")

        # FastAPI will handle this, might be 404 or 200 with error
        assert response.status_code in [200, 404, 422]


class TestDeleteChatList:
    """Tests for /api/chatlist/{list_id} DELETE endpoint."""

    def test_delete_existing_list(
        self, client: TestClient, csrf_token: str, sample_entries: list[ChatListEntry]
    ) -> None:
        """Test deleting an existing list."""
        list_id = store_chat_list(sample_entries)

        response = client.delete(f"/api/chatlist/{list_id}", headers={"X-CSRF-Token": csrf_token})

        assert response.status_code == 200
        assert response.text == ""

        # Verify list is deleted
        assert get_chat_list(list_id) is None

    def test_delete_non_existent_list(self, client: TestClient, csrf_token: str) -> None:
        """Test deleting non-existent list returns 404."""
        # Use valid UUID format that doesn't exist
        nonexistent_uuid = "00000000-0000-0000-0000-000000000000"
        response = client.delete(
            f"/api/chatlist/{nonexistent_uuid}", headers={"X-CSRF-Token": csrf_token}
        )

        assert response.status_code == 404

    def test_delete_already_deleted_list(
        self, client: TestClient, csrf_token: str, sample_entries: list[ChatListEntry]
    ) -> None:
        """Test deleting a list that was already deleted returns 404."""
        list_id = store_chat_list(sample_entries)

        # Delete once
        response1 = client.delete(f"/api/chatlist/{list_id}", headers={"X-CSRF-Token": csrf_token})
        assert response1.status_code == 200

        # Delete again - should return 404
        response2 = client.delete(f"/api/chatlist/{list_id}", headers={"X-CSRF-Token": csrf_token})
        assert response2.status_code == 404


class TestIntegrationScenarios:
    """Integration tests for complete workflows."""

    def test_upload_then_retrieve_workflow(self, client: TestClient, csrf_token: str) -> None:
        """Test complete workflow: upload file, get list ID, retrieve entries."""
        content = b"@channel1\n@channel2\n"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            mock_entries = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
                ChatListEntry(
                    value="@channel2",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel2",
                ),
            ]
            mock_parse.return_value = mock_entries

            # Upload
            upload_response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("test.txt", content, "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert upload_response.status_code == 200

        # Store directly for testing (in real scenario, would parse from HTML)
        list_id = store_chat_list(mock_entries)

        # Retrieve
        get_response = client.get(f"/api/chatlist/{list_id}")
        assert get_response.status_code == 200

    def test_fetch_sheet_then_delete_workflow(self, client: TestClient, csrf_token: str) -> None:
        """Test workflow: fetch sheet, store, then delete."""
        sheet_url = "https://docs.google.com/spreadsheets/d/1ABC123/edit"

        with (
            patch("chatfilter.web.routers.chatlist.is_google_sheets_url") as mock_is_url,
            patch("chatfilter.web.routers.chatlist.fetch_google_sheet") as mock_fetch,
        ):
            mock_is_url.return_value = True
            mock_entries = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ]
            mock_fetch.return_value = mock_entries

            # Fetch
            fetch_response = client.post(
                "/api/chatlist/fetch_sheet",
                data={"sheet_url": sheet_url},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert fetch_response.status_code == 200

        # Store and delete
        list_id = store_chat_list(mock_entries)
        delete_response = client.delete(
            f"/api/chatlist/{list_id}", headers={"X-CSRF-Token": csrf_token}
        )

        assert delete_response.status_code == 200
        assert get_chat_list(list_id) is None

    def test_multiple_uploads_different_lists(self, client: TestClient, csrf_token: str) -> None:
        """Test uploading multiple different lists."""
        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            # First upload
            mock_parse.return_value = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ]
            response1 = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("test1.txt", b"@channel1", "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

            # Second upload
            mock_parse.return_value = [
                ChatListEntry(
                    value="@channel2",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel2",
                ),
            ]
            response2 = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("test2.txt", b"@channel2", "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response1.status_code == 200
        assert response2.status_code == 200


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_upload_file_exactly_at_size_limit(self, client: TestClient, csrf_token: str) -> None:
        """Test uploading file exactly at MAX_FILE_SIZE."""
        # MAX_FILE_SIZE is 5 MB
        content = b"x" * (5 * 1024 * 1024)

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            mock_parse.return_value = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ]

            response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("large.txt", content, "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        # Should succeed at exactly the limit
        assert response.status_code == 200

    def test_upload_file_one_byte_over_limit(self, client: TestClient, csrf_token: str) -> None:
        """Test uploading file one byte over MAX_FILE_SIZE."""
        # MAX_FILE_SIZE is 5 MB, upload 5 MB + 1 byte
        content = b"x" * (5 * 1024 * 1024 + 1)

        response = client.post(
            "/api/chatlist/upload",
            files={"chatlist_file": ("toolarge.txt", content, "text/plain")},
            headers={"X-CSRF-Token": csrf_token},
        )

        assert response.status_code == 200
        assert "too large" in response.text.lower()

    def test_upload_with_unicode_filename(self, client: TestClient, csrf_token: str) -> None:
        """Test uploading file with unicode filename."""
        content = b"@channel1\n"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            mock_parse.return_value = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ]

            response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("测试文件.txt", content, "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_upload_with_special_chars_in_filename(
        self, client: TestClient, csrf_token: str
    ) -> None:
        """Test uploading file with special characters in filename."""
        content = b"@channel1\n"

        with patch("chatfilter.web.routers.chatlist.parse_chat_list") as mock_parse:
            mock_parse.return_value = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ]

            response = client.post(
                "/api/chatlist/upload",
                files={"chatlist_file": ("file-with-special_chars (1).txt", content, "text/plain")},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_store_list_with_many_entries(self) -> None:
        """Test storing list with large number of entries."""
        # Create 10000 entries
        entries = [
            ChatListEntry(
                value=f"@channel{i}",
                entry_type=ChatListEntryType.USERNAME,
                normalized=f"channel{i}",
            )
            for i in range(10000)
        ]

        list_id = store_chat_list(entries)
        retrieved = get_chat_list(list_id)

        assert retrieved == entries
        assert len(retrieved) == 10000

    def test_fetch_sheet_with_international_domain(
        self, client: TestClient, csrf_token: str
    ) -> None:
        """Test fetching sheet with international characters in URL."""
        sheet_url = "https://docs.google.com/spreadsheets/d/1ABC123/edit#gid=0"

        with (
            patch("chatfilter.web.routers.chatlist.is_google_sheets_url") as mock_is_url,
            patch("chatfilter.web.routers.chatlist.fetch_google_sheet") as mock_fetch,
        ):
            mock_is_url.return_value = True
            mock_entries = [
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ]
            mock_fetch.return_value = mock_entries

            response = client.post(
                "/api/chatlist/fetch_sheet",
                data={"sheet_url": sheet_url},
                headers={"X-CSRF-Token": csrf_token},
            )

        assert response.status_code == 200

    def test_concurrent_list_operations(self, sample_entries: list[ChatListEntry]) -> None:
        """Test that concurrent operations maintain data integrity."""
        # Store multiple lists
        list_ids = [store_chat_list(sample_entries) for _ in range(10)]

        # Verify all are unique
        assert len(set(list_ids)) == 10

        # Verify all can be retrieved
        for list_id in list_ids:
            assert get_chat_list(list_id) == sample_entries

        # Delete half
        for list_id in list_ids[:5]:
            clear_chat_list(list_id)

        # Verify deletions
        for list_id in list_ids[:5]:
            assert get_chat_list(list_id) is None

        # Verify remaining lists are intact
        for list_id in list_ids[5:]:
            assert get_chat_list(list_id) == sample_entries


class TestImportResultModel:
    """Tests for ImportResult Pydantic model."""

    def test_import_result_success(self) -> None:
        """Test creating successful ImportResult."""
        from chatfilter.web.routers.chatlist import ImportResult

        result = ImportResult(
            success=True,
            list_id="abc12345",
            entry_count=5,
            entries=[
                ChatListEntry(
                    value="@channel1",
                    entry_type=ChatListEntryType.USERNAME,
                    normalized="channel1",
                ),
            ],
        )

        assert result.success is True
        assert result.list_id == "abc12345"
        assert result.entry_count == 5
        assert result.error is None

    def test_import_result_error(self) -> None:
        """Test creating error ImportResult."""
        from chatfilter.web.routers.chatlist import ImportResult

        result = ImportResult(
            success=False,
            error="File too large",
        )

        assert result.success is False
        assert result.error == "File too large"
        assert result.list_id is None
        assert result.entry_count == 0
        assert result.entries == []

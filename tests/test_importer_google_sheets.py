"""Comprehensive tests for Google Sheets importer module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from chatfilter.importer.google_sheets import (
    GoogleSheetsError,
    build_csv_export_url,
    extract_gid,
    extract_sheet_id,
    fetch_google_sheet,
    is_google_sheets_url,
)
from chatfilter.importer.parser import ChatListEntry, ChatListEntryType, ParseError


class TestExtractSheetId:
    """Tests for extract_sheet_id function."""

    def test_extract_from_full_url(self) -> None:
        """Test extracting ID from full Google Sheets URL."""
        url = "https://docs.google.com/spreadsheets/d/1a2b3c4d5e6f/edit#gid=123"
        result = extract_sheet_id(url)
        assert result == "1a2b3c4d5e6f"

    def test_extract_from_url_without_gid(self) -> None:
        """Test extracting ID from URL without GID."""
        url = "https://docs.google.com/spreadsheets/d/1a2b3c4d5e6f/edit"
        result = extract_sheet_id(url)
        assert result == "1a2b3c4d5e6f"

    def test_extract_from_url_without_https(self) -> None:
        """Test extracting ID from URL without https prefix."""
        url = "docs.google.com/spreadsheets/d/1a2b3c4d5e6f/edit"
        result = extract_sheet_id(url)
        assert result == "1a2b3c4d5e6f"

    def test_extract_from_http_url(self) -> None:
        """Test extracting ID from http (not https) URL."""
        url = "http://docs.google.com/spreadsheets/d/1a2b3c4d5e6f/edit"
        result = extract_sheet_id(url)
        assert result == "1a2b3c4d5e6f"

    def test_extract_with_underscores_and_dashes(self) -> None:
        """Test extracting ID with underscores and dashes."""
        url = "https://docs.google.com/spreadsheets/d/1_abc-DEF_123/edit"
        result = extract_sheet_id(url)
        assert result == "1_abc-DEF_123"

    def test_extract_from_short_url(self) -> None:
        """Test extracting ID from short URL without /edit suffix."""
        url = "https://docs.google.com/spreadsheets/d/1a2b3c4d5e6f"
        result = extract_sheet_id(url)
        assert result == "1a2b3c4d5e6f"

    def test_extract_case_insensitive(self) -> None:
        """Test that URL matching is case insensitive."""
        url = "HTTPS://DOCS.GOOGLE.COM/SPREADSHEETS/D/1a2b3c4d5e6f/EDIT"
        result = extract_sheet_id(url)
        assert result == "1a2b3c4d5e6f"

    def test_extract_with_query_params(self) -> None:
        """Test extracting ID from URL with query parameters."""
        url = "https://docs.google.com/spreadsheets/d/1a2b3c4d5e6f/edit?usp=sharing"
        result = extract_sheet_id(url)
        assert result == "1a2b3c4d5e6f"

    def test_extract_with_multiple_path_segments(self) -> None:
        """Test extracting ID from URL with additional path segments."""
        url = "https://docs.google.com/spreadsheets/d/1a2b3c4d5e6f/edit/something/else"
        result = extract_sheet_id(url)
        assert result == "1a2b3c4d5e6f"

    def test_invalid_url_raises_error(self) -> None:
        """Test that invalid URL raises GoogleSheetsError."""
        url = "https://example.com/not-a-sheet"
        with pytest.raises(GoogleSheetsError, match="Invalid Google Sheets URL"):
            extract_sheet_id(url)

    def test_empty_url_raises_error(self) -> None:
        """Test that empty URL raises GoogleSheetsError."""
        with pytest.raises(GoogleSheetsError, match="Invalid Google Sheets URL"):
            extract_sheet_id("")

    def test_google_docs_url_raises_error(self) -> None:
        """Test that Google Docs URL (not Sheets) raises error."""
        url = "https://docs.google.com/document/d/1a2b3c4d5e6f/edit"
        with pytest.raises(GoogleSheetsError, match="Invalid Google Sheets URL"):
            extract_sheet_id(url)

    def test_malformed_sheets_url_raises_error(self) -> None:
        """Test that malformed Sheets URL raises error."""
        url = "https://docs.google.com/spreadsheets/"
        with pytest.raises(GoogleSheetsError, match="Invalid Google Sheets URL"):
            extract_sheet_id(url)


class TestExtractGid:
    """Tests for extract_gid function."""

    def test_extract_from_fragment(self) -> None:
        """Test extracting GID from URL fragment."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit#gid=456"
        result = extract_gid(url)
        assert result == "456"

    def test_extract_from_query_params(self) -> None:
        """Test extracting GID from query parameters."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit?gid=789"
        result = extract_gid(url)
        assert result == "789"

    def test_no_gid_returns_none(self) -> None:
        """Test that URL without GID returns None."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        result = extract_gid(url)
        assert result is None

    def test_empty_url_returns_none(self) -> None:
        """Test that empty URL returns None."""
        result = extract_gid("")
        assert result is None

    def test_gid_zero(self) -> None:
        """Test extracting GID with value 0."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit#gid=0"
        result = extract_gid(url)
        assert result == "0"

    def test_fragment_takes_priority_over_query(self) -> None:
        """Test that fragment GID takes priority over query GID."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit?gid=111#gid=222"
        result = extract_gid(url)
        assert result == "222"

    def test_fragment_with_multiple_params(self) -> None:
        """Test extracting GID from fragment with multiple parameters."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit#gid=456&range=A1:B10"
        result = extract_gid(url)
        assert result == "456"

    def test_query_with_multiple_params(self) -> None:
        """Test extracting GID from query with multiple parameters."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit?usp=sharing&gid=789&rm=minimal"
        result = extract_gid(url)
        assert result == "789"

    def test_url_without_scheme(self) -> None:
        """Test extracting GID from URL without scheme."""
        url = "docs.google.com/spreadsheets/d/abc123/edit#gid=999"
        result = extract_gid(url)
        assert result == "999"


class TestBuildCsvExportUrl:
    """Tests for build_csv_export_url function."""

    def test_build_without_gid(self) -> None:
        """Test building export URL without GID."""
        result = build_csv_export_url("abc123")
        expected = "https://docs.google.com/spreadsheets/d/abc123/export?format=csv"
        assert result == expected

    def test_build_with_gid(self) -> None:
        """Test building export URL with GID."""
        result = build_csv_export_url("abc123", "456")
        expected = "https://docs.google.com/spreadsheets/d/abc123/export?format=csv&gid=456"
        assert result == expected

    def test_build_with_gid_zero(self) -> None:
        """Test building export URL with GID 0."""
        result = build_csv_export_url("abc123", "0")
        expected = "https://docs.google.com/spreadsheets/d/abc123/export?format=csv&gid=0"
        assert result == expected

    def test_build_with_gid_none(self) -> None:
        """Test building export URL with explicit None GID."""
        result = build_csv_export_url("abc123", None)
        expected = "https://docs.google.com/spreadsheets/d/abc123/export?format=csv"
        assert result == expected

    def test_build_with_complex_sheet_id(self) -> None:
        """Test building export URL with complex sheet ID."""
        sheet_id = "1_abc-DEF_123-xyz_789"
        result = build_csv_export_url(sheet_id, "999")
        expected = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=csv&gid=999"
        assert result == expected


class TestIsGoogleSheetsUrl:
    """Tests for is_google_sheets_url function."""

    def test_valid_sheets_url(self) -> None:
        """Test that valid Sheets URL returns True."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        assert is_google_sheets_url(url) is True

    def test_sheets_url_without_https(self) -> None:
        """Test that Sheets URL without https returns True."""
        url = "docs.google.com/spreadsheets/d/abc123"
        assert is_google_sheets_url(url) is True

    def test_case_insensitive_match(self) -> None:
        """Test that matching is case insensitive."""
        url = "HTTPS://DOCS.GOOGLE.COM/SPREADSHEETS/D/ABC123"
        assert is_google_sheets_url(url) is True

    def test_non_sheets_url(self) -> None:
        """Test that non-Sheets URL returns False."""
        url = "https://example.com/some/path"
        assert is_google_sheets_url(url) is False

    def test_google_docs_url(self) -> None:
        """Test that Google Docs URL returns False."""
        url = "https://docs.google.com/document/d/abc123/edit"
        assert is_google_sheets_url(url) is False

    def test_empty_url(self) -> None:
        """Test that empty URL returns False."""
        assert is_google_sheets_url("") is False

    def test_partial_match(self) -> None:
        """Test that partial match in larger text returns True."""
        url = "Check out this sheet: https://docs.google.com/spreadsheets/d/abc123"
        assert is_google_sheets_url(url) is True


class TestFetchGoogleSheet:
    """Tests for fetch_google_sheet async function."""

    @pytest.mark.asyncio
    async def test_successful_fetch(self) -> None:
        """Test successful fetching and parsing of Google Sheet."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit#gid=0"
        csv_content = "username\n@channel1\n@channel2\ntest_user"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        assert len(result) == 3
        assert all(isinstance(entry, ChatListEntry) for entry in result)
        assert result[0].normalized == "channel1"
        assert result[1].normalized == "channel2"
        assert result[2].normalized == "test_user"

    @pytest.mark.asyncio
    async def test_fetch_with_custom_timeout(self) -> None:
        """Test that custom timeout is passed to AsyncClient."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "username\n@test"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            await fetch_google_sheet(url, timeout=60.0)

            # Verify AsyncClient was called with correct timeout
            mock_client.assert_called_once()
            call_kwargs = mock_client.call_args[1]
            assert call_kwargs["timeout"] == 60.0
            assert call_kwargs["follow_redirects"] is True

    @pytest.mark.asyncio
    async def test_fetch_builds_correct_export_url(self) -> None:
        """Test that correct CSV export URL is built and requested."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit#gid=456"
        csv_content = "username\n@test"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_get = AsyncMock(return_value=mock_response)
            mock_context.__aenter__.return_value.get = mock_get
            mock_client.return_value = mock_context

            await fetch_google_sheet(url)

            # Verify the correct export URL was called
            expected_url = "https://docs.google.com/spreadsheets/d/abc123/export?format=csv&gid=456"
            mock_get.assert_called_once_with(expected_url)

    @pytest.mark.asyncio
    async def test_invalid_url_raises_error(self) -> None:
        """Test that invalid URL raises GoogleSheetsError immediately."""
        url = "https://example.com/not-a-sheet"

        with pytest.raises(GoogleSheetsError, match="Invalid Google Sheets URL"):
            await fetch_google_sheet(url)

    @pytest.mark.asyncio
    async def test_timeout_error(self) -> None:
        """Test that timeout exception is caught and wrapped."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.TimeoutException("Request timed out")
            )
            mock_client.return_value = mock_context

            with pytest.raises(GoogleSheetsError, match="Request timed out"):
                await fetch_google_sheet(url)

    @pytest.mark.asyncio
    async def test_404_error(self) -> None:
        """Test that 404 error is caught with appropriate message."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"

        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPStatusError(
                    "Not found",
                    request=MagicMock(),
                    response=mock_response,
                )
            )
            mock_client.return_value = mock_context

            with pytest.raises(GoogleSheetsError, match="Spreadsheet not found"):
                await fetch_google_sheet(url)

    @pytest.mark.asyncio
    async def test_403_error(self) -> None:
        """Test that 403 error is caught with appropriate message."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"

        mock_response = MagicMock()
        mock_response.status_code = 403

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPStatusError(
                    "Forbidden",
                    request=MagicMock(),
                    response=mock_response,
                )
            )
            mock_client.return_value = mock_context

            with pytest.raises(GoogleSheetsError, match="Access denied"):
                await fetch_google_sheet(url)

    @pytest.mark.asyncio
    async def test_500_error(self) -> None:
        """Test that 500 error is caught with generic HTTP error message."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"

        mock_response = MagicMock()
        mock_response.status_code = 500

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.HTTPStatusError(
                    "Server error",
                    request=MagicMock(),
                    response=mock_response,
                )
            )
            mock_client.return_value = mock_context

            with pytest.raises(GoogleSheetsError, match="HTTP error"):
                await fetch_google_sheet(url)

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        """Test that general request error is caught and wrapped."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(
                side_effect=httpx.RequestError("Connection failed")
            )
            mock_client.return_value = mock_context

            with pytest.raises(GoogleSheetsError, match="Request failed"):
                await fetch_google_sheet(url)

    @pytest.mark.asyncio
    async def test_html_response_error(self) -> None:
        """Test that HTML response (instead of CSV) raises error."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"

        mock_response = MagicMock()
        mock_response.text = "<html><body>Login required</body></html>"
        mock_response.headers = {"content-type": "text/html; charset=utf-8"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            with pytest.raises(GoogleSheetsError, match="Received HTML instead of CSV"):
                await fetch_google_sheet(url)

    @pytest.mark.asyncio
    async def test_parse_error_wrapped(self) -> None:
        """Test that ParseError is caught and wrapped in GoogleSheetsError."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"

        mock_response = MagicMock()
        mock_response.text = "invalid csv content"
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            with patch("chatfilter.importer.google_sheets.parse_csv") as mock_parse:
                mock_parse.side_effect = ParseError("Parse failed")

                with pytest.raises(GoogleSheetsError, match="Failed to parse sheet data"):
                    await fetch_google_sheet(url)

    @pytest.mark.asyncio
    async def test_empty_sheet(self) -> None:
        """Test fetching empty sheet returns empty list."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = ""

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        assert result == []

    @pytest.mark.asyncio
    async def test_sheet_with_headers_only(self) -> None:
        """Test fetching sheet with only headers."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "username,description\n"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        assert result == []

    @pytest.mark.asyncio
    async def test_sheet_with_multiple_columns(self) -> None:
        """Test fetching sheet with multiple columns."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "username,category,notes\n@channel1,tech,interesting\n@channel2,news,daily"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        assert len(result) == 2
        assert result[0].normalized == "channel1"
        assert result[1].normalized == "channel2"

    @pytest.mark.asyncio
    async def test_sheet_with_links(self) -> None:
        """Test fetching sheet with Telegram links."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "link\nhttps://t.me/channel1\nt.me/channel2"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        assert len(result) == 2
        assert result[0].entry_type == ChatListEntryType.LINK
        assert result[1].entry_type == ChatListEntryType.LINK

    @pytest.mark.asyncio
    async def test_sheet_with_numeric_ids(self) -> None:
        """Test fetching sheet with numeric chat IDs."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "id\n1234567890\n-1001234567890"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        assert len(result) == 2
        assert result[0].entry_type == ChatListEntryType.ID
        assert result[1].entry_type == ChatListEntryType.ID

    @pytest.mark.asyncio
    async def test_sheet_with_comments_and_empty_lines(self) -> None:
        """Test that comments and empty lines are filtered out."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "username\n@channel1\n\n#comment line\n@channel2\n"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        # Should only get the two valid channels, comments/empty lines filtered
        assert len(result) == 2
        assert result[0].normalized == "channel1"
        assert result[1].normalized == "channel2"

    @pytest.mark.asyncio
    async def test_fetch_without_gid(self) -> None:
        """Test fetching sheet without GID (default to first sheet)."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "username\n@test"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_get = AsyncMock(return_value=mock_response)
            mock_context.__aenter__.return_value.get = mock_get
            mock_client.return_value = mock_context

            await fetch_google_sheet(url)

            # Verify URL doesn't include gid parameter
            called_url = mock_get.call_args[0][0]
            assert "gid=" not in called_url

    @pytest.mark.asyncio
    async def test_content_type_with_charset(self) -> None:
        """Test that content-type with charset is handled correctly."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "username\n@test"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv; charset=utf-8"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_missing_content_type_header(self) -> None:
        """Test handling of missing content-type header."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "username\n@test"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {}  # No content-type header
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        # Should still work if content is valid CSV
        assert len(result) == 1


class TestGoogleSheetsError:
    """Tests for GoogleSheetsError exception class."""

    def test_exception_can_be_raised(self) -> None:
        """Test that GoogleSheetsError can be raised."""
        with pytest.raises(GoogleSheetsError):
            raise GoogleSheetsError("Test error")

    def test_exception_message(self) -> None:
        """Test that exception message is preserved."""
        try:
            raise GoogleSheetsError("Custom error message")
        except GoogleSheetsError as e:
            assert str(e) == "Custom error message"

    def test_exception_is_exception_subclass(self) -> None:
        """Test that GoogleSheetsError is a subclass of Exception."""
        assert issubclass(GoogleSheetsError, Exception)

    def test_exception_with_empty_message(self) -> None:
        """Test creating exception with empty message."""
        error = GoogleSheetsError("")
        assert str(error) == ""


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_extract_sheet_id_with_very_long_id(self) -> None:
        """Test extracting very long sheet ID."""
        long_id = "a" * 100
        url = f"https://docs.google.com/spreadsheets/d/{long_id}/edit"
        result = extract_sheet_id(url)
        assert result == long_id

    def test_extract_gid_with_very_large_number(self) -> None:
        """Test extracting very large GID number."""
        url = "https://docs.google.com/spreadsheets/d/abc/edit#gid=999999999999"
        result = extract_gid(url)
        assert result == "999999999999"

    def test_is_google_sheets_url_with_special_characters(self) -> None:
        """Test URL detection with special characters in path."""
        url = "https://docs.google.com/spreadsheets/d/abc-_123/edit?foo=bar&baz=qux#gid=0"
        assert is_google_sheets_url(url) is True

    @pytest.mark.asyncio
    async def test_fetch_with_unicode_content(self) -> None:
        """Test fetching sheet with Unicode characters."""
        url = "https://docs.google.com/spreadsheets/d/abc123/edit"
        csv_content = "username\n@канал1\n@チャンネル2\n@قناة3"

        mock_response = MagicMock()
        mock_response.text = csv_content
        mock_response.headers = {"content-type": "text/csv"}
        mock_response.raise_for_status = MagicMock()

        with patch("chatfilter.importer.google_sheets.httpx.AsyncClient") as mock_client:
            mock_context = AsyncMock()
            mock_context.__aenter__.return_value.get = AsyncMock(return_value=mock_response)
            mock_client.return_value = mock_context

            result = await fetch_google_sheet(url)

        # Should handle Unicode usernames
        assert len(result) == 3

    def test_extract_sheet_id_preserves_case(self) -> None:
        """Test that sheet ID case is preserved."""
        url = "https://docs.google.com/spreadsheets/d/AbC123XyZ/edit"
        result = extract_sheet_id(url)
        assert result == "AbC123XyZ"

    def test_build_csv_export_url_with_empty_string_gid(self) -> None:
        """Test that empty string GID is treated as falsy."""
        result = build_csv_export_url("abc123", "")
        # Empty string is falsy, so should not include gid
        expected = "https://docs.google.com/spreadsheets/d/abc123/export?format=csv"
        assert result == expected

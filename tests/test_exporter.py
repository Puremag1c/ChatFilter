"""Tests for CSV exporter module."""

import csv
import io
from datetime import UTC, datetime, timedelta
from pathlib import Path

from chatfilter.exporter import export_to_csv, to_csv_rows
from chatfilter.exporter.csv import CSV_HEADERS, UTF8_BOM
from chatfilter.models import AnalysisResult, Chat, ChatMetrics, ChatType


def create_test_result(
    chat_id: int = 123,
    title: str = "Test Chat",
    chat_type: ChatType = ChatType.GROUP,
    username: str | None = "testchat",
    message_count: int = 100,
    unique_authors: int = 10,
    history_hours: float = 24.0,
) -> AnalysisResult:
    """Create a test AnalysisResult for testing."""
    now = datetime.now(UTC)
    return AnalysisResult(
        chat=Chat(
            id=chat_id,
            title=title,
            chat_type=chat_type,
            username=username,
        ),
        metrics=ChatMetrics(
            message_count=message_count,
            unique_authors=unique_authors,
            history_hours=history_hours,
            first_message_at=now - timedelta(hours=history_hours),
            last_message_at=now,
        ),
        analyzed_at=now,
    )


class TestToCsvRows:
    """Tests for to_csv_rows function."""

    def test_empty_results_yields_header_only(self) -> None:
        """Test that empty results yields only header row."""
        rows = list(to_csv_rows([]))

        assert len(rows) == 1
        assert rows[0] == CSV_HEADERS

    def test_single_result(self) -> None:
        """Test converting single result to CSV rows."""
        result = create_test_result()
        rows = list(to_csv_rows([result]))

        assert len(rows) == 2  # Header + 1 data row
        assert rows[0] == CSV_HEADERS

        # Check data row
        data_row = rows[1]
        assert data_row[0] == "https://t.me/testchat"  # chat_link
        assert data_row[1] == "Test Chat"  # chat_title
        assert data_row[2] == "group"  # chat_type
        assert data_row[3] == ""  # slowmode_seconds (None)
        assert data_row[4] == "100"  # message_count
        assert data_row[5] == "10"  # unique_authors

    def test_multiple_results(self) -> None:
        """Test converting multiple results."""
        results = [
            create_test_result(chat_id=1, title="Chat 1"),
            create_test_result(chat_id=2, title="Chat 2"),
            create_test_result(chat_id=3, title="Chat 3"),
        ]
        rows = list(to_csv_rows(results))

        assert len(rows) == 4  # Header + 3 data rows
        assert rows[1][1] == "Chat 1"
        assert rows[2][1] == "Chat 2"
        assert rows[3][1] == "Chat 3"

    def test_chat_without_username(self) -> None:
        """Test that chats without username use tg:// link."""
        result = create_test_result(chat_id=456, username=None)
        rows = list(to_csv_rows([result]))

        assert rows[1][0] == "tg://chat?id=456"

    def test_different_chat_types(self) -> None:
        """Test that chat types are exported correctly."""
        results = [
            create_test_result(chat_type=ChatType.PRIVATE),
            create_test_result(chat_type=ChatType.GROUP),
            create_test_result(chat_type=ChatType.SUPERGROUP),
            create_test_result(chat_type=ChatType.CHANNEL),
            create_test_result(chat_type=ChatType.FORUM),
        ]
        rows = list(to_csv_rows(results))

        assert rows[1][2] == "private"
        assert rows[2][2] == "group"
        assert rows[3][2] == "supergroup"
        assert rows[4][2] == "channel"
        assert rows[5][2] == "forum"

    def test_history_hours_formatting(self) -> None:
        """Test that history hours is formatted to 2 decimal places."""
        result = create_test_result(history_hours=24.5678)
        rows = list(to_csv_rows([result]))

        assert rows[1][6] == "24.57"  # Rounded to 2 decimal places

    def test_messages_per_hour_formatting(self) -> None:
        """Test that messages per hour is formatted correctly."""
        result = create_test_result(message_count=100, history_hours=24.0)
        rows = list(to_csv_rows([result]))

        # 100 / 24 = 4.166...
        assert rows[1][7] == "4.17"


class TestExportToCsv:
    """Tests for export_to_csv function."""

    def test_returns_string(self) -> None:
        """Test that export_to_csv returns a string."""
        results = [create_test_result()]
        content = export_to_csv(results)

        assert isinstance(content, str)
        assert len(content) > 0

    def test_includes_bom_by_default(self) -> None:
        """Test that UTF-8 BOM is included by default."""
        results = [create_test_result()]
        content = export_to_csv(results)

        assert content.startswith(UTF8_BOM)

    def test_can_exclude_bom(self) -> None:
        """Test that BOM can be excluded."""
        results = [create_test_result()]
        content = export_to_csv(results, include_bom=False)

        assert not content.startswith(UTF8_BOM)

    def test_valid_csv_format(self) -> None:
        """Test that output is valid CSV."""
        results = [create_test_result()]
        content = export_to_csv(results, include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        assert len(rows) == 2
        assert rows[0] == CSV_HEADERS

    def test_writes_to_file(self, tmp_path: Path) -> None:
        """Test writing CSV to file."""
        results = [create_test_result()]
        output_file = tmp_path / "results.csv"

        content = export_to_csv(results, output_file)

        assert output_file.exists()
        file_content = output_file.read_text(encoding="utf-8")
        # Normalize line endings for cross-platform comparison
        assert file_content.replace("\r\n", "\n") == content.replace("\r\n", "\n")

    def test_file_has_bom(self, tmp_path: Path) -> None:
        """Test that file has UTF-8 BOM."""
        results = [create_test_result()]
        output_file = tmp_path / "results.csv"

        export_to_csv(results, output_file)

        # Read raw bytes to check BOM
        raw_content = output_file.read_bytes()
        assert raw_content.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM bytes

    def test_handles_special_characters(self) -> None:
        """Test that special characters are properly escaped."""
        result = create_test_result(title='Chat with "quotes" and, commas')
        content = export_to_csv([result], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        assert rows[1][1] == 'Chat with "quotes" and, commas'

    def test_handles_unicode(self) -> None:
        """Test that unicode characters are handled correctly."""
        result = create_test_result(title="Чат с эмодзи 🎉")
        content = export_to_csv([result], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        assert rows[1][1] == "Чат с эмодзи 🎉"

    def test_empty_results_produces_header_only(self) -> None:
        """Test that empty results produces header row only."""
        content = export_to_csv([], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        assert len(rows) == 1
        assert rows[0] == CSV_HEADERS

    def test_handles_rtl_characters(self) -> None:
        """Test that RTL (right-to-left) characters are handled correctly."""
        # RTL override and marks
        result = create_test_result(
            title="Chat \u202eالعربية\u202c with RTL",  # RTL override + Arabic + Pop
        )
        content = export_to_csv([result], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # Should preserve RTL characters as-is
        assert "\u202e" in rows[1][1]
        assert "العربية" in rows[1][1]

    def test_handles_zero_width_characters(self) -> None:
        """Test that zero-width characters are handled correctly."""
        # Zero-width space, joiner, non-joiner
        result = create_test_result(
            title="Chat\u200bwith\u200czero\u200dwidth",
        )
        content = export_to_csv([result], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # Should preserve zero-width characters
        assert "\u200b" in rows[1][1]
        assert "\u200c" in rows[1][1]
        assert "\u200d" in rows[1][1]

    def test_handles_complex_emoji(self) -> None:
        """Test complex emoji including skin tones and ZWJ sequences."""
        # Emoji with skin tone modifier and ZWJ sequences
        result = create_test_result(
            title="Chat 👨‍👩‍👧‍👦 👍🏽 🏳️‍🌈",  # Family, thumbs up with skin tone, rainbow flag
        )
        content = export_to_csv([result], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # Should preserve complex emoji
        assert "👨‍👩‍👧‍👦" in rows[1][1]
        assert "👍🏽" in rows[1][1]
        assert "🏳️‍🌈" in rows[1][1]

    def test_handles_mixed_special_characters(self) -> None:
        """Test handling of mixed special characters in chat titles."""
        # Combination of emoji, RTL, zero-width, quotes, commas
        result = create_test_result(
            title='🎉 "Test\u200bChat" العربية, with everything! 🚀',
        )
        content = export_to_csv([result], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # Should preserve all characters correctly
        expected = '🎉 "Test\u200bChat" العربية, with everything! 🚀'
        assert rows[1][1] == expected

    def test_handles_newlines_in_chat_title(self) -> None:
        """Test that newlines in chat titles are handled correctly."""
        result = create_test_result(
            title="Chat\nwith\nnewlines",
        )
        content = export_to_csv([result], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # CSV should preserve newlines within quoted fields
        assert rows[1][1] == "Chat\nwith\nnewlines"

    def test_handles_very_long_chat_names(self) -> None:
        """Test that very long chat names are handled correctly."""
        # Create a chat name that's 500 characters long
        long_name = (
            "A" * 100 + " " + "B" * 100 + " " + "C" * 100 + " " + "D" * 100 + " " + "E" * 100
        )
        assert len(long_name) == 504  # 500 letters + 4 spaces

        result = create_test_result(title=long_name)
        content = export_to_csv([result], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # Should preserve the full long name
        assert rows[1][1] == long_name
        assert len(rows[1][1]) == 504

    def test_handles_extremely_long_chat_names_with_unicode(self) -> None:
        """Test that extremely long chat names with unicode are handled correctly."""
        # Create a chat name with 1000+ characters including unicode
        long_name = "🎉 " * 250 + "Тест " * 50 + "العربية " * 50 + "测试 " * 50
        # Verify it's actually long
        assert len(long_name) > 1000

        result = create_test_result(title=long_name)
        content = export_to_csv([result], include_bom=False)

        reader = csv.reader(io.StringIO(content))
        rows = list(reader)

        # Should preserve the full long name with unicode
        assert rows[1][1] == long_name
        # Verify emoji and unicode are preserved
        assert "🎉" in rows[1][1]
        assert "Тест" in rows[1][1]
        assert "العربية" in rows[1][1]
        assert "测试" in rows[1][1]


class TestDynamicCsvExport:
    """Tests for dynamic CSV export based on GroupSettings."""

    def test_all_metrics_enabled(self) -> None:
        """Test CSV export with all metrics enabled (default)."""
        from chatfilter.exporter.csv import export_group_results_to_csv, to_csv_rows_dynamic
        from chatfilter.models.group import GroupSettings

        settings = GroupSettings()  # All True by default
        results_data = [
            {
                "chat_ref": "@test_channel",
                "metrics_data": {
                    "title": "Test Channel",
                    "chat_type": "channel",
                    "subscribers": 1000,
                    "messages_per_hour": 10.5,
                    "unique_authors_per_hour": 5.25,
                    "moderation": True,
                    "captcha": False,
                    "status": "done",
                },
                "analyzed_at": datetime.now(UTC),
            }
        ]

        rows = list(to_csv_rows_dynamic(results_data, settings))

        # Should have all columns
        assert len(rows) == 2  # Header + 1 data row
        headers = rows[0]
        assert "chat_ref" in headers
        assert "title" in headers
        assert "chat_type" in headers
        assert "subscribers" in headers
        assert "messages_per_hour" in headers
        assert "unique_authors_per_hour" in headers
        assert "moderation" in headers
        assert "captcha" in headers
        assert "status" in headers

        data_row = rows[1]
        assert data_row[0] == "@test_channel"
        assert data_row[1] == "Test Channel"

    def test_selective_metrics(self) -> None:
        """Test CSV export with only some metrics enabled."""
        from chatfilter.exporter.csv import to_csv_rows_dynamic
        from chatfilter.models.group import GroupSettings

        settings = GroupSettings(
            detect_chat_type=True,
            detect_subscribers=False,
            detect_activity=True,
            detect_unique_authors=False,
            detect_moderation=False,
            detect_captcha=False,
            time_window=24,
        )

        results_data = [
            {
                "chat_ref": "@test_channel",
                "metrics_data": {
                    "title": "Test Channel",
                    "chat_type": "channel",
                    "messages_per_hour": 10.5,
                    "status": "done",
                },
                "analyzed_at": datetime.now(UTC),
            }
        ]

        rows = list(to_csv_rows_dynamic(results_data, settings))

        headers = rows[0]
        # Should only have selected columns
        assert "chat_ref" in headers
        assert "title" in headers
        assert "chat_type" in headers
        assert "messages_per_hour" in headers
        assert "status" in headers

        # Should NOT have disabled columns
        assert "subscribers" not in headers
        assert "unique_authors_per_hour" not in headers
        assert "moderation" not in headers
        assert "captcha" not in headers

    def test_minimal_metrics(self) -> None:
        """Test CSV export with all metrics disabled."""
        from chatfilter.exporter.csv import to_csv_rows_dynamic
        from chatfilter.models.group import GroupSettings

        settings = GroupSettings(
            detect_chat_type=False,
            detect_subscribers=False,
            detect_activity=False,
            detect_unique_authors=False,
            detect_moderation=False,
            detect_captcha=False,
            time_window=24,
        )

        results_data = [
            {
                "chat_ref": "@test_channel",
                "metrics_data": {
                    "title": "Test Channel",
                    "status": "done",
                },
                "analyzed_at": datetime.now(UTC),
            }
        ]

        rows = list(to_csv_rows_dynamic(results_data, settings))

        headers = rows[0]
        # Should only have mandatory columns
        assert headers == ["chat_ref", "title", "status"]

        data_row = rows[1]
        assert data_row[0] == "@test_channel"
        assert data_row[1] == "Test Channel"
        assert data_row[2] == "done"

    def test_none_settings_includes_all_columns(self) -> None:
        """Test that None settings includes all columns (backward compatibility)."""
        from chatfilter.exporter.csv import to_csv_rows_dynamic

        results_data = [
            {
                "chat_ref": "@test_channel",
                "metrics_data": {
                    "title": "Test Channel",
                    "chat_type": "channel",
                    "subscribers": 1000,
                    "messages_per_hour": 10.5,
                    "unique_authors_per_hour": 5.25,
                    "moderation": True,
                    "captcha": False,
                    "status": "done",
                },
                "analyzed_at": datetime.now(UTC),
            }
        ]

        rows = list(to_csv_rows_dynamic(results_data, settings=None))

        headers = rows[0]
        # All columns should be included
        assert "chat_type" in headers
        assert "subscribers" in headers
        assert "messages_per_hour" in headers
        assert "unique_authors_per_hour" in headers
        assert "moderation" in headers
        assert "captcha" in headers

    def test_formatting_boolean_fields(self) -> None:
        """Test that boolean fields are formatted as yes/no."""
        from chatfilter.exporter.csv import to_csv_rows_dynamic
        from chatfilter.models.group import GroupSettings

        settings = GroupSettings(
            detect_moderation=True,
            detect_captcha=True,
        )

        results_data = [
            {
                "chat_ref": "@test1",
                "metrics_data": {
                    "title": "Test 1",
                    "moderation": True,
                    "captcha": False,
                    "status": "done",
                },
                "analyzed_at": datetime.now(UTC),
            },
            {
                "chat_ref": "@test2",
                "metrics_data": {
                    "title": "Test 2",
                    "moderation": False,
                    "captcha": True,
                    "status": "done",
                },
                "analyzed_at": datetime.now(UTC),
            },
        ]

        rows = list(to_csv_rows_dynamic(results_data, settings))

        # Row 1: moderation=True, captcha=False
        assert "yes" in rows[1]
        assert "no" in rows[1]

        # Row 2: moderation=False, captcha=True
        assert "no" in rows[2]
        assert "yes" in rows[2]

    def test_export_to_file_with_settings(self, tmp_path: Path) -> None:
        """Test exporting group results to file with settings."""
        from chatfilter.exporter.csv import export_group_results_to_csv
        from chatfilter.models.group import GroupSettings

        settings = GroupSettings(
            detect_chat_type=True,
            detect_activity=True,
        )

        results_data = [
            {
                "chat_ref": "@test_channel",
                "metrics_data": {
                    "title": "Test Channel",
                    "chat_type": "channel",
                    "messages_per_hour": 10.5,
                    "status": "done",
                },
                "analyzed_at": datetime.now(UTC),
            }
        ]

        output_file = tmp_path / "results.csv"
        content = export_group_results_to_csv(results_data, settings, output_file)

        # File should exist
        assert output_file.exists()

        # Content should be returned
        assert isinstance(content, str)
        assert "chat_ref" in content
        assert "Test Channel" in content

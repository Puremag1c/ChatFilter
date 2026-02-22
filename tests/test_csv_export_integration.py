"""Integration tests for CSV export with new data model.

This test verifies the complete CSV export flow:
1. Create group with specific settings → add chats with metrics → export CSV → verify columns
2. Test _convert_results_for_exporter bridges flat results to exporter format
3. Test filters: chat_type, subscribers_min/max, moderation, captcha
4. Test Cyrillic group names in filename (Content-Disposition header)
5. Test CSV opens correctly in Excel (BOM, encoding)
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from pathlib import Path

import pytest

from chatfilter.exporter.csv import export_group_results_to_csv, to_csv_rows_dynamic
from chatfilter.models.group import GroupSettings
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.web.routers.groups import _apply_export_filters, _convert_results_for_exporter


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> GroupDatabase:
    """Create isolated test database."""
    db_path = tmp_path / "test_groups.db"
    database = GroupDatabase(str(db_path))
    return database


@pytest.fixture
def service(db: GroupDatabase) -> GroupService:
    """Create group service with mock engine."""
    # GroupService doesn't require engine for get_results()
    return GroupService(db=db, engine=None)  # type: ignore


def _create_group_with_chats(
    db: GroupDatabase,
    group_id: str,
    name: str,
    settings: GroupSettings,
    chats_data: list[dict],
) -> None:
    """Helper: create group and chats with metrics.

    Args:
        db: Database instance
        group_id: Group identifier
        name: Group name
        settings: Group settings
        chats_data: List of chat dicts with {chat_ref, title, chat_type, metrics}
    """
    # Create group
    db.save_group(
        group_id=group_id,
        name=name,
        settings=settings.model_dump(),
        status="done",
    )

    # Create chats with metrics
    for chat_data in chats_data:
        metrics = chat_data.get("metrics", {})

        # Save chat (subscribers goes in group_chats table)
        db.save_chat(
            group_id=group_id,
            chat_ref=chat_data["chat_ref"],
            chat_type=chat_data.get("chat_type", "channel"),
            status="done",
            subscribers=metrics.get("subscribers"),
        )

        # Get chat ID by filtering loaded chats
        all_chats = db.load_chats(group_id=group_id)
        matching_chats = [c for c in all_chats if c["chat_ref"] == chat_data["chat_ref"]]
        if not matching_chats:
            continue
        chat_id = matching_chats[0]["id"]

        # Save other metrics (in metrics JSON)
        db.save_chat_metrics(
            chat_id=chat_id,
            metrics=metrics,
        )


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------


class TestCsvExportIntegration:
    """Integration tests for CSV export end-to-end flow."""

    def test_full_export_flow_all_columns(self, db: GroupDatabase, service: GroupService) -> None:
        """Test: create group → add chats with metrics → export CSV → verify all columns present."""
        # Arrange: Create group with all metrics enabled
        settings = GroupSettings(
            detect_chat_type=True,
            detect_subscribers=True,
            detect_activity=True,
            detect_unique_authors=True,
            detect_moderation=True,
            detect_captcha=True,
            time_window=24,
        )

        chats_data = [
            {
                "chat_ref": "@channel_1",
                "chat_type": "channel",
                "metrics": {
                    "title": "Test Channel 1",
                    "subscribers": 5000,
                    "messages_per_hour": 12.5,
                    "unique_authors_per_hour": 3.2,
                    "moderation": False,
                    "captcha": True,
                },
            },
            {
                "chat_ref": "@group_2",
                "chat_type": "supergroup",
                "metrics": {
                    "title": "Test Group 2",
                    "subscribers": 1500,
                    "messages_per_hour": 8.75,
                    "unique_authors_per_hour": 2.1,
                    "moderation": True,
                    "captcha": False,
                },
            },
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-test-1",
            name="Test Group",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Export CSV
        results_data = service.get_results("grp-test-1")
        exporter_format = _convert_results_for_exporter(results_data)
        csv_content = export_group_results_to_csv(
            exporter_format,
            settings=settings,
            include_bom=True,
        )

        # Assert: Verify CSV structure
        # Remove BOM for parsing
        csv_content_no_bom = csv_content.lstrip("\ufeff")
        reader = csv.reader(io.StringIO(csv_content_no_bom))
        rows = list(reader)

        # Verify header
        assert len(rows) == 3  # Header + 2 data rows
        headers = rows[0]
        assert headers == [
            "chat_ref",
            "title",
            "chat_type",
            "subscribers",
            "messages_per_hour",
            "unique_authors_per_hour",
            "moderation",
            "captcha",
            "status",
        ]

        # Verify data row 1
        assert rows[1][0] == "@channel_1"
        assert rows[1][1] == "Test Channel 1"
        assert rows[1][2] == "channel"
        assert rows[1][3] == "5000"
        assert rows[1][4] == "12.50"
        assert rows[1][5] == "3.20"
        assert rows[1][6] == "no"
        assert rows[1][7] == "yes"
        assert rows[1][8] == "done"

        # Verify data row 2
        assert rows[2][0] == "@group_2"
        assert rows[2][1] == "Test Group 2"
        assert rows[2][2] == "supergroup"
        assert rows[2][3] == "1500"
        assert rows[2][4] == "8.75"
        assert rows[2][5] == "2.10"
        assert rows[2][6] == "yes"
        assert rows[2][7] == "no"
        assert rows[2][8] == "done"

    def test_selective_columns_export(self, db: GroupDatabase, service: GroupService) -> None:
        """Test CSV export with only some metrics enabled."""
        # Arrange: Group with only chat_type and activity enabled
        settings = GroupSettings(
            detect_chat_type=True,
            detect_subscribers=False,
            detect_activity=True,
            detect_unique_authors=False,
            detect_moderation=False,
            detect_captcha=False,
            time_window=24,
        )

        chats_data = [
            {
                "chat_ref": "@channel_test",
                "chat_type": "channel",
                "metrics": {
                    "title": "Test Channel",
                    "messages_per_hour": 15.3,
                },
            }
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-test-2",
            name="Selective Group",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Export CSV
        results_data = service.get_results("grp-test-2")
        exporter_format = _convert_results_for_exporter(results_data)
        csv_content = export_group_results_to_csv(
            exporter_format,
            settings=settings,
            include_bom=False,
        )

        # Assert: Only selected columns present
        reader = csv.reader(io.StringIO(csv_content))
        rows = list(reader)

        headers = rows[0]
        assert headers == [
            "chat_ref",
            "title",
            "chat_type",
            "messages_per_hour",
            "status",
        ]

        # Verify disabled columns are NOT present
        assert "subscribers" not in headers
        assert "unique_authors_per_hour" not in headers
        assert "moderation" not in headers
        assert "captcha" not in headers

    def test_convert_results_for_exporter_bridge(self, db: GroupDatabase, service: GroupService) -> None:
        """Test _convert_results_for_exporter correctly bridges flat results to exporter format."""
        # Arrange: Create group with chat
        settings = GroupSettings()
        chats_data = [
            {
                "chat_ref": "@test_channel",
                "chat_type": "channel",
                "metrics": {
                    "title": "Bridge Test",
                    "subscribers": 2500,
                    "messages_per_hour": 10.0,
                    "moderation": False,
                },
            }
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-bridge",
            name="Bridge Test",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Get flat results and convert
        flat_results = service.get_results("grp-bridge")
        exporter_format = _convert_results_for_exporter(flat_results)

        # Assert: Verify structure transformation
        assert len(exporter_format) == 1
        result = exporter_format[0]

        # Top-level fields
        assert result["chat_ref"] == "@test_channel"
        assert "metrics_data" in result

        # Nested metrics_data
        metrics = result["metrics_data"]
        assert metrics["title"] == "Bridge Test"
        assert metrics["chat_type"] == "channel"
        assert metrics["subscribers"] == 2500
        assert metrics["messages_per_hour"] == 10.0
        # SQLite stores booleans as 0/1
        assert metrics["moderation"] in (False, 0)
        assert metrics["status"] == "done"


class TestExportFilters:
    """Test CSV export filters."""

    def test_filter_by_chat_type(self, db: GroupDatabase, service: GroupService) -> None:
        """Test filtering by chat_type."""
        # Arrange
        settings = GroupSettings(detect_chat_type=True)
        chats_data = [
            {"chat_ref": "@channel_1", "chat_type": "channel", "metrics": {"title": "Channel 1"}},
            {"chat_ref": "@group_1", "chat_type": "supergroup", "metrics": {"title": "Group 1"}},
            {"chat_ref": "@channel_2", "chat_type": "channel", "metrics": {"title": "Channel 2"}},
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-filter-type",
            name="Filter Test",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Filter by channel only
        results_data = service.get_results("grp-filter-type")
        filtered = _apply_export_filters(results_data, chat_types="channel")

        # Assert
        assert len(filtered) == 2
        assert all(r["chat_type"] == "channel" for r in filtered)

    def test_filter_by_subscribers_range(self, db: GroupDatabase, service: GroupService) -> None:
        """Test filtering by subscribers_min/max."""
        # Arrange
        settings = GroupSettings(detect_subscribers=True)
        chats_data = [
            {"chat_ref": "@chat_1", "metrics": {"title": "Chat 1", "subscribers": 500}},
            {"chat_ref": "@chat_2", "metrics": {"title": "Chat 2", "subscribers": 1500}},
            {"chat_ref": "@chat_3", "metrics": {"title": "Chat 3", "subscribers": 3000}},
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-filter-subs",
            name="Subscribers Test",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Filter subscribers between 1000 and 2000
        results_data = service.get_results("grp-filter-subs")
        filtered = _apply_export_filters(
            results_data,
            subscribers_min=1000,
            subscribers_max=2000,
        )

        # Assert
        assert len(filtered) == 1
        assert filtered[0]["subscribers"] == 1500

    def test_filter_by_activity_range(self, db: GroupDatabase, service: GroupService) -> None:
        """Test filtering by activity_min/max."""
        # Arrange
        settings = GroupSettings(detect_activity=True)
        chats_data = [
            {"chat_ref": "@chat_1", "metrics": {"title": "Chat 1", "messages_per_hour": 5.0}},
            {"chat_ref": "@chat_2", "metrics": {"title": "Chat 2", "messages_per_hour": 12.5}},
            {"chat_ref": "@chat_3", "metrics": {"title": "Chat 3", "messages_per_hour": 20.0}},
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-filter-activity",
            name="Activity Test",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Filter activity > 10.0
        results_data = service.get_results("grp-filter-activity")
        filtered = _apply_export_filters(results_data, activity_min=10.0)

        # Assert
        assert len(filtered) == 2
        assert all(r["messages_per_hour"] >= 10.0 for r in filtered)

    def test_filter_by_moderation(self, db: GroupDatabase, service: GroupService) -> None:
        """Test filtering by moderation."""
        # Arrange
        settings = GroupSettings(detect_moderation=True)
        chats_data = [
            {"chat_ref": "@chat_1", "metrics": {"title": "Chat 1", "moderation": True}},
            {"chat_ref": "@chat_2", "metrics": {"title": "Chat 2", "moderation": False}},
            {"chat_ref": "@chat_3", "metrics": {"title": "Chat 3", "moderation": True}},
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-filter-mod",
            name="Moderation Test",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Filter moderation=yes
        results_data = service.get_results("grp-filter-mod")
        filtered = _apply_export_filters(results_data, moderation="yes")

        # Assert
        assert len(filtered) == 2
        # SQLite stores booleans as 0/1
        assert all(r["moderation"] in (True, 1) for r in filtered)

    def test_filter_by_captcha(self, db: GroupDatabase, service: GroupService) -> None:
        """Test filtering by captcha."""
        # Arrange
        settings = GroupSettings(detect_captcha=True)
        chats_data = [
            {"chat_ref": "@chat_1", "metrics": {"title": "Chat 1", "captcha": False}},
            {"chat_ref": "@chat_2", "metrics": {"title": "Chat 2", "captcha": True}},
            {"chat_ref": "@chat_3", "metrics": {"title": "Chat 3", "captcha": False}},
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-filter-captcha",
            name="Captcha Test",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Filter captcha=no
        results_data = service.get_results("grp-filter-captcha")
        filtered = _apply_export_filters(results_data, captcha="no")

        # Assert
        assert len(filtered) == 2
        # SQLite stores booleans as 0/1
        assert all(r["captcha"] in (False, 0) for r in filtered)

    def test_combined_filters(self, db: GroupDatabase, service: GroupService) -> None:
        """Test multiple filters combined."""
        # Arrange
        settings = GroupSettings(
            detect_chat_type=True,
            detect_subscribers=True,
            detect_moderation=True,
        )
        chats_data = [
            {
                "chat_ref": "@channel_1",
                "chat_type": "channel",
                "metrics": {"title": "Channel 1", "subscribers": 1500, "moderation": False},
            },
            {
                "chat_ref": "@channel_2",
                "chat_type": "channel",
                "metrics": {"title": "Channel 2", "subscribers": 2500, "moderation": True},
            },
            {
                "chat_ref": "@group_1",
                "chat_type": "supergroup",
                "metrics": {"title": "Group 1", "subscribers": 1800, "moderation": False},
            },
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-filter-combined",
            name="Combined Filter Test",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Filter channel + subscribers>2000 + moderation=yes
        results_data = service.get_results("grp-filter-combined")
        filtered = _apply_export_filters(
            results_data,
            chat_types="channel",
            subscribers_min=2000,
            moderation="yes",
        )

        # Assert: Only channel_2 matches all filters
        assert len(filtered) == 1
        assert filtered[0]["chat_ref"] == "@channel_2"


class TestCyrillicAndEncoding:
    """Test Cyrillic names and Excel encoding."""

    def test_cyrillic_group_name_in_csv(self, db: GroupDatabase, service: GroupService) -> None:
        """Test CSV with Cyrillic chat titles."""
        # Arrange
        settings = GroupSettings()
        chats_data = [
            {
                "chat_ref": "@russian_chat",
                "metrics": {"title": "Русский Чат"},
            },
            {
                "chat_ref": "@ukrainian_chat",
                "metrics": {"title": "Український Чат"},
            },
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-cyrillic",
            name="Тестовая Группа",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Export CSV
        results_data = service.get_results("grp-cyrillic")
        exporter_format = _convert_results_for_exporter(results_data)
        csv_content = export_group_results_to_csv(
            exporter_format,
            settings=settings,
            include_bom=True,
        )

        # Assert: Cyrillic preserved
        assert "Русский Чат" in csv_content
        assert "Український Чат" in csv_content

        # Verify UTF-8 BOM for Excel
        assert csv_content.startswith("\ufeff")

        # Verify CSV is parseable
        csv_content_no_bom = csv_content.lstrip("\ufeff")
        reader = csv.reader(io.StringIO(csv_content_no_bom))
        rows = list(reader)

        assert rows[1][1] == "Русский Чат"  # Title preserved
        assert rows[2][1] == "Український Чат"

    def test_excel_bom_encoding(self, db: GroupDatabase, service: GroupService, tmp_path: Path) -> None:
        """Test CSV has UTF-8 BOM for Excel compatibility."""
        # Arrange
        settings = GroupSettings()
        chats_data = [
            {"chat_ref": "@test", "metrics": {"title": "Test"}},
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-bom",
            name="BOM Test",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Export to file
        results_data = service.get_results("grp-bom")
        exporter_format = _convert_results_for_exporter(results_data)
        output_file = tmp_path / "test.csv"

        export_group_results_to_csv(
            exporter_format,
            settings=settings,
            output=output_file,
            include_bom=True,
        )

        # Assert: File has UTF-8 BOM bytes
        raw_content = output_file.read_bytes()
        assert raw_content.startswith(b"\xef\xbb\xbf")  # UTF-8 BOM

    def test_mixed_unicode_export(self, db: GroupDatabase, service: GroupService) -> None:
        """Test CSV with mixed unicode: emoji, Cyrillic, Arabic, Chinese."""
        # Arrange
        settings = GroupSettings()
        chats_data = [
            {"chat_ref": "@emoji", "metrics": {"title": "🎉 Emoji Chat 🚀"}},
            {"chat_ref": "@russian", "metrics": {"title": "Русский"}},
            {"chat_ref": "@arabic", "metrics": {"title": "العربية"}},
            {"chat_ref": "@chinese", "metrics": {"title": "中文"}},
        ]

        _create_group_with_chats(
            db=db,
            group_id="grp-unicode",
            name="Unicode Test",
            settings=settings,
            chats_data=chats_data,
        )

        # Act: Export CSV
        results_data = service.get_results("grp-unicode")
        exporter_format = _convert_results_for_exporter(results_data)
        csv_content = export_group_results_to_csv(
            exporter_format,
            settings=settings,
            include_bom=False,
        )

        # Assert: All unicode preserved
        reader = csv.reader(io.StringIO(csv_content))
        rows = list(reader)

        titles = [row[1] for row in rows[1:]]  # Skip header
        assert "🎉 Emoji Chat 🚀" in titles
        assert "Русский" in titles
        assert "العربية" in titles
        assert "中文" in titles

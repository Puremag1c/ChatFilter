"""Tests for CSV export validation.

Tests that CSV export columns match exactly the selected metrics in GroupSettings.
Validates dynamic column generation based on metric checkboxes.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from chatfilter.models.group import GroupSettings
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase


@pytest.fixture
def group_service(isolated_tmp_dir) -> GroupService:
    """Create GroupService with isolated database."""
    db_path = isolated_tmp_dir / "groups.db"
    db = GroupDatabase(db_path)
    return GroupService(db)


@pytest.fixture
def test_group_with_results(group_service: GroupService) -> str:
    """Create test group with completed analysis results.

    Returns group_id with 3 chats analyzed and results stored.
    """
    # Create group with default settings
    group = group_service.create_group(
        name="Test Export Group",
        chat_refs=[
            "https://t.me/testchat1",
            "https://t.me/testchat2",
            "@testchat3",
        ],
    )

    # Store analysis results for each chat
    results_data = [
        {
            "chat_ref": "https://t.me/testchat1",
            "metrics_data": {
                "title": "Test Chat 1",
                "chat_type": "group",
                "subscribers": 1234,
                "messages_per_hour": 15.5,
                "unique_authors_per_hour": 8.2,
                "moderation": True,
                "captcha": False,
                "status": "ok",
            },
            "analyzed_at": datetime.now(UTC),
        },
        {
            "chat_ref": "https://t.me/testchat2",
            "metrics_data": {
                "title": "Test Chat 2",
                "chat_type": "channel_comments",
                "subscribers": 5678,
                "messages_per_hour": 3.1,
                "unique_authors_per_hour": 2.0,
                "moderation": False,
                "captcha": True,
                "status": "ok",
            },
            "analyzed_at": datetime.now(UTC),
        },
        {
            "chat_ref": "@testchat3",
            "metrics_data": {
                "title": "Test Chat 3",
                "chat_type": "forum",
                "subscribers": 999,
                "messages_per_hour": 0.5,
                "unique_authors_per_hour": 0.3,
                "moderation": False,
                "captcha": False,
                "status": "ok",
            },
            "analyzed_at": datetime.now(UTC),
        },
    ]

    for result in results_data:
        group_service._db.save_result(
            group_id=group.id,
            chat_ref=result["chat_ref"],
            metrics_data=result["metrics_data"],
            analyzed_at=result["analyzed_at"],
        )

    return group.id


def parse_csv(csv_content: str) -> tuple[list[str], list[dict[str, str]]]:
    """Parse CSV content into headers and rows.

    Args:
        csv_content: CSV string content

    Returns:
        Tuple of (headers, rows) where rows is list of dicts
    """
    # Strip BOM if present
    if csv_content.startswith('\ufeff'):
        csv_content = csv_content[1:]

    reader = csv.DictReader(io.StringIO(csv_content))
    headers = reader.fieldnames or []
    rows = list(reader)

    return headers, rows


class TestCSVExportColumnValidation:
    """Test CSV export columns match selected metrics."""

    def test_metrics_1_2_5_only(
        self,
        group_service: GroupService,
        test_group_with_results: str,
    ):
        """Test CSV with metrics 1,2,5: chat_type, subscribers, moderation.

        Expected columns: chat_ref, title, chat_type, subscribers, moderation, status
        """
        # Update settings: only metrics 1,2,5
        settings = GroupSettings(
            detect_chat_type=True,
            detect_subscribers=True,
            detect_activity=False,
            detect_unique_authors=False,
            detect_moderation=True,
            detect_captcha=False,
            time_window=24,
        )
        group_service.update_settings(test_group_with_results, settings)

        # Export CSV
        from chatfilter.exporter.csv import export_group_results_to_csv

        results_data = group_service._db.load_results(test_group_with_results)
        csv_content = export_group_results_to_csv(
            results_data,
            settings=settings,
            include_bom=True,
        )

        # Parse CSV
        headers, rows = parse_csv(csv_content)

        # Verify headers
        expected_headers = [
            "chat_ref",
            "title",
            "chat_type",
            "subscribers",
            "moderation",
            "status",
        ]
        assert headers == expected_headers, f"Headers mismatch. Got: {headers}"

        # Verify 3 data rows
        assert len(rows) == 3

        # Find test chat 1 row (order not guaranteed)
        test_chat_1 = next(
            (row for row in rows if row["chat_ref"] == "https://t.me/testchat1"),
            None,
        )
        assert test_chat_1 is not None, "Test chat 1 not found in results"

        # Verify test chat 1 data
        assert test_chat_1["title"] == "Test Chat 1"
        assert test_chat_1["chat_type"] == "group"
        assert test_chat_1["subscribers"] == "1234"
        assert test_chat_1["moderation"] == "yes"
        assert test_chat_1["status"] == "ok"

        # Verify NO activity columns present
        assert "messages_per_hour" not in headers
        assert "unique_authors_per_hour" not in headers
        assert "captcha" not in headers

    def test_metrics_3_4_6_only(
        self,
        group_service: GroupService,
        test_group_with_results: str,
    ):
        """Test CSV with metrics 3,4,6: activity, unique_authors, captcha.

        Expected columns: chat_ref, title, messages_per_hour,
                         unique_authors_per_hour, captcha, status
        """
        # Update settings: only metrics 3,4,6
        settings = GroupSettings(
            detect_chat_type=False,
            detect_subscribers=False,
            detect_activity=True,
            detect_unique_authors=True,
            detect_moderation=False,
            detect_captcha=True,
            time_window=24,
        )
        group_service.update_settings(test_group_with_results, settings)

        # Export CSV
        from chatfilter.exporter.csv import export_group_results_to_csv

        results_data = group_service._db.load_results(test_group_with_results)
        csv_content = export_group_results_to_csv(
            results_data,
            settings=settings,
            include_bom=True,
        )

        # Parse CSV
        headers, rows = parse_csv(csv_content)

        # Verify headers
        expected_headers = [
            "chat_ref",
            "title",
            "messages_per_hour",
            "unique_authors_per_hour",
            "captcha",
            "status",
        ]
        assert headers == expected_headers, f"Headers mismatch. Got: {headers}"

        # Verify 3 data rows
        assert len(rows) == 3

        # Find test chat 1 row (order not guaranteed)
        test_chat_1 = next(
            (row for row in rows if row["chat_ref"] == "https://t.me/testchat1"),
            None,
        )
        assert test_chat_1 is not None, "Test chat 1 not found in results"

        # Verify test chat 1 data
        assert test_chat_1["title"] == "Test Chat 1"
        assert test_chat_1["messages_per_hour"] == "15.50"
        assert test_chat_1["unique_authors_per_hour"] == "8.20"
        assert test_chat_1["captcha"] == "no"
        assert test_chat_1["status"] == "ok"

        # Verify NO type/subscribers/moderation columns
        assert "chat_type" not in headers
        assert "subscribers" not in headers
        assert "moderation" not in headers

    def test_all_6_metrics(
        self,
        group_service: GroupService,
        test_group_with_results: str,
    ):
        """Test CSV with all 6 metrics enabled.

        Expected all columns: chat_ref, title, chat_type, subscribers,
                             messages_per_hour, unique_authors_per_hour,
                             moderation, captcha, status
        """
        # Update settings: all metrics enabled
        settings = GroupSettings(
            detect_chat_type=True,
            detect_subscribers=True,
            detect_activity=True,
            detect_unique_authors=True,
            detect_moderation=True,
            detect_captcha=True,
            time_window=24,
        )
        group_service.update_settings(test_group_with_results, settings)

        # Export CSV
        from chatfilter.exporter.csv import export_group_results_to_csv

        results_data = group_service._db.load_results(test_group_with_results)
        csv_content = export_group_results_to_csv(
            results_data,
            settings=settings,
            include_bom=True,
        )

        # Parse CSV
        headers, rows = parse_csv(csv_content)

        # Verify headers
        expected_headers = [
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
        assert headers == expected_headers, f"Headers mismatch. Got: {headers}"

        # Verify 3 data rows
        assert len(rows) == 3

        # Find test chat 1 row (order not guaranteed)
        test_chat_1 = next(
            (row for row in rows if row["chat_ref"] == "https://t.me/testchat1"),
            None,
        )
        assert test_chat_1 is not None, "Test chat 1 not found in results"

        # Verify all columns present in test chat 1
        assert test_chat_1["title"] == "Test Chat 1"
        assert test_chat_1["chat_type"] == "group"
        assert test_chat_1["subscribers"] == "1234"
        assert test_chat_1["messages_per_hour"] == "15.50"
        assert test_chat_1["unique_authors_per_hour"] == "8.20"
        assert test_chat_1["moderation"] == "yes"
        assert test_chat_1["captcha"] == "no"
        assert test_chat_1["status"] == "ok"

    def test_no_metrics_selected(
        self,
        group_service: GroupService,
        test_group_with_results: str,
    ):
        """Test CSV with no metrics selected.

        Expected only: chat_ref, title, status
        """
        # Update settings: no metrics
        settings = GroupSettings(
            detect_chat_type=False,
            detect_subscribers=False,
            detect_activity=False,
            detect_unique_authors=False,
            detect_moderation=False,
            detect_captcha=False,
            time_window=24,
        )
        group_service.update_settings(test_group_with_results, settings)

        # Export CSV
        from chatfilter.exporter.csv import export_group_results_to_csv

        results_data = group_service._db.load_results(test_group_with_results)
        csv_content = export_group_results_to_csv(
            results_data,
            settings=settings,
            include_bom=True,
        )

        # Parse CSV
        headers, rows = parse_csv(csv_content)

        # Verify headers - minimal set
        expected_headers = [
            "chat_ref",
            "title",
            "status",
        ]
        assert headers == expected_headers, f"Headers mismatch. Got: {headers}"

        # Verify 3 data rows
        assert len(rows) == 3

        # Find test chat 1 row (order not guaranteed)
        test_chat_1 = next(
            (row for row in rows if row["chat_ref"] == "https://t.me/testchat1"),
            None,
        )
        assert test_chat_1 is not None, "Test chat 1 not found in results"

        # Verify minimal data
        assert test_chat_1["title"] == "Test Chat 1"
        assert test_chat_1["status"] == "ok"

        # Verify NO metric columns present
        assert "chat_type" not in headers
        assert "subscribers" not in headers
        assert "messages_per_hour" not in headers
        assert "unique_authors_per_hour" not in headers
        assert "moderation" not in headers
        assert "captcha" not in headers

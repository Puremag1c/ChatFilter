"""Phase 1 — "download" button available after import/scraping.

Business rule: user paid for scraping / imported a list — must be able
to download it right away, even for chats that have not been analyzed.

Tests:
  1. Exporter handles PENDING chats (empty metrics cells, chat_ref shown).
  2. get_results() returns PENDING rows too (not filtered out).
  3. Scraper persists titles into chat_metrics so PENDING rows carry
     the platform-provided title in the export.
  4. UI template shows the Download button whenever stats.total > 0
     (previously: only after stats.analyzed > 0).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from chatfilter.exporter.csv import export_group_results_to_csv
from chatfilter.models.group import ChatTypeEnum, GroupChatStatus, GroupSettings
from chatfilter.service.group_service import GroupService
from chatfilter.storage.group_database import GroupDatabase
from chatfilter.web.routers.groups.export import (
    _convert_results_for_exporter as _convert_to_exporter_format,
)


# ------------------------------------------------------------------
# shared setup
# ------------------------------------------------------------------


@pytest.fixture
def db(tmp_path: Path) -> GroupDatabase:
    db_path = tmp_path / "test.db"
    return GroupDatabase(str(db_path))


@pytest.fixture
def service(db: GroupDatabase) -> GroupService:
    return GroupService(db=db)


def _make_group(db: GroupDatabase, group_id: str = "g1") -> None:
    from chatfilter.models.group import GroupStatus

    db.save_group(
        group_id=group_id,
        name="Test Group",
        settings=GroupSettings().model_dump(),
        status=GroupStatus.PENDING.value,
    )


# ------------------------------------------------------------------
# 1. service.get_results returns PENDING rows
# ------------------------------------------------------------------


class TestGetResultsIncludesPending:
    def test_pending_chats_are_in_results(
        self, db: GroupDatabase, service: GroupService
    ) -> None:
        _make_group(db)
        db.save_chat(
            group_id="g1",
            chat_ref="@just_imported",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )

        results = service.get_results("g1")

        assert len(results) == 1
        assert results[0]["chat_ref"] == "@just_imported"
        assert results[0]["status"] == GroupChatStatus.PENDING.value
        # empty/missing metrics are fine
        assert results[0].get("title") in (None, "")

    def test_mixed_pending_and_done_both_returned(
        self, db: GroupDatabase, service: GroupService
    ) -> None:
        _make_group(db)
        db.save_chat(
            group_id="g1",
            chat_ref="@pending1",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )
        db.save_chat(
            group_id="g1",
            chat_ref="@done1",
            chat_type=ChatTypeEnum.GROUP.value,
            status=GroupChatStatus.DONE.value,
            subscribers=500,
        )

        results = service.get_results("g1")

        refs = {r["chat_ref"] for r in results}
        assert refs == {"@pending1", "@done1"}


# ------------------------------------------------------------------
# 2. CSV export survives PENDING rows
# ------------------------------------------------------------------


class TestExportPendingRows:
    def test_export_includes_pending_with_empty_cells(
        self, db: GroupDatabase, service: GroupService
    ) -> None:
        _make_group(db)
        db.save_chat(
            group_id="g1",
            chat_ref="@just_imported",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )
        db.save_chat(
            group_id="g1",
            chat_ref="@done_group",
            chat_type=ChatTypeEnum.GROUP.value,
            status=GroupChatStatus.DONE.value,
            subscribers=1000,
        )
        # Add metrics for the done chat only.
        done_id = [c["id"] for c in db.load_chats(group_id="g1") if c["chat_ref"] == "@done_group"][
            0
        ]
        db.save_chat_metrics(
            done_id,
            {
                "title": "Done Group",
                "subscribers": 1000,
                "chat_type": ChatTypeEnum.GROUP.value,
                "moderation": False,
            },
        )

        results = service.get_results("g1")
        text = export_group_results_to_csv(
            _convert_to_exporter_format(results), GroupSettings()
        )
        # both rows present
        assert "@just_imported" in text
        assert "@done_group" in text
        # done row has its title
        assert "Done Group" in text


# ------------------------------------------------------------------
# 3. Scraper-provided titles reach the export for PENDING chats.
# ------------------------------------------------------------------


class TestScrapedTitlesPersistToExport:
    def test_scraped_title_saved_and_exported_for_pending_chat(
        self, db: GroupDatabase, service: GroupService
    ) -> None:
        """After scraping, an unanalyzed chat still has a title from the platform.

        This is the contract the scraper must honour: if it learned a title
        from tlgrm/tgstat/etc., it writes it into chat_metrics so the PENDING
        export row isn't blank.
        """
        _make_group(db)
        # Simulate what the orchestrator must do after save_chat:
        db.save_chat(
            group_id="g1",
            chat_ref="@scraped_chat",
            chat_type=ChatTypeEnum.PENDING.value,
            status=GroupChatStatus.PENDING.value,
        )
        chat_id = db.load_chats(group_id="g1")[0]["id"]
        db.save_chat_metrics(chat_id, {"title": "Scraped Title Here"})

        results = service.get_results("g1")
        assert results[0].get("title") == "Scraped Title Here"

        text = export_group_results_to_csv(
            _convert_to_exporter_format(results), GroupSettings()
        )
        assert "Scraped Title Here" in text


# ------------------------------------------------------------------
# 4. UI condition — Download button visible when stats.total > 0
# ------------------------------------------------------------------


class TestDownloadButtonVisibility:
    """The group-card template shows the Download button when there are chats,
    not when any of them have been analyzed.

    We assert on the raw template source — no need to render. The condition
    change is the one-liner fix in the template.
    """

    def test_template_condition_is_total_not_analyzed(self) -> None:
        tpl_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "chatfilter"
            / "templates"
            / "partials"
            / "group_card.html"
        )
        source = tpl_path.read_text()
        # The download-button block must key off stats.total, never analyzed>0.
        # Grab the lines around "Download results".
        idx = source.find("Download results")
        assert idx != -1, "Download results label missing from template"
        # Scan up to ~200 chars above the label for the if-condition.
        above = source[max(0, idx - 400) : idx]
        assert "stats.total > 0" in above, (
            "Download button must be guarded by stats.total > 0, "
            "not stats.analyzed > 0"
        )
        assert "stats.analyzed > 0" not in above, (
            "Old condition stats.analyzed > 0 still present — "
            "user cannot download after scraping/import"
        )

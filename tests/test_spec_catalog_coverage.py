"""Generated tests for SPEC.md v0.28+ catalog feature coverage gaps.

Covers requirements not explicitly tested by existing test suite:
1. AnalysisModeEnum.to_group_settings() — quick and deep modes
2. CatalogChat.is_fresh() — freshness check logic
3. list_catalog_chats() with filters — catalog DB filtering
4. update_catalog_metrics() EMA logic — metrics averaging
5. get_analysis_freshness_days() and get_max_chats_per_account() defaults
6. /catalog and /api/catalog HTTP endpoints — basic availability
"""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

os.environ.setdefault("CHATFILTER_API_ID", "123456")
os.environ.setdefault("CHATFILTER_API_HASH", "test_hash_abcdef123456789")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db():
    """Create a temporary GroupDatabase for testing."""
    from chatfilter.storage.group_database import GroupDatabase

    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_catalog.db"
        yield GroupDatabase(db_path)


@pytest.fixture
def sample_catalog_chat():
    """Create a sample CatalogChat."""
    from chatfilter.models.catalog import AnalysisModeEnum, CatalogChat
    from chatfilter.models.group import ChatTypeEnum

    return CatalogChat(
        id="@testchat",
        telegram_id=123456,
        title="Test Chat",
        chat_type=ChatTypeEnum.GROUP,
        subscribers=500,
        moderation=True,
        messages_per_hour=10.0,
        unique_authors_per_hour=5.0,
        captcha=False,
        analysis_mode=AnalysisModeEnum.DEEP,
        last_check=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# 1. AnalysisModeEnum.to_group_settings()
# ---------------------------------------------------------------------------


class TestAnalysisModeToGroupSettings:
    """SPEC req #5: Quick vs Deep analysis modes map to correct GroupSettings."""

    def test_quick_mode_disables_activity_and_authors(self) -> None:
        """Quick mode: detect_activity and detect_unique_authors must be False."""
        from chatfilter.models.catalog import AnalysisModeEnum

        settings = AnalysisModeEnum.QUICK.to_group_settings()
        assert settings.detect_chat_type is True
        assert settings.detect_subscribers is True
        assert settings.detect_moderation is True
        # Quick mode should NOT enable deep features
        assert settings.detect_activity is False
        assert settings.detect_unique_authors is False
        assert settings.detect_captcha is False

    def test_quick_mode_time_window_24h(self) -> None:
        """SPEC: time_window is fixed at 24 hours."""
        from chatfilter.models.catalog import AnalysisModeEnum

        settings = AnalysisModeEnum.QUICK.to_group_settings()
        assert settings.time_window == 24

    def test_deep_mode_enables_all_features(self) -> None:
        """Deep mode: all features including activity, authors, captcha must be True."""
        from chatfilter.models.catalog import AnalysisModeEnum

        settings = AnalysisModeEnum.DEEP.to_group_settings()
        assert settings.detect_chat_type is True
        assert settings.detect_subscribers is True
        assert settings.detect_moderation is True
        assert settings.detect_activity is True
        assert settings.detect_unique_authors is True
        assert settings.detect_captcha is True

    def test_deep_mode_time_window_24h(self) -> None:
        """SPEC: Deep mode time_window is also fixed at 24 hours."""
        from chatfilter.models.catalog import AnalysisModeEnum

        settings = AnalysisModeEnum.DEEP.to_group_settings()
        assert settings.time_window == 24

    def test_deep_includes_everything_quick_does(self) -> None:
        """SPEC: Deep analysis always includes everything from quick mode."""
        from chatfilter.models.catalog import AnalysisModeEnum

        quick = AnalysisModeEnum.QUICK.to_group_settings()
        deep = AnalysisModeEnum.DEEP.to_group_settings()

        # Everything quick enables, deep also enables
        assert quick.detect_chat_type == deep.detect_chat_type
        assert quick.detect_subscribers == deep.detect_subscribers
        assert quick.detect_moderation == deep.detect_moderation


# ---------------------------------------------------------------------------
# 2. CatalogChat.is_fresh()
# ---------------------------------------------------------------------------


class TestCatalogChatIsFresh:
    """SPEC req #1: Fresh data check for cache reuse."""

    def test_fresh_chat_within_period(self) -> None:
        """Chat last checked 1 day ago is fresh with 7-day freshness."""
        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        chat = CatalogChat(
            id="@fresh",
            telegram_id=1,
            title="Fresh Chat",
            chat_type=ChatTypeEnum.GROUP,
            last_check=datetime.now(UTC) - timedelta(days=1),
        )
        assert chat.is_fresh(freshness_days=7) is True

    def test_stale_chat_beyond_period(self) -> None:
        """Chat last checked 8 days ago is stale with 7-day freshness."""
        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        chat = CatalogChat(
            id="@stale",
            telegram_id=2,
            title="Stale Chat",
            chat_type=ChatTypeEnum.GROUP,
            last_check=datetime.now(UTC) - timedelta(days=8),
        )
        assert chat.is_fresh(freshness_days=7) is False

    def test_no_last_check_is_not_fresh(self) -> None:
        """Chat without last_check is never fresh."""
        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        chat = CatalogChat(
            id="@never",
            telegram_id=3,
            title="Never Checked",
            chat_type=ChatTypeEnum.GROUP,
            last_check=None,
        )
        assert chat.is_fresh(freshness_days=7) is False

    def test_exactly_at_boundary_is_fresh(self) -> None:
        """Chat last checked exactly freshness_days ago is still fresh (boundary)."""
        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        # Set last_check to exactly freshness_days ago minus 1 second (just inside)
        chat = CatalogChat(
            id="@boundary",
            telegram_id=4,
            title="Boundary Chat",
            chat_type=ChatTypeEnum.GROUP,
            last_check=datetime.now(UTC) - timedelta(days=7) + timedelta(seconds=1),
        )
        assert chat.is_fresh(freshness_days=7) is True

    def test_freshness_days_one(self) -> None:
        """With freshness_days=1: checked 23h ago is fresh, 25h ago is stale."""
        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        fresh = CatalogChat(
            id="@fresh1",
            telegram_id=5,
            title="Fresh",
            chat_type=ChatTypeEnum.GROUP,
            last_check=datetime.now(UTC) - timedelta(hours=23),
        )
        stale = CatalogChat(
            id="@stale1",
            telegram_id=6,
            title="Stale",
            chat_type=ChatTypeEnum.GROUP,
            last_check=datetime.now(UTC) - timedelta(hours=25),
        )
        assert fresh.is_fresh(freshness_days=1) is True
        assert stale.is_fresh(freshness_days=1) is False


# ---------------------------------------------------------------------------
# 3. list_catalog_chats() with filters
# ---------------------------------------------------------------------------


class TestListCatalogChatsFilters:
    """SPEC req #2: Catalog page filters all fields."""

    def _make_chat(self, db, *, chat_id: str, telegram_id: int, **kwargs):
        """Helper to save a chat with defaults."""
        from chatfilter.models.catalog import AnalysisModeEnum, CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        chat = CatalogChat(
            id=chat_id,
            telegram_id=telegram_id,
            title=kwargs.get("title", f"Chat {chat_id}"),
            chat_type=kwargs.get("chat_type", ChatTypeEnum.GROUP),
            subscribers=kwargs.get("subscribers", 100),
            moderation=kwargs.get("moderation", False),
            captcha=kwargs.get("captcha", False),
            messages_per_hour=kwargs.get("messages_per_hour", 1.0),
            unique_authors_per_hour=kwargs.get("unique_authors_per_hour", 1.0),
            last_check=kwargs.get("last_check", datetime.now(UTC)),
            analysis_mode=kwargs.get("analysis_mode", AnalysisModeEnum.QUICK),
        )
        db.save_catalog_chat(chat)
        return chat

    def test_no_filters_returns_all(self, temp_db) -> None:
        """Empty filters return all catalog chats."""
        self._make_chat(temp_db, chat_id="@a", telegram_id=1)
        self._make_chat(temp_db, chat_id="@b", telegram_id=2)
        results , _ = temp_db.list_catalog_chats()
        assert len(results) == 2

    def test_filter_by_chat_type(self, temp_db) -> None:
        """Filter by chat_type returns only matching chats."""
        from chatfilter.models.group import ChatTypeEnum

        self._make_chat(temp_db, chat_id="@group", telegram_id=1, chat_type=ChatTypeEnum.GROUP)
        self._make_chat(
            temp_db,
            chat_id="@channel",
            telegram_id=2,
            chat_type=ChatTypeEnum.CHANNEL_NO_COMMENTS,
        )

        groups , _ = temp_db.list_catalog_chats({"chat_type": "group"})
        assert len(groups) == 1
        assert groups[0].id == "@group"

    def test_filter_by_min_subscribers(self, temp_db) -> None:
        """Filter by min_subscribers returns only chats with enough subscribers."""
        self._make_chat(temp_db, chat_id="@small", telegram_id=1, subscribers=100)
        self._make_chat(temp_db, chat_id="@large", telegram_id=2, subscribers=1000)

        results , _ = temp_db.list_catalog_chats({"min_subscribers": 500})
        assert len(results) == 1
        assert results[0].id == "@large"

    def test_filter_by_max_subscribers(self, temp_db) -> None:
        """Filter by max_subscribers excludes chats with too many subscribers."""
        self._make_chat(temp_db, chat_id="@small", telegram_id=1, subscribers=100)
        self._make_chat(temp_db, chat_id="@large", telegram_id=2, subscribers=1000)

        results , _ = temp_db.list_catalog_chats({"max_subscribers": 500})
        assert len(results) == 1
        assert results[0].id == "@small"

    def test_filter_by_has_moderation(self, temp_db) -> None:
        """Filter by has_moderation=True returns only moderated chats."""
        self._make_chat(temp_db, chat_id="@mod", telegram_id=1, moderation=True)
        self._make_chat(temp_db, chat_id="@nomod", telegram_id=2, moderation=False)

        results , _ = temp_db.list_catalog_chats({"has_moderation": True})
        assert len(results) == 1
        assert results[0].id == "@mod"

    def test_filter_by_has_captcha(self, temp_db) -> None:
        """Filter by has_captcha=True returns only captcha-protected chats."""
        self._make_chat(temp_db, chat_id="@captcha", telegram_id=1, captcha=True)
        self._make_chat(temp_db, chat_id="@nocaptcha", telegram_id=2, captcha=False)

        results , _ = temp_db.list_catalog_chats({"has_captcha": True})
        assert len(results) == 1
        assert results[0].id == "@captcha"

    def test_filter_by_min_activity(self, temp_db) -> None:
        """Filter by min_activity returns only active chats."""
        self._make_chat(temp_db, chat_id="@active", telegram_id=1, messages_per_hour=50.0)
        self._make_chat(temp_db, chat_id="@quiet", telegram_id=2, messages_per_hour=1.0)

        results , _ = temp_db.list_catalog_chats({"min_activity": 10.0})
        assert len(results) == 1
        assert results[0].id == "@active"

    def test_filter_by_fresh_only(self, temp_db) -> None:
        """Filter by fresh_only returns only recently-checked chats."""
        self._make_chat(
            temp_db,
            chat_id="@fresh",
            telegram_id=1,
            last_check=datetime.now(UTC) - timedelta(days=1),
        )
        self._make_chat(
            temp_db,
            chat_id="@stale",
            telegram_id=2,
            last_check=datetime.now(UTC) - timedelta(days=10),
        )

        results , _ = temp_db.list_catalog_chats({"fresh_only": 7})
        assert len(results) == 1
        assert results[0].id == "@fresh"

    def test_combined_filters(self, temp_db) -> None:
        """Multiple filters combine with AND logic."""
        from chatfilter.models.group import ChatTypeEnum

        self._make_chat(
            temp_db,
            chat_id="@match",
            telegram_id=1,
            chat_type=ChatTypeEnum.GROUP,
            subscribers=500,
            moderation=True,
        )
        self._make_chat(
            temp_db,
            chat_id="@nomatch_type",
            telegram_id=2,
            chat_type=ChatTypeEnum.CHANNEL_NO_COMMENTS,
            subscribers=500,
            moderation=True,
        )
        self._make_chat(
            temp_db,
            chat_id="@nomatch_subs",
            telegram_id=3,
            chat_type=ChatTypeEnum.GROUP,
            subscribers=50,
            moderation=True,
        )

        results , _ = temp_db.list_catalog_chats(
            {"chat_type": "group", "min_subscribers": 200, "has_moderation": True}
        )
        assert len(results) == 1
        assert results[0].id == "@match"


    def test_filter_no_captcha_includes_null(self, temp_db) -> None:
        """Regression test: has_captcha=False must include both NULL and 0 values.

        Covers fix for bug: WHERE captcha=0 OR captcha IS NULL
        """
        from chatfilter.models.catalog import AnalysisModeEnum, CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        # Chat with captcha=False (explicitly no captcha, will be 0 in DB)
        chat_false = CatalogChat(
            id="@false_captcha",
            telegram_id=1002,
            title="Chat with False captcha",
            chat_type=ChatTypeEnum.GROUP,
            captcha=False,
            last_check=datetime.now(UTC),
            analysis_mode=AnalysisModeEnum.QUICK,
        )
        temp_db.save_catalog_chat(chat_false)

        # Chat with captcha=True (has captcha, will be 1 in DB)
        chat_true = CatalogChat(
            id="@true_captcha",
            telegram_id=1003,
            title="Chat with True captcha",
            chat_type=ChatTypeEnum.GROUP,
            captcha=True,
            last_check=datetime.now(UTC),
            analysis_mode=AnalysisModeEnum.QUICK,
        )
        temp_db.save_catalog_chat(chat_true)

        # Create chat with captcha=False then manually update DB to set NULL
        # (simulating a chat that was never checked for captcha)
        chat_null = CatalogChat(
            id="@null_captcha",
            telegram_id=1001,
            title="Chat with NULL captcha",
            chat_type=ChatTypeEnum.GROUP,
            captcha=False,  # Will be inserted as 0, then we update to NULL
            last_check=datetime.now(UTC),
            analysis_mode=AnalysisModeEnum.QUICK,
        )
        temp_db.save_catalog_chat(chat_null)

        # Update directly to NULL to simulate unchecked captcha
        with temp_db._connection() as conn:
            conn.execute("UPDATE chat_catalog SET captcha = NULL WHERE id = ?", ("@null_captcha",))

        # Filter: has_captcha=False should return BOTH NULL and False chats
        results , _ = temp_db.list_catalog_chats({"has_captcha": False})

        result_ids = {r.id for r in results}
        assert "@null_captcha" in result_ids, "NULL captcha chat should be included"
        assert "@false_captcha" in result_ids, "False captcha chat should be included"
        assert "@true_captcha" not in result_ids, "True captcha chat should NOT be included"

    def test_filter_chat_type_uses_real_enum_values(self, temp_db) -> None:
        """Regression test: chat_type filter uses real ChatTypeEnum values.

        Ensures filter dropdown values match actual DB enum values.
        """
        from chatfilter.models.group import ChatTypeEnum

        # Insert chats with different types
        self._make_chat(temp_db, chat_id="@test_group", telegram_id=2001, chat_type=ChatTypeEnum.GROUP)
        self._make_chat(temp_db, chat_id="@test_forum", telegram_id=2002, chat_type=ChatTypeEnum.FORUM)
        self._make_chat(
            temp_db,
            chat_id="@test_channel_no_comments",
            telegram_id=2003,
            chat_type=ChatTypeEnum.CHANNEL_NO_COMMENTS,
        )
        self._make_chat(
            temp_db,
            chat_id="@test_channel_comments",
            telegram_id=2004,
            chat_type=ChatTypeEnum.CHANNEL_COMMENTS,
        )

        # Test forum filter
        forum_results , _ = temp_db.list_catalog_chats({"chat_type": "forum"})
        forum_ids = {r.id for r in forum_results}
        assert forum_ids == {"@test_forum"}, f"Expected only forum chat, got {forum_ids}"

        # Test channel_no_comments filter
        channel_results , _ = temp_db.list_catalog_chats({"chat_type": "channel_no_comments"})
        channel_ids = {r.id for r in channel_results}
        assert channel_ids == {"@test_channel_no_comments"}, f"Expected only channel_no_comments chat, got {channel_ids}"

        # Test channel_comments filter
        channel_comments_results , _ = temp_db.list_catalog_chats({"chat_type": "channel_comments"})
        channel_comments_ids = {r.id for r in channel_comments_results}
        assert channel_comments_ids == {"@test_channel_comments"}, f"Expected only channel_comments chat, got {channel_comments_ids}"

        # Test group filter
        group_results , _ = temp_db.list_catalog_chats({"chat_type": "group"})
        group_ids = {r.id for r in group_results}
        assert group_ids == {"@test_group"}, f"Expected only group chat, got {group_ids}"


# ---------------------------------------------------------------------------
# 4. update_catalog_metrics() EMA logic
# ---------------------------------------------------------------------------


class TestUpdateCatalogMetricsEMA:
    """SPEC req #4: Scheduler averages metrics with EMA."""

    def _save_chat(self, db, chat_id: str, mph: float, uaph: float):
        """Helper to create a catalog chat with metrics."""
        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        chat = CatalogChat(
            id=chat_id,
            telegram_id=hash(chat_id) % 100000,
            title=f"Chat {chat_id}",
            chat_type=ChatTypeEnum.GROUP,
            messages_per_hour=mph,
            unique_authors_per_hour=uaph,
            last_check=datetime.now(UTC),
        )
        db.save_catalog_chat(chat)

    def test_ema_update_blends_values(self, temp_db) -> None:
        """EMA update produces expected blended value: alpha*new + (1-alpha)*old."""
        chat_id = "@ema_test"
        old_mph = 10.0
        new_mph = 20.0
        alpha = 0.3
        expected = alpha * new_mph + (1 - alpha) * old_mph  # 13.0

        self._save_chat(temp_db, chat_id, mph=old_mph, uaph=5.0)
        temp_db.update_catalog_metrics(
            chat_id,
            {"messages_per_hour": new_mph},
            use_ema=True,
            alpha=alpha,
        )

        chat = temp_db.get_catalog_chat(chat_id)
        assert chat is not None
        assert abs(chat.messages_per_hour - expected) < 0.001

    def test_direct_overwrite_replaces_value(self, temp_db) -> None:
        """Without EMA (use_ema=False), value is directly overwritten."""
        chat_id = "@overwrite_test"
        self._save_chat(temp_db, chat_id, mph=10.0, uaph=5.0)

        temp_db.update_catalog_metrics(
            chat_id,
            {"messages_per_hour": 99.0},
            use_ema=False,
        )

        chat = temp_db.get_catalog_chat(chat_id)
        assert chat is not None
        assert chat.messages_per_hour == 99.0

    def test_ema_on_null_uses_new_value(self, temp_db) -> None:
        """If existing metric is NULL, EMA falls back to new value directly."""
        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        # Save chat with messages_per_hour=0 (DB will store NULL via COALESCE logic)
        chat = CatalogChat(
            id="@null_test",
            telegram_id=999,
            title="Null Test",
            chat_type=ChatTypeEnum.GROUP,
            messages_per_hour=0.0,  # coerced to NULL in storage
        )
        temp_db.save_catalog_chat(chat)

        temp_db.update_catalog_metrics(
            "@null_test",
            {"messages_per_hour": 15.0},
            use_ema=True,
            alpha=0.3,
        )

        updated = temp_db.get_catalog_chat("@null_test")
        assert updated is not None
        # When NULL, EMA CASE sets it to new value (15.0)
        assert updated.messages_per_hour == 15.0

    def test_update_sets_last_check(self, temp_db) -> None:
        """update_catalog_metrics always updates last_check timestamp."""
        chat_id = "@lastcheck_test"
        old_time = datetime.now(UTC) - timedelta(hours=2)

        from chatfilter.models.catalog import CatalogChat
        from chatfilter.models.group import ChatTypeEnum

        chat = CatalogChat(
            id=chat_id,
            telegram_id=12345,
            title="LastCheck Test",
            chat_type=ChatTypeEnum.GROUP,
            messages_per_hour=5.0,
            last_check=old_time,
        )
        temp_db.save_catalog_chat(chat)

        temp_db.update_catalog_metrics(chat_id, {"messages_per_hour": 6.0})

        updated = temp_db.get_catalog_chat(chat_id)
        assert updated is not None
        assert updated.last_check is not None
        # last_check should be more recent than old_time
        last = updated.last_check
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        assert last > old_time


# ---------------------------------------------------------------------------
# 5. Admin settings defaults
# ---------------------------------------------------------------------------


class TestAdminSettingsDefaults:
    """SPEC req #6: Admin configurable parameters have correct defaults."""

    def test_max_chats_per_account_default_300(self, temp_db) -> None:
        """Default max_chats_per_account is 300."""
        result = temp_db.get_max_chats_per_account()
        assert result == 300

    def test_analysis_freshness_days_default_7(self, temp_db) -> None:
        """Default analysis_freshness_days is 7."""
        result = temp_db.get_analysis_freshness_days()
        assert result == 7

    def test_set_and_get_max_chats(self, temp_db) -> None:
        """set_setting/get_max_chats_per_account round-trip."""
        temp_db.set_setting("max_chats_per_account", "150")
        assert temp_db.get_max_chats_per_account() == 150

    def test_set_and_get_freshness_days(self, temp_db) -> None:
        """set_setting/get_analysis_freshness_days round-trip."""
        temp_db.set_setting("analysis_freshness_days", "14")
        assert temp_db.get_analysis_freshness_days() == 14

    def test_upsert_setting_updates_value(self, temp_db) -> None:
        """Setting the same key twice uses upsert (no duplicate)."""
        temp_db.set_setting("max_chats_per_account", "100")
        temp_db.set_setting("max_chats_per_account", "200")
        result = temp_db.get_max_chats_per_account()
        assert result == 200


# ---------------------------------------------------------------------------
# 6. /catalog and /api/catalog HTTP endpoint availability
# ---------------------------------------------------------------------------


class TestCatalogEndpoints:
    """SPEC req #2: Catalog page accessible to logged-in users."""

    @pytest.fixture
    def client(self):
        """Create test client."""
        from fastapi.testclient import TestClient

        from chatfilter.web.app import create_app

        app = create_app()
        return TestClient(app)

    @pytest.mark.xfail(
        reason="SPEC req: catalog requires login, but auth enforcement is missing. "
        "See bug: SMOKE: [Backend] /catalog accessible without authentication"
    )
    def test_catalog_page_redirects_unauthenticated(self, client) -> None:
        """Unauthenticated GET /catalog should redirect to login (302) or return 401."""
        response = client.get("/catalog", follow_redirects=False)
        assert response.status_code in (302, 401, 403), (
            f"Expected redirect/auth error for unauthenticated /catalog, got {response.status_code}"
        )

    @pytest.mark.xfail(
        reason="SPEC req: catalog requires login, but auth enforcement is missing. "
        "See bug: SMOKE: [Backend] /catalog accessible without authentication"
    )
    def test_api_catalog_redirects_unauthenticated(self, client) -> None:
        """Unauthenticated GET /api/catalog should redirect to login or return 401."""
        response = client.get("/api/catalog", follow_redirects=False)
        assert response.status_code in (302, 401, 403), (
            f"Expected auth error for unauthenticated /api/catalog, got {response.status_code}"
        )

    def test_catalog_route_exists(self, client) -> None:
        """GET /catalog route exists (not 404)."""
        response = client.get("/catalog", follow_redirects=False)
        assert response.status_code != 404, "/catalog route should be registered"

    def test_api_catalog_route_exists(self, client) -> None:
        """GET /api/catalog route exists (not 404)."""
        response = client.get("/api/catalog", follow_redirects=False)
        assert response.status_code != 404, "/api/catalog route should be registered"

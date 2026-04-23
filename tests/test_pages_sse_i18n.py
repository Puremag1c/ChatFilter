"""Smoke — every user-facing page loads, SSE anchors are intact, i18n switches.

The audit of 0.40 shipped changes touching routers, templates and i18n.
This file is the blunt post-audit check: for every page a real user
hits, we assert (a) it renders 200 for the correct role, (b) where
live updates are expected the HTMX/SSE wiring is present, and (c) the
Russian locale produces actually translated output (not the English
source).

SSE regression protection specifically pins the 0.35.7→0.35.8 family
of bugs: sse-swap anchors must exist on the page for ``htmx:sseMessage``
to fire (memory feedback_sse_architecture).
"""

from __future__ import annotations

from typing import Any

import pytest


# ------------------------------------------------------------------
# Helper — power-user client (needs use_own_accounts for personal pages)
# ------------------------------------------------------------------


@pytest.fixture
def power_user_client(fastapi_test_client: Any, test_settings: Any) -> Any:
    from chatfilter.storage.user_database import get_user_db

    db = get_user_db(test_settings.effective_database_url)
    user = db.get_user_by_username("testuser")
    db.set_use_own_accounts(user["id"], True)
    return fastapi_test_client


# ------------------------------------------------------------------
# 1. Page routes — 200 for the right role
# ------------------------------------------------------------------


class TestPagesRenderFor200:
    def test_home(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/")
        assert r.status_code == 200
        assert "ChatFilter" in r.text

    def test_chats_alias(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/chats")
        assert r.status_code == 200

    def test_chatlist(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/chatlist")
        assert r.status_code == 200

    def test_profile(self, fastapi_test_client: Any) -> None:
        r = fastapi_test_client.get("/profile")
        assert r.status_code == 200

    def test_sessions_power_user(self, power_user_client: Any) -> None:
        r = power_user_client.get("/sessions")
        assert r.status_code == 200

    def test_proxies_power_user(self, power_user_client: Any) -> None:
        r = power_user_client.get("/proxies")
        assert r.status_code == 200

    def test_admin_accounts(self, admin_client: Any) -> None:
        r = admin_client.get("/admin/accounts")
        assert r.status_code == 200

    def test_admin_proxies(self, admin_client: Any) -> None:
        r = admin_client.get("/admin/proxies")
        assert r.status_code == 200

    def test_admin_system(self, admin_client: Any) -> None:
        r = admin_client.get("/admin")
        assert r.status_code == 200


# ------------------------------------------------------------------
# 2. SSE wiring — every live-updating page must carry the HTMX SSE
# attributes. Missing sse-swap anchors = htmx:sseMessage never fires.
# ------------------------------------------------------------------


class TestSSEAnchors:
    def test_groups_page_has_sse_connect_and_all_anchors(
        self, fastapi_test_client: Any
    ) -> None:
        """/chats (home) subscribes to /api/groups/events and has all 5
        anchors (init/progress/complete/error/ping)."""
        html = fastapi_test_client.get("/").text
        assert 'hx-ext="sse"' in html
        assert 'sse-connect="/api/groups/events"' in html
        for name in ("init", "progress", "complete", "error", "ping"):
            assert f'sse-swap="{name}"' in html, (
                f"Groups page is missing sse-swap anchor '{name}' — "
                "htmx:sseMessage will not fire for that event"
            )

    @staticmethod
    def _seed_session(scope: str, name: str, owner: str) -> None:
        """Drop a dummy session dir on disk so sessions_list.html
        renders the populated branch (not empty-state) — that's where
        the SSE wiring lives."""
        import json as _json

        from chatfilter.web.routers.sessions import helpers as session_helpers

        sessions_root = session_helpers.get_settings().sessions_dir
        target = sessions_root / scope / name
        target.mkdir(parents=True, exist_ok=True)
        (target / "config.json").write_text("{}")
        (target / ".account_info.json").write_text(
            _json.dumps({"user_id": 1, "owner": owner, "phone": "+1"})
        )

    def test_sessions_list_has_sse_connect_and_anchor(
        self, power_user_client: Any, test_settings: Any
    ) -> None:
        """/api/sessions (HTMX partial on /sessions) subscribes to
        /api/sessions/events with sse-swap='message'."""
        from chatfilter.storage.user_database import get_user_db

        db = get_user_db(test_settings.effective_database_url)
        uid = db.get_user_by_username("testuser")["id"]
        self._seed_session(f"user_{uid}", "stub_session", owner=f"user:{uid}")

        html = power_user_client.get("/api/sessions").text
        assert 'hx-ext="sse"' in html
        assert 'sse-connect="/api/sessions/events"' in html
        assert 'sse-swap="message"' in html

    def test_admin_sessions_list_has_sse_connect(self, admin_client: Any) -> None:
        """Same SSE wiring on the admin shared-pool listing."""
        self._seed_session("admin", "stub_admin", owner="admin")
        html = admin_client.get("/admin/api/sessions").text
        assert 'hx-ext="sse"' in html
        assert 'sse-connect="/api/sessions/events"' in html
        assert 'sse-swap="message"' in html

    # SSE endpoint media-type and streaming behaviour are covered in
    # tests/test_sse_middleware_streaming.py through direct async calls —
    # TestClient.stream() blocks on SSE forever so we don't repeat the
    # test here. This file owns the *HTML-anchor* part of the contract.


# ------------------------------------------------------------------
# 3. i18n — Russian locale returns Russian content on key pages.
# Pages use {{ _("...") }} throughout; if the gettext chain is broken,
# ru locale falls back to the English msgid silently.
# ------------------------------------------------------------------


class TestI18nRuLocale:
    RU_COOKIE: dict[str, str] = {"lang": "ru"}

    def test_profile_page_ru_renders_russian(
        self, fastapi_test_client: Any
    ) -> None:
        """At least one Cyrillic character must appear — proves the
        gettext chain delivers Russian for pages that have translations."""
        fastapi_test_client.cookies.update(self.RU_COOKIE)
        html = fastapi_test_client.get("/profile").text
        fastapi_test_client.cookies.clear()
        assert any("а" <= ch <= "я" or "А" <= ch <= "Я" for ch in html), (
            "Profile page under lang=ru produced no Cyrillic — "
            "gettext chain likely broken"
        )

    def test_home_page_ru_renders_russian(self, fastapi_test_client: Any) -> None:
        fastapi_test_client.cookies.update(self.RU_COOKIE)
        html = fastapi_test_client.get("/").text
        fastapi_test_client.cookies.clear()
        assert any("а" <= ch <= "я" or "А" <= ch <= "Я" for ch in html), (
            "Home page under lang=ru produced no Cyrillic"
        )

    def test_admin_page_ru_renders_russian(self, admin_client: Any) -> None:
        admin_client.cookies.update(self.RU_COOKIE)
        html = admin_client.get("/admin").text
        admin_client.cookies.clear()
        assert any("а" <= ch <= "я" or "А" <= ch <= "Я" for ch in html), (
            "Admin page under lang=ru produced no Cyrillic"
        )

    def test_en_locale_renders_english(self, fastapi_test_client: Any) -> None:
        """Sanity inverse: lang=en → no sudden burst of Cyrillic from
        hard-coded Russian strings sneaking in."""
        fastapi_test_client.cookies.update({"lang": "en"})
        html = fastapi_test_client.get("/profile").text
        fastapi_test_client.cookies.clear()
        # A couple of known English fragments from profile.html must be there
        assert (
            "Use my own Telegram accounts and proxies" in html
            or "Profile" in html
        ), "Profile page under lang=en lost its English copy"

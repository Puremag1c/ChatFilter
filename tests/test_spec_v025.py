"""Regression tests for SPEC.md v0.25.0 requirements.

Covers:
- Must Have #1: i18n completeness — all msgids English, no empty translations
- Must Have #2: Instant card feedback — card-loading overlay on Start/Resume/Reanalyze
- Must Have #3: Badge simplification — only chat-type badges, no status badges
- Must Have #4: Auto-retry ERROR chats — already tested in test_group_engine.py (smoke here)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).parent.parent


# ---------------------------------------------------------------------------
# #1  i18n completeness
# ---------------------------------------------------------------------------


class TestI18nCompleteness:
    """Verify i18n is clean: English msgids everywhere, no empty translations."""

    def test_no_russian_msgids_in_templates(self, project_root: Path) -> None:
        """All _() calls in HTML templates must use English strings only."""
        templates_dir = project_root / "src" / "chatfilter" / "templates"
        assert templates_dir.exists()

        ru_char = re.compile(r"[а-яА-ЯёЁ]", re.UNICODE)
        # Match _("...") and _('...')
        gettext_call = re.compile(r"""_\(["'](.*?)["']\)""", re.DOTALL)

        violations: list[str] = []
        for html_file in templates_dir.rglob("*.html"):
            content = html_file.read_text(encoding="utf-8")
            for m in gettext_call.finditer(content):
                if ru_char.search(m.group(1)):
                    rel = html_file.relative_to(project_root)
                    violations.append(f"{rel}: {m.group(0)!r}")

        assert not violations, "Found Russian msgids in templates (must be English):\n" + "\n".join(
            violations
        )

    def test_no_russian_msgids_in_python_sources(self, project_root: Path) -> None:
        """All _() calls in Python source files must use English strings only."""
        src_dir = project_root / "src" / "chatfilter"
        assert src_dir.exists()

        ru_char = re.compile(r"[а-яА-ЯёЁ]", re.UNICODE)
        gettext_call = re.compile(r"""_\(["'](.*?)["']\)""", re.DOTALL)

        violations: list[str] = []
        for py_file in src_dir.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8")
            for m in gettext_call.finditer(content):
                if ru_char.search(m.group(1)):
                    rel = py_file.relative_to(project_root)
                    violations.append(f"{rel}: {m.group(0)!r}")

        assert not violations, (
            "Found Russian msgids in Python sources (must be English):\n" + "\n".join(violations)
        )

    def test_en_po_no_empty_msgstr(self, project_root: Path) -> None:
        """English .po file must have translations for every msgid."""
        po_path = project_root / "src/chatfilter/i18n/locales/en/LC_MESSAGES/messages.po"
        assert po_path.exists(), f"en/messages.po not found: {po_path}"

        content = po_path.read_text(encoding="utf-8")
        entries = re.split(r"\n\n+", content)

        empty: list[str] = []
        for entry in entries:
            # Skip header (msgid "")
            if re.search(r'^msgid ""$', entry, re.MULTILINE):
                continue
            # Find msgid
            msgid_m = re.search(r'^msgid "(.*)"', entry, re.MULTILINE)
            if not msgid_m:
                continue
            # Check msgstr is truly empty (not a multi-line PO continuation)
            # In PO format: msgstr ""\n"..." is non-empty (multi-line string)
            msgstr_empty = re.search(r'^msgstr ""\s*$', entry, re.MULTILINE)
            if msgstr_empty and not re.match(r'\s*"', entry[msgstr_empty.end() :]):
                empty.append(repr(msgid_m.group(1)))

        assert not empty, f"English .po has {len(empty)} empty msgstr entries:\n" + "\n".join(
            empty[:20]
        )

    def test_ru_po_no_empty_msgstr(self, project_root: Path) -> None:
        """Russian .po file must have translations for every msgid."""
        po_path = project_root / "src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.po"
        assert po_path.exists(), f"ru/messages.po not found: {po_path}"

        content = po_path.read_text(encoding="utf-8")
        entries = re.split(r"\n\n+", content)

        empty: list[str] = []
        for entry in entries:
            if re.search(r'^msgid ""$', entry, re.MULTILINE):
                continue
            msgid_m = re.search(r'^msgid "(.*)"', entry, re.MULTILINE)
            if not msgid_m:
                continue
            # Check msgstr is truly empty (not a multi-line PO continuation)
            # In PO format: msgstr ""\n"..." is non-empty (multi-line string)
            msgstr_empty = re.search(r'^msgstr ""\s*$', entry, re.MULTILINE)
            if msgstr_empty and not re.match(r'\s*"', entry[msgstr_empty.end() :]):
                empty.append(repr(msgid_m.group(1)))

        assert not empty, f"Russian .po has {len(empty)} empty msgstr entries:\n" + "\n".join(
            empty[:20]
        )

    def test_js_locale_en_no_empty_values(self, project_root: Path) -> None:
        """en.json JS locale has been removed (translations now server-rendered).

        This test is deprecated: static JSON locale files are no longer used.
        Translations are now inline server-rendered in the template context.
        """
        pytest.skip("Static JSON locale files removed; translations now server-rendered")

    def test_js_locale_ru_no_empty_values(self, project_root: Path) -> None:
        """ru.json JS locale has been removed (translations now server-rendered).

        This test is deprecated: static JSON locale files are no longer used.
        Translations are now inline server-rendered in the template context.
        """
        pytest.skip("Static JSON locale files removed; translations now server-rendered")

    def test_en_json_and_ru_json_have_same_keys(self, project_root: Path) -> None:
        """en.json and ru.json have been removed (translations now server-rendered).

        This test is deprecated: static JSON locale files are no longer used.
        Translations are now inline server-rendered in the template context.
        """
        pytest.skip("Static JSON locale files removed; translations now server-rendered")


# ---------------------------------------------------------------------------
# #2  Instant card feedback
# ---------------------------------------------------------------------------


class TestInstantCardFeedback:
    """Verify card-loading overlay is applied on Start/Resume/Reanalyze."""

    def test_chats_page_js_adds_card_loading_on_start(self, project_root: Path) -> None:
        """chats-page.js must add card-loading class when Start button is clicked."""
        js_path = project_root / "src/chatfilter/static/js/chats-page.js"
        assert js_path.exists(), f"chats-page.js not found: {js_path}"

        content = js_path.read_text(encoding="utf-8")

        assert "card-loading" in content, (
            "chats-page.js must add 'card-loading' CSS class for instant card feedback"
        )
        assert re.search(r"/start$", content) or re.search(r"\/start", content), (
            "chats-page.js must handle /start endpoint for loading state"
        )

    def test_chats_page_js_handles_resume_and_reanalyze(self, project_root: Path) -> None:
        """chats-page.js must add card-loading for Resume and Reanalyze buttons."""
        js_path = project_root / "src/chatfilter/static/js/chats-page.js"
        content = js_path.read_text(encoding="utf-8")

        assert re.search(r"resume", content), (
            "chats-page.js must handle /resume endpoint for loading state"
        )
        assert re.search(r"reanalyze", content), (
            "chats-page.js must handle /reanalyze endpoint for loading state"
        )

    def test_card_loading_css_defined(self, project_root: Path) -> None:
        """CSS for .group-card.card-loading overlay must be defined."""
        chats_html = project_root / "src/chatfilter/templates/chats.html"
        assert chats_html.exists()

        content = chats_html.read_text(encoding="utf-8")

        assert "card-loading" in content, (
            "chats.html must define .card-loading CSS for the loading overlay"
        )
        # Must have both the overlay and spinner pseudo-elements
        assert "card-loading::after" in content or "card-loading::before" in content, (
            "chats.html must define ::after or ::before for card-loading spinner/overlay"
        )

    def test_card_loading_is_removed_on_error(self, project_root: Path) -> None:
        """chats-page.js must remove card-loading class on request error."""
        js_path = project_root / "src/chatfilter/static/js/chats-page.js"
        content = js_path.read_text(encoding="utf-8")

        # Must remove the loading class in error handling
        remove_pattern = re.compile(r"classList\.remove\(['\"]card-loading['\"]", re.MULTILINE)
        assert remove_pattern.search(content), (
            "chats-page.js must remove 'card-loading' class on request failure"
        )


# ---------------------------------------------------------------------------
# #3  Badge simplification
# ---------------------------------------------------------------------------


class TestBadgeSimplification:
    """Verify group_card.html shows only chat-type badges, not status badges."""

    def test_no_pending_badge_in_group_card(self, project_root: Path) -> None:
        """group_card.html must not render a Pending count badge."""
        card_path = project_root / "src/chatfilter/templates/partials/group_card.html"
        assert card_path.exists()
        content = card_path.read_text(encoding="utf-8")

        # The Pending status badge (e.g. "Pending: N" as a standalone badge span)
        # should not exist. A status-badge showing the overall group status is ok.
        # We look for badge spans with "Pending" as a label.
        assert not re.search(r'class="[^"]*badge[^"]*"[^>]*>\s*.*[Pp]ending.*:\s*\d', content), (
            "group_card.html must not render a Pending count badge (SPEC #3)"
        )

    def test_no_done_count_badge_in_group_card(self, project_root: Path) -> None:
        """group_card.html must not render a Done count badge."""
        card_path = project_root / "src/chatfilter/templates/partials/group_card.html"
        content = card_path.read_text(encoding="utf-8")

        assert not re.search(r'class="[^"]*badge[^"]*"[^>]*>\s*.*[Dd]one.*:\s*\d', content), (
            "group_card.html must not render a Done count badge (SPEC #3)"
        )

    def test_no_skipped_badge_in_group_card(self, project_root: Path) -> None:
        """group_card.html must not render a Skipped badge."""
        card_path = project_root / "src/chatfilter/templates/partials/group_card.html"
        content = card_path.read_text(encoding="utf-8")

        assert not re.search(r'class="[^"]*badge[^"]*"[^>]*>\s*.*[Ss]kipped', content), (
            "group_card.html must not render a Skipped badge (SPEC #3)"
        )

    def test_chat_type_badges_present_in_group_card(self, project_root: Path) -> None:
        """group_card.html must show chat-type badges: Groups, Forums, Channels+, Channels, Dead."""
        card_path = project_root / "src/chatfilter/templates/partials/group_card.html"
        content = card_path.read_text(encoding="utf-8")

        required_types = ["Groups", "Forums", "Channels+", "Channels", "Dead"]
        for badge_type in required_types:
            assert badge_type in content, (
                f"group_card.html must have '{badge_type}' chat-type badge (SPEC #3)"
            )


# ---------------------------------------------------------------------------
# #4  Auto-retry smoke
# ---------------------------------------------------------------------------


class TestAutoRetrySmoke:
    """Smoke: verify auto-retry implementation exists in group_engine."""

    def test_finalize_group_accepts_retry_done_param(self) -> None:
        """_finalize_group must accept retry_done parameter."""
        import inspect

        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        sig = inspect.signature(GroupAnalysisEngine._finalize_group)
        assert "retry_done" in sig.parameters, (
            "_finalize_group must have retry_done parameter for auto-retry logic"
        )

    def test_start_analysis_accepts_error_retry_param(self) -> None:
        """start_analysis must accept _error_retry parameter."""
        import inspect

        from chatfilter.analyzer.group_engine import GroupAnalysisEngine

        sig = inspect.signature(GroupAnalysisEngine.start_analysis)
        assert "_error_retry" in sig.parameters, (
            "start_analysis must have _error_retry parameter to prevent retry loops"
        )

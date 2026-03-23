"""Test for chats page i18n translations.

Verifies that all chats-page template strings return Russian correctly via gettext.
This is a regression test to prevent recurrence of the .mo staleness bug
(ChatFilter-8vr): stale .mo file caused RU mode to show English strings.
"""

from __future__ import annotations

import gettext
from pathlib import Path

import pytest


@pytest.fixture
def ru_translations():
    """Load Russian translations from compiled .mo file."""
    project_root = Path(__file__).parent.parent
    mo_path = project_root / "src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.mo"
    assert mo_path.exists(), f"Russian .mo file not found: {mo_path}"

    with open(mo_path, "rb") as f:
        translation = gettext.GNUTranslations(f)
    return translation


class TestChatsPageRuTranslations:
    """Verify chats.html template strings are translated to Russian."""

    def test_chat_groups_title(self, ru_translations):
        """'Chat Groups' should be 'Чаты'."""
        result = ru_translations.gettext("Chat Groups")
        assert result == "Чаты", f"Expected 'Чаты', got {result!r}"

    def test_manage_and_analyze(self, ru_translations):
        """'Manage and analyze groups of chats' should be in Russian."""
        result = ru_translations.gettext("Manage and analyze groups of chats")
        assert result == "Управление и анализ групп чатов", (
            f"Expected 'Управление и анализ групп чатов', got {result!r}"
        )

    def test_groups(self, ru_translations):
        """'Groups' should be 'Группы'."""
        result = ru_translations.gettext("Groups")
        assert result == "Группы", f"Expected 'Группы', got {result!r}"

    def test_import_chats(self, ru_translations):
        """'Import chats' should be 'Импорт чатов'."""
        result = ru_translations.gettext("Import chats")
        assert result == "Импорт чатов", f"Expected 'Импорт чатов', got {result!r}"

    def test_groups_list(self, ru_translations):
        """'Groups list' should be 'Список групп'."""
        result = ru_translations.gettext("Groups list")
        assert result == "Список групп", f"Expected 'Список групп', got {result!r}"

    def test_loading_groups(self, ru_translations):
        """'Loading groups...' should be 'Загрузка аккаунтов...'."""
        result = ru_translations.gettext("Loading groups...")
        assert result == "Загрузка аккаунтов...", (
            f"Expected 'Загрузка аккаунтов...', got {result!r}"
        )


class TestGroupCardRuTranslations:
    """Verify group_card.html template strings are translated to Russian."""

    def test_analysis_error(self, ru_translations):
        """'Analysis error' should be 'Ошибка анализа'."""
        result = ru_translations.gettext("Analysis error")
        assert result == "Ошибка анализа", f"Expected 'Ошибка анализа', got {result!r}"

    def test_no_updates_stuck(self, ru_translations):
        """Stuck analysis warning should be in Russian."""
        result = ru_translations.gettext("No updates for 60 seconds. Analysis may be stuck.")
        assert result == "Нет обновлений 60 секунд. Анализ мог зависнуть.", (
            f"Expected Russian stuck warning, got {result!r}"
        )

    def test_total_chats(self, ru_translations):
        """'Total chats' should be 'Всего чатов'."""
        result = ru_translations.gettext("Total chats")
        assert result == "Всего чатов", f"Expected 'Всего чатов', got {result!r}"

    def test_processed(self, ru_translations):
        """'Processed' should be 'Обработано'."""
        result = ru_translations.gettext("Processed")
        assert result == "Обработано", f"Expected 'Обработано', got {result!r}"

    def test_current_chat(self, ru_translations):
        """'Current chat' should be 'Текущий чат'."""
        result = ru_translations.gettext("Current chat")
        assert result == "Текущий чат", f"Expected 'Текущий чат', got {result!r}"

    def test_dead_badge(self, ru_translations):
        """'Dead' (chat type badge) should be 'Мёртвые'."""
        result = ru_translations.gettext("Dead")
        assert result == "Мёртвые", f"Expected 'Мёртвые', got {result!r}"

    def test_forums_badge(self, ru_translations):
        """'Forums' should be 'Форумы'."""
        result = ru_translations.gettext("Forums")
        assert result == "Форумы", f"Expected 'Форумы', got {result!r}"

    def test_channels_plus_badge(self, ru_translations):
        """'Channels+' should be 'Каналы+'."""
        result = ru_translations.gettext("Channels+")
        assert result == "Каналы+", f"Expected 'Каналы+', got {result!r}"

    def test_channels_badge(self, ru_translations):
        """'Channels' should be 'Каналы'."""
        result = ru_translations.gettext("Channels")
        assert result == "Каналы", f"Expected 'Каналы', got {result!r}"

    def test_start_analysis_button(self, ru_translations):
        """'Start analysis' should be 'Начать анализ'."""
        result = ru_translations.gettext("Start analysis")
        assert result == "Начать анализ", f"Expected 'Начать анализ', got {result!r}"

    def test_stop_analysis_button(self, ru_translations):
        """'Stop analysis' should be 'Остановить анализ'."""
        result = ru_translations.gettext("Stop analysis")
        assert result == "Остановить анализ", f"Expected 'Остановить анализ', got {result!r}"

    def test_resume_analysis_button(self, ru_translations):
        """'Resume analysis' should be 'Возобновить анализ'."""
        result = ru_translations.gettext("Resume analysis")
        assert result == "Возобновить анализ", f"Expected 'Возобновить анализ', got {result!r}"

    def test_restart_analysis_button(self, ru_translations):
        """'Restart analysis' should be 'Перезапустить анализ'."""
        result = ru_translations.gettext("Restart analysis")
        assert result == "Перезапустить анализ", f"Expected 'Перезапустить анализ', got {result!r}"

    def test_download_results_button(self, ru_translations):
        """'Download results' should be 'Скачать результаты'."""
        result = ru_translations.gettext("Download results")
        assert result == "Скачать результаты", f"Expected 'Скачать результаты', got {result!r}"

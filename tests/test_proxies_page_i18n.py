"""Test for proxy page i18n translations.

Verifies that all proxy-page template strings return Russian correctly via gettext.
This is a SMOKE test to verify ChatFilter-7xd: i18n RU mode shows English on Proxies page.

Root cause (ChatFilter-8vr): .mo file was stale, not recompiled after .po fixes.
This test confirms the .mo file is now up-to-date with correct translations.
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


class TestProxiesPageRuTranslations:
    """Verify proxy page template strings are translated to Russian."""

    def test_proxy_pool_title(self, ru_translations):
        """'Proxy Pool' should be 'Пул прокси'."""
        result = ru_translations.gettext("Proxy Pool")
        assert result == "Пул прокси", f"Expected 'Пул прокси', got {result!r}"

    def test_proxy_list_title(self, ru_translations):
        """'Proxy List' should be 'Список прокси'."""
        result = ru_translations.gettext("Proxy List")
        assert result == "Список прокси", f"Expected 'Список прокси', got {result!r}"

    def test_add_new_proxy(self, ru_translations):
        """'Add new proxy' should be 'Добавить новый прокси'."""
        result = ru_translations.gettext("Add new proxy")
        assert result == "Добавить новый прокси", (
            f"Expected 'Добавить новый прокси', got {result!r}"
        )

    def test_failed_to_load_proxies(self, ru_translations):
        """'Failed to load proxies. Please refresh the page.' translation."""
        result = ru_translations.gettext("Failed to load proxies. Please refresh the page.")
        assert result == "Не удалось загрузить прокси. Пожалуйста, обновите страницу.", (
            f"Expected correct Russian translation, got {result!r}"
        )

    def test_list_of_configured_proxies(self, ru_translations):
        """'List of configured proxies' should be 'Список настроенных прокси'."""
        result = ru_translations.gettext("List of configured proxies")
        assert result == "Список настроенных прокси", (
            f"Expected 'Список настроенных прокси', got {result!r}"
        )

    def test_loading_proxies(self, ru_translations):
        """'Loading proxies...' should be 'Загрузка прокси...'."""
        result = ru_translations.gettext("Loading proxies...")
        assert result == "Загрузка прокси...", f"Expected 'Загрузка прокси...', got {result!r}"

    def test_port(self, ru_translations):
        """'Port' should be 'Порт' (not 'Импорт')."""
        result = ru_translations.gettext("Port")
        assert result == "Порт", f"Expected 'Порт', got {result!r}"

    def test_working_proxy(self, ru_translations):
        """'Working - last checked' should be 'Работает — последняя проверка'."""
        result = ru_translations.gettext("Working - last checked")
        assert result == "Работает — последняя проверка", (
            f"Expected 'Работает — последняя проверка', got {result!r}"
        )

    def test_testing(self, ru_translations):
        """'Testing...' should be 'Тестирование...' (not 'Всё ещё работаю...')."""
        result = ru_translations.gettext("Testing...")
        assert result == "Тестирование...", f"Expected 'Тестирование...', got {result!r}"

    def test_consecutive_failures(self, ru_translations):
        """'consecutive failures' should be 'последовательных ошибок'."""
        result = ru_translations.gettext("consecutive failures")
        assert result == "последовательных ошибок", (
            f"Expected 'последовательных ошибок', got {result!r}"
        )

    def test_untested(self, ru_translations):
        """'Untested' should be 'Не проверялся' (not 'Аккаунт удалён')."""
        result = ru_translations.gettext("Untested")
        assert result == "Не проверялся", f"Expected 'Не проверялся', got {result!r}"

    def test_none(self, ru_translations):
        """'None' should be 'Нет' (not 'Заблокирован')."""
        result = ru_translations.gettext("None")
        assert result == "Нет", f"Expected 'Нет', got {result!r}"

    def test_authentication_failed(self, ru_translations):
        """'Authentication Failed' should be 'Ошибка авторизации'."""
        result = ru_translations.gettext("Authentication Failed")
        assert result == "Ошибка авторизации", f"Expected 'Ошибка авторизации', got {result!r}"

    def test_no_authentication(self, ru_translations):
        """'No authentication' should be 'Без аутентификации'."""
        result = ru_translations.gettext("No authentication")
        assert result == "Без аутентификации", f"Expected 'Без аутентификации', got {result!r}"

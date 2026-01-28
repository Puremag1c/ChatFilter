"""Tests for i18n translation utilities.

Tests cover:
- get_translations: loading translations
- get_current_locale / set_current_locale: locale context
- gettext_func / ngettext_func: translation functions
"""

from __future__ import annotations

from chatfilter.i18n.translations import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    _,
    get_current_locale,
    get_translations,
    gettext_func,
    ngettext,
    ngettext_func,
    set_current_locale,
)


class TestSupportedLanguages:
    """Tests for language configuration."""

    def test_supported_languages(self) -> None:
        """Should have expected languages."""
        assert "en" in SUPPORTED_LANGUAGES
        assert "ru" in SUPPORTED_LANGUAGES

    def test_default_language(self) -> None:
        """Default language should be English."""
        assert DEFAULT_LANGUAGE == "en"


class TestGetTranslations:
    """Tests for get_translations function."""

    def test_returns_translations(self) -> None:
        """Should return translations object."""
        result = get_translations("en")

        # Should be some form of translations object
        assert hasattr(result, "gettext")

    def test_caches_translations(self) -> None:
        """Should cache translations per locale."""
        from chatfilter.i18n import translations as trans_module

        # Clear cache
        trans_module._translations_cache.clear()

        # First call
        result1 = get_translations("en")
        # Second call should use cache
        result2 = get_translations("en")

        assert result1 is result2

    def test_falls_back_to_default(self) -> None:
        """Should fall back to default for unsupported locale."""
        result = get_translations("invalid_locale")

        # Should get default language translations
        assert result is not None


class TestGetSetCurrentLocale:
    """Tests for get/set current locale functions."""

    def test_get_current_locale_default(self) -> None:
        """Should return default locale initially."""
        from chatfilter.i18n.translations import _current_locale

        # Reset to default
        _current_locale.set(DEFAULT_LANGUAGE)

        result = get_current_locale()

        assert result == DEFAULT_LANGUAGE

    def test_set_current_locale(self) -> None:
        """Should set locale for current context."""
        set_current_locale("ru")

        result = get_current_locale()

        assert result == "ru"

        # Reset
        set_current_locale("en")

    def test_set_unsupported_locale_falls_back(self) -> None:
        """Should fall back to default for unsupported locale."""
        set_current_locale("invalid")

        result = get_current_locale()

        assert result == DEFAULT_LANGUAGE


class TestGettextFunc:
    """Tests for gettext_func function."""

    def test_returns_string(self) -> None:
        """Should return translated string."""
        result = gettext_func("Hello")

        assert isinstance(result, str)

    def test_underscore_alias(self) -> None:
        """_ should be alias for gettext_func."""
        assert _ is gettext_func


class TestNgettextFunc:
    """Tests for ngettext_func function."""

    def test_singular(self) -> None:
        """Should return singular form for n=1."""
        result = ngettext_func("item", "items", 1)

        assert isinstance(result, str)

    def test_plural(self) -> None:
        """Should return plural form for n>1."""
        result = ngettext_func("item", "items", 2)

        assert isinstance(result, str)

    def test_ngettext_alias(self) -> None:
        """ngettext should be alias for ngettext_func."""
        assert ngettext is ngettext_func

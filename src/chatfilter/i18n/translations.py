"""Core i18n translation utilities."""

from __future__ import annotations

import gettext
from contextvars import ContextVar
from pathlib import Path

from babel.support import Translations

# Supported languages
SUPPORTED_LANGUAGES = ["en", "ru"]
DEFAULT_LANGUAGE = "en"

# Context variable to store current locale per request
_current_locale: ContextVar[str] = ContextVar("current_locale", default=DEFAULT_LANGUAGE)

# Path to locales directory
LOCALES_DIR = Path(__file__).parent / "locales"

# Cache for loaded translations
_translations_cache: dict[str, gettext.GNUTranslations | gettext.NullTranslations] = {}


def get_translations(locale: str) -> gettext.GNUTranslations | gettext.NullTranslations:
    """Get translations for the specified locale.

    Args:
        locale: Language code (e.g., 'en', 'ru')

    Returns:
        GNUTranslations object for the locale, or NullTranslations if not found
    """
    if locale not in SUPPORTED_LANGUAGES:
        locale = DEFAULT_LANGUAGE

    if locale not in _translations_cache:
        try:
            translations = Translations.load(
                dirname=str(LOCALES_DIR), locales=[locale], domain="messages"
            )
            _translations_cache[locale] = translations
        except FileNotFoundError:
            # Return null translations if locale files not found
            _translations_cache[locale] = gettext.NullTranslations()

    return _translations_cache[locale]


def get_current_locale() -> str:
    """Get the current locale for this request context.

    Returns:
        Current locale code (e.g., 'en', 'ru')
    """
    return _current_locale.get()


def set_current_locale(locale: str) -> None:
    """Set the current locale for this request context.

    Args:
        locale: Language code to set (e.g., 'en', 'ru')
    """
    if locale not in SUPPORTED_LANGUAGES:
        locale = DEFAULT_LANGUAGE
    _current_locale.set(locale)


def gettext_func(message: str) -> str:
    """Translate a message using the current locale.

    This is the main translation function to use in Python code.

    Args:
        message: The message to translate

    Returns:
        Translated message
    """
    locale = get_current_locale()
    translations = get_translations(locale)
    result: str = translations.gettext(message)
    return result


def ngettext_func(singular: str, plural: str, n: int) -> str:
    """Translate a message with pluralization support.

    Args:
        singular: Singular form of the message
        plural: Plural form of the message
        n: Count to determine which form to use

    Returns:
        Translated message in appropriate form
    """
    locale = get_current_locale()
    translations = get_translations(locale)
    result: str = translations.ngettext(singular, plural, n)
    return result


# Convenience aliases
_ = gettext_func
ngettext = ngettext_func

"""Core i18n translation utilities."""

from __future__ import annotations

import gettext
import logging
from contextvars import ContextVar
from pathlib import Path

from babel.support import NullTranslations, Translations

logger = logging.getLogger(__name__)

# Supported languages
SUPPORTED_LANGUAGES = ["en", "ru"]
DEFAULT_LANGUAGE = "en"

# Context variable to store current locale per request
_current_locale: ContextVar[str] = ContextVar("current_locale", default=DEFAULT_LANGUAGE)

# Path to locales directory
LOCALES_DIR = Path(__file__).parent / "locales"

# Cache for loaded translations
_translations_cache: dict[str, gettext.GNUTranslations | gettext.NullTranslations] = {}


def _compile_mo_files_if_needed() -> None:
    """Auto-compile .po files to .mo if .po is newer than .mo.

    Runs at module import time so developers never forget the compile step.
    Fails gracefully if babel is unavailable or compilation errors occur.
    """
    try:
        from babel.messages.mofile import write_mo
        from babel.messages.pofile import read_po
    except ImportError:
        logger.debug("babel not available, skipping auto-compile of .mo files")
        return

    for locale in SUPPORTED_LANGUAGES:
        po_path = LOCALES_DIR / locale / "LC_MESSAGES" / "messages.po"
        mo_path = LOCALES_DIR / locale / "LC_MESSAGES" / "messages.mo"

        if not po_path.exists():
            continue

        needs_compile = not mo_path.exists() or po_path.stat().st_mtime > mo_path.stat().st_mtime
        if not needs_compile:
            continue

        try:
            with open(po_path, "rb") as f:
                catalog = read_po(f, locale=locale)
            with open(mo_path, "wb") as f:
                write_mo(f, catalog)
            logger.info(f"Compiled {po_path.name} -> {mo_path.name} for locale '{locale}'")
        except Exception as exc:
            logger.warning(
                f"Failed to compile .mo for locale '{locale}': {exc}. "
                f"Using existing .mo file if available."
            )


_compile_mo_files_if_needed()


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
            # Log warning and use NullTranslations (returns msgid as-is, i.e., English strings)
            logger.warning(
                f"Translation file (.mo) missing for locale '{locale}' at {LOCALES_DIR}. "
                f"Using English strings (msgid)."
            )
            _translations_cache[locale] = NullTranslations()

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

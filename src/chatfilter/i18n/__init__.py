"""Internationalization (i18n) support for ChatFilter."""

from chatfilter.i18n.translations import (
    _,
    get_current_locale,
    get_translations,
    ngettext,
    set_current_locale,
)

__all__ = ["_", "ngettext", "get_translations", "get_current_locale", "set_current_locale"]

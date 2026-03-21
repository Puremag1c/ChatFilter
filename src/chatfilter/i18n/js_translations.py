"""JS translation key mapping module.

Provides JS_KEYS dict (dotted key -> English msgid) and get_js_translations()
which returns a nested dict of translated values for a given locale.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from chatfilter.i18n.translations import get_translations

_EN_JSON = Path(__file__).parent.parent / "static/js/locales/en.json"


def _flatten(obj: dict, prefix: str = "") -> dict[str, str]:
    """Recursively flatten a nested dict to dotted keys."""
    result: dict[str, str] = {}
    for key, value in obj.items():
        full_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            result.update(_flatten(value, full_key))
        else:
            result[full_key] = str(value)
    return result


def _load_js_keys() -> dict[str, str]:
    with open(_EN_JSON, encoding="utf-8") as f:
        data = json.load(f)
    return _flatten(data)


# Maps dotted JS keys to English text (gettext msgid)
JS_KEYS: dict[str, str] = _load_js_keys()


def _set_nested(d: dict, dotted_key: str, value: str) -> None:
    """Set a value in a nested dict using a dotted key path."""
    parts = dotted_key.split(".")
    node = d
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value


@lru_cache(maxsize=8)
def get_js_translations(locale: str) -> dict:
    """Return nested translation dict for the given locale.

    Uses the gettext catalog for translations. Falls back to English msgid
    if a translation is missing.

    Args:
        locale: Language code (e.g., 'en', 'ru')

    Returns:
        Nested dict matching en.json structure with translated values
    """
    catalog = get_translations(locale)
    result: dict = {}
    for dotted_key, english_text in JS_KEYS.items():
        translated = catalog.gettext(english_text)
        _set_nested(result, dotted_key, translated)
    return result

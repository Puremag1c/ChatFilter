"""Translation completeness CI tests.

Verifies that all translations are complete and consistent across locales:
1. All JS_KEYS English texts exist as msgids in messages.po for each locale
2. No empty msgstr in any .po file (every non-plural msgid has a translation)
3. All JS_KEYS msgids exist in both en.po and ru.po (JS parity across locales)
4. Interpolation variables match between msgid and msgstr for JS entries
5. JS_KEYS dict values match their corresponding en.po msgstr (consistency)
"""

from __future__ import annotations

import re
from pathlib import Path

import polib
import pytest

from chatfilter.i18n.js_translations import JS_KEYS
from chatfilter.i18n.translations import SUPPORTED_LANGUAGES

_LOCALES_DIR = Path(__file__).parent.parent / "src/chatfilter/i18n/locales"
_LOCALES = list(SUPPORTED_LANGUAGES)


def _po_path(locale: str) -> Path:
    return _LOCALES_DIR / locale / "LC_MESSAGES" / "messages.po"


def _load_po(locale: str) -> polib.POFile:
    return polib.pofile(str(_po_path(locale)))


def _extract_interp_vars(text: str) -> set[str]:
    """Extract interpolation variables from a string.

    Handles both Python-style %(name)s and brace-style {name} variables.
    """
    percent_vars = set(re.findall(r"%\(\w+\)[sdrf]", text))
    brace_vars = set(re.findall(r"\{\w+\}", text))
    return percent_vars | brace_vars


# ---------------------------------------------------------------------------
# Test 1: JS_KEYS English texts exist as msgids in every locale's .po
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("locale", _LOCALES)
def test_js_keys_exist_in_po(locale: str) -> None:
    """All JS_KEYS English texts must be present as msgids in every locale's .po."""
    po = _load_po(locale)
    existing_msgids = {entry.msgid for entry in po if entry.msgid}

    missing = [text for text in JS_KEYS.values() if text not in existing_msgids]

    assert not missing, (
        f"[{locale}] {len(missing)} JS_KEYS value(s) missing from messages.po:\n"
        + "\n".join(f"  - {text!r}" for text in sorted(missing)[:20])
    )


# ---------------------------------------------------------------------------
# Test 2: No empty msgstr in any .po file (excluding plural-form entries)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("locale", _LOCALES)
def test_no_empty_translations(locale: str) -> None:
    """Every non-plural msgid must have a non-empty msgstr."""
    po = _load_po(locale)

    empty = [
        entry.msgid
        for entry in po
        if entry.msgid and not entry.msgstr and not entry.msgid_plural
    ]

    assert not empty, (
        f"[{locale}] {len(empty)} untranslated msgid(s) (empty msgstr):\n"
        + "\n".join(f"  - {msgid!r}" for msgid in sorted(empty)[:20])
    )


# ---------------------------------------------------------------------------
# Test 3: JS_KEYS msgids exist in all locales (parity check for JS entries)
# ---------------------------------------------------------------------------


def test_js_keys_parity_across_locales() -> None:
    """All JS_KEYS English texts must be present in every supported locale's .po.

    This ensures that when a JS translation key is added to one locale it is
    also added to all others.
    """
    js_msgids = set(JS_KEYS.values())

    failures: list[str] = []
    for locale in _LOCALES:
        po = _load_po(locale)
        existing = {entry.msgid for entry in po if entry.msgid}
        missing = js_msgids - existing
        if missing:
            failures.append(
                f"[{locale}] missing {len(missing)} JS msgid(s):\n"
                + "\n".join(f"    - {m!r}" for m in sorted(missing)[:10])
            )

    assert not failures, "JS translation parity failures:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# Test 4: Interpolation variables match between msgid and msgstr (JS entries)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("locale", _LOCALES)
def test_js_keys_interpolation_vars_match(locale: str) -> None:
    """Interpolation variables in JS_KEYS entries must be preserved in translations."""
    po = _load_po(locale)
    msgid_to_entry = {entry.msgid: entry for entry in po if entry.msgid}

    mismatches: list[str] = []
    for _js_key, english_text in JS_KEYS.items():
        entry = msgid_to_entry.get(english_text)
        if entry is None or not entry.msgstr:
            # Missing entries are caught by test_js_keys_exist_in_po
            continue

        expected_vars = _extract_interp_vars(english_text)
        if not expected_vars:
            continue  # No variables to check

        actual_vars = _extract_interp_vars(entry.msgstr)
        if expected_vars != actual_vars:
            mismatches.append(
                f"  {english_text!r}\n"
                f"    expected vars: {sorted(expected_vars)}\n"
                f"    got vars:      {sorted(actual_vars)}\n"
                f"    msgstr: {entry.msgstr!r}"
            )

    assert not mismatches, (
        f"[{locale}] {len(mismatches)} interpolation variable mismatch(es):\n"
        + "\n".join(mismatches[:10])
    )


# ---------------------------------------------------------------------------
# Test 5: JS_KEYS dict values match their en.po msgstr (consistency check)
# ---------------------------------------------------------------------------


def test_js_keys_match_en_po_msgstr() -> None:
    """JS_KEYS values (English text) must equal the en.po msgstr for the same msgid.

    This ensures the JS translation mapping stays in sync with the gettext catalog.
    """
    po_en = _load_po("en")
    en_msgstr = {entry.msgid: entry.msgstr for entry in po_en if entry.msgid and entry.msgstr}

    mismatches: list[str] = []
    for js_key, english_text in JS_KEYS.items():
        if english_text not in en_msgstr:
            # Covered by test_js_keys_exist_in_po
            continue
        catalog_msgstr = en_msgstr[english_text]
        if english_text != catalog_msgstr:
            mismatches.append(
                f"  JS key {js_key!r}:\n"
                f"    JS_KEYS value: {english_text!r}\n"
                f"    en.po msgstr:  {catalog_msgstr!r}"
            )

    assert not mismatches, (
        f"{len(mismatches)} JS_KEYS/en.po inconsistency(ies):\n"
        + "\n".join(mismatches[:10])
    )

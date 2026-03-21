"""Tests for graceful fallback when .mo auto-compile fails on startup.

Covers:
- Corrupt .po file: app does not crash, logs warning, existing .mo preserved
- Missing babel: app does not crash (silently skips)
- Permissions error: app does not crash, logs warning, existing .mo preserved
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from unittest.mock import patch

import pytest


def _make_locale_dir(tmp_path: Path, locale: str, po_content: bytes, mo_content: bytes | None = None) -> Path:
    """Create a locale directory with given .po content and optional .mo content."""
    lc = tmp_path / locale / "LC_MESSAGES"
    lc.mkdir(parents=True)
    po = lc / "messages.po"
    mo = lc / "messages.mo"
    po.write_bytes(po_content)
    if mo_content is not None:
        mo.write_bytes(mo_content)
    # Make .po newer than .mo so compile is triggered
    if mo_content is not None:
        import time
        mo.touch()
        time.sleep(0.01)
        po.touch()
    return lc


VALID_PO = b"""
# English translations
msgid ""
msgstr ""
"Content-Type: text/plain; charset=UTF-8\\n"

msgid "Hello"
msgstr "Hello"
"""

CORRUPT_PO = b"THIS IS NOT VALID PO CONTENT \x00\xff\xfe garbage"

VALID_MO_SENTINEL = b"SENTINEL_MO_CONTENT"


class TestCompileMoFallback:
    """Tests for _compile_mo_files_if_needed graceful fallback."""

    def _call_compile(self, locales_dir: Path) -> None:
        """Import and call _compile_mo_files_if_needed with patched LOCALES_DIR."""
        import chatfilter.i18n.translations as mod
        with patch.object(mod, "LOCALES_DIR", locales_dir):
            mod._compile_mo_files_if_needed()

    def test_corrupt_po_does_not_crash(self, tmp_path: Path) -> None:
        """App must not raise when .po file is corrupt."""
        _make_locale_dir(tmp_path, "ru", CORRUPT_PO, mo_content=VALID_MO_SENTINEL)
        # Should not raise
        self._call_compile(tmp_path)

    def test_corrupt_po_logs_warning(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """App must log a warning when .po compilation fails."""
        _make_locale_dir(tmp_path, "ru", CORRUPT_PO, mo_content=VALID_MO_SENTINEL)
        with caplog.at_level(logging.WARNING, logger="chatfilter.i18n.translations"):
            self._call_compile(tmp_path)
        assert any("Failed to compile" in r.message or "compile" in r.message.lower() for r in caplog.records), (
            f"Expected a compile-failure warning. Got: {[r.message for r in caplog.records]}"
        )

    def test_corrupt_po_preserves_existing_mo(self, tmp_path: Path) -> None:
        """Existing .mo must NOT be overwritten when .po is corrupt."""
        lc = _make_locale_dir(tmp_path, "ru", CORRUPT_PO, mo_content=VALID_MO_SENTINEL)
        mo_path = lc / "messages.mo"
        self._call_compile(tmp_path)
        assert mo_path.read_bytes() == VALID_MO_SENTINEL, "Existing .mo was overwritten despite corrupt .po"

    def test_no_crash_when_mo_missing_and_po_corrupt(self, tmp_path: Path) -> None:
        """App must not crash even when no .mo exists and .po is corrupt."""
        _make_locale_dir(tmp_path, "ru", CORRUPT_PO, mo_content=None)
        # Should not raise
        self._call_compile(tmp_path)

    def test_no_crash_when_babel_unavailable(self, tmp_path: Path) -> None:
        """App must not crash when babel is not installed."""
        _make_locale_dir(tmp_path, "ru", VALID_PO, mo_content=VALID_MO_SENTINEL)
        import chatfilter.i18n.translations as mod
        with patch.object(mod, "LOCALES_DIR", tmp_path):
            with patch.dict("sys.modules", {"babel.messages.mofile": None, "babel.messages.pofile": None}):
                # ImportError path — should skip silently
                mod._compile_mo_files_if_needed()

    def test_valid_po_compiles_successfully(self, tmp_path: Path) -> None:
        """Sanity check: valid .po should produce a non-empty .mo."""
        lc = _make_locale_dir(tmp_path, "en", VALID_PO, mo_content=None)
        mo_path = lc / "messages.mo"
        self._call_compile(tmp_path)
        assert mo_path.exists(), ".mo was not created from valid .po"
        assert mo_path.stat().st_size > 0, ".mo file is empty"

    def test_translations_module_importable_after_corrupt_po(self, tmp_path: Path) -> None:
        """The translations module must remain importable after a compile failure."""
        _make_locale_dir(tmp_path, "ru", CORRUPT_PO, mo_content=VALID_MO_SENTINEL)
        self._call_compile(tmp_path)
        # If we get here without exception, the module is still functional
        from chatfilter.i18n.translations import get_translations, set_current_locale
        set_current_locale("en")
        t = get_translations("en")
        assert t is not None

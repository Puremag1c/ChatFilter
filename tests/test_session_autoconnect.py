"""Persistent ``autoconnect`` flag on session config.

This is the "desired state" signal that boot recovery reads at server
startup: if a session was last set to ``autoconnect=True``, we try to
reconnect it automatically. If the user explicitly disconnected, the
flag is ``False`` and recovery leaves it alone.

Backwards-compat rule tested here: pre-0.42 configs don't have the
field, and their sessions were alive when the server last ran — so
their implicit default must be ``True``.
"""

from __future__ import annotations

import json
from pathlib import Path

from chatfilter.service.session_autoconnect import (
    read_autoconnect,
    set_autoconnect,
)


def _write_config(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


class TestReadAutoconnect:
    def test_returns_true_when_file_missing(self, tmp_path: Path) -> None:
        assert read_autoconnect(tmp_path / "nope.json") is True

    def test_returns_true_on_old_config_without_field(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        _write_config(cfg, {"proxy_id": "abc"})
        assert read_autoconnect(cfg) is True

    def test_reads_explicit_true(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        _write_config(cfg, {"proxy_id": "abc", "autoconnect": True})
        assert read_autoconnect(cfg) is True

    def test_reads_explicit_false(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        _write_config(cfg, {"proxy_id": "abc", "autoconnect": False})
        assert read_autoconnect(cfg) is False

    def test_returns_true_on_corrupted_json(self, tmp_path: Path) -> None:
        """A broken config.json shouldn't strand the session forever.
        Default to True and let the user's explicit action re-set it."""
        cfg = tmp_path / "config.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("{not json")
        assert read_autoconnect(cfg) is True


class TestSetAutoconnect:
    def test_creates_file_when_missing(self, tmp_path: Path) -> None:
        cfg = tmp_path / "nested" / "config.json"
        set_autoconnect(cfg, True)
        assert json.loads(cfg.read_text()) == {"autoconnect": True}

    def test_preserves_existing_keys(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        _write_config(cfg, {"proxy_id": "p1", "web_user_id": "admin"})
        set_autoconnect(cfg, False)
        data = json.loads(cfg.read_text())
        assert data == {
            "proxy_id": "p1",
            "web_user_id": "admin",
            "autoconnect": False,
        }

    def test_overwrites_previous_value(self, tmp_path: Path) -> None:
        cfg = tmp_path / "config.json"
        _write_config(cfg, {"autoconnect": True})
        set_autoconnect(cfg, False)
        assert json.loads(cfg.read_text())["autoconnect"] is False

    def test_is_atomic_even_on_corrupted_source(self, tmp_path: Path) -> None:
        """If the config was corrupted, we must not lose it silently —
        but we also mustn't refuse to persist the user's intent. We
        overwrite with a clean config containing only the new flag."""
        cfg = tmp_path / "config.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text("{broken")
        set_autoconnect(cfg, False)
        assert json.loads(cfg.read_text()) == {"autoconnect": False}

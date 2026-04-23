"""One-shot migration of legacy raw-UUID proxy pools into the Phase-2 layout.

Before Phase 2 the proxy-pool files were keyed by the raw user_id —
``proxies_<uuid>.json``. After Phase 2 /api/proxies is keyed by
``admin`` (for is_admin=True) or ``user_<id>``. Old files became
invisible to both views. This migration re-classifies them:

  - owner in DB was is_admin → merge into proxies_admin.json
  - owner in DB was regular → rename to proxies_user_<id>.json
  - orphan (no such user) → merge into proxies_admin.json so they
    don't vanish
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def migrate_in(monkeypatch: Any):
    """Use the autouse ``_isolate_data_dir`` settings so proxy_pool's
    ``get_settings()`` (import-bound) sees the same paths our seeds
    write to."""
    from chatfilter.config import get_settings
    from chatfilter.storage.user_database import get_user_db

    settings = get_settings()  # isolated_settings from the autouse fixture

    db = get_user_db(settings.effective_database_url)
    admin_id = db.create_user("admin1", "pw12345678", is_admin=True)
    user_id = db.create_user("regular", "pw12345678", is_admin=False)

    from chatfilter.storage.proxy_pool import migrate_legacy_proxy_pools

    return migrate_legacy_proxy_pools, settings, admin_id, user_id


def _seed_proxy_file(settings, key: str, name: str, proxy_id: str | None = None) -> Path:
    """Write a minimal proxies_<key>.json with one entry."""
    import uuid

    if proxy_id is None:
        proxy_id = str(uuid.uuid4())
    p = settings.config_dir / f"proxies_{key}.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps([
        {
            "id": proxy_id,
            "name": name,
            "type": "socks5",
            "host": "10.0.0.1",
            "port": 1080,
            "username": "",
            "password": "",
            "status": "untested",
            "last_ping_at": None,
            "last_success_at": None,
            "consecutive_failures": 0,
        }
    ]))
    return p


class TestMigrateLegacyProxyPools:
    def test_admin_owner_merges_into_admin_pool(self, migrate_in) -> None:
        migrate, settings, admin_id, _ = migrate_in
        _seed_proxy_file(settings, admin_id, "AdminLegacy")

        stats = migrate(settings.effective_database_url)

        assert stats["merged"] == 1
        assert not (settings.config_dir / f"proxies_{admin_id}.json").exists()
        merged = json.loads((settings.config_dir / "proxies_admin.json").read_text())
        assert any(p["name"] == "AdminLegacy" for p in merged)

    def test_regular_user_renames_to_user_scope(self, migrate_in) -> None:
        migrate, settings, _, user_id = migrate_in
        _seed_proxy_file(settings, user_id, "UserLegacy")

        stats = migrate(settings.effective_database_url)

        assert stats["renamed"] == 1
        assert (settings.config_dir / f"proxies_user_{user_id}.json").exists()
        assert not (settings.config_dir / f"proxies_{user_id}.json").exists()

    def test_orphan_goes_to_admin_pool(self, migrate_in) -> None:
        """A proxy file keyed by a UUID that no longer matches any user."""
        migrate, settings, _, _ = migrate_in
        _seed_proxy_file(settings, "ghost-uuid-xxx", "OrphanProxy")

        stats = migrate(settings.effective_database_url)

        assert stats["merged"] == 1
        merged = json.loads((settings.config_dir / "proxies_admin.json").read_text())
        assert any(p["name"] == "OrphanProxy" for p in merged)

    def test_canonical_files_untouched(self, migrate_in) -> None:
        migrate, settings, _, _ = migrate_in
        _seed_proxy_file(settings, "admin", "PreExistingAdmin")
        _seed_proxy_file(settings, "default", "Default")
        _seed_proxy_file(settings, "user_42", "PreExistingUser")

        stats = migrate(settings.effective_database_url)

        assert stats["unchanged"] == 3
        assert stats["merged"] == 0
        assert stats["renamed"] == 0

    def test_merge_dedups_by_id(self, migrate_in) -> None:
        import uuid

        migrate, settings, admin_id, _ = migrate_in
        shared_id = str(uuid.uuid4())
        settings.config_dir.mkdir(parents=True, exist_ok=True)
        # Canonical admin pool already has the shared proxy id.
        (settings.config_dir / "proxies_admin.json").write_text(json.dumps([
            {
                "id": shared_id,
                "name": "Canonical",
                "type": "socks5",
                "host": "1.1.1.1",
                "port": 1080,
                "username": "",
                "password": "",
                "status": "untested",
                "last_ping_at": None,
                "last_success_at": None,
                "consecutive_failures": 0,
            }
        ]))
        # Legacy file (under admin user's raw UUID) carries the SAME id.
        _seed_proxy_file(settings, admin_id, "LegacyDup", proxy_id=shared_id)

        migrate(settings.effective_database_url)

        merged = json.loads((settings.config_dir / "proxies_admin.json").read_text())
        assert len(merged) == 1, "duplicate proxy id must not duplicate entries"
        # Canonical wins (it was first) — legacy did not overwrite it.
        assert merged[0]["name"] == "Canonical"

    def test_idempotent(self, migrate_in) -> None:
        migrate, settings, admin_id, _ = migrate_in
        _seed_proxy_file(settings, admin_id, "AdminLegacy")

        first = migrate(settings.effective_database_url)
        second = migrate(settings.effective_database_url)

        assert first["merged"] == 1
        assert second["merged"] == 0
        assert second["renamed"] == 0

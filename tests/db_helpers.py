"""Database test helpers — create pre-migrated test databases."""

from __future__ import annotations

from pathlib import Path

from chatfilter.storage.group_database import GroupDatabase
from chatfilter.storage.migrate import run_migrations
from chatfilter.storage.user_database import UserDatabase


def make_group_db(path: Path | str) -> GroupDatabase:
    """Create a GroupDatabase with Alembic migrations applied."""
    url = _to_url(path)
    run_migrations(url)
    return GroupDatabase(url)


def make_user_db(path: Path | str) -> UserDatabase:
    """Create a UserDatabase with Alembic migrations applied."""
    url = _to_url(path)
    run_migrations(url)
    return UserDatabase(url)


def _to_url(path: Path | str) -> str:
    if "://" in str(path):
        return str(path)
    p = Path(path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{p}"

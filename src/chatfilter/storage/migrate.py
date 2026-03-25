"""Database migration helper.

Provides run_migrations() for programmatic use (tests, app startup).
"""

from __future__ import annotations

from pathlib import Path


def run_migrations(db_url: str, revision: str = "head") -> None:
    """Run Alembic migrations to the specified revision.

    Args:
        db_url: Database URL (sqlite:///... or postgresql://...).
        revision: Target revision (default: "head").
    """
    from alembic import command
    from alembic.config import Config

    ini_path = Path(__file__).resolve().parent.parent.parent.parent / "alembic.ini"
    if ini_path.exists():
        alembic_cfg = Config(str(ini_path))
    else:
        alembic_cfg = Config()
        alembic_cfg.set_main_option(
            "script_location",
            str(Path(__file__).resolve().parent / "migrations"),
        )

    alembic_cfg.set_main_option("sqlalchemy.url", db_url)

    command.upgrade(alembic_cfg, revision)

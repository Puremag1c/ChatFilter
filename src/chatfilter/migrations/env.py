"""Alembic environment configuration.

Supports both online and offline migration modes.
Database URL is resolved from ChatFilter settings.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from chatfilter.storage.models import metadata

config = context.config


def _get_url() -> str:
    """Get database URL from Alembic config or ChatFilter settings."""
    url = config.get_main_option("sqlalchemy.url")
    if url:
        return url
    from chatfilter.config import get_settings

    return get_settings().effective_database_url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (generate SQL script)."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (direct database connection)."""
    cfg = config.get_section(config.config_ini_section, {})
    cfg["sqlalchemy.url"] = _get_url()

    connectable = engine_from_config(
        cfg,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=metadata)
        with context.begin_transaction():
            context.run_migrations()

    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

"""SQLAlchemy engine factory.

Provides create_db_engine() which builds an Engine from a URL string,
applying SQLite-specific PRAGMAs when appropriate.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine


def create_db_engine(url: str, **kwargs: Any) -> Engine:
    """Create a SQLAlchemy engine from a database URL.

    For SQLite URLs, automatically sets:
      - PRAGMA foreign_keys = ON
      - PRAGMA busy_timeout = 30000

    Args:
        url: Database URL (e.g. "sqlite:///path/to/db" or "postgresql://...")
        **kwargs: Extra keyword arguments forwarded to create_engine.

    Returns:
        Configured SQLAlchemy Engine.
    """
    engine = create_engine(url, **kwargs)

    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn: Any, _rec: Any) -> None:
            cursor = dbapi_conn.execute("PRAGMA foreign_keys = ON")
            cursor.close()
            cursor = dbapi_conn.execute("PRAGMA busy_timeout = 30000")
            cursor.close()

    return engine

"""SQLAlchemy-based backend for the Database abstraction.

Replaces raw sqlite3 with a SQLAlchemy Engine while keeping full
backward compatibility with existing SQL queries that use ``?``
placeholders and ``row["column"]`` access.
"""

from __future__ import annotations

import re
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import inspect as sa_inspect
from sqlalchemy import text
from sqlalchemy.engine import Connection, CursorResult, Engine

from .database import Database
from .engine import create_db_engine


class _DictRow:
    """Row wrapper that supports both ``row["col"]`` and ``row[0]`` access."""

    __slots__ = ("_data", "_keys")

    def __init__(self, mapping: Any) -> None:
        self._keys: tuple[str, ...] = tuple(mapping.keys())
        self._data: dict[str, Any] = dict(mapping)

    def __getitem__(self, key: str | int) -> Any:
        if isinstance(key, int):
            return self._data[self._keys[key]]
        return self._data[key]

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def keys(self) -> tuple[str, ...]:
        return self._keys


class _CursorWrapper:
    """Wraps a SQLAlchemy CursorResult to look like a DB-API cursor.

    Provides ``.fetchone()``, ``.fetchall()``, ``.lastrowid``, ``.rowcount``.
    Rows are returned as ``_DictRow`` instances.
    """

    __slots__ = ("_result", "lastrowid", "rowcount")

    def __init__(self, result: CursorResult[Any]) -> None:
        self._result = result
        self.lastrowid: int | None = getattr(result, "lastrowid", None)
        self.rowcount: int = result.rowcount

    def fetchone(self) -> _DictRow | None:
        row = self._result.mappings().fetchone()
        return _DictRow(row) if row is not None else None

    def fetchall(self) -> list[_DictRow]:
        return [_DictRow(r) for r in self._result.mappings().fetchall()]

    def __iter__(self) -> Iterator[_DictRow]:
        return iter(self.fetchall())


# Pre-compiled regex for converting ? placeholders.
_QMARK_RE = re.compile(r"\?")


class _ConnectionWrapper:
    """Wraps a SQLAlchemy Connection to accept ``?`` placeholders.

    Converts ``?`` → ``:p0, :p1, …`` so that existing raw SQL
    keeps working through SQLAlchemy's ``text()`` interface.
    """

    __slots__ = ("_conn",)

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def execute(self, sql: str, params: Any = None) -> _CursorWrapper:
        converted_sql, bound = self._convert(sql, params)
        result = self._conn.execute(text(converted_sql), bound)
        return _CursorWrapper(result)

    # ------------------------------------------------------------------
    @staticmethod
    def _convert(sql: str, params: Any) -> tuple[str, dict[str, Any]]:
        """Replace ``?`` markers with ``:p0, :p1, …`` named params."""
        if params is None or (isinstance(params, (list, tuple)) and len(params) == 0):
            return sql, {}

        if isinstance(params, dict):
            return sql, params

        bound: dict[str, Any] = {}
        counter = 0

        def _replacer(m: re.Match[str]) -> str:
            nonlocal counter
            key = f"p{counter}"
            bound[key] = params[counter]
            counter += 1
            return f":{key}"

        new_sql = _QMARK_RE.sub(_replacer, sql)
        return new_sql, bound


def _path_to_url(path_str: str) -> str:
    """Convert a filesystem path to a sqlite:/// URL."""
    p = Path(path_str).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{p}"


class SQLiteDatabase(Database):
    """SQLAlchemy-based implementation of the Database base class.

    Accepts either a filesystem path (``Path`` / ``str``) or a full
    database URL.  Paths are converted to ``sqlite:///…`` automatically.

    On first connection, if the database has no tables, Alembic migrations
    are applied automatically (convenient for tests and first-run).
    """

    def __init__(self, db_path: Path | str) -> None:
        path_str = str(db_path)
        if "://" in path_str:
            self._db_url = path_str
        else:
            self._db_url = _path_to_url(path_str)

        self._engine: Engine = create_db_engine(self._db_url)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Auto-migrate if the database has no tables."""
        needs_migration = False
        with self._engine.connect() as conn:
            insp = sa_inspect(conn)
            tables = insp.get_table_names()
            needs_migration = not tables or "alembic_version" not in tables

        if needs_migration:
            # Dispose engine to release all connections before Alembic runs
            self._engine.dispose()
            from .migrate import run_migrations

            run_migrations(self._db_url)
            # Re-create engine after migration
            self._engine = create_db_engine(self._db_url)

    def _initialize_schema(self) -> None:
        """No-op. Schema is managed by Alembic."""

    @contextmanager
    def _connection(self) -> Generator[_ConnectionWrapper, None, None]:
        """Context manager for database connections with automatic commit/rollback."""
        with self._engine.connect() as conn:
            wrapper = _ConnectionWrapper(conn)
            try:
                yield wrapper
                conn.commit()
            except Exception:
                conn.rollback()
                raise

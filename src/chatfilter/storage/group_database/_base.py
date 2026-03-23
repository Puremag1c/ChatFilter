"""Type stub base for mixin classes that compose with SQLiteDatabase."""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:

    class DatabaseMixinBase:
        """Type stubs for mixins — only visible to mypy, not at runtime."""

        db_path: Path

        @contextmanager
        def _connection(self) -> Generator[sqlite3.Connection, None, None]: ...

        @staticmethod
        def _datetime_to_str(dt: datetime | None) -> str | None: ...

        @staticmethod
        def _str_to_datetime(s: str | None) -> datetime | None: ...

else:
    # At runtime, mixins don't need a base — SQLiteDatabase provides everything via MRO
    class DatabaseMixinBase:
        pass

"""Type stub base for mixin classes that compose with Database backends."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:

    class DatabaseMixinBase:
        """Type stubs for mixins — only visible to mypy, not at runtime."""

        @contextmanager
        def _connection(self) -> Generator[Any, None, None]: ...

        @staticmethod
        def _datetime_to_str(dt: datetime | None) -> str | None: ...

        @staticmethod
        def _str_to_datetime(s: str | None) -> datetime | None: ...

else:
    # At runtime, the concrete backend (SQLiteDatabase etc.) provides everything via MRO
    class DatabaseMixinBase:
        pass

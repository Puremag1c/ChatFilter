"""Database schema mixin for GroupDatabase.

Schema creation and migrations are handled by Alembic (``chatfilter migrate``).
This mixin is kept for MRO compatibility but does no work.
"""

from ._base import DatabaseMixinBase


class SchemaMixin(DatabaseMixinBase):
    """Mixin providing database schema initialization.

    All schema management is now handled by Alembic migrations.
    Run ``chatfilter migrate`` to create or update tables.
    """

    def _initialize_schema(self) -> None:
        """No-op. Schema is managed by Alembic."""

"""Add ``idempotency_key`` to ``ai_transactions`` with a partial UNIQUE index.

Closes the audit-discovered double-charge race (Fix #2): the scheduler's
pre-charge debits the user via ``billing.charge`` in one SQLite
connection, then writes ``charged_amount`` on the queue row in a second
connection. A crash between the two meant the user was debited but the
queue row still had ``charged_amount = 0``; on startup
``reset_running_tasks_to_queued`` would re-queue the task, and the
scheduler would debit a SECOND time.

With an idempotency key tied to ``queue_task:<task_id>`` the second
debit attempt fails the UNIQUE constraint on ``ai_transactions`` and
``atomic_charge`` bails out without touching the balance — user pays
once even if the scheduler re-claims the task.

Partial index (``WHERE idempotency_key IS NOT NULL``) keeps the existing
non-scheduler charges (AI tokens etc.) unaffected — they pass ``None``
and continue to insert without uniqueness concerns.

Revision ID: 016
Create Date: 2026-04-23
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "016"
down_revision: str | None = "015"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "ai_transactions",
        sa.Column("idempotency_key", sa.String(), nullable=True),
    )
    op.create_index(
        "idx_ai_tx_idempotency_key",
        "ai_transactions",
        ["idempotency_key"],
        unique=True,
        sqlite_where=sa.text("idempotency_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("idx_ai_tx_idempotency_key", table_name="ai_transactions")
    op.drop_column("ai_transactions", "idempotency_key")

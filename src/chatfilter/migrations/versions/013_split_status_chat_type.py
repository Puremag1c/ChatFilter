"""Reclassify historical dead chats: status='error' + chat_type='dead' → status='done'.

In the old orthogonal-less model, dead/banned/private chats were recorded
with ``status='error'`` even though Telegram actually answered and told us
the chat was unusable.  Phase 0 splits these axes: ``status`` only tracks
the analysis *process* (PENDING/DONE/ERROR), and ``chat_type`` records the
verdict (DEAD/BANNED/...).

This migration promotes rows that were clearly "Telegram answered, the
chat is dead" to ``status='done'`` so they appear correctly in the UI
and so billing at Phase 5 treats them as billable.  We can only fix rows
where ``chat_type='dead'`` — historical rows with ``status='error'`` and
other chat_type values can't be disambiguated (might have been real
errors or historically-banned-before-we-had-that-enum).  Those stay ERROR.

Revision ID: 013
Create Date: 2026-04-22
"""

from __future__ import annotations

from alembic import op

revision: str = "013"
down_revision: str | None = "012"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        "UPDATE group_chats SET status = 'done' WHERE status = 'error' AND chat_type = 'dead'"
    )


def downgrade() -> None:
    # Restore the previous behaviour (dead chats marked as error).
    op.execute(
        "UPDATE group_chats SET status = 'error' WHERE status = 'done' AND chat_type = 'dead'"
    )

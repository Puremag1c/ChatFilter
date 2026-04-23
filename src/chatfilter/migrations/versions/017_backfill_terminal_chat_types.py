"""Extend the Phase-0 backfill to banned/restricted/private chat_types.

Migration 013 promoted ``status='error' AND chat_type='dead'`` to
``status='done'`` but stopped there because at the time we couldn't
disambiguate other error rows. Audit of v0.40 revealed that
``chat_type IN ('banned','restricted','private')`` is just as
unambiguously "Telegram answered, chat is terminal" as 'dead', and
leaving those rows at ``status='error'`` hides legitimate verdicts
behind a fake-error state (they don't render in the UI and billing
skips them even though the service was rendered).

This migration finishes the job. Kept separate from 013 because 013
is already shipped to users — changing an applied migration is a
footgun; a new revision is the safe path.

Revision ID: 017
Create Date: 2026-04-23
"""

from __future__ import annotations

from alembic import op

revision: str = "017"
down_revision: str | None = "016"
branch_labels: tuple[str, ...] | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        "UPDATE group_chats SET status = 'done' "
        "WHERE status = 'error' "
        "  AND chat_type IN ('banned', 'restricted', 'private')"
    )


def downgrade() -> None:
    # Only revert rows we touched — skip those that have a real error
    # recorded so we don't smuggle them back into 'error' as artefacts.
    op.execute(
        "UPDATE group_chats SET status = 'error' "
        "WHERE status = 'done' "
        "  AND chat_type IN ('banned', 'restricted', 'private') "
        "  AND (error IS NULL OR error = '')"
    )

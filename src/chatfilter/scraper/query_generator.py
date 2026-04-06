"""AI-powered search query generator for Telegram channel discovery."""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from chatfilter.ai.service import AIService

logger = logging.getLogger(__name__)

_PROMPT_TEMPLATE = (
    "Generate 4-6 search queries for finding Telegram channels AND chats/groups matching this description: "
    "{user_text}. "
    "Include a mix of channel-focused queries (using terms like 'канал', 'channel') and "
    "chat/group-focused queries (using terms like 'группа', 'чат', 'group', 'chat'). "
    "If the user explicitly requests only channels or only chats/groups, generate queries for that type only. "
    "Include Russian and English variations. "
    "Return as JSON array of strings only, no explanation."
)


class QueryGenerator:
    """Generates search queries from natural language using AI."""

    def __init__(self, ai_service: AIService) -> None:
        self._ai = ai_service

    async def generate(
        self, user_text: str, user_id: str | None = None
    ) -> tuple[list[str], float, bool, str | None, int, int]:
        """Generate search queries from a natural language description.

        Args:
            user_text: Natural language description of desired channels.
            user_id: Optional user identifier for billing tracking.

        Returns:
            Tuple of (query strings, ai_cost_usd, fallback_used, model, tokens_in, tokens_out).
            Falls back to ([user_text], 0.0, True, None, 0, 0) if AI fails.
        """
        prompt = _PROMPT_TEMPLATE.format(user_text=user_text)
        try:
            response = await self._ai.complete(prompt, user_id=user_id)
            queries = _parse_json_array(response.content)
            if queries:
                return (
                    queries,
                    response.cost_usd,
                    False,
                    response.model,
                    response.tokens_in,
                    response.tokens_out,
                )
            logger.warning("AI returned empty query list for input: %r", user_text)
            return (
                [user_text],
                response.cost_usd,
                True,
                response.model,
                response.tokens_in,
                response.tokens_out,
            )
        except Exception:
            logger.exception("AI query generation failed for input: %r", user_text)

        return [user_text], 0.0, True, None, 0, 0


def _parse_json_array(text: str) -> list[str]:
    """Extract a JSON array of strings from AI response text.

    Handles cases where the AI wraps JSON in markdown code blocks.
    Returns empty list if parsing fails or result is not a list of strings.
    """
    # Strip markdown code fences if present
    cleaned = re.sub(r"```(?:json)?\s*", "", text).strip()

    # Try to find a JSON array anywhere in the text
    match = re.search(r"\[.*\]", cleaned, re.DOTALL)
    if match:
        cleaned = match.group(0)

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError:
        return []

    if not isinstance(parsed, list):
        return []

    return [str(item) for item in parsed if item]

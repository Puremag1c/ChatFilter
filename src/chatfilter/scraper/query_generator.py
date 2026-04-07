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
    "You are a search strategist. The user wants to find Telegram channels and "
    "chats/groups matching this description:\n"
    '"{user_text}"\n\n'
    "Your job is to THINK about what this audience actually does, where they hang out, "
    "what topics they discuss — then generate 6-10 diverse search queries that cover "
    "different angles and subtopics.\n\n"
    "LANGUAGE: Choose query languages based on what the TARGET AUDIENCE actually speaks. "
    "For example:\n"
    '- "канадская молодежь" → queries in English/French (Canadians speak EN/FR)\n'
    '- "русские эмигранты в Канаде" → queries in Russian (audience is Russian-speaking)\n'
    '- "турецкие чаты" → queries in Turkish\n'
    "Do NOT blindly duplicate every query in Russian and English.\n\n"
    "EXAMPLE: for 'молодые канадцы' you should think:\n"
    '- Direct: "Canadian youth group", "jeunesse canadienne"\n'
    '- Music/culture: "Canadian indie music", "concerts Toronto Montreal"\n'
    '- Student life: "university Canada students", "McGill UofT chat"\n'
    '- Gaming/hobbies: "gaming Canada", "esports Canadian"\n'
    '- Local communities: "Vancouver youth", "Toronto young professionals"\n'
    "- Subcultures: what subcultures exist in this demographic?\n\n"
    "RULES:\n"
    "- Generate 6-10 queries covering DIFFERENT angles, not just rephrasing.\n"
    "- Each query MUST stay relevant to the target audience.\n"
    "- Do NOT add 'site:t.me' or 'telegram' — search is already Telegram-specific.\n"
    "- Keep queries short (2-5 words).\n\n"
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

"""AI-powered search query generator for Telegram channel discovery."""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from chatfilter.ai.service import AIService

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are an expert search strategist for Telegram channel/chat discovery.

<task>
Generate 15-30 short search queries to find Telegram channels and groups \
matching the user's description. The queries will be sent to Telegram catalog \
search engines (NOT Google), so do NOT add "site:t.me" or "telegram".
</task>

<language_rules>
Choose query language based on the TARGET AUDIENCE's language:
- "канадская молодежь" → English/French (Canadians speak EN/FR)
- "русские эмигранты в Канаде" → Russian (audience is Russian-speaking)
- "турецкие чаты" → Turkish
Do NOT blindly duplicate queries in multiple languages.
</language_rules>

<query_length_distribution>
- ~15% single-word queries (broad category keywords)
- ~50% two-word queries (the main bulk — specific combinations)
- ~35% three-word queries (precise niche phrases)
</query_length_distribution>

<strategy>
Think about what the target audience ACTUALLY does:
- Direct topic keywords
- Geographic locations (cities, regions)
- Activities (music, sports, gaming, student life)
- Subcultures and communities
- Related professions and interests
- Local slang and community names
</strategy>

<output_format>
Return a JSON array of strings. No explanation, no markdown.
Example: ["query one", "query two", "three"]
</output_format>"""

_USER_PROMPT_TEMPLATE = """\
Find Telegram channels and chats for: {user_text}

Generate 15-30 diverse search queries following the rules above."""


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
        prompt = _USER_PROMPT_TEMPLATE.format(user_text=user_text)
        model = self._ai.get_stage_model("query")
        try:
            response = await self._ai.complete(
                prompt,
                user_id=user_id,
                system_prompt=_SYSTEM_PROMPT,
                model_override=model,
            )
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
    """Extract a JSON array of strings from AI response text."""
    cleaned = re.sub(r"```(?:json)?\s*", "", text).strip()

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

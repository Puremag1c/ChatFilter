"""Tests for AI cost estimation fallback logic."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from chatfilter.ai.service import AIService


@pytest.fixture
def ai_service() -> AIService:
    """Provide an AIService with a mocked database."""
    mock_db = MagicMock()
    return AIService(db=mock_db)


class TestEstimateCost:
    """Tests for AIService._estimate_cost fallback behaviour."""

    def test_returns_litellm_cost_when_available(self, ai_service: AIService) -> None:
        """When LiteLLM returns a valid positive cost, use it directly."""
        response = MagicMock()
        with patch("chatfilter.ai.service.litellm.completion_cost", return_value=0.0042):
            cost = ai_service._estimate_cost(
                response, tokens_in=100, tokens_out=50, model="test-model"
            )
        assert cost == 0.0042

    def test_falls_back_when_litellm_returns_none(self, ai_service: AIService) -> None:
        """When LiteLLM returns None, estimate from tokens."""
        response = MagicMock()
        with patch("chatfilter.ai.service.litellm.completion_cost", return_value=None):
            cost = ai_service._estimate_cost(
                response, tokens_in=1000, tokens_out=500, model="test-model"
            )
        expected = 1000 * 5e-6 + 500 * 15e-6
        assert cost == pytest.approx(expected)

    def test_falls_back_when_litellm_returns_zero(self, ai_service: AIService) -> None:
        """When LiteLLM returns 0.0, estimate from tokens."""
        response = MagicMock()
        with patch("chatfilter.ai.service.litellm.completion_cost", return_value=0.0):
            cost = ai_service._estimate_cost(
                response, tokens_in=200, tokens_out=100, model="test-model"
            )
        expected = 200 * 5e-6 + 100 * 15e-6
        assert cost == pytest.approx(expected)

    def test_falls_back_when_litellm_raises(self, ai_service: AIService) -> None:
        """When LiteLLM raises an exception, estimate from tokens."""
        response = MagicMock()
        with patch(
            "chatfilter.ai.service.litellm.completion_cost", side_effect=Exception("unknown model")
        ):
            cost = ai_service._estimate_cost(
                response, tokens_in=500, tokens_out=200, model="test-model"
            )
        expected = 500 * 5e-6 + 200 * 15e-6
        assert cost == pytest.approx(expected)

    def test_minimum_floor_when_no_tokens_and_no_cost(self, ai_service: AIService) -> None:
        """When both cost and tokens are missing, charge minimum floor."""
        response = MagicMock()
        with patch("chatfilter.ai.service.litellm.completion_cost", return_value=None):
            cost = ai_service._estimate_cost(
                response, tokens_in=0, tokens_out=0, model="test-model"
            )
        assert cost == AIService._FALLBACK_MINIMUM_COST

    def test_logs_warning_on_fallback(
        self, ai_service: AIService, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Fallback estimation emits a warning log."""
        response = MagicMock()
        with patch("chatfilter.ai.service.litellm.completion_cost", return_value=None):
            ai_service._estimate_cost(response, tokens_in=100, tokens_out=50, model="test-model")
        assert any("Cost unavailable" in r.message for r in caplog.records)

    def test_logs_warning_on_minimum_floor(
        self, ai_service: AIService, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Minimum floor charging emits a warning log."""
        response = MagicMock()
        with patch("chatfilter.ai.service.litellm.completion_cost", side_effect=ValueError("oops")):
            ai_service._estimate_cost(response, tokens_in=0, tokens_out=0, model="test-model")
        assert any("minimum" in r.message for r in caplog.records)

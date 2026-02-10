"""Tests for i18n locale middleware.

Tests cover:
- LocaleMiddleware: language detection and setting
- _detect_locale: detection from cookie, query param, header
- _parse_accept_language: Accept-Language header parsing
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from chatfilter.i18n.middleware import LocaleMiddleware
from chatfilter.i18n.translations import DEFAULT_LANGUAGE


class TestLocaleMiddleware:
    """Tests for LocaleMiddleware class."""

    @pytest.fixture
    def middleware(self) -> LocaleMiddleware:
        """Create middleware instance."""
        app = MagicMock()
        return LocaleMiddleware(app)

    @pytest.mark.asyncio
    async def test_sets_locale_from_cookie(self, middleware: LocaleMiddleware) -> None:
        """Should detect locale from cookie."""
        request = MagicMock(spec=Request)
        request.cookies = {"lang": "ru"}
        request.query_params = {}
        request.headers = {}

        response = MagicMock(spec=Response)
        response.set_cookie = MagicMock()
        call_next = AsyncMock(return_value=response)

        with patch("chatfilter.i18n.middleware.set_current_locale") as mock_set:
            await middleware.dispatch(request, call_next)

            mock_set.assert_called_with("ru")

    @pytest.mark.asyncio
    async def test_sets_locale_from_query_param(self, middleware: LocaleMiddleware) -> None:
        """Should detect locale from query param."""
        request = MagicMock(spec=Request)
        request.cookies = {}
        request.query_params = {"lang": "ru"}
        request.headers = {}

        response = MagicMock(spec=Response)
        response.set_cookie = MagicMock()
        call_next = AsyncMock(return_value=response)

        with patch("chatfilter.i18n.middleware.set_current_locale") as mock_set:
            await middleware.dispatch(request, call_next)

            mock_set.assert_called_with("ru")

    @pytest.mark.asyncio
    async def test_sets_cookie_on_response(self, middleware: LocaleMiddleware) -> None:
        """Should set lang cookie on response."""
        request = MagicMock(spec=Request)
        request.cookies = {"lang": "en"}
        request.query_params = {}
        request.headers = {}

        response = MagicMock(spec=Response)
        response.set_cookie = MagicMock()
        call_next = AsyncMock(return_value=response)

        await middleware.dispatch(request, call_next)

        response.set_cookie.assert_called_once()
        call_kwargs = response.set_cookie.call_args[1]
        assert call_kwargs["key"] == "lang"
        assert call_kwargs["httponly"] is False  # Allow JS access


class TestDetectLocale:
    """Tests for _detect_locale method."""

    @pytest.fixture
    def middleware(self) -> LocaleMiddleware:
        """Create middleware instance."""
        app = MagicMock()
        return LocaleMiddleware(app)

    def test_from_cookie(self, middleware: LocaleMiddleware) -> None:
        """Should detect from cookie first."""
        request = MagicMock()
        request.cookies = {"lang": "ru"}
        request.query_params = {"lang": "en"}
        request.headers = {"Accept-Language": "en"}

        result = middleware._detect_locale(request)

        assert result == "ru"

    def test_from_query_param(self, middleware: LocaleMiddleware) -> None:
        """Should detect from query param second."""
        request = MagicMock()
        request.cookies = {}
        request.query_params = {"lang": "ru"}
        request.headers = {"Accept-Language": "en"}

        result = middleware._detect_locale(request)

        assert result == "ru"

    def test_from_accept_language(self, middleware: LocaleMiddleware) -> None:
        """Should detect from Accept-Language header."""
        request = MagicMock()
        request.cookies = {}
        request.query_params = {}
        request.headers = {"Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8"}

        result = middleware._detect_locale(request)

        assert result == "ru"

    def test_fallback_to_default(self, middleware: LocaleMiddleware) -> None:
        """Should fall back to default."""
        request = MagicMock()
        request.cookies = {}
        request.query_params = {}
        request.headers = {}

        result = middleware._detect_locale(request)

        assert result == DEFAULT_LANGUAGE

    def test_ignores_unsupported_locale(self, middleware: LocaleMiddleware) -> None:
        """Should ignore unsupported locales."""
        request = MagicMock()
        request.cookies = {"lang": "fr"}  # Not supported
        request.query_params = {}
        request.headers = {}

        result = middleware._detect_locale(request)

        assert result == DEFAULT_LANGUAGE


class TestParseAcceptLanguage:
    """Tests for _parse_accept_language method."""

    @pytest.fixture
    def middleware(self) -> LocaleMiddleware:
        """Create middleware instance."""
        app = MagicMock()
        return LocaleMiddleware(app)

    def test_simple_header(self, middleware: LocaleMiddleware) -> None:
        """Should parse simple Accept-Language."""
        result = middleware._parse_accept_language("ru")

        assert result == "ru"

    def test_with_quality(self, middleware: LocaleMiddleware) -> None:
        """Should parse with quality values."""
        result = middleware._parse_accept_language("en;q=0.9,ru;q=1.0")

        # ru has higher quality
        assert result == "ru"

    def test_with_region(self, middleware: LocaleMiddleware) -> None:
        """Should extract language from region code."""
        result = middleware._parse_accept_language("ru-RU")

        assert result == "ru"

    def test_multiple_languages(self, middleware: LocaleMiddleware) -> None:
        """Should return first supported language."""
        result = middleware._parse_accept_language("fr,de,ru")

        # fr and de not supported, ru is
        assert result == "ru"

    def test_no_supported(self, middleware: LocaleMiddleware) -> None:
        """Should return None if no supported language."""
        result = middleware._parse_accept_language("fr,de,it")

        assert result is None

    def test_empty_header(self, middleware: LocaleMiddleware) -> None:
        """Should return None for empty header."""
        result = middleware._parse_accept_language("")

        assert result is None

    def test_malformed_quality(self, middleware: LocaleMiddleware) -> None:
        """Should handle malformed quality values."""
        result = middleware._parse_accept_language("ru;q=invalid")

        assert result == "ru"  # Should still parse language

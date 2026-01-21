"""Language detection middleware for FastAPI."""

from __future__ import annotations

from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from chatfilter.i18n.translations import (
    DEFAULT_LANGUAGE,
    SUPPORTED_LANGUAGES,
    set_current_locale,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable


class LocaleMiddleware(BaseHTTPMiddleware):
    """Middleware to detect and set the user's preferred language."""

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        """Detect language from cookie, query param, or Accept-Language header.

        Priority order:
        1. 'lang' cookie
        2. 'lang' query parameter
        3. Accept-Language header
        4. Default language (English)

        Args:
            request: The incoming request
            call_next: Next middleware/handler in chain

        Returns:
            Response from next handler
        """
        locale = self._detect_locale(request)
        set_current_locale(locale)

        response = await call_next(request)

        # If locale was set via query param, set it in cookie for future requests
        if "lang" in request.query_params:
            response.set_cookie(
                key="lang",
                value=locale,
                max_age=31536000,  # 1 year
                httponly=True,
                samesite="lax",
            )

        return response

    def _detect_locale(self, request: Request) -> str:
        """Detect the preferred locale from the request.

        Args:
            request: The incoming request

        Returns:
            Detected locale code
        """
        # 1. Check cookie
        locale = request.cookies.get("lang")
        if locale and locale in SUPPORTED_LANGUAGES:
            return locale

        # 2. Check query parameter
        locale = request.query_params.get("lang")
        if locale and locale in SUPPORTED_LANGUAGES:
            return locale

        # 3. Parse Accept-Language header
        accept_language = request.headers.get("Accept-Language", "")
        if accept_language:
            locale = self._parse_accept_language(accept_language)
            if locale:
                return locale

        # 4. Fallback to default
        return DEFAULT_LANGUAGE

    def _parse_accept_language(self, accept_language: str) -> str | None:
        """Parse Accept-Language header and return best matching locale.

        Args:
            accept_language: Accept-Language header value

        Returns:
            Best matching supported locale, or None if no match
        """
        # Parse header like: "en-US,en;q=0.9,ru;q=0.8"
        languages = []
        for lang_entry in accept_language.split(","):
            parts = lang_entry.strip().split(";")
            lang = parts[0].strip().lower()

            # Extract quality value (default 1.0)
            quality = 1.0
            if len(parts) > 1 and parts[1].strip().startswith("q="):
                try:
                    quality = float(parts[1].strip()[2:])
                except ValueError:
                    quality = 1.0

            # Extract primary language code (e.g., "en" from "en-US")
            lang_code = lang.split("-")[0]
            languages.append((lang_code, quality))

        # Sort by quality (highest first)
        languages.sort(key=lambda x: x[1], reverse=True)

        # Find first supported language
        for lang_code, _ in languages:
            if lang_code in SUPPORTED_LANGUAGES:
                return lang_code

        return None

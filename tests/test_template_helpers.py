"""Tests for template helper functions.

Tests cover:
- get_template_context: context with CSRF, i18n, request
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from starlette.requests import Request


class TestGetTemplateContext:
    """Tests for get_template_context function."""

    def test_returns_context_dict(self) -> None:
        """Should return context dictionary."""
        from chatfilter.web.template_helpers import get_template_context

        request = MagicMock(spec=Request)
        request.cookies = {}
        request.state = MagicMock(spec=[])

        with patch("chatfilter.web.session.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_get_session.return_value = mock_session

            with patch("chatfilter.web.csrf.get_csrf_token") as mock_csrf:
                mock_csrf.return_value = "test-csrf-token"

                with patch("chatfilter.i18n.translations.get_current_locale") as mock_locale:
                    mock_locale.return_value = "en"

                    with patch("chatfilter.i18n.translations.get_translations") as mock_trans:
                        mock_translations = MagicMock()
                        mock_translations.gettext = MagicMock(side_effect=lambda x: x)
                        mock_translations.ngettext = MagicMock(
                            side_effect=lambda s, p, n: s if n == 1 else p
                        )
                        mock_trans.return_value = mock_translations

                        with patch("chatfilter.web.app.get_templates") as mock_templates:
                            mock_env = MagicMock()
                            mock_templates.return_value = MagicMock(env=mock_env)

                            result = get_template_context(request)

                            assert "request" in result
                            assert "csrf_token" in result
                            assert "locale" in result
                            assert "_" in result
                            assert "gettext" in result
                            assert "ngettext" in result

    def test_includes_extra_kwargs(self) -> None:
        """Should include additional kwargs in context."""
        from chatfilter.web.template_helpers import get_template_context

        request = MagicMock(spec=Request)
        request.cookies = {}
        request.state = MagicMock(spec=[])

        with patch("chatfilter.web.session.get_session") as mock_get_session:
            mock_session = MagicMock()
            mock_get_session.return_value = mock_session

            with patch("chatfilter.web.csrf.get_csrf_token") as mock_csrf:
                mock_csrf.return_value = "token"

                with patch("chatfilter.i18n.translations.get_current_locale") as mock_locale:
                    mock_locale.return_value = "en"

                    with patch("chatfilter.i18n.translations.get_translations") as mock_trans:
                        mock_translations = MagicMock()
                        mock_trans.return_value = mock_translations

                        with patch("chatfilter.web.app.get_templates") as mock_templates:
                            mock_env = MagicMock()
                            mock_templates.return_value = MagicMock(env=mock_env)

                            result = get_template_context(
                                request,
                                custom_var="custom_value",
                                another_var=123,
                            )

                            assert result["custom_var"] == "custom_value"
                            assert result["another_var"] == 123

    def test_csrf_token_present_in_context(self) -> None:
        """CSRF token should be present in context with proper format."""
        from chatfilter.web.template_helpers import get_template_context

        request = MagicMock(spec=Request)
        request.cookies = {}
        request.state = MagicMock(spec=[])

        with patch("chatfilter.web.session.get_session") as mock_get_session:
            from chatfilter.web.session import SessionData

            # Use a real session
            mock_session = SessionData(session_id="test-session-123")
            mock_get_session.return_value = mock_session

            with patch("chatfilter.i18n.translations.get_current_locale") as mock_locale:
                mock_locale.return_value = "ru"

                with patch("chatfilter.i18n.translations.get_translations") as mock_trans:
                    mock_translations = MagicMock()
                    mock_trans.return_value = mock_translations

                    with patch("chatfilter.web.app.get_templates") as mock_templates:
                        mock_env = MagicMock()
                        mock_templates.return_value = MagicMock(env=mock_env)

                        result = get_template_context(request)

                        # CSRF token should be a URL-safe string
                        assert isinstance(result["csrf_token"], str)
                        assert len(result["csrf_token"]) >= 40
                        # Locale should be present
                        assert result["locale"] == "ru"

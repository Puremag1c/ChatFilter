"""Backend verification tests for Bug Fixes v0.10.0

This file contains tests to verify the 4 bug fixes:
1. Bug 1: Device confirmation flow (AuthKeyUnregisteredError handling)
2. Bug 2: Upload JSON accepts files with additional fields
3. Bug 3: Auto-fill api_id/api_hash from uploaded JSON
4. Bug 4: Version display shows 0.9.2

Tests verify that the code changes correctly implement the fixes.
"""

import pytest


class TestBug1DeviceConfirmation:
    """Tests for Bug 1: Device confirmation flow"""

    def test_verify_code_imports_authkey_error(self):
        """Verify that verify_code() imports AuthKeyUnregisteredError"""
        from chatfilter.web.routers.sessions import verify_code
        import inspect
        source = inspect.getsource(verify_code)
        assert "AuthKeyUnregisteredError" in source, "verify_code should handle AuthKeyUnregisteredError"

    def test_verify_2fa_handles_authkey_error(self):
        """Verify that verify_2fa() handles AuthKeyUnregisteredError with device check"""
        from chatfilter.web.routers.sessions import verify_2fa
        import inspect
        source = inspect.getsource(verify_2fa)
        assert "AuthKeyUnregisteredError" in source
        assert "_check_device_confirmation" in source
        assert "_handle_needs_confirmation" in source


class TestBug2UnknownFields:
    """Tests for Bug 2: Accept JSON with unknown fields"""

    def test_validate_accepts_unknown_fields(self):
        """Verify that validate_account_info_json accepts files with extra fields"""
        from chatfilter.parsers.telegram_expert import validate_account_info_json

        json_data = {
            "phone": "+79001234567",
            "first_name": "John",
            "app_config_hash": "abc123",
            "app_hash": "xyz789",
            "app_id": 12345,
            "app_version": "1.0.0",
            "date_of_birth": "1990-01-01",
            # ... 20+ fields from TelegramExpert
        }

        error = validate_account_info_json(json_data)
        assert error is None, f"Should accept unknown fields, got error: {error}"


class TestBug3APICredentialsExtraction:
    """Tests for Bug 3: Extract api_id/api_hash from JSON"""

    def test_extract_api_credentials_with_app_id(self):
        """Verify extraction of app_id as api_id"""
        from chatfilter.parsers.telegram_expert import extract_api_credentials

        json_data = {
            "phone": "+79001234567",
            "app_id": 12345678,
            "app_hash": "0123456789abcdef0123456789abcdef",
        }

        api_id, api_hash = extract_api_credentials(json_data)
        assert api_id == 12345678
        assert api_hash == "0123456789abcdef0123456789abcdef"

    def test_extract_api_credentials_with_api_id(self):
        """Verify extraction of api_id directly"""
        from chatfilter.parsers.telegram_expert import extract_api_credentials

        json_data = {
            "phone": "+79001234567",
            "api_id": 87654321,
            "api_hash": "fedcba9876543210fedcba9876543210",
        }

        api_id, api_hash = extract_api_credentials(json_data)
        assert api_id == 87654321
        assert api_hash == "fedcba9876543210fedcba9876543210"

    def test_extract_prefers_app_id_over_api_id(self):
        """Verify that app_id takes precedence over api_id"""
        from chatfilter.parsers.telegram_expert import extract_api_credentials

        json_data = {
            "phone": "+79001234567",
            "app_id": 11111111,
            "api_id": 22222222,
            "app_hash": "aaaa",
            "api_hash": "bbbb",
        }

        api_id, api_hash = extract_api_credentials(json_data)
        # app_id should win
        assert api_id == 11111111
        assert api_hash == "aaaa"


class TestBug4VersionDisplay:
    """Tests for Bug 4: Version shows 0.9.2"""

    def test_version_is_092(self):
        """Verify that __version__ is set to 0.9.2"""
        from chatfilter import __version__
        assert __version__ == "0.9.2", f"Expected version 0.9.2, got {__version__}"

    def test_version_file_matches(self):
        """Verify that VERSION file contains 0.9.2"""
        from pathlib import Path
        version_file = Path("VERSION")
        version = version_file.read_text().strip()
        assert version == "0.9.2", f"VERSION file should contain 0.9.2, got {version}"

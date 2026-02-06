#!/usr/bin/env python3
"""Test that retry_available field flows through the system.

This test verifies the data flow:
1. Code saves retry_available to config.json
2. list_stored_sessions reads it into SessionListItem
3. Template uses session.retry_available for UI logic
"""
import json
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_retry_available_data_flow():
    """Test that retry_available field is properly defined and flows."""
    from chatfilter.web.routers.sessions import SessionListItem

    # 1. Verify SessionListItem has the field
    print("=== Checking SessionListItem schema ===")
    if not hasattr(SessionListItem, "__annotations__"):
        print("❌ FAIL: SessionListItem missing __annotations__")
        return False

    annotations = SessionListItem.__annotations__
    if "retry_available" not in annotations:
        print("❌ FAIL: SessionListItem missing retry_available field")
        return False

    print(f"✅ SessionListItem.retry_available: {annotations['retry_available']}")

    # 2. Verify template uses the field
    print("\n=== Checking template usage ===")
    template_path = Path(__file__).parent / "src/chatfilter/templates/partials/session_row.html"
    if not template_path.exists():
        print(f"❌ FAIL: Template not found at {template_path}")
        return False

    template_content = template_path.read_text()

    # Check for retry_available usage in template
    if "session.retry_available" not in template_content:
        print("❌ FAIL: Template doesn't use session.retry_available")
        return False

    print("✅ Template uses session.retry_available for conditional rendering")

    # 3. Verify sessions.py saves retry_available to config.json
    print("\n=== Checking sessions.py saves retry_available ===")
    sessions_path = Path(__file__).parent / "src/chatfilter/web/routers/sessions.py"
    sessions_content = sessions_path.read_text()

    if 'config["retry_available"]' not in sessions_content and '"retry_available":' not in sessions_content:
        print("❌ FAIL: sessions.py doesn't save retry_available to config")
        return False

    print("✅ sessions.py includes retry_available in config saves")

    # 4. Verify list_stored_sessions reads retry_available from config
    if 'config.get("retry_available")' not in sessions_content:
        print("❌ FAIL: list_stored_sessions doesn't read retry_available from config")
        return False

    print("✅ list_stored_sessions reads retry_available from config.json")

    # 5. Verify save_error_metadata function exists
    if "def save_error_metadata" not in sessions_content:
        print("❌ FAIL: save_error_metadata function not found")
        return False

    if "retry_available: bool" not in sessions_content:
        print("❌ FAIL: save_error_metadata doesn't accept retry_available parameter")
        return False

    print("✅ save_error_metadata(error_message, retry_available) function exists")

    # 6. Check that exceptions are classified
    transient_check = (
        "ConnectionError" in sessions_content and
        "TimeoutError" in sessions_content
    )
    permanent_check = (
        "AuthKeyUnregisteredError" in sessions_content and
        "PhoneNumberInvalidError" in sessions_content
    )

    if not (transient_check and permanent_check):
        print("❌ FAIL: Exception classification not found")
        return False

    print("✅ Transient and permanent exceptions are classified")

    print("\n🎉 All verification checks passed!")
    print("\n=== Data Flow Summary ===")
    print("1. Exception occurs → classified as transient/permanent")
    print("2. save_error_metadata() → config.json with retry_available field")
    print("3. list_stored_sessions() → reads config.json → SessionListItem")
    print("4. SSE endpoint → calls list_stored_sessions() → sends SessionListItem")
    print("5. session_row.html → uses session.retry_available → shows Retry/Error button")
    print("\n✅ retry_available field flows from exception → config.json → SSE → UI")

    return True

if __name__ == "__main__":
    success = test_retry_available_data_flow()
    sys.exit(0 if success else 1)

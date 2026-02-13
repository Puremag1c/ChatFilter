"""Manual backend logic verification for v0.8.2 bugfixes.

This script verifies the backend logic for:
1. Bug 1: get_session_config_status checks encrypted credentials
2. Bug 2: Error message flow from connect_session
3. Bug 3: Russian translations are present
"""

import json
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

def test_bug1_logic():
    """Verify Bug 1: get_session_config_status function logic."""
    from chatfilter.web.routers.sessions import get_session_config_status
    from unittest.mock import patch, MagicMock
    import tempfile
    
    print("Testing Bug 1: Encrypted credentials check...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        session_dir = Path(tmpdir) / "test_session"
        session_dir.mkdir(parents=True)
        
        # Create config with null credentials (like the bug scenario)
        config = {
            "api_id": None,
            "api_hash": None,
            "proxy_id": "test-proxy"
        }
        (session_dir / "config.json").write_text(json.dumps(config))
        
        # Mock SecureCredentialManager to simulate encrypted credentials
        with patch("chatfilter.web.routers.sessions.SecureCredentialManager") as mock_mgr_cls:
            mock_mgr = MagicMock()
            mock_mgr.has_credentials.return_value = True
            mock_mgr_cls.return_value = mock_mgr
            
            # Mock proxy check
            with patch("chatfilter.web.routers.sessions.get_proxy_by_id") as mock_proxy:
                mock_proxy.return_value = {"id": "test-proxy", "host": "127.0.0.1"}
                
                status = get_session_config_status(session_dir)
                
                # Should NOT be needs_api_id since encrypted credentials exist
                assert status == "disconnected", f"Expected 'disconnected' but got '{status}'"
                print("✓ Bug 1 fix verified: Status is 'disconnected' with encrypted credentials")
    
    print()

def test_bug2_template():
    """Verify Bug 2: Template renders error_message."""
    from jinja2 import Environment, FileSystemLoader
    
    print("Testing Bug 2: Error message display in template...")
    
    template_dir = Path("src/chatfilter/templates")
    env = Environment(loader=FileSystemLoader(str(template_dir)))
    env.globals["_"] = lambda x: x  # Mock translation
    
    template = env.get_template("partials/session_row.html")
    
    session_data = {
        "session_id": "test",
        "state": "error",
        "error_message": "Phone number required",
    }
    
    html = template.render(session=session_data)
    
    # Check error_message appears in HTML
    assert "Phone number required" in html, "Error message not found in template output"
    print("✓ Bug 2 fix verified: error_message rendered in template")
    print()

def test_bug3_translations():
    """Verify Bug 3: Russian translations exist."""
    print("Testing Bug 3: Russian translations...")
    
    po_file = Path("src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.po")
    assert po_file.exists(), "messages.po not found"
    
    po_content = po_file.read_text(encoding="utf-8")
    
    required = [
        ("Needs Auth", "Требуется авторизация"),
        ("Needs API ID", "Требуется API ID"),
        ("Session Expired", "Сессия истекла"),
    ]
    
    for msgid, expected_msgstr in required:
        assert f'msgid "{msgid}"' in po_content, f"Missing msgid for '{msgid}'"
        assert expected_msgstr in po_content, f"Missing translation for '{msgid}'"
        print(f"✓ Found translation: '{msgid}' → '{expected_msgstr}'")
    
    # Check .mo file exists
    mo_file = Path("src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.mo")
    assert mo_file.exists(), "messages.mo not compiled"
    print("✓ Bug 3 fix verified: All translations present and compiled")
    print()

if __name__ == "__main__":
    try:
        test_bug1_logic()
        test_bug2_template()
        test_bug3_translations()
        print("=" * 60)
        print("ALL BACKEND LOGIC TESTS PASSED ✓")
        print("=" * 60)
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

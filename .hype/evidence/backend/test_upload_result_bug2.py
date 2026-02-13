"""Test for Bug 2: upload_result.html JS error fix."""

import pytest
from pathlib import Path


def test_upload_result_handles_both_form_ids():
    """Test upload_result.html can handle both upload-form and session-config-form IDs."""
    template_path = Path("src/chatfilter/templates/partials/upload_result.html")
    
    content = template_path.read_text()
    
    # Check for safe form access with null-check (Bug 2 fix)
    assert "getElementById('upload-form') || document.getElementById('session-config-form')" in content
    assert "if (form)" in content
    
    # Should NOT have hardcoded 'upload-form' without fallback
    # Count occurrences of getElementById('upload-form')
    lines = content.split('\n')
    upload_form_lines = [l for l in lines if "getElementById('upload-form')" in l]
    
    # All occurrences should be paired with session-config-form fallback
    for line in upload_form_lines:
        assert "session-config-form" in line, f"Line missing fallback: {line}"


def test_upload_result_reset_has_null_check():
    """Test upload_result.html reset() call has null-check."""
    template_path = Path("src/chatfilter/templates/partials/upload_result.html")
    
    content = template_path.read_text()
    
    # Should have if (form) before calling .reset()
    # This prevents "Cannot read properties of null" error
    assert "if (form) form.reset()" in content or ("if (form)" in content and ".reset()" in content)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

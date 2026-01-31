#!/usr/bin/env python3
"""Add duplicate operation protection to verify_code and verify_2fa."""
from pathlib import Path

sessions_file = Path("src/chatfilter/web/routers/sessions.py")
content = sessions_file.read_text(encoding="utf-8")

# Fix verify_code and verify_2fa imports
content = content.replace(
    "from chatfilter.web.auth_state import AuthStep, get_auth_state_manager",
    "from chatfilter.web.auth_state import AuthStep, DuplicateOperationError, get_auth_state_manager"
)

# Add check in verify_code (after safe_name, before get_auth_state)
verify_code_check = '''
    # Prevent duplicate auth requests
    can_proceed = await auth_manager.mark_operation_in_progress(safe_name, "verify-code")
    if not can_proceed:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("An authentication request is already in progress for this session. Please wait."),
            },
            status_code=409,
        )
'''

verify_code_marker = '''    # Get auth state
    auth_state = await auth_manager.get_auth_state(auth_id)'''

if verify_code_check not in content:
    content = content.replace(
        verify_code_marker,
        verify_code_check + '\n' + verify_code_marker,
        1  # First occurrence only (verify_code)
    )
    print("✓ Added duplicate check to verify_code")

# Add check in verify_2fa
verify_2fa_check = '''
    # Prevent duplicate auth requests
    can_proceed = await auth_manager.mark_operation_in_progress(safe_name, "verify-2fa")
    if not can_proceed:
        return templates.TemplateResponse(
            request=request,
            name="partials/auth_result.html",
            context={
                "success": False,
                "error": _("An authentication request is already in progress for this session. Please wait."),
            },
            status_code=409,
        )
'''

# For verify_2fa, marker is same but it's second occurrence
# Let's find it by looking after "async def verify_2fa"
verify_2fa_start = content.find("async def verify_2fa")
if verify_2fa_start > 0:
    verify_2fa_section = content[verify_2fa_start:]
    marker_pos = verify_2fa_section.find(verify_code_marker)
    if marker_pos > 0 and verify_2fa_check not in verify_2fa_section:
        # Replace in the verify_2fa section
        verify_2fa_section_fixed = verify_2fa_section.replace(
            verify_code_marker,
            verify_2fa_check + '\n' + verify_code_marker,
            1
        )
        content = content[:verify_2fa_start] + verify_2fa_section_fixed
        print("✓ Added duplicate check to verify_2fa")

# Write back
sessions_file.write_text(content, encoding="utf-8")
print(f"\n✓ Applied changes to {sessions_file}")

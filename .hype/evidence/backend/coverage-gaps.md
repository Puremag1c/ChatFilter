# Backend Test Coverage Gaps for v0.10.0 Bugs

## Bug 1: Device Confirmation Flow (P0 - CRITICAL)

### Existing Tests
- ✅ `test_device_confirmation.py` - Unit tests for device confirmation detection
- ✅ `test_device_confirmation_timeout.py` - Integration tests for timeout/cleanup
- ❌ Tests are FAILING (4 failures) - **This confirms the bug exists**

### Failed Tests (Evidence of Bug):
1. `test_verify_2fa_auth_key_unregistered_needs_confirmation` - FAILED
   - Expected: "needs_confirmation" in HTML response
   - Actual: Shows error "Failed to verify password. Please try again."
   - **Root cause**: Code shows error instead of device confirmation state

2. `test_verify_code_auth_key_unregistered_needs_confirmation` - FAILED
   - Expected: "needs_confirmation" in HTML response
   - Actual: Shows error "Failed to verify code. Please check the code and try again."
   - **Root cause**: Same as above, wrong error handling

3. `test_check_device_confirmation_auth_key_unregistered` - FAILED
   - Expected: `_check_device_confirmation()` returns True
   - Actual: Returns False
   - **Root cause**: False positive detection issue mentioned in SPEC.md

4. `test_auto_2fa_auth_key_unregistered_needs_confirmation` - FAILED
   - Error: TypeError: object MagicMock can't be used in 'await' expression
   - **Root cause**: Tries to await on auth_manager.remove_auth_state (MagicMock not properly configured)

5. `test_polling_task_handles_auth_key_unregistered_error` - FAILED
   - Expected: publish('testsession', 'disconnected')
   - Actual: publish('testsession', 'error')
   - **Root cause**: Polling treats AuthKeyUnregisteredError as fatal error, not transient state

### Coverage Gaps
- ❌ No test for "successful device confirmation after polling" with real Telegram API behavior
- ❌ No test for "creating fresh client vs reusing dead client" scenario
- ❌ No test for "reconnect flow" after AuthKeyUnregisteredError
- ✅ Polling timeout behavior is tested
- ✅ Cleanup on RPC error is tested

### Test Requirements from SPEC.md NOT covered:
- Manual test required: "After confirmation on other device → session auto-transitions to 'Connected'"
- Edge case: "Show understandable error when cannot determine state"

---

## Bug 2: JS Error in upload_result.html (P1)

### Existing Tests
- ❌ NO tests found for `upload_result.html` JavaScript behavior
- ❌ NO tests for session import save flow end-to-end
- ❌ NO tests checking form reset after save

### Coverage Gaps
- ❌ No test for "save imported session → no JS error"
- ❌ No test for "form reset works for both upload-form and session-config-form"
- ❌ No test for "UI doesn't hang after error dismissal"
- ❌ No JavaScript/frontend tests at all (Python backend tests only)

### Note
Bug 2 requires **functional UI testing** (Playwright or similar), not just backend tests.
Backend tests cannot catch:
- JavaScript errors in browser console
- Form element access failures (getElementById returning null)
- UI hanging/freezing

---

## Summary

### Bug 1 Status: **CONFIRMED BY FAILING TESTS**
- Test failures prove the bug exists
- Current implementation does NOT properly handle device confirmation flow
- Tests expect "needs_confirmation" state, code returns errors instead

### Bug 2 Status: **NOT COVERED BY EXISTING TESTS**
- No frontend/JavaScript tests exist
- Backend tests cannot detect client-side JS errors
- Requires visual/functional tester or manual verification

### Recommendations for Architect

1. **Bug 1**: Fix code to pass existing tests (tests are correct, code is wrong)
   - Investigate `_check_device_confirmation()` false positive issue
   - Fix error handling in `verify_code()` and `verify_2fa()` to show device confirmation instead of errors
   - Fix `_poll_device_confirmation()` to not treat AuthKeyUnregisteredError as fatal

2. **Bug 2**: Add frontend tests OR manual test plan
   - Option A: Add Playwright test for session import flow
   - Option B: Document manual test steps for QA
   - Fix `upload_result.html` to use null-safe form access


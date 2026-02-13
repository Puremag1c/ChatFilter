# Test Maintenance Issue: Disconnect Endpoint Tests

## Issue
2 tests in test_sessions_router.py fail:
- test_disconnect_session_success
- test_disconnect_session_not_connected

## Root Cause
Disconnect endpoint behavior changed in commit e03a71f:
- **Old behavior:** Returned HTML with "Authorize" button
- **New behavior:** Returns empty response with HX-Reswap: none (SSE OOB swap handles DOM update)

Tests still expect old behavior.

## Impact
- **Functional impact:** NONE (disconnect works correctly in production)
- **Test impact:** 2 tests fail, but disconnect flow is tested elsewhere
- **Severity:** P2 (test maintenance only)

## Recommendation
**DO NOT create bug** - this is outside SPEC.md scope (device confirmation bug fix).

The disconnect endpoint is working correctly (as documented in comments). Tests just need updating to match current implementation.

If needed, create separate P2 task for test maintenance:
- Update test expectations to check for empty response + HX-Reswap header
- Or verify SSE OOB swap behavior instead

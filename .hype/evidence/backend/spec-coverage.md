# SPEC.md Test Coverage Analysis

## Bug 1: verify-code returns inline form instead of updating row (P0)

### Existing Tests ✅
- `tests/integration/test_auth_flow_fixes.py::TestVerifyCodeNeeds2FA::test_verify_code_returns_session_row_on_needs_2fa`
  - Verifies that verify-code with SessionPasswordNeededError returns `<tr>` (session row)
  - Checks for `needs_2fa` status class
  - Verifies 2FA button is present with correct data attributes

### Coverage Status: **COMPLETE**

## Bug 2: After 2FA - fake "connected", on refresh shows error (P0)

### Existing Tests ✅
- `tests/integration/test_auth_flow_fixes.py::TestVerify2FASuccess::test_verify_2fa_returns_session_row_on_success`
  - Verifies that verify-2fa success returns `<tr>` (session row)
  - Checks for `connected` status class
  - Verifies Disconnect button is present

### Additional Requirements from SPEC.md
1. ✅ Session should be really connected through session_manager (mocked in test)
2. ⚠️  **GAP**: Telegram "Is this you?" confirmation not tested
   - SPEC.md mentions: "Telegram может запросить подтверждение входа с другого устройства"
   - Current test doesn't simulate this case

### Coverage Status: **PARTIAL** - Missing device confirmation test

## Bug 3: Navigation doesn't translate on language switch (P1)

### Existing Tests ✅
- `tests/integration/test_auth_flow_fixes.py::TestLanguageSwitchTranslation::test_nav_menu_en_default`
- `tests/integration/test_auth_flow_fixes.py::TestLanguageSwitchTranslation::test_nav_menu_ru_via_cookie`

### Coverage Status: **COMPLETE**

## Full Flow Test ✅
- `tests/integration/test_auth_flow_fixes.py::TestFullAuthFlowNoRefresh::test_code_to_2fa_to_connected_flow`
  - Tests complete flow: code → needs_2fa → 2FA → connected
  - Verifies both responses are `<tr>` elements with same ID (HTMX swap compatible)

## Summary

| Requirement | Coverage | Gap |
|------------|----------|-----|
| Bug 1: Code → 2FA returns row | ✅ Complete | None |
| Bug 2: 2FA → Connected | ⚠️  Partial | Device confirmation |
| Bug 3: Language translation | ✅ Complete | None |
| Full flow test | ✅ Complete | None |

## Test Gap Identified

**Missing Test**: Telegram device confirmation flow
- **Scenario**: After code + 2FA, Telegram requires "Is this you?" confirmation from another device
- **Expected**: Show status "Подтвердите вход в другом клиенте Telegram"
- **Current**: Not tested (may show fake "connected")
- **Priority**: P1 (not blocker, but mentioned in SPEC.md)


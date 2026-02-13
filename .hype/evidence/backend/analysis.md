# Backend Test Analysis

## Test Execution Summary
- Total tests: 1916
- Passed: 1905
- Failed: 11
- Skipped: 14
- Duration: 199.28s

## Failed Tests Analysis

### Critical failures related to SPEC.md (connect flow):

1. **test_scenario_3_expired_session_auto_send_code** - SPEC Must Have #2
   - Expected: secure_delete_file called once when session expired
   - Actual: Called 0 times
   - Issue: Session expired handling does NOT auto-delete expired session.session
   - **BLOCKS SPEC requirement: "автоматически удалить session.session и запустить send_code flow"**

2. **test_scenario_4_normal_connect_success** - SPEC Must Have #4
   - Expected: connect() called once with session_id
   - Actual: Called 0 times
   - Logs: "Session has config issue: API credentials required"
   - Issue: Connect flow blocked by config check, even when setup is complete
   - **BLOCKS SPEC requirement: "Connect ВСЕГДА доводит до результата"**

3. **test_scenario_5_banned_account** - SPEC Must Have #4
   - Expected: publish('test_session', 'banned')
   - Actual: publish('test_session', 'needs_config')
   - Issue: Banned account not detected, config check happens first
   - **BLOCKS SPEC requirement: "Аккаунт забанен/заморожен/деактивирован → статус `banned`"**

4. **test_session_recovery (3 tests)** - SPEC Must Have #2
   - All 3 recovery tests fail: AuthKeyUnregistered, SessionRevoked, SessionExpired
   - Expected: secure_delete_file called
   - Actual: Called 0 times
   - **BLOCKS SPEC requirement: "автоматически удалить session.session и запустить send_code flow"**

5. **test_recovery_without_phone_publishes_error** - Edge case
   - Expected: secure_delete_file called when phone missing
   - Actual: Called 0 times
   - Related to recovery mechanism

### Non-critical failures (out of SPEC scope):

6. **test_error_state_specific_fallback** - Error message formatting
   - Expected generic fallback message
   - Actual: Specific network error message
   - Not blocking, just test expectation mismatch

7. **test_multiple_sensitive_patterns** - Error message sanitization
   - Similar to above, not blocking

8. **test_returns_memory_stats** - Missing psutil dependency
   - Optional monitoring feature, not in SPEC

9. **test_memory_values_consistent** - Missing psutil dependency
   - Optional monitoring feature, not in SPEC

## Root Cause Analysis

### Problem 1: Config check runs BEFORE session file check
**File:** `src/chatfilter/web/routers/sessions.py:2831`
**Log:** "Session 'test_session' has config issue: API credentials required"

Connect flow currently checks:
1. Config (api_id, api_hash, proxy) FIRST
2. Session file state LATER

This violates SPEC ordering:
1. Should check session file state FIRST (expired → auto-recovery)
2. Config check SECOND

### Problem 2: Auto-recovery NOT implemented
`secure_delete_file()` is never called in test scenarios, meaning:
- AuthKeyUnregistered → no auto-delete
- SessionRevoked → no auto-delete
- SessionExpired → no auto-delete

**SPEC requires:** "При получении AuthKeyUnregistered/SessionRevoked/SessionExpired во время connect — автоматически удалить session.session и запустить send_code flow"

## Coverage Gaps vs SPEC.md

### Must Have #1: Save ≠ Connect
- ✅ Tests exist: No failures related to Save
- Status: Likely already implemented

### Must Have #2: Убрать session_expired
- ❌ Tests FAIL: Auto-recovery not working
- Missing: Automatic session.session deletion
- Missing: Transparent recovery flow

### Must Have #3: Убрать corrupted_session
- ⚠️ No specific tests found
- Should add test for corrupted session detection

### Must Have #4: Упрощённый Connect flow
- ❌ Tests FAIL: Connect blocked by config check
- ❌ Tests FAIL: Banned account not detected
- Order of checks is wrong

### Must Have #5: Финальный набор состояний
- ⚠️ No tests validating 8-state model
- No tests checking removed states

## Recommended Actions

1. Fix connect flow order (P0)
   - Move session file check BEFORE config check
   - Auto-recover expired/revoked/corrupted sessions

2. Implement auto-recovery (P0)
   - Call secure_delete_file() when detecting invalid session
   - Transparently restart send_code flow

3. Fix banned account detection (P0)
   - Check account status BEFORE config check

4. Add missing tests (P1)
   - Corrupted session handling
   - 8-state model validation
   - Removed states verification


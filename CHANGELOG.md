# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.1] - 2026-02-22

### Fixed
- Fix integration/test_group_analysis.py: adapt 16 tests to new schema
- Fix pytest config: add pythonpath=[src] for src-layout
- Fix test_group_database.py: remove group_results references, use new columns
- Fix test_reanalysis.py: adapt to new schema (metrics as columns)
- SMOKE: [Backend] 25 tests fail due to database schema mismatch (group_results removed)
- SMOKE: [Backend] 3 test files cannot load due to missing imports (_ResolvedChat, CAPTCHA_BOTS)
- SMOKE: [Backend] Group status computation not implemented — 8 test failures
- SMOKE: [Backend] group_tasks table not tested
- SMOKE: [Backend] Migration v5 not tested — risk of data loss
- SMOKE: [Backend] New data model (metrics as columns) not validated
- SMOKE: [Must Have] Progress bar counts only DONE, ignores ERROR chats

## [0.11.0] - 2026-02-21

### Added
- Chat reassignment on ban — try other accounts before marking DEAD
- Live badges via SSE — progress events include status breakdown

### Fixed
- Fix stale test: test_time_window_limits_message_fetch expects old broken behavior
- SMOKE: [Tests] time_window validation incomplete - enum vs range
- SMOKE: [Backend] Missing partial_data parameter in moderation check
- SSE completion — engine sends None sentinel, JS stops timer
- Fix offset_date in iter_messages — activity will stop being 0

### Changed
- [UX] Add error states and retry UI for failed chats
- [Security] Validate time_window parameter to prevent resource exhaustion
- [Reliability] Add timeout to iter_messages for massive chats
- [UX] Show INCREMENT scope preview before analysis
- [Reliability] Handle late SSE subscriber after completion
- Add metrics_version to activity results for INCREMENT recount

## [0.10.9] - 2026-02-21

### Fixed
- Fix: test_startup_smoke uses system chatfilter instead of venv
- SMOKE: [Backend] INCREMENT mode counts DONE chats as analyzed instead of skipping
- SMOKE: [Backend] Progress counter not monotonic - decreases during multi-account analysis
- SMOKE: [Must Have] group_card.html scripts not executed - innerHTML bypass
- SMOKE: [Must Have] SSE events not dispatched - missing sse-swap attributes in group_card.html

## [0.10.8] - 2026-02-19

### Fixed
- Fix: Add 5-minute timeout to Phase 2 activity analysis
- Fix: pyproject.toml version out of sync (0.10.6 vs 0.10.7)
- SMOKE: [Backend] GroupStats model lost status breakdown (test failure)
- SMOKE: [Backend] Missing tests for 5-minute chat analysis timeout
- SMOKE: [Backend] Missing tests for SSE heartbeat & stale detection
- SMOKE: [Backend] Resume concurrent requests return 400 instead of 409
- SMOKE: [Backend] Resume nonexistent group HTTPException not caught

### Changed
- [Architecture] Clarify: SSE vs polling for live progress — choose one approach
- [Architecture] Use SSE instead of polling for live progress updates
- [OPS] Add smoke test for SSE progress endpoint
- [Reliability] Add idempotency check for concurrent resume requests
- [Reliability] Add server-side empty state validation in resume endpoint
- [Reliability] Add SSE fallback to polling on connection failure
- [Reliability] Add SSE heartbeat and client-side reconnection logic
- [Reliability] Graceful shutdown: cancel in-progress analysis tasks before startup recovery
- [Security] Add DB lock for startup recovery to prevent race condition
- [Security] Add group existence and status validation to resume endpoint
- [Security] Add structured logging for chat timeout events
- [UX] Add empty state check before resume analysis
- [UX] Auto-refresh card state when user returns to /chats page
- [UX] Design and implement 'stale analysis' warning UI element
- [UX] Show 'Starting analysis...' state immediately after start button click
- [UX] Show failed chat details with retry option

## [0.10.7] - 2026-02-19

### Added
- **Resume paused groups**: POST /api/groups/{group_id}/resume endpoint for resuming paused analyses
  - 'Продолжить анализ' button for paused groups
  - Atomic status transitions with conflict detection (409 for concurrent requests)
  - Validation: 404 for non-existent groups, 400 for non-paused or empty groups
  - Only pending and failed chats reanalyzed (done chats skipped)
- **SSE real-time progress**: Group cards now update via Server-Sent Events instead of polling
  - Current chat name and elapsed time visible during analysis
  - Progress bar updates in real-time
  - Card auto-updates to completed/paused/failed status without page reload
- **Startup crash recovery**: Server restart detection with automatic state recovery
  - Orphaned in_progress groups automatically reset to paused
  - Stale analyzing chats reset to pending
  - Recovery logged at startup

### Changed
- **Status localization**: Group status badges now show translated text (in_progress → Анализируется)
  - Russian translations: pending→Ожидание, in_progress→Анализируется, paused→Приостановлен, completed→Завершён, failed→Ошибка

### Fixed
- **Phase 1 timeout**: Added 5-minute per-chat timeout in Phase 1 analysis
  - Chats stuck in analyzing state now marked as failed with timeout error
  - Analysis continues for remaining chats instead of hanging entire group

## [0.10.6] - 2026-02-19

### Fixed
- SMOKE: [Server] Dev server failed to start
- SMOKE: [Must Have] Retest endpoint returns JSON instead of HTML
- SMOKE: [Must Have] Static CSS served stale — spinner fix not applied to browser
- SMOKE: [Backend] Proxy retest saves UNTESTED status prematurely
- SMOKE: [Visual] Retest endpoint returns English labels instead of user locale
- SMOKE: [Must Have] Status text does not change to Testing... during proxy retest

### Changed
- [Security] Sanitize error messages in retest endpoint
- [OPS] Add smoke test: verify app starts and responds
- [UX] Add empty state to proxy pool page when no proxies configured
- [OPS] Add unit tests for retest_proxy and update_proxy_health
- [UX] Ensure spinner clears and new status appears after successful retest

## [0.10.5] - 2026-02-19

### Fixed
- HTMX loading state: spinner on status icon + disabled button during test
- Retest endpoint now returns HTML <tr> instead of JSON for proper HTMX swap
- retest_proxy: don't save UNTESTED status before health check completes
- update_proxy_health: propagate storage write errors

### Changed
- [OPS] Add unit tests for retest_proxy and update_proxy_health
- [Architecture] Consolidate spinner CSS: replace spinner-sm with spinner-small

## [0.10.4] - 2026-02-19

### Fixed
- SMOKE: [Must Have] Pre-connect proxy diagnostic doesn't update session_manager state — session stuck in Connecting

### Changed
- [Reliability] Add explicit timeout for SOCKS5 handshake in health check
- [OPS] Integration test for real SOCKS5 proxy health check
- [Security] Add SOCKS5 auth failure handling without credential exposure
- [UX] Document error message UI delivery for pre-connect diagnostic
- [Security] Sanitize proxy credentials in logs and error messages
- [UX] Add loading states for SOCKS5 health check and pre-connect diagnostic
- [Reliability] Pre-connect proxy test must timeout faster than full connect
- Tests for SOCKS5 health check and pre-connect diagnostics
- Pre-connect proxy diagnostic in _do_connect_in_background_v2
- SOCKS5 health check: replace TCP-only with full SOCKS5 handshake + Telegram DC tunnel
- Plan reviewed
- Planning complete: v0.10.4 proxy diagnostics

## [0.10.3] - 2026-02-19

### Fixed
- Fix: __init__.py __version__ stuck at 0.9.12, should be 0.10.2
- Fix: test_orphan_safety_net_fills_missing_results timeout (>30s regression)
- SMOKE: [Backend] Phase 1 retry logic missing floodwait_retry_count initialization

### Changed
- [Security] Verify FloodWait exception sanitization in logs
- [Security] Add global analysis timeout to prevent DoS via FloodWait
- Fix INCREMENT early-exit: all-DONE must proceed to Phase 2
- Increase MAX_FLOODWAIT_SECONDS to 1800 and base join delay to 5s
- Phase 2: Handle RateLimitedJoinError with proper wait
- Add RateLimitedJoinError subclass to preserve FloodWait seconds

## [0.10.2] - 2026-02-18

### Fixed
- SMOKE: [Backend] AttributeError: 'State' object has no attribute 'session_manager'
- SMOKE: [Backend] Test failure: test_start_returns_hx_trigger_header
- SMOKE: [Export] CSV export crashes with ValueError on string messages_per_hour
- SMOKE: [Must Have] Card does not update to in_progress on Start analysis click
- SMOKE: [Must Have] Error toast swallowed by hx-swap=none on start/reanalyze buttons
- SMOKE: [Must Have] Reanalyze endpoint crashes: cannot access local variable json
- [Backend] Fix INCREMENT progress counter: count only chats-to-process, not all done+failed
- [Backend] Make start/reanalyze endpoints non-blocking (asyncio.create_task)
- [Frontend] Add toast on analysis start + trigger polling after button click

## [0.10.1] - 2026-02-17

### Fixed
- Fix account task exception: save dead results after asyncio.gather failure
- Fix outer exception handler: save dead results for remaining chats
- SMOKE: [Regression] test_overwrite_resets_chat_statuses broken by orphan safety net
- SMOKE: [Must Have 4] test_all_chats_get_results_pass_or_dead times out (>30s)
- Add orphan safety net: verify all chats have group_results after Phase 1

### Changed
- [Reliability] Atomic database updates in exception handlers
- [OPS] Add assertion: verify result count matches chat count before completion
- [OPS] Add regression test: 100+ chats must all get results
- [UX] Show account recovery notification in analysis progress
- [Reliability] Handle FloodWaitError in outer exception handler
- Add tests for account-level exception recovery
- Add test for outer exception handler in _phase1_resolve_account
- Plan reviewed
- Planning complete: v0.10.1 analysis completion fix

## [0.10.0] - 2026-02-17

### Added
- Add re-analysis mode parameter to start_analysis()

### Fixed
- SMOKE: [Backend] Missing tests: re-analysis feature (100% untested)
- SMOKE: [Backend] Missing tests: all chats get results guarantee
- SMOKE: [Backend] API signature mismatch in _save_phase1_result()
- SMOKE: [Backend] Database schema missing subscribers column
- SMOKE: [Backend] Missing test: FloodWait continuation
- SMOKE: [Backend] Missing tests: exclude_dead checkbox removal
- SMOKE: [Backend] Database migration fails to remove duplicates
- SMOKE: [Backend] CSV export includes error_reason when not selected
- Ensure save_result() called for every chat (dead included)
- Add retry mechanism to Phase 2 activity analysis
- Replace break with retry queue in Phase 1 FloodWait handler

### Changed
- Resolve rebase conflict: Add retry mechanism to Phase 2 activity analysis
- [Security] Add MAX_RETRY_COUNT constant to prevent DoS
- [Reliability] Re-check account health before retry attempts
- [Reliability] Add per-chat timeout to prevent retry queue stalls
- [Architecture] Add unique constraint on (group_id, chat_ref) for group_results
- [Reliability] Add UNIQUE constraint on group_results (group_id, chat_ref)
- [OPS] Add FloodWait monitoring and statistics
- [Security] Add UNIQUE index on group_results to prevent race condition
- [OPS] Add integration tests for retry mechanism and incremental analysis
- [Security] Prevent concurrent re-analysis on same group (409/429)
- [UX] Add confirmation modal for 'Перезапустить анализ' button
- [UX] Add detailed retry progress messages in SSE stream
- Add re-analysis API endpoints
- Implement skip logic for already-collected metrics in analysis loop
- Add upsert_result() to group_database for incremental analysis

## [0.9.12] - 2026-02-17

### Fixed
- FloodWait retry mechanism no longer silently skips chats after exhausting retries
- All chats now saved in group_results table, including dead/failed chats

### Removed
- Removed 'Exclude dead' checkbox from export modal (dead chats filterable via Chat Types)

### Added
- Incremental re-analysis mode (supplement existing metrics without clearing data)
- Full re-analysis mode (overwrite all metrics, clear existing data)
- Re-analysis buttons on group card UI ('Дополнить анализ' and 'Перезапустить анализ')

## [0.9.11] - 2026-02-16

### Fixed
- SMOKE: [Server] Dev server failed to start
- Bug #2: Publish SSE progress events during analysis
- Bug #3: Fix stop_analysis chat status reset and restart logic
- Bug #1B: Add Subscribers column to analysis_results.html UI table
- Bug #1A: Ensure subscribers saved in group_results and included in CSV fallback
- Bug #4: Detect CHANNEL_COMMENTS via linked_chat_id in _channel_to_chat_type
- Bug #5: Fix chat type checkboxes in export modal

### Changed
- [UX] Add empty state for analysis results (0 results after completion)
- Optimize SSE progress event DB queries in group_engine
- [Reliability] Log GetFullChannelRequest failures at WARNING level
- [Reliability] Add crash recovery: reset ANALYZING chats on start
- [Architecture] Make _ResolvedChat.linked_chat_id optional with default
- [Security] Sanitize error messages in HTTP responses and logs
- [OPS] Add runtime validation: detect silent failures in analysis loop
- [Security] Add rate limiting for GetFullChannelRequest API calls
- [OPS] Integration tests: verify 10 test scenarios from SPEC.md
- Plan reviewed
- Planning v0.9.11 complete

## [0.9.10] - 2026-02-16

### Fixed
- SMOKE: [Must Have] Preview count broken - 422 on empty subscriber fields
- SMOKE: [Must Have] Export crashes with 500 for Cyrillic group names
- SMOKE: [Backend] Export filter modal not implemented
- SMOKE: [Must Have] Subscriber filter min=0 excludes all chats with NULL subscribers
- SMOKE: [Must Have] Export filename loses Cyrillic group name
- SMOKE: [Must Have] Chat type filter has no effect on preview count
- Bug: dead chats marked as pending — fix ChatTypeEnum in error handler
- Bug: fix export filename — use group name instead of timestamp

### Changed
- [Architecture] Add Pydantic model for export filter params
- [Architecture] Extract shared export filter function
- [Security] Sanitize group name in export filename to prevent path traversal
- [OPS] Add rate limit handling for GetFullChannelRequest
- [Reliability] Sanitize filename in export to prevent path traversal
- [Reliability] Add FloodWait retry logic for GetFullChannelRequest
- [UX] Add loading state for export modal
- Backend: add export filter modal endpoint
- Backend: add export preview count endpoint
- Backend: add filter params to export endpoint

## [0.9.9] - 2026-02-14

### Fixed
- Fix SSE duplicate cards: HX-Trigger single-source-of-truth pattern
- SMOKE: [Backend] Export bug test fails with CSRF error (403)
- SMOKE: [Backend] Export returns 404 JSON instead of CSV when no results
- SMOKE: [Visual] SSE polling causes duplicate group cards on /chats page

### Changed
- Analyze: root cause of SSE duplicate cards regression (regressed 2x)
- [Reliability] Add FloodWait retry for Phase 1 get_entity calls
- [Security] Add CSRF protection to settings update endpoint
- Plan reviewed
- [OPS] E2E test: settings modal UI and analysis flow
- [Reliability] Handle GetFullChannel failure for invite links gracefully
- [UX] Add failed chats details view or tooltip
- [Reliability] Ensure re-run analysis clears old data atomically before start
- [UX] Show moderation-skipped chats count in group card
- [OPS] Validate CSV export: columns match selected metrics

## [0.9.8] - 2026-02-13

### Fixed
- SMOKE: [API] GET /api/groups returns error 'group' is undefined
- SMOKE: [Backend] Google Sheets importer async mock issue
- SMOKE: [Backend] Group API endpoints have 0% test coverage
- SMOKE: [Backend] GroupDatabase has 0% test coverage
- SMOKE: [Backend] GroupStatus missing FAILED state causes runtime error
- SMOKE: [Backend] Resume analysis does not clear failed chat errors
- SMOKE: [Must Have] /chats page not replaced with groups interface
- SMOKE: [Must Have] CSV export button missing from group cards
- SMOKE: [Must Have] Excessive SSE polling during in_progress (~7 req/sec)
- SMOKE: [Must Have] No analysis settings modal per group
- SMOKE: [Must Have] No create-group modal (upload file/URL/GSheets)
- SMOKE: [Must Have] Stop analysis causes JS error querySelector null
- Start analysis fails silently (no error shown to user)
- Wire GroupAnalysisEngine into router start/stop endpoints

### Changed
- API router: /api/groups SSE progress + CSV export
- DI + Groups router: CRUD endpoints
- GroupAnalysisEngine: Phase 1 — join/resolve chats
- GroupAnalysisEngine: Phase 2 — analysis via TaskQueue
- GroupAnalysisEngine: Phase 3 leave + stop/resume/subscribe
- MERGE READY: GroupEngine Phase 1 — delete stale untracked file then merge branch
- Security: Google Sheets response size limit
- UI: Build groups frontend (replace /chats page)

## [0.9.7] - 2026-02-12

### Fixed
- Fix: 9 connect_session tests fail - SessionBlockedError instead of Connecting
- Fix: 2 device_confirmation tests fail - MagicMock not AsyncMock for remove_auth_state
- [Reliability] Fix race condition in adopt_client validation
- Fix 2: Return HTTP 4xx/5xx for error responses in verify_2fa and verify_code
- Fix 1: Add auth_state cleanup in generic exception handlers
- Fix 3: Remove await from client.session.save() (root cause)
- SMOKE: [API] FileNotFoundError handlers missing status_code
- [Reliability] Add auth_state cleanup in verify_code generic exception handler
- Fix 4: Accurate error messages (not 'Failed to verify password')
- Sync __init__.py version 0.9.4 → 0.9.5

### Changed
- [Security] Prevent 2FA password leakage in exception traceback
- [Security] Add session file write lock (race condition)
- [UX] Fix button states and loading feedback in 2FA/SMS modals
- Nice-to-have: Add auth_state cleanup in OSError/TimeoutError handlers

## [0.9.6] - 2026-02-12

### Fixed
- **Infinite 2FA loop**: Fixed TypeError from awaiting synchronous session.save() method (commit e09e690)
  - Root cause: `await client.session.save()` but Telethon's session.save() returns None (not awaitable)
  - Symptom: Generic exception handler caught TypeError → returned HTTP 200 → UI showed success but auth failed → infinite loop
  - Solution: Changed to `client.session.save()` without await on line 3060 in sessions.py

## [0.9.5] - 2026-02-12

### Fixed
- Fix: Add AsyncMock for session_manager.adopt_client in test_verify_code_auto_2fa_success
- SMOKE: [Backend] Test mock incomplete - client.session.save() not AsyncMock
- Fix: Add AsyncMock for adopt_client in 2 test setups
- SMOKE: [Backend] 6 tests expect old error message format

### Changed
- Rewrite _finalize_reconnect_auth() to use adopt_client instead of disconnect+reconnect
- Add adopt_client() method to SessionManager
- [Reliability] Add client cleanup for RPCError/Exception in _poll_device_confirmation
- [Reliability] Add error handling for adopt_client failure in _finalize_reconnect_auth
- [UX] Device confirmation timeout should publish 'error' not 'disconnected'
- [Security] Add authorization validation in adopt_client()
- [OPS] Add E2E test for full auth flow (reauth → 2FA → device confirmation → connected)
- Write tests for adopt_client() and rewritten _finalize_reconnect_auth()
- Update _poll_device_confirmation to use adopt_client path
- Add unit tests for SessionManager.adopt_client()
- [UX] Add specific error message when adopt_client fails
- Planning complete for v0.10.0
- Nice-to-have: Improve error logging in _finalize_reconnect_auth

## [0.9.4] - 2026-02-11

### Fixed
- Update 5 device confirmation tests to match new AuthKeyUnregisteredError semantics
- [Bug1] Fix _poll_device_confirmation() to handle AuthKeyUnregisteredError as fatal
- [Bug1] Fix _check_device_confirmation() to not return True on AuthKeyUnregisteredError
- [Bug1] Remove false-positive device confirmation detection from AuthKeyUnregisteredError handlers
- [Bug2] Fix JS error 'Cannot read properties of null' in upload_result.html

### Changed
- [UX] Add device confirmation feedback in modal before close
- [OPS] Add automated test suite for device confirmation flow (prevent regression)
- [Reliability] Add auth_state cleanup when _poll_device_confirmation() fails fatally
- [OPS] Add automated tests for Bug2 (JS error in upload_result.html)
- [Bug1] Manual test: device confirmation flow
- [Bug1] Improve error message for AuthKeyUnregisteredError in verify_code/verify_2fa
- [Reliability] Protect _finalize_reconnect_auth() from timeout race condition

## [0.9.3] - 2026-02-11

### Fixed
- **Bug 3: API credentials extraction**: Extract api_id/api_hash from uploaded JSON and pass to validation template
- **Bug 2: JSON field validation**: Remove strict field allowlist in validate_account_info_json()
- **Bug 1b: AuthKeyUnregisteredError handling**: Fix AuthKeyUnregisteredError handling in verify_2fa()
- **Bug 1a: AuthKeyUnregisteredError handling**: Fix AuthKeyUnregisteredError handling in verify_code()
- **Bug 4: Version sync**: Update __version__ to 0.9.2 in __init__.py
- **SMOKE: API credentials auto-fill**: Fix api_id/api_hash from JSON not auto-filled in import form

### Changed
- **[Security] Credential cleanup**: Zero extracted api_id/api_hash after encryption
- **[OPS] Manual test protocol**: Create manual test protocol for v0.10.0 release
- **[Reliability] Device confirmation fallback**: Add fallback if _check_device_confirmation() fails

### Testing
- Added test verifying api_id/api_hash data attributes in validation response
- Verified all 4 bug fixes pass integration tests

## [0.9.2] - 2026-02-11

### Fixed
- **AuthKeyUnregisteredError handling**: Fixed _check_device_confirmation to catch AuthKeyUnregisteredError and return needs_confirmation instead of propagating error
- **Integration test mocks**: Fixed broken mocks causing device confirmation integration tests to fail (SMOKE)
- **Test assertions**: Fixed 2 stale disconnect_session tests asserting old response format

### Changed
- **[Security] Rate limiting**: Added rate limiting to device confirmation polling to prevent API abuse
- **[Security] Expired confirmation disconnect**: Add forced disconnect for expired device confirmation
- **[Security] AuthKeyUnregisteredError validation**: Validate AuthKeyUnregisteredError legitimacy in device confirmation
- **[Reliability] Polling cleanup**: Added cleanup for background polling task on auth state expiry
- **[Reliability] Duplicate polling prevention**: Prevent duplicate polling tasks for device confirmation
- **[Reliability] AuthKeyUnregisteredError verification**: Verify AuthKeyUnregisteredError handling in polling loop
- **[Reliability] Session file atomicity**: Add atomic session file write with backup in _finalize_reconnect_auth
- **[Reliability] Fallback handling**: Add fallback if _finalize_reconnect_auth fails during polling
- **[Reliability] Race condition handling**: Handle race between polling completion and timeout
- **[UX] Network error handling**: Handle network error during confirmation polling
- **[Architecture] Polling task deduplication**: Prevent duplicate polling tasks for same session
- **[Architecture] Auth state client access**: Ensure polling has access to auth_state client

### Testing
- Added integration test for device confirmation timeout scenario
- Added test for AuthKeyUnregisteredError → needs_confirmation flow
- Added background polling task for device confirmation → connected transition test
- **[OPS] Shutdown cleanup verification**: Verify background polling task cleanup on app shutdown

## [0.9.1] - 2026-02-11

### Fixed
- **AuthKeyUnregisteredError handling**: Fixed _check_device_confirmation to catch AuthKeyUnregisteredError and return needs_confirmation instead of propagating error
- **Integration test mocks**: Fixed broken mocks causing device confirmation integration tests to fail

### Changed
- **[Security] Rate limiting**: Added rate limiting to device confirmation polling to prevent API abuse
- **[Reliability] Polling cleanup**: Added cleanup for background polling task on auth state expiry
- **[Reliability] Duplicate polling prevention**: Prevent duplicate polling tasks for device confirmation
- **[Reliability] AuthKeyUnregisteredError verification**: Verify AuthKeyUnregisteredError handling in polling loop
- **[Reliability] Session file atomicity**: Add atomic session file write with backup in _finalize_reconnect_auth
- **[Reliability] Fallback handling**: Add fallback if _finalize_reconnect_auth fails during polling
- **[Reliability] Race condition handling**: Handle race between polling completion and timeout
- **[Reliability] Concurrent verify prevention**: Prevent concurrent verify operations during device confirmation polling
- **[Security] Expired confirmation disconnect**: Add forced disconnect for expired device confirmation
- **[Security] AuthKeyUnregisteredError validation**: Validate AuthKeyUnregisteredError legitimacy in device confirmation
- **[UX] Network error handling**: Handle network error during confirmation polling
- **[Architecture] Polling task deduplication**: Prevent duplicate polling tasks for same session
- **[Architecture] Auth state client access**: Ensure polling has access to auth_state client
- **[OPS] Shutdown cleanup verification**: Verify background polling task cleanup on app shutdown

### Testing
- Added integration test for device confirmation timeout scenario
- Added test for AuthKeyUnregisteredError → needs_confirmation flow
- Added background polling task for device confirmation → connected transition test

## [0.9.0] - 2026-02-10

### Fixed
- **Device confirmation detection**: Fixed Telegram "Is this you?" confirmation showing fake "connected" status. Now shows "Awaiting Confirmation" with clear message to confirm in other Telegram app, auto-updates when confirmed
- **AuthKeyUnregisteredError handling**: Fixed _check_device_confirmation to catch AuthKeyUnregisteredError and return needs_confirmation instead of propagating error to verify_2fa/verify_code callers
- **Background polling for confirmation**: Added background polling task that detects when user confirms on another device and auto-transitions session to connected state via SSE

## [0.8.5] - 2026-02-10

### Fixed
- **Bug1: JS code modal handler**: Close modal and update row after code verification
- **Bug1: verify-code endpoint**: Return session_row on needs_2fa instead of reconnect_success
- **Bug2: JS 2FA modal handler**: Verify close and update row after 2FA verification
- **Bug2: _finalize_reconnect_auth**: Connect via session_manager after successful 2FA
- **Bug2: verify-2fa endpoint**: Return session_row on success
- **Bug2: verify-code success**: Return session_row instead of reconnect_success
- **SMOKE: Disconnect triggers querySelector JS error**: Fixed JS error when disconnecting session
- **SMOKE: Missing auth_code_form_reconnect.html**: Fixed 500 error on code verify errors due to missing template
- **SMOKE: Navigation not translated**: Fixed .po entries marked obsolete causing navigation to show untranslated strings

### Changed
- **[OPS] Integration tests**: Added integration tests for auth flow fixes
- **[Reliability] Session manager connection**: Added proper session_manager connection after auth completion
- **[Reliability] Auth flow timeout**: Added timeout for auth flow operations to prevent hangs
- **[Reliability] Translation race condition**: Fixed race condition in translation loading
- **[Reliability] Telegram confirmation**: Handle Telegram "Is this you?" confirmation dialog
- **[Security] Rate limiting**: Added rate limiting for auth endpoints to prevent abuse
- **[Security] Session ID validation**: Added session_id validation to prevent path traversal attacks
- **[Security] HTTPS validation**: Validate HTTPS in production environment
- **[Security] Zero sensitive data**: Zero sensitive data in memory after use
- **[Troubleshoot] Persistent timeout**: Resolved persistent timeout for ChatFilter-gvnoc
- **[UX] Telegram confirmation flow**: Handle Telegram "Is this you?" confirmation flow with better UX

## [0.8.4] - 2026-02-10

### Fixed
- **disconnecting state usage**: Fixed disconnecting state still used in sessions.py, violates 8-state model
- **removed state cleanup**: Fixed missing tests for removed state cleanup verification
- **needs_config localization**: Fixed needs_config state shows raw text instead of localized label in HTMX response
- **Connect flow tests**: Fixed needs_config early return blocks testing
- **Connect without credentials**: Fixed Connect on account without API creds returns HTTP 400 instead of needs_config
- **Edit button routing**: Fixed Edit button returns 404 for saved account
- **Connect error handling**: Fixed Connect button error destroys session list
- **Session list display**: Fixed saved account not appearing in session list
- **Test state format**: Fixed tests expect string state, got tuple (state, error)
- **Mock completeness**: Fixed incomplete mocks in test_needs_2fa_to_connected_success, test_needs_code_to_needs_2fa, test_needs_code_to_connected_success

### Changed
- **Rebase conflict resolution**: Resolved multiple rebase conflicts from parallel bug fixes
- **Evidence tests**: Updated evidence tests for needs_config state migration

## [0.8.3] - 2026-02-09

### Fixed
- **SMOKE: Backend Russian translations**: Fixed missing Russian translations for session statuses
- **SMOKE: session_expired rendering**: Fixed session_expired status not being rendered in template (shows raw key in EN+RU)
- **SMOKE: session_expired translation**: Fixed session_expired status not translated to Russian
- **Connect error visibility**: Fixed Connect button failing silently - now shows error message when connection fails
- **Session status detection**: Fixed get_session_config_status() to check SecureCredentialManager for encrypted credentials
- **API credential validation**: Re-validates API credentials when changed

### Changed
- **Conflict resolution**: Resolved multiple rebase conflicts from parallel bug fixes
- **Shell environment**: Fixed broken shell environment in executor-0 worktree
- **Error handling**: Improved error handling for missing phone in account_info BEFORE send_code
- **Race condition prevention**: Prevents race condition on parallel Connect clicks
- **Timeout handling**: Added timeout for _send_verification_code_and_create_auth() and background connect task
- **Security improvements**: Sanitized error messages before publishing to SSE
- **Credential logging**: Prevented credential leakage in get_session_config_status() logs
- **File corruption handling**: Handles corrupted .credentials.enc gracefully

## [0.8.2] - 2026-02-09

### Fixed
- **Session status detection**: Fixed get_session_config_status() to check SecureCredentialManager for encrypted credentials
  - Sessions with valid encrypted credentials now show correct status instead of "Setup Required"
  - Maintains backward compatibility with plaintext config.json
- **Error message visibility**: Fixed Connect button failing silently without showing error messages
  - Error messages now displayed inline in session row when Connect fails
  - Clear "Phone number required" message when phone is missing
  - Proxy and network errors now visible to user
- **Russian translations**: Added missing Russian translations for session statuses
  - All session statuses now translated (Needs Auth, Needs API ID, Setup Required)
  - Added tooltip translations for authorization and error states

## [0.8.1] - 2026-02-08

### Fixed
- **Session not found in background task**: Fixed silent connection failures when session.session file was missing
- **Auto 2FA entry**: Fixed sign_in being called only once instead of twice for 2FA authentication
- **Verification code modal**: Fixed modal auto-opening and blocking page on load
- **Upload form validation**: Fixed 422 errors caused by missing api_id/api_hash fields in form submission
- **Connect ImportError**: Fixed crashes with "get_proxy_manager missing" import error
- **Upload directory creation**: Fixed upload save logic failing when directory not created
- **Build configuration**: Fixed build command failures in testing.yaml
- **Testing configuration**: Fixed testing.yaml configuration issues
- **Deployment sync**: Fixed server running outdated code due to FileNotFoundError fix not being deployed
- **FileNotFoundError handling**: Fixed connect failures when session.session file is missing
- **Setup Required UI**: Fixed disabled "Wait..." button appearing instead of actionable Setup/Edit button
- **Session list template**: Fixed missing has_session_file check for disconnected status in sessions_list.html
- **has_session_file check**: Fixed reporting True when session.session file is actually missing
- **Test regression**: Fixed button label test failures after changing 'Connect' to 'Authorize'
- **Upload file input**: Fixed upload form only accepting .session files, now also accepts .json files
- **Race condition**: Fixed race condition in connect_session logic

### Changed
- **Upload form**: Simplified upload form to accept both .session and .json files
- **TOCTOU protection**: Improved upload_session security against race conditions
- **Connect logic**: Simplified connect_session to auto-delete invalid sessions and resend codes
- **Session status**: Removed session_expired status entirely from codebase
- **Session listing**: Refactored list_stored_sessions to use config.json + account_info as source of truth

## [0.8.0] - 2026-02-06

### Security
- **CSRF Token Fix**: All fetch POST/DELETE requests now include X-CSRF-Token header
  - Fixed sessions_list.html verify-code and verify-2fa
  - Fixed analysis_results.html export/csv
  - Fixed chats.html dismiss_notification
  - Fixed analysis_progress.html cancel
  - Fixed results.html export/csv and dismiss_notification
- **Input Validation**: Added format validation for verification code (5-6 digits only)
- **Input Validation**: Added validation for 2FA password input

### Changed
- **Clean Session UI**: Reconnect no longer shows modal - directly initiates connection
  - Removed reconnect_modal.html and related endpoints
  - Session status now determines action button (Connect/Disconnect/Reconnect/Enter Code/Enter 2FA/Edit)
  - Simplified three-button layout: [Action] [Edit] [Delete]
- **Add Account Modal**: Button changed from "Send Code" to "Save" for clarity
- **i18n**: Added translations for all new/changed UI strings (EN and RU)

### Fixed
- **Mobile CSS**: All buttons now have consistent sizing with 44px minimum tap target
- **Double-click Prevention**: Connect/Disconnect buttons now disabled during operation

### Removed
- Orphaned /reconnect-form endpoint
- Orphaned /send-code endpoint
- Orphaned reconnect templates

## [0.7.2] - 2026-02-05

### Fixed
- **Loading Spinner on Connect**: Fixed loading spinner not appearing when clicking Connect button
  - Root cause: `connect_session` endpoint was synchronous, blocking HTTP response for 30s while awaiting Telegram
  - Solution: Endpoint now returns immediately with `connecting` state, runs connect in background task
  - SSE delivers final state (connected/error) when connection completes
- **JavaScript querySelector Error**: Fixed `querySelector null` JS error on Connect action
  - Caused by attempts to manipulate DOM elements that didn't exist due to architectural mismatch
  - Resolved by architectural fix above - no more client-side spinner manipulation needed
- **HTMX swapError on Connect**: Fixed HTMX swap errors during connection attempts
  - Added proper error handling for race conditions between SSE updates and HTMX responses

### Changed
- **Connect Architecture**: `connect_session` endpoint is now non-blocking
  - Returns row with `connecting` state immediately (<100ms response)
  - Background task handles actual Telegram connection
  - Realtime updates delivered via existing SSE infrastructure

## [0.7.1] - 2026-02-04

### Fixed
- **Network Error Detection**: Fixed overly broad OSError handling that incorrectly classified filesystem errors (PermissionError, FileNotFoundError) as network errors
  - Now checks specific errno codes (ENETUNREACH, EHOSTUNREACH, ECONNREFUSED, etc.) before treating OSError as network error
  - Prevents endpoints returning 503 Service Unavailable for non-network issues
- **Error Page Styling**: Browser error pages now show styled HTML instead of raw JSON
  - Added error.html template with consistent navigation and retry options
  - Exception handlers detect Accept header to choose between JSON and HTML responses
- **SSE Cross-Tab Updates**: Fixed SSE events not updating UI in other browser tabs
  - Implemented dedicated sse.js module that auto-connects to /api/sessions/events
  - EventSource reconnects automatically on connection loss

## [0.7.0] - 2026-02-04

### Added
- **Realtime Session Status**: Sessions list now updates automatically without page refresh
  - Server-Sent Events (SSE) endpoint `/api/sessions/events` streams status changes
  - HTMX SSE extension integrates with session list for live updates
  - Event bus architecture with rate limiting (10 events/sec per session) and deduplication
- **Loading States for Actions**: All action buttons now show visual feedback
  - Spinner replaces status during Connect, Disconnect, Reconnect operations
  - Loading state for Send Code, Verify Code, Verify 2FA actions
  - Prevents double-click with debounce protection
- **Status Transition Audit**: Documented all valid session state transitions
  - Matrix of status → action → new status mappings
  - Ensures consistent UI behavior across all flows

### Changed
- **Session Row Updates**: Individual rows refresh via SSE instead of full page reload
- **Error State Handling**: Improved error display in UI with retry options
- **Modal Submit Feedback**: Error responses now show in modal instead of silent failure

### Fixed
- **2FA Modal CSS Selectors**: Renamed `2fa-modal` IDs to `twofa-modal` for valid CSS
- **Session Lock**: Added locking to prevent concurrent operations on same session
- **Telegram Timeout**: Added 30-second timeout for Telegram API operations to prevent hangs

### Security
- **Input Validation**: Added validation for auth endpoint inputs (phone, code, password)
- **Rate Limiting**: Event bus prevents flooding from rapid status changes

### Testing
- **E2E Tests**: End-to-end test for realtime status updates
- **Integration Tests**: SSE endpoint connection and event delivery tests
- **Loading State Tests**: Coverage for all 6 action button loading states

## [0.6.4] - 2026-02-02

### Fixed
- **Reconnect Flow Complete Fix**: Fixed all issues with reconnecting expired sessions
  - `send_code()` now returns reconnect-specific template with correct endpoint
  - Reconnect code form posts to `/api/sessions/{session_id}/verify-code` (was: wrong endpoint for new sessions)
  - Reconnect code form targets `#reconnect-result` (was: non-existent `#auth-flow-result`)
  - Error responses use `reconnect_result.html` template for proper UI feedback
- **needs_code/needs_2fa Modal Handlers**: Modals now have working submit handlers
  - Added JavaScript handlers for code and 2FA verification modals
  - Handlers POST to correct endpoints with `session_id` and `auth_id`
  - `auth_id` passed via `data-auth-id` attribute on buttons
  - Double-submit prevention with button disabling
- **Reconnect Modal Not Visible**: Added `show` class to reconnect modal so it displays correctly when loaded via HTMX
- **Enter Code/2FA Buttons Not Working**: Fixed buttons for `needs_code` and `needs_2fa` states - removed `disabled` attribute, added correct modal trigger classes
- **Modal CSS Class Mismatch**: Changed JavaScript to use `show` class instead of `visible` to match CSS definitions
- **Empty Code/2FA Modals**: Added input fields to code verification and 2FA password modals
- **Missing Translations**: Fixed status text using untranslated strings
- **Missing FloodWaitError Import**: Added missing import in verify_code and verify_2fa endpoints

### Changed
- **Error Recovery for Reconnect**: verify-code returns reconnect-specific template on error for consistent flow
- **Deleted Unused Modal Duplicates**: Removed duplicate modal files (`partials/modal_code.html`, `partials/modal_2fa.html`) that were not being used

## [0.6.3] - 2026-02-01

### Fixed
- **i18n Race Condition**: Fixed race condition where language switcher and version check used i18n before initialization
  - i18n.js now exposes a `ready` Promise
  - language-switcher.js and version-check.js wait for i18n to be ready before using translations
- **Missing Locale Keys**: Added `language.current_aria` and `language.switch_to` keys to en.json and ru.json
- **Version Check 404**: Fixed `/api/version/check-updates` endpoint returning 404
- **Favicon 404**: Added `/favicon.ico` route to suppress browser 404 errors
- **Missing HX-Trigger Header**: Fixed `connect_session` endpoint not returning HX-Trigger header in early return path
- **Corrupted Session Files**: System now handles corrupted .session files gracefully with option to delete and recreate
- **Error Message Sanitization**: Exception messages are now sanitized to prevent information leakage of internal paths and details

### Added
- **Complete Russian Translations**: Filled all 584 empty Russian translations in messages.po
  - Full localization of UI: navigation, buttons, statuses, dialogs, error messages
  - Language switching now properly displays Russian interface
- **Session State Validation**: Connection/disconnection endpoints now validate session state before operations
  - Prevents race conditions and duplicate operations
  - Clear error messages for incompatible state transitions
- **Connection Timeout Protection**: Session connection attempts now have explicit 30-second timeout
  - Returns user-friendly error if Telegram API hangs
  - Prevents indefinite waits and improves responsiveness
- **API Credential Validation**: Changing API_ID/API_HASH now triggers full re-authorization
  - Validates credentials work with Telegram API
  - Shows code/2FA modal if authentication required
  - Only saves after successful validation
- **Transient Error Retry Logic**: API credential validation retries on transient network errors
  - Exponential backoff with max 3 attempts
  - Distinguishes network errors from invalid credentials
- **Auth Flow Protection**: Authentication endpoints track failed attempts and lock session after excessive failures
  - Max 5 failed attempts per session
  - 15-minute lockout period before retry allowed
- **Phone Number Sanitization**: Phone number input in auth flow is now sanitized
  - Removes spaces, dashes, parentheses
  - Validates format before sending to Telegram API
  - Clear error messages for invalid formats
- **Telegram Rate Limiting**: FloodWaitError from Telegram API now shows user-friendly message
  - Displays wait time required before retry
  - Helps users understand rate limiting
- **Dead Session Recovery**: Dead/expired sessions show clear status with recovery options
  - Distinct visual treatment for different error types
  - Reconnect button initiates re-auth flow
  - Preserves session ID for recovery

### Changed
- **Code Cleanup**: Audit and refactoring of sessions module
  - Removed unused code and duplicate logic
  - Simplified overly complex code paths
  - Improved code maintainability and readability

## [0.6.2] - 2026-01-28

### Fixed
- **i18n Race Condition**: Fixed race condition where language switcher and version check used i18n before initialization
  - i18n.js now exposes a `ready` Promise
  - language-switcher.js and version-check.js wait for i18n to be ready before using translations
- **Missing Locale Keys**: Added `language.current_aria` and `language.switch_to` keys to en.json and ru.json
- **Version Check 404**: Fixed `/api/version/check-updates` endpoint returning 404
- **Favicon 404**: Added `/favicon.ico` route to suppress browser 404 errors

### Added
- **Complete Russian Translations**: Filled all 584 empty Russian translations in messages.po
  - Full localization of UI: navigation, buttons, statuses, dialogs, error messages
  - Language switching now properly displays Russian interface

## [0.6.1] - 2026-01-28

### Changed
- **API Refactoring**: Major P3 cleanup of API routers
  - Extracted common helpers to reduce code duplication
  - Added Pydantic models for request/response validation
  - Standardized naming conventions across endpoints
- **Retry Logic**: Extracted retry logic into reusable `RetryContext` class
- **Code Cleanup**: Removed dead code and obsolete build infrastructure

### Fixed
- **Tests**: Repaired 88 failing tests across the test suite
  - Fixed 63 tests with missing `exports_dir` configuration
  - Resolved 25 additional test failures across 4 test files
  - Replaced useless `assert True` with real assertions
- **Type Annotations**: Fixed `type: ignore` comments and nullable return types
- **Settings**: Use `settings.max_messages_limit` and errno constants correctly

### Added
- **Test Coverage**: Comprehensive tests for 16 previously untested modules
- **API Validation**: Input validation and error handling for API endpoints
- **i18n**: Integrated `i18n.t()` in JavaScript files for full frontend internationalization

### Removed
- Unused `config.py` code
- Dead code and obsolete build infrastructure

## [0.6.0] - 2026-01-27

### Added
- **Complete Russian translations**: Full i18n support for all UI elements
  - 500+ translation entries for sessions, proxies, modals, buttons, status indicators
  - Error messages from Python code now translate (proxy errors, configuration errors)
  - Language switching works correctly in both directions (RU ↔ EN)

### Removed
- **Desktop Application**: Removed native window and system tray functionality
  - Removed pywebview native window (application now runs as pure CLI server)
  - Removed pystray system tray icon
  - Removed PyInstaller binary builds for Windows, macOS, and Linux
  - Distribution is now Python package only (`pip install chatfilter`)
- **Dependencies**: Removed 6 desktop-related dependencies
  - pystray, Pillow, pywebview
  - pyobjc-framework-Cocoa, pyobjc-framework-WebKit (macOS only)
- **Build Infrastructure**: Removed binary build system
  - Removed chatfilter.spec, build.sh, entitlements.plist
  - Removed GitHub Actions workflows for binary builds

### Changed
- **CLI Mode**: `chatfilter` command now runs uvicorn directly
  - Blocks until Ctrl+C (no background threading)
  - Hot reload enabled in debug mode (`--debug`)
  - Prints URL to console on startup
- **Installation**: Install via `pip install chatfilter`
  - Lighter package without GUI dependencies
  - Works on any Python 3.11+ environment
- **Credential Storage**: Switched from OS keychain to encrypted file backend
  - No more repeated password prompts on macOS
  - Credentials stored in encrypted files in data directory

### Migration
Users upgrading from 0.5.x desktop app:
1. Uninstall the desktop application
2. Install via pip: `pip install chatfilter`
3. Run: `chatfilter --port 8000`
4. Open browser manually: http://127.0.0.1:8000

### Fixed
- **Deactivated Account Detection**: Connect now validates account can access dialogs
  - Previously deactivated accounts could show "Connected" status falsely
  - Now shows "Banned" status with proper error message
  - Uses `iter_dialogs(limit=1)` check instead of just `get_me()`
- **Session Path**: Fixed ChatAnalysisService using wrong sessions directory
  - Was hardcoded to `./data/sessions` instead of `settings.sessions_dir`
  - Caused "Session not found" errors when selecting sessions on Chats page
- **HTMX Session Select**: Added missing `name` attribute to session dropdown
  - HTMX `hx-include` requires `name` to send form value
  - Fixed 422 "Field required" error when selecting session

## [0.5.2] - 2026-01-27

### Fixed
- **Session Status**: Fixed session status not updating after connect/disconnect
  - Previously only the button updated, leaving status cell stale
  - Now the entire row updates with correct state
- **Error Display**: Error messages shown in tooltip on hover instead of inline text
  - Cleaner UI with status-only display
  - Full error message visible on hover

## [0.5.1] - 2026-01-27

### Fixed
- **JavaScript**: Fixed broken `hyperlist.min.js` file that contained error text instead of library code
  - HyperList library was not loading, causing "Unexpected identifier 'found'" console error
  - Virtual scrolling in chat list now works correctly

## [0.5.0] - 2026-01-27

### Added
- **Session Connect/Disconnect**: Added explicit connect/disconnect buttons for each session
  - Connect button for disconnected sessions
  - Disconnect button for connected sessions
  - Retry button for error states (proxy error, flood wait)
  - Disabled state for banned accounts and unconfigured sessions
- **Extended Session Status**: More detailed session status indicators
  - Connected, Disconnected, Connecting, Disconnecting states
  - Banned (account blocked by Telegram)
  - Flood Wait (temporary rate limit)
  - Proxy Error (proxy connection failed)
  - Not Configured, Proxy Missing states
  - Error messages shown in tooltip on hover

### Removed
- **Keyboard Shortcuts**: Removed keyboard shortcuts feature and help modal
  - Removed `static/js/keyboard-shortcuts.js` (671 lines)
  - Removed keyboard shortcuts button from header
- **Header Status Indicators**: Removed global Telegram status from header
  - Removed "Telegram Connection Status" indicator
  - Removed "User logged in" indicator
  - These were redundant with per-session status display

### Changed
- **Code Cleanup**: Removed duplicate helper functions
  - Consolidated `get_session_manager()` and `get_chat_service()` functions
  - Removed duplicates from `routers/chats.py` (now uses `dependencies.py`)

## [0.4.12] - 2026-01-27

### Fixed
- **Auto-open browser**: Actually removed auto-open browser on startup (was documented in 0.4.11 but code remained)
- **Proxy settings lost on import**: Fixed proxy_id not being saved when importing or uploading sessions

## [0.4.11] - 2026-01-27

### Added
- **Native Window**: Application now runs in native window using pywebview
  - Replaces browser-based UI with native macOS/Windows/Linux window
  - uvicorn server runs in background thread
  - Fallback to headless mode if pywebview unavailable

### Changed
- **No auto-open browser**: Removed automatic browser launch on startup
  - Use tray icon menu "Open in Browser" to access web UI
  - Native window opens automatically instead

## [0.4.10] - 2026-01-27

### Fixed
- **macOS Tray Icon**: Fixed tray icon not appearing on macOS
  - Root cause: `run_detached()` was called from ThreadPoolExecutor worker thread instead of main thread
  - NSStatusItem requires main thread for initialization
  - Now calls `run_detached()` directly from main thread on macOS

## [0.4.9] - 2026-01-27

### Fixed
- **UI**: Fixed `querySelector` crash when loading session file (null-check for activeTab)
- **Proxy Pool**: Fixed UI disappearing and showing raw JSON when testing proxy (changed HTMX swap to trigger refresh)
- **macOS Tray**: Fixed missing tray icon and Dock icon on macOS
  - Added `pyobjc-framework-Cocoa` dependency
  - Added pyobjc hiddenimports for PyInstaller
  - Added `LSUIElement`, `NSHighResolutionCapable` to Info.plist

### Changed
- CI coverage threshold lowered to 76%

## [0.4.8] - 2026-01-26

### Fixed
- **P0: Proxy storage path**: Fixed "Read-only file system" error on macOS by using `settings.config_dir` instead of app bundle path for proxy storage
- **P1: Tray icon AppTranslocation**: Disabled tray icon when running from macOS App Translocation to prevent "Application Not Responding"
- **P1: Infinite loading spinner**: Added HTMX error handlers to show error message instead of spinning forever when API calls fail

### Changed
- Proxy pool now stores data in user config directory (`~/Library/Application Support/ChatFilter/config/proxies.json`)
- Legacy proxy migration checks both old app bundle location and new config directory
- Bundled htmx, hyperlist, chart.js locally instead of CDN (fixes offline/firewall issues)

## [0.4.7] - 2026-01-26

### Fixed
- **macOS AppTranslocation**: Data directory now auto-relocates to `~/Library/Application Support/ChatFilter` when running from read-only locations (downloaded .app from DMG)
- **Tray icon timeout**: Added 5-second timeout for tray initialization to prevent "Application Not Responding" on macOS

### Added
- **Proxy health monitoring**: Background task pings proxies every 5 minutes, auto-disables after 3 failures
- **Proxy status indicators**: Working (🟢), No ping (🔴), Untested (⚪) shown in proxy list
- **Retest button**: Manual proxy health check with instant status update

### Changed
- **Sessions page UX overhaul**: Single "Add Account" button with modal for upload or phone auth
- **Account list**: Shows status (Working/Not authorized/Disabled), proxy assignment, edit/delete actions
- **Merged proxy pages**: Combined `/proxy` and `/proxies` into single `/proxies` page
- Removed legacy global proxy support (`proxy.json`), all proxies now use pool

## [0.4.6] - 2026-01-26

### Fixed
- PyInstaller spec version sync with package version
- Added proper app icons for macOS/Windows builds
- Lazy import pystray to prevent crashes on headless systems

## [0.4.5] - 2026-01-25

### Added
- Phone-based session creation with code/2FA authentication flow
- Session config form with api_id, api_hash, proxy selection
- Proxy pool UI with add/edit modal and delete confirmation
- System tray icon integration (macOS menu bar, Windows system tray, Linux AppIndicator)
- Headless environment detection for graceful tray skip

### Fixed
- Proxy JSON deserialization type coercion

## [0.4.0] - 2026-01-24

### Changed
- **Complete UI redesign**: Transformed web interface to minimalist Apple-style design
  - Replaced Material Design bright blue with muted iOS blue (#007aff)
  - Redesigned header with white/light-gray background and thin border
  - Reduced shadows throughout (from 4px to 1-2px, lower opacity)
  - Reduced border-radius for cleaner geometry (from 8px to 4-6px)
  - Updated buttons to flat design with subtle 1px borders
  - Lightened font weights for better readability (font-weight: 400-500 max)
  - Increased white space and padding for improved breathing room
  - Removed pulsing animations from status indicators for cleaner feel

### Fixed
- Bug ChatFilter-e385: Tooltips and alerts now properly use CSS variables for text colors
  - Text colors now correctly adapt between light and dark themes
  - Added theme-specific variables: `--warning-text`, `--info-text`, `--success-text`, `--danger-text`

## [0.3.0] - 2026-01-23

### Added
- Russian language support (i18n) for web interface templates
- Network connectivity monitoring with graceful degradation
- Automatic update checking from GitHub releases

### Changed
- Upgraded CI to Python 3.12
- Optimized CI pipeline for faster builds (~30min vs 2.5h)
- Improved smoke tests with better output capture and diagnostics

### Fixed
- Windows CI compatibility: emoji encoding, pipe buffer blocking, timer resolution
- Test stability improvements across all platforms
- PyInstaller build now includes all required submodules
- Jinja2 template dependency for i18n support

## [0.2.0] - 2026-01-21

### Added
- Encrypted storage with Fernet symmetric encryption
- Machine-derived encryption keys for portable security
- Key rotation support with versioned file format

### Fixed
- Session management reliability improvements

## [0.1.0] - 2026-01-20

### Added
- Initial release of ChatFilter
- Telegram chat import and export functionality
- Message filtering and analysis
- Web-based UI for chat management
- Task queue system with deduplication
- Comprehensive smoke tests for binary releases
- Antivirus false positive mitigation for PyInstaller builds
- Unified error handling system in Web UI

### Fixed
- Memory leaks in long-running background tasks
- Task deduplication to prevent duplicate analysis runs

### Documentation
- Windows SmartScreen bypass instructions

[Unreleased]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.9...HEAD
[0.10.9]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.8...v0.10.9
[0.10.8]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.7...v0.10.8
[0.10.7]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.6...v0.10.7
[0.10.6]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.5...v0.10.6
[0.10.5]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.4...v0.10.5
[0.10.4]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.3...v0.10.4
[0.10.3]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.2...v0.10.3
[0.10.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.1...v0.10.2
[0.10.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.12...v0.10.0
[0.9.12]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.11...v0.9.12
[0.9.11]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.10...v0.9.11
[0.9.10]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.9...v0.9.10
[0.9.9]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.8...v0.9.9
[0.9.8]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.7...v0.9.8
[0.9.7]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.6...v0.9.7
[0.9.6]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.5...v0.9.6
[0.9.5]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.4...v0.9.5
[0.9.4]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.3...v0.9.4
[0.9.3]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.2...v0.9.3
[0.9.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.1...v0.9.2
[0.9.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.0...v0.9.1
[0.9.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.5...v0.9.0
[0.8.5]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.4...v0.8.5
[0.8.4]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.3...v0.8.4
[0.8.3]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.7.2...v0.8.0
[0.7.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.4...v0.7.0
[0.6.4]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.5.2...v0.6.0
[0.5.2]: https://github.com/Puremag1c/ChatFilter/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/Puremag1c/ChatFilter/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.12...v0.5.0
[0.4.12]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.11...v0.4.12
[0.4.11]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.10...v0.4.11
[0.4.10]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.9...v0.4.10
[0.4.9]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.8...v0.4.9
[0.4.8]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.7...v0.4.8
[0.4.7]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.6...v0.4.7
[0.4.6]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Puremag1c/ChatFilter/releases/tag/v0.1.0

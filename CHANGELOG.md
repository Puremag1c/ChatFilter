# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Puremag1c/ChatFilter/compare/v0.9.0...HEAD
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

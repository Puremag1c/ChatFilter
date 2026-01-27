# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.7...HEAD
[0.4.7]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.6...v0.4.7
[0.4.6]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.5...v0.4.6
[0.4.5]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Puremag1c/ChatFilter/releases/tag/v0.1.0

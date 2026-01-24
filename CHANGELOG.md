# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Puremag1c/ChatFilter/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Puremag1c/ChatFilter/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Puremag1c/ChatFilter/releases/tag/v0.1.0

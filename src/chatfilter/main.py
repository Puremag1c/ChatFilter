"""Main entry point for ChatFilter."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


def setup_logging(
    level: str = "INFO",
    debug: bool = False,
    verbose: bool = False,
    log_to_file: bool = True,
    log_file_path: Path | None = None,
    log_file_max_bytes: int = 10 * 1024 * 1024,
    log_file_backup_count: int = 5,
    log_format: str = "text",
    module_levels: dict[str, str] | None = None,
) -> None:
    """Configure logging for the application with console and optional file output.

    Sets up structured logging with:
    - Console handler for immediate feedback
    - Optional rotating file handler for persistent logs
    - Consistent timestamp format
    - Module-level granularity
    - Optional JSON format for log aggregators
    - Per-module log level configuration

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR)
        debug: If True, overrides level to DEBUG
        verbose: If True, enables verbose logging (more detailed operation logs)
        log_to_file: Enable file logging in addition to console
        log_file_path: Path to log file (if None and log_to_file=True, uses default)
        log_file_max_bytes: Maximum size per log file before rotation
        log_file_backup_count: Number of rotated backup files to keep
        log_format: Log format ('text' for human-readable, 'json' for structured)
        module_levels: Dict of module names to log levels (e.g., {'chatfilter.telegram': 'DEBUG'})
    """
    # Determine effective level: debug or verbose both enable DEBUG
    if debug or verbose:
        effective_level = logging.DEBUG
    else:
        effective_level = getattr(logging, level.upper(), logging.INFO)

    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(effective_level)

    # Clear any existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Import filters and formatters
    from chatfilter.utils.logging import (
        ChatContextFilter,
        CorrelationIDFilter,
        JSONFormatter,
        LogSanitizer,
        SanitizingFormatter,
        configure_module_levels,
    )

    # Create appropriate formatter based on log_format
    if log_format == "json":
        formatter: logging.Formatter = JSONFormatter(sanitize=True)
    else:
        # Text format with correlation ID and chat ID support
        text_format = "%(asctime)s [%(levelname)s] [%(correlation_id)s] [chat:%(chat_id)s] %(name)s: %(message)s"
        date_format = "%Y-%m-%d %H:%M:%S"
        formatter = SanitizingFormatter(text_format, datefmt=date_format)

    # Console handler - always enabled
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(effective_level)
    console_handler.setFormatter(formatter)
    # Add filters to handler (filters are not inherited by child loggers)
    console_handler.addFilter(LogSanitizer())
    console_handler.addFilter(CorrelationIDFilter())
    console_handler.addFilter(ChatContextFilter())
    root_logger.addHandler(console_handler)

    # File handler - optional with rotation
    if log_to_file and log_file_path:
        try:
            # Ensure log directory exists
            log_file_path.parent.mkdir(parents=True, exist_ok=True)

            # Create rotating file handler
            file_handler = RotatingFileHandler(
                log_file_path,
                maxBytes=log_file_max_bytes,
                backupCount=log_file_backup_count,
                encoding="utf-8",
            )
            file_handler.setLevel(effective_level)
            file_handler.setFormatter(formatter)
            # Add filters to handler
            file_handler.addFilter(LogSanitizer())
            file_handler.addFilter(CorrelationIDFilter())
            file_handler.addFilter(ChatContextFilter())
            root_logger.addHandler(file_handler)

            # Log to confirm file logging is active
            logging.info(f"File logging enabled: {log_file_path}")
            logging.debug(
                f"Log rotation: max {log_file_max_bytes / (1024 * 1024):.1f} MB, "
                f"{log_file_backup_count} backups"
            )
        except (OSError, PermissionError) as e:
            # Graceful degradation - continue with console-only logging
            logging.warning(f"Failed to initialize file logging: {e}. Using console-only logging.")

    # Configure per-module log levels
    if module_levels:
        configure_module_levels(module_levels)
        logging.debug(f"Configured module log levels: {module_levels}")

    # Log verbose mode if enabled
    if verbose and not debug:
        logging.info("Verbose logging enabled")


def _handle_reset_password() -> None:
    """Handle reset-password subcommand."""
    import argparse
    import sqlite3

    from sqlalchemy.exc import OperationalError as SAOperationalError

    from chatfilter.config import get_settings
    from chatfilter.storage.user_database import UserDatabase

    parser = argparse.ArgumentParser(
        prog="chatfilter reset-password",
        description="Reset a user's password",
    )
    parser.add_argument("username", help="Username to reset password for")
    parser.add_argument("password", help="New password (min 8 characters)")
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Data directory path (default: from settings/env)",
    )

    args = parser.parse_args(sys.argv[2:])

    if len(args.password) < 8:
        print("Error: Password must be at least 8 characters long", file=sys.stderr)
        sys.exit(1)

    settings = get_settings()
    if args.data_dir:
        from chatfilter.config import Settings, reset_settings

        reset_settings()
        settings = Settings(data_dir=Path(args.data_dir))

    try:
        db = UserDatabase(settings.effective_database_url)
        user = db.get_user_by_username(args.username)
        if user is None:
            print(f"Error: User '{args.username}' not found", file=sys.stderr)
            sys.exit(1)
        db.update_password(user["id"], args.password)
        print(f"Password for '{args.username}' has been reset successfully")
        sys.exit(0)
    except (SAOperationalError, sqlite3.OperationalError) as e:
        if "database is locked" in str(e):
            print(
                "Error: Database is locked (the app may be running). "
                "Stop the app first before resetting a password.",
                file=sys.stderr,
            )
        else:
            print(f"Error: Database error: {e}", file=sys.stderr)
        sys.exit(1)


def _handle_migrate() -> None:
    """Handle migrate subcommand — run Alembic migrations."""
    import argparse

    from alembic import command

    from chatfilter.config import get_settings

    parser = argparse.ArgumentParser(
        prog="chatfilter migrate",
        description="Run database migrations",
    )
    parser.add_argument(
        "--revision",
        default="head",
        help="Target revision (default: head)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Data directory path (default: from settings/env)",
    )

    args = parser.parse_args(sys.argv[2:])

    settings = get_settings()
    if args.data_dir:
        from chatfilter.config import Settings, reset_settings

        reset_settings()
        settings = Settings(data_dir=Path(args.data_dir))

    settings.ensure_data_dirs()

    db_url = settings.effective_database_url
    alembic_cfg = _get_alembic_config(db_url)

    print(f"Running migrations on: {db_url}")
    command.upgrade(alembic_cfg, args.revision)
    print("Migrations complete.")

    # Auto-import from legacy split databases (groups.db + users.db)
    if db_url.startswith("sqlite:///"):
        from chatfilter.storage.legacy_import import import_legacy_databases

        db_path = Path(db_url.removeprefix("sqlite:///"))
        import_legacy_databases(db_path)


def _get_alembic_config(db_url: str) -> Any:
    """Build Alembic config pointing to our migrations."""
    from pathlib import Path as _Path

    from alembic.config import Config

    ini_path = _Path(__file__).resolve().parent.parent.parent / "alembic.ini"
    if not ini_path.exists():
        alembic_cfg = Config()
        alembic_cfg.set_main_option(
            "script_location",
            str(_Path(__file__).resolve().parent / "migrations"),
        )
    else:
        alembic_cfg = Config(str(ini_path))

    alembic_cfg.set_main_option("sqlalchemy.url", db_url)
    return alembic_cfg


def _handle_db_check() -> None:
    """Handle db-check subcommand — check if migration is needed."""
    from alembic.script import ScriptDirectory

    from chatfilter.config import get_settings
    from chatfilter.storage.engine import create_db_engine

    settings = get_settings()
    db_url = settings.effective_database_url
    alembic_cfg = _get_alembic_config(db_url)
    script = ScriptDirectory.from_config(alembic_cfg)
    head = script.get_current_head()

    print(f"Database: {db_url}")

    # Check current revision
    engine = create_db_engine(db_url)
    current: str | None = None
    try:
        with engine.connect() as conn:
            from sqlalchemy import inspect as sa_inspect
            from sqlalchemy import text

            insp = sa_inspect(conn)
            if "alembic_version" in insp.get_table_names():
                row = conn.execute(text("SELECT version_num FROM alembic_version")).fetchone()
                if row:
                    current = row[0]
    except Exception:
        pass
    finally:
        engine.dispose()

    if current is None:
        print("Status: not initialized")
        print("Run: chatfilter migrate")
        sys.exit(1)
    elif current == head:
        print(f"Status: up to date (revision {current})")
        sys.exit(0)
    else:
        print(f"Status: migration needed ({current} → {head})")
        print("Run: chatfilter migrate")
        sys.exit(1)


def _migrate_api_credentials(settings: Any) -> None:
    """Strip api_id/api_hash from existing sessions at startup (one-time migration).

    For each session directory under sessions_dir:
    - Removes api_id/api_hash from config.json (keeps other fields)
    - Removes api_id/api_hash from .credentials.enc (keeps proxy_id, 2fa)
    - Writes .api_migrated marker to skip on subsequent starts
    """
    import json

    from chatfilter.security.credentials import EncryptedFileBackend

    sessions_dir = settings.sessions_dir
    if not sessions_dir.exists():
        logging.info("API credentials migration: no sessions directory, nothing to migrate")
        return

    migrated_count = 0
    skipped_count = 0

    # Structure: sessions_dir/user_id/session_name/
    for user_dir in sessions_dir.iterdir():
        if not user_dir.is_dir():
            continue
        for session_dir in user_dir.iterdir():
            if not session_dir.is_dir():
                continue
            if not (session_dir / "config.json").exists():
                continue

            marker = session_dir / ".api_migrated"
            if marker.exists():
                skipped_count += 1
                continue

            session_id = f"{user_dir.name}/{session_dir.name}"
            try:
                # 1. Strip api_id/api_hash from config.json
                config_path = session_dir / "config.json"
                config_data = json.loads(config_path.read_text(encoding="utf-8"))
                changed = False
                for key in ("api_id", "api_hash"):
                    if key in config_data:
                        del config_data[key]
                        changed = True
                if changed:
                    config_path.write_text(
                        json.dumps(config_data, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )

                # 2. Strip api_id/api_hash from .credentials.enc
                backend = EncryptedFileBackend(session_dir)
                backend.migrate_strip_api_credentials()

                # 3. Write marker
                marker.touch()
                migrated_count += 1
            except Exception as e:
                logging.error(f"API credentials migration failed for session '{session_id}': {e}")

    logging.info(
        f"API credentials migration: {migrated_count} sessions migrated, "
        f"{skipped_count} skipped (already migrated)"
    )


def main() -> None:
    """Run ChatFilter web application."""
    if len(sys.argv) > 1 and sys.argv[1] == "reset-password":
        _handle_reset_password()
        return

    if len(sys.argv) > 1 and sys.argv[1] == "migrate":
        _handle_migrate()
        return

    if len(sys.argv) > 1 and sys.argv[1] == "db-check":
        _handle_db_check()
        return

    import argparse

    import uvicorn

    from chatfilter import __version__
    from chatfilter.config import Settings, get_settings, reset_settings

    # Load settings from env/.env first for defaults
    env_settings = get_settings()

    parser = argparse.ArgumentParser(
        description="ChatFilter - Telegram chat filtering and analysis tool"
    )
    parser.add_argument(
        "--host",
        default=env_settings.host,
        help=f"Host to bind to (default: {env_settings.host}, env: CHATFILTER_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=env_settings.port,
        help=f"Port to bind to (default: {env_settings.port}, env: CHATFILTER_PORT)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=env_settings.debug,
        help="Enable debug mode (env: CHATFILTER_DEBUG)",
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help=f"Data directory path (default: {env_settings.data_dir}, env: CHATFILTER_DATA_DIR)",
    )
    parser.add_argument(
        "--log-level",
        default=env_settings.log_level,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help=f"Logging level (default: {env_settings.log_level}, env: CHATFILTER_LOG_LEVEL)",
    )
    parser.add_argument(
        "--log-format",
        default=env_settings.log_format,
        choices=["text", "json"],
        help=f"Log format: 'text' for human-readable, 'json' for structured (default: {env_settings.log_format}, env: CHATFILTER_LOG_FORMAT)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=env_settings.verbose,
        help="Enable verbose logging with detailed operation information (env: CHATFILTER_VERBOSE)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Validate configuration and exit (deprecated, use --validate)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate configuration and exit without starting server",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run startup diagnostics and exit (checks network, DNS, Telegram connectivity, permissions)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"ChatFilter {__version__}",
    )

    args = parser.parse_args()

    # Create settings with CLI overrides
    # Reset cache to apply CLI args
    reset_settings()

    cli_overrides = {
        "host": args.host,
        "port": args.port,
        "debug": args.debug,
        "log_level": args.log_level,
        "log_format": args.log_format,
        "verbose": args.verbose,
    }
    if args.data_dir:
        from pathlib import Path

        cli_overrides["data_dir"] = Path(args.data_dir)

    settings = Settings(**cli_overrides)

    # Handle --self-test
    if args.self_test:
        import asyncio
        import json

        from chatfilter.self_test import SelfTest

        print("=" * 80)
        print("RUNNING SELF-TEST DIAGNOSTICS")
        print("=" * 80)
        print()

        # Run self-test
        self_test = SelfTest(settings)
        asyncio.run(self_test.run_all_tests())

        # Display results in table format
        print(self_test.format_table())

        # Also export JSON for programmatic consumption
        json_output = self_test.to_dict()
        print()
        print("JSON OUTPUT:")
        print(json.dumps(json_output, indent=2))

        # Exit with appropriate code
        if self_test.has_failures():
            sys.exit(1)
        else:
            sys.exit(0)

    # Handle --validate or --check-config
    if args.validate or args.check_config:
        settings.print_config()
        print()

        # Run strict validation
        errors = settings.validate()
        warnings = settings.check()

        if errors:
            print("Configuration validation failed:")
            for error in errors:
                print(f"\n{error}")
            sys.exit(1)

        if warnings:
            print("Configuration warnings:")
            for warning in warnings:
                print(f"  • {warning}")
            print()

        print("Configuration is valid")
        sys.exit(0)

    setup_logging(
        level=settings.log_level,
        debug=settings.debug,
        verbose=settings.verbose,
        log_to_file=settings.log_to_file,
        log_file_path=settings.log_file_path if settings.log_to_file else None,
        log_file_max_bytes=settings.log_file_max_bytes,
        log_file_backup_count=settings.log_file_backup_count,
        log_format=settings.log_format,
        module_levels=settings.log_module_levels if settings.log_module_levels else None,
    )

    # Validate configuration before starting server (fail-fast)
    errors = settings.validate()
    if errors:
        print("Configuration validation failed:")
        for error in errors:
            print(f"\n{error}")
        print("\nRun with --validate to check configuration without starting the server")
        sys.exit(1)

    # Auto-switch data_dir if in read-only location (e.g., macOS AppTranslocation)
    from chatfilter.config import _get_default_data_dir, _is_path_in_readonly_location

    is_readonly, readonly_reason = _is_path_in_readonly_location(settings.data_dir)
    if is_readonly:
        safe_data_dir = _get_default_data_dir()
        print()
        print("=" * 60)
        print("NOTICE: Auto-relocating data directory")
        print("=" * 60)
        print(f"  Original: {settings.data_dir}")
        print(f"  Reason:   {readonly_reason}")
        print(f"  New:      {safe_data_dir}")
        print("=" * 60)
        print()

        # Recreate settings with safe data_dir
        cli_overrides["data_dir"] = safe_data_dir
        settings = Settings(**cli_overrides)

    # Check if this is the first run
    is_first_run = settings.is_first_run()

    # Ensure data directories exist
    dir_errors = settings.ensure_data_dirs()
    if dir_errors:
        print()
        print("=" * 60)
        print("ERROR: Failed to create required directories")
        print("=" * 60)
        for error in dir_errors:
            print(error)
            print()
        print("The application cannot start without write access to the data directory.")
        print()
        print("To fix this issue:")
        print("  1. Use a writable location with --data-dir:")
        print("       chatfilter --data-dir ~/ChatFilter")
        print("  2. Or grant write permissions to the current location")
        print()
        print("Run --self-test to diagnose permission issues")
        print("=" * 60)
        sys.exit(1)

    # Startup banner with system information
    import platform

    print("=" * 60)
    print(f"ChatFilter v{__version__}")
    print("=" * 60)
    if is_first_run:
        print("Welcome! This is your first run.")
        print("=" * 60)
    print(f"Python:        {platform.python_version()}")
    print(f"OS:            {platform.system()} {platform.release()}")
    print(f"Server:        http://{settings.host}:{settings.port}")
    print(f"Data dir:      {settings.data_dir}")
    print(f"Sessions dir:  {settings.sessions_dir}")
    print(f"Exports dir:   {settings.exports_dir}")
    print(f"Log level:     {settings.log_level}")
    print(f"Log format:    {settings.log_format}")
    if settings.verbose:
        print("Verbose:       enabled")
    if settings.log_to_file:
        print(f"Log file:      {settings.log_file_path}")
    print("=" * 60)

    # Show first run setup guide
    if is_first_run:
        print()
        print("FIRST RUN SETUP GUIDE")
        print("=" * 60)
        print()
        print("Follow these steps to get started with ChatFilter:")
        print()
        print("1. Get your Telegram API credentials:")
        print("   • Visit https://my.telegram.org/apps")
        print("   • Log in with your phone number")
        print("   • Create a new application to get api_id and api_hash")
        print()
        print("2. Open ChatFilter in your browser:")
        print(f"   • Navigate to http://{settings.host}:{settings.port}")
        print()
        print("3. Upload your session or create a new one:")
        print("   • Click 'Upload Session' to use an existing session")
        print("   • Or click 'New Session' to authenticate")
        print()
        print("4. Start analyzing your chats:")
        print("   • Select chats from the list")
        print("   • Configure filters and criteria")
        print("   • Export results to CSV or JSON")
        print()
        print("=" * 60)
        print()

    # Mark first run as complete if directories were created successfully
    if is_first_run and not dir_errors:
        settings.mark_first_run_complete()

    # One-time migration: strip api_id/api_hash from existing sessions
    _migrate_api_credentials(settings)

    # Run uvicorn server (blocks until Ctrl+C)
    print(f"\nServer running at http://{settings.host}:{settings.port}")
    print("Press Ctrl+C to stop\n")

    try:
        uvicorn.run(
            "chatfilter.web.app:app",
            host=settings.host,
            port=settings.port,
            reload=settings.debug,
            log_level="debug" if settings.debug else "info",
            timeout_keep_alive=5,
            timeout_graceful_shutdown=30,
        )
    except KeyboardInterrupt:
        pass
    finally:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()

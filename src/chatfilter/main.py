"""Main entry point for ChatFilter."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logging(
    level: str = "INFO",
    debug: bool = False,
    log_to_file: bool = True,
    log_file_path: Path | None = None,
    log_file_max_bytes: int = 10 * 1024 * 1024,
    log_file_backup_count: int = 5,
) -> None:
    """Configure logging for the application with console and optional file output.

    Sets up structured logging with:
    - Console handler for immediate feedback
    - Optional rotating file handler for persistent logs
    - Consistent timestamp format
    - Module-level granularity

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR)
        debug: If True, overrides level to DEBUG
        log_to_file: Enable file logging in addition to console
        log_file_path: Path to log file (if None and log_to_file=True, uses default)
        log_file_max_bytes: Maximum size per log file before rotation
        log_file_backup_count: Number of rotated backup files to keep
    """
    effective_level = logging.DEBUG if debug else getattr(logging, level.upper(), logging.INFO)

    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(effective_level)

    # Clear any existing handlers to avoid duplicates
    root_logger.handlers.clear()

    # Import filters and formatter
    from chatfilter.utils.logging import (
        CorrelationIDFilter,
        LogSanitizer,
        SanitizingFormatter,
    )

    # Define consistent format with correlation ID support
    # Use SanitizingFormatter to sanitize complete output including exception tracebacks
    log_format = "%(asctime)s [%(levelname)s] [%(correlation_id)s] %(name)s: %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    formatter = SanitizingFormatter(log_format, datefmt=date_format)

    # Console handler - always enabled
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(effective_level)
    console_handler.setFormatter(formatter)
    # Add filters to handler (filters are not inherited by child loggers)
    console_handler.addFilter(LogSanitizer())
    console_handler.addFilter(CorrelationIDFilter())
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


def main() -> None:
    """Run ChatFilter web application."""
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
    }
    if args.data_dir:
        from pathlib import Path

        cli_overrides["data_dir"] = Path(args.data_dir)

    settings = Settings(**cli_overrides)

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
        log_to_file=settings.log_to_file,
        log_file_path=settings.log_file_path if settings.log_to_file else None,
        log_file_max_bytes=settings.log_file_max_bytes,
        log_file_backup_count=settings.log_file_backup_count,
    )

    # Validate configuration before starting server (fail-fast)
    errors = settings.validate()
    if errors:
        print("Configuration validation failed:")
        for error in errors:
            print(f"\n{error}")
        print("\nRun with --validate to check configuration without starting the server")
        sys.exit(1)

    # Check if this is the first run
    is_first_run = settings.is_first_run()

    # Ensure data directories exist
    dir_errors = settings.ensure_data_dirs()
    if dir_errors:
        print("Warning: Some directories could not be created:")
        for error in dir_errors:
            print(f"  • {error}")
        print("Continuing anyway, but some features may not work correctly.")
        print()

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

    try:
        uvicorn.run(
            "chatfilter.web.app:app",
            host=settings.host,
            port=settings.port,
            reload=settings.debug,
            log_level="debug" if settings.debug else "info",
        )
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()

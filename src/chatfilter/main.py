"""Main entry point for ChatFilter."""

from __future__ import annotations

import logging
import sys


def setup_logging(level: str = "INFO", debug: bool = False) -> None:
    """Configure logging for the application.

    Args:
        level: Log level string (DEBUG, INFO, WARNING, ERROR)
        debug: If True, overrides level to DEBUG
    """
    effective_level = logging.DEBUG if debug else getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=effective_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


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
            print("❌ Configuration validation failed:")
            for error in errors:
                print(f"\n{error}")
            sys.exit(1)

        if warnings:
            print("⚠️  Configuration warnings:")
            for warning in warnings:
                print(f"  • {warning}")
            print()

        print("✅ Configuration is valid")
        sys.exit(0)

    setup_logging(level=settings.log_level, debug=settings.debug)

    # Validate configuration before starting server (fail-fast)
    errors = settings.validate()
    if errors:
        print("❌ Configuration validation failed:")
        for error in errors:
            print(f"\n{error}")
        print("\nRun with --validate to check configuration without starting the server")
        sys.exit(1)

    # Ensure data directories exist
    settings.ensure_data_dirs()

    print(f"ChatFilter v{__version__}")
    print(f"Starting server at http://{settings.host}:{settings.port}")
    print(f"Data directory: {settings.data_dir}")

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

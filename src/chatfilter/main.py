"""Main entry point for ChatFilter."""

from __future__ import annotations

import logging
import sys


def setup_logging(debug: bool = False) -> None:
    """Configure logging for the application."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main() -> None:
    """Run ChatFilter web application."""
    import argparse

    import uvicorn

    from chatfilter import __version__

    parser = argparse.ArgumentParser(
        description="ChatFilter - Telegram chat filtering and analysis tool"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--version", action="version", version=f"ChatFilter {__version__}")

    args = parser.parse_args()

    setup_logging(debug=args.debug)

    print(f"ChatFilter v{__version__}")
    print(f"Starting server at http://{args.host}:{args.port}")

    try:
        uvicorn.run(
            "chatfilter.web.app:app",
            host=args.host,
            port=args.port,
            reload=args.debug,
            log_level="debug" if args.debug else "info",
        )
    except KeyboardInterrupt:
        print("\nShutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()

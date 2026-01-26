"""System tray icon functionality for ChatFilter.

Provides system tray integration with menu for quick access to common actions.

Platform-specific behavior (pystray backends):

macOS (menu bar):
    - Backend: NSStatusItem via pyobjc
    - Location: Menu bar (top-right)
    - Left-click: Opens menu (no default action support)
    - Double-click on "Open in Browser": Opens browser (default=True)
    - Notifications: Not supported
    - Threading: run() must be from main thread, but run_detached() works from any thread

Windows (system tray):
    - Backend: Native win32 system tray
    - Location: System tray (bottom-right, near clock)
    - Left-click: Opens browser (default action)
    - Right-click: Shows menu
    - Notifications: Supported (not currently used)
    - Threading: Safe from any thread

Linux (varies by desktop):
    - Backend options (in preference order):
        1. AppIndicator - Works well, but no default action support
        2. GTK - Full features, may need GNOME Shell extension
        3. XOrg - Fallback, only default action (no menu)
    - Set PYSTRAY_BACKEND env var to force specific backend
    - May not work at all on some desktop environments (Wayland issues)
    - Notifications: Not supported on XOrg backend

Runtime feature detection:
    - Icon.HAS_MENU: Menu support available
    - Icon.HAS_DEFAULT: Default action support
    - Icon.HAS_NOTIFICATION: Notification support
"""

from __future__ import annotations

import logging
import os
import platform
import signal
import webbrowser
from collections.abc import Callable
from typing import TYPE_CHECKING

from PIL import Image, ImageDraw
from pystray import Icon, Menu, MenuItem

if TYPE_CHECKING:
    from pystray import Icon as IconType

logger = logging.getLogger(__name__)


def _log_platform_info() -> None:
    """Log platform-specific tray icon information for debugging."""
    system = platform.system()

    if system == "Darwin":
        logger.debug("Tray backend: macOS menu bar (NSStatusItem via pyobjc)")
    elif system == "Windows":
        logger.debug("Tray backend: Windows system tray (win32)")
    elif system == "Linux":
        backend = os.environ.get("PYSTRAY_BACKEND", "auto")
        logger.debug(f"Tray backend: Linux (PYSTRAY_BACKEND={backend})")
        # Note: Linux tray support varies by desktop environment
        logger.debug(
            "Note: Linux tray support depends on desktop environment. "
            "Set PYSTRAY_BACKEND=appindicator|gtk|xorg to force specific backend."
        )
    else:
        logger.debug(f"Tray backend: Unknown platform ({system})")

    # Log feature availability
    has_menu = getattr(Icon, "HAS_MENU", True)  # Default True for older pystray
    has_default = getattr(Icon, "HAS_DEFAULT_ACTION", True)
    logger.debug(f"Tray features: menu={has_menu}, default_action={has_default}")


# Global reference to the running tray icon
_running_icon: Icon | None = None


def _generate_icon_from_emoji() -> Image.Image:
    """Generate a tray icon from emoji 📊 using Pillow.

    Creates a simple icon with a bar chart representation.
    This is a temporary solution until custom icon is provided.

    Returns:
        PIL Image suitable for system tray icon.
    """
    # Create a 64x64 RGBA image with transparent background
    size = 64
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Draw a simple bar chart representation (📊 emoji style)
    # Background circle
    padding = 2
    draw.ellipse(
        [padding, padding, size - padding, size - padding],
        fill=(52, 152, 219, 255),  # Blue background
    )

    # Draw bars (white)
    bar_color = (255, 255, 255, 255)
    bar_width = 10
    base_y = 50
    bars = [
        (14, 35),  # x, height
        (28, 25),  # x, height
        (42, 40),  # x, height
    ]

    for x, height in bars:
        draw.rectangle(
            [x, base_y - height, x + bar_width, base_y],
            fill=bar_color,
        )

    return image


def create_tray_icon(
    host: str = "127.0.0.1",
    port: int = 8000,
    on_exit: Callable[[], None] | None = None,
) -> Icon:
    """Create and configure the system tray icon.

    Args:
        host: Server host for "Open in Browser" action.
        port: Server port for "Open in Browser" action.
        on_exit: Optional callback to execute on exit. If None, stops the icon.

    Returns:
        Configured pystray Icon instance (not yet running).
    """
    url = f"http://{host}:{port}"

    def open_browser(icon: IconType, item: MenuItem) -> None:
        """Open ChatFilter in the default web browser."""
        logger.info(f"Opening browser: {url}")
        webbrowser.open(url)

    def exit_app(icon: IconType, item: MenuItem) -> None:
        """Exit the application by triggering graceful shutdown."""
        logger.info("Exit requested from tray menu")
        icon.stop()
        if on_exit:
            on_exit()
        else:
            # Default behavior: send SIGINT to trigger uvicorn graceful shutdown
            logger.info("Sending SIGINT for graceful shutdown")
            os.kill(os.getpid(), signal.SIGINT)

    # Generate icon image
    icon_image = _generate_icon_from_emoji()

    # Create menu
    menu = Menu(
        MenuItem("Open in Browser", open_browser, default=True),
        Menu.SEPARATOR,
        MenuItem("Exit", exit_app),
    )

    # Create icon
    icon = Icon(
        name="ChatFilter",
        icon=icon_image,
        title="ChatFilter",
        menu=menu,
    )

    logger.debug("Tray icon created")
    return icon


def start_tray_icon(
    host: str = "127.0.0.1",
    port: int = 8000,
    on_exit: Callable[[], None] | None = None,
) -> Icon | None:
    """Start the system tray icon in a background thread.

    Creates and starts the tray icon using run_detached(), which runs
    the icon in a separate thread without blocking the main thread.

    Args:
        host: Server host for "Open in Browser" action.
        port: Server port for "Open in Browser" action.
        on_exit: Optional callback to execute on exit.

    Returns:
        The running Icon instance, or None if tray is not supported.
    """
    global _running_icon

    try:
        _log_platform_info()
        icon = create_tray_icon(host=host, port=port, on_exit=on_exit)
        icon.run_detached()
        _running_icon = icon
        logger.info("Tray icon started")
        return icon
    except Exception as e:
        logger.warning(f"Failed to start tray icon: {e}")
        return None


def stop_tray_icon() -> None:
    """Stop the running system tray icon.

    Safe to call even if tray icon is not running.
    """
    global _running_icon

    if _running_icon is not None:
        try:
            _running_icon.stop()
            logger.info("Tray icon stopped")
        except Exception as e:
            logger.warning(f"Error stopping tray icon: {e}")
        finally:
            _running_icon = None

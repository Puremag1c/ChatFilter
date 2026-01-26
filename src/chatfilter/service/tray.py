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
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pystray import Icon as IconType

logger = logging.getLogger(__name__)

# Lazy-loaded pystray module (imported only when GUI is available)
_pystray: Any = None


def _load_pystray() -> Any:
    """Lazily load pystray module.

    This avoids import-time errors on headless systems where pystray
    tries to connect to X11/Wayland during module initialization.

    Returns:
        The pystray module, or None if import fails.
    """
    global _pystray
    if _pystray is None:
        try:
            import pystray

            _pystray = pystray
        except Exception as e:
            logger.warning(f"Failed to import pystray: {e}")
            return None
    return _pystray


def _is_gui_available() -> bool:
    """Check if a GUI environment is available for displaying tray icon.

    Returns:
        True if GUI is likely available, False for headless environments.
    """
    system = platform.system()

    if system == "Linux":
        # Check for X11 or Wayland display
        display = os.environ.get("DISPLAY")
        wayland = os.environ.get("WAYLAND_DISPLAY")

        if not display and not wayland:
            logger.debug("No DISPLAY or WAYLAND_DISPLAY set — headless Linux detected")
            return False

        logger.debug(f"Linux display: DISPLAY={display}, WAYLAND_DISPLAY={wayland}")
        return True

    elif system == "Darwin":
        # macOS: check if running in a GUI session
        # SSH sessions without screen sharing won't have access to WindowServer
        ssh_connection = os.environ.get("SSH_CONNECTION")

        if ssh_connection and not os.environ.get("DISPLAY"):
            logger.debug("SSH session without X forwarding — headless macOS detected")
            return False

        return True

    elif system == "Windows":
        # Windows: check if running as a service or in non-interactive session
        # For now, assume GUI is available on Windows
        # Service detection would require win32 API which may not be available
        return True

    # Unknown platform — try anyway, let pystray handle it
    return True


def _log_platform_info(pystray_module: Any) -> None:
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
    Icon = pystray_module.Icon
    has_menu = getattr(Icon, "HAS_MENU", True)  # Default True for older pystray
    has_default = getattr(Icon, "HAS_DEFAULT_ACTION", True)
    logger.debug(f"Tray features: menu={has_menu}, default_action={has_default}")


# Global reference to the running tray icon
_running_icon: Any = None


def _load_tray_icon() -> Any:
    """Load tray icon from static/images/tray-icon.png.

    Falls back to generating an icon if the file is not found.

    Returns:
        PIL Image suitable for system tray icon.
    """
    from PIL import Image

    from chatfilter.utils.paths import get_base_path

    icon_path = get_base_path() / "static" / "images" / "tray-icon.png"

    if icon_path.exists():
        logger.debug(f"Loading tray icon from {icon_path}")
        return Image.open(icon_path)
    else:
        logger.warning(f"Tray icon not found at {icon_path}, generating fallback")
        return _generate_fallback_icon()


def _generate_fallback_icon() -> Any:
    """Generate a fallback tray icon using Pillow.

    Creates a simple icon with a bar chart representation.
    Used only when tray-icon.png is not available.

    Returns:
        PIL Image suitable for system tray icon.
    """
    from PIL import Image, ImageDraw

    # Create a 64x64 RGBA image with transparent background
    size = 64
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Draw a simple bar chart representation
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
    pystray_module: Any,
    host: str = "127.0.0.1",
    port: int = 8000,
    on_exit: Callable[[], None] | None = None,
) -> Any:
    """Create and configure the system tray icon.

    Args:
        pystray_module: The loaded pystray module.
        host: Server host for "Open in Browser" action.
        port: Server port for "Open in Browser" action.
        on_exit: Optional callback to execute on exit. If None, stops the icon.

    Returns:
        Configured pystray Icon instance (not yet running).
    """
    Icon = pystray_module.Icon
    Menu = pystray_module.Menu
    MenuItem = pystray_module.MenuItem

    url = f"http://{host}:{port}"

    def open_browser(icon: IconType, item: Any) -> None:
        """Open ChatFilter in the default web browser."""
        logger.info(f"Opening browser: {url}")
        webbrowser.open(url)

    def exit_app(icon: IconType, item: Any) -> None:
        """Exit the application by triggering graceful shutdown."""
        logger.info("Exit requested from tray menu")
        icon.stop()
        if on_exit:
            on_exit()
        else:
            # Default behavior: send SIGINT to trigger uvicorn graceful shutdown
            logger.info("Sending SIGINT for graceful shutdown")
            os.kill(os.getpid(), signal.SIGINT)

    # Load icon image from file (with fallback to generated)
    icon_image = _load_tray_icon()

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
    timeout: float = 5.0,
) -> Any:
    """Start the system tray icon in a background thread with timeout.

    Creates and starts the tray icon using run_detached(), which runs
    the icon in a separate thread without blocking the main thread.

    On headless environments (no GUI), logs a warning and skips tray creation.
    The application continues to work normally without the tray icon.

    If tray initialization takes longer than timeout, the function returns
    None and the app continues without tray support (graceful degradation).

    Args:
        host: Server host for "Open in Browser" action.
        port: Server port for "Open in Browser" action.
        on_exit: Optional callback to execute on exit.
        timeout: Maximum seconds to wait for tray initialization (default: 5.0).

    Returns:
        The running Icon instance, or None if tray is not supported,
        running in a headless environment, or initialization timed out.
    """
    from concurrent.futures import ThreadPoolExecutor
    from concurrent.futures import TimeoutError as FuturesTimeoutError

    global _running_icon

    # Check for headless environment before attempting tray creation
    if not _is_gui_available():
        logger.warning(
            "No GUI environment detected — tray icon disabled. Application continues without tray."
        )
        return None

    # Lazy load pystray only when GUI is available
    pystray_module = _load_pystray()
    if pystray_module is None:
        logger.warning("pystray module not available. Application continues without tray.")
        return None

    def _init_tray() -> Any:
        """Initialize tray in a separate thread to detect hangs."""
        _log_platform_info(pystray_module)
        icon = create_tray_icon(pystray_module, host=host, port=port, on_exit=on_exit)
        icon.run_detached()
        return icon

    try:
        # Run tray initialization with timeout to prevent app hangs
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_init_tray)
            try:
                icon = future.result(timeout=timeout)
                _running_icon = icon
                logger.info("Tray icon started")
                return icon
            except FuturesTimeoutError:
                logger.warning(
                    f"Tray initialization timed out after {timeout}s. "
                    "This may happen on macOS with AppTranslocation or sandboxed environments. "
                    "Application continues without tray."
                )
                return None
    except Exception as e:
        logger.warning(f"Failed to start tray icon: {e}. Application continues without tray.")
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

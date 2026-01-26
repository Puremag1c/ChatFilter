"""System tray icon functionality for ChatFilter.

Provides system tray integration with menu for quick access to common actions.
"""

from __future__ import annotations

import logging
import webbrowser
from collections.abc import Callable
from typing import TYPE_CHECKING

from PIL import Image, ImageDraw
from pystray import Icon, Menu, MenuItem

if TYPE_CHECKING:
    from pystray import Icon as IconType

logger = logging.getLogger(__name__)


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
        """Exit the application."""
        logger.info("Exit requested from tray menu")
        icon.stop()
        if on_exit:
            on_exit()

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

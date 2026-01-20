"""Path utilities for PyInstaller compatibility.

This module provides utilities for resolving paths that work correctly
both in development and when bundled with PyInstaller.
"""

from __future__ import annotations

import sys
from pathlib import Path


def get_base_path() -> Path:
    """Get the base application path.

    Returns the correct base path whether running in development or
    frozen (PyInstaller) mode.

    In PyInstaller:
    - sys._MEIPASS: temporary directory where bundled files are extracted
    - Use this for accessing data files (templates, static, certificates)

    In development:
    - Returns the package directory (chatfilter package root)

    Returns:
        Path: Base directory for the application

    Example:
        ```python
        base = get_base_path()
        templates = base / "templates"
        static = base / "static"
        ```
    """
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        # Running in PyInstaller bundle
        # sys._MEIPASS is the temp directory where PyInstaller extracts files
        base = Path(sys._MEIPASS)  # type: ignore[attr-defined]
        # PyInstaller extracts to _MEIPASS/chatfilter/templates, etc.
        # Return the chatfilter subdirectory
        return base / "chatfilter"
    else:
        # Running in development
        # Return the chatfilter package directory
        return Path(__file__).parent.parent


def get_application_path() -> Path:
    """Get the actual application executable path.

    Returns the directory containing the application executable or script.
    Use this for locating configuration files, logs, or user data that should
    be near the executable, not for bundled resources.

    Returns:
        Path: Directory containing the application executable

    Example:
        ```python
        app_dir = get_application_path()
        config_file = app_dir / "config.ini"
        log_file = app_dir / "app.log"
        ```
    """
    if getattr(sys, 'frozen', False):
        # Running in PyInstaller bundle
        # sys.executable is the path to the bundled executable
        return Path(sys.executable).parent
    else:
        # Running in development
        # Return the project root (parent of src)
        return Path(__file__).parent.parent.parent.parent


def is_frozen() -> bool:
    """Check if application is running in frozen (PyInstaller) mode.

    Returns:
        bool: True if running as PyInstaller bundle, False otherwise

    Example:
        ```python
        if is_frozen():
            print("Running as standalone executable")
        else:
            print("Running in development mode")
        ```
    """
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')

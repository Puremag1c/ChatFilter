"""Diagnostic information collector for user support and troubleshooting."""

from __future__ import annotations

import json
import logging
import platform
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from chatfilter.config import Settings

logger = logging.getLogger(__name__)


def get_os_info() -> dict[str, str]:
    """Get operating system information.

    Returns:
        Dictionary with OS details (system, release, version, machine)
    """
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "platform": platform.platform(),
    }


def get_python_info() -> dict[str, str]:
    """Get Python runtime information.

    Returns:
        Dictionary with Python version and implementation details
    """
    return {
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "compiler": platform.python_compiler(),
    }


def get_dependency_versions() -> str:
    """Get installed dependency versions using pip freeze.

    Returns:
        String containing pip freeze output, or error message if unavailable
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout
        return f"Error getting dependencies (exit code {result.returncode}): {result.stderr}"
    except subprocess.TimeoutExpired:
        return "Error: pip freeze command timed out"
    except Exception as e:
        return f"Error getting dependencies: {e}"


def get_disk_space(path: Path) -> dict[str, Any]:
    """Get disk space information for a given path.

    Args:
        path: Path to check disk space for

    Returns:
        Dictionary with total, used, and free space in bytes and human-readable format
    """
    try:
        stat = shutil.disk_usage(path)
        return {
            "total_bytes": stat.total,
            "used_bytes": stat.used,
            "free_bytes": stat.free,
            "total_gb": round(stat.total / (1024**3), 2),
            "used_gb": round(stat.used / (1024**3), 2),
            "free_gb": round(stat.free / (1024**3), 2),
            "percent_used": round((stat.used / stat.total) * 100, 1),
        }
    except Exception as e:
        logger.warning(f"Failed to get disk space for {path}: {e}")
        return {"error": str(e)}


def sanitize_config(settings: Settings) -> dict[str, Any]:
    """Get sanitized configuration without secrets.

    Removes sensitive information like API credentials and passwords
    while preserving useful configuration details.

    Args:
        settings: Application settings instance

    Returns:
        Dictionary with sanitized configuration
    """
    return {
        "host": settings.host,
        "port": settings.port,
        "debug": settings.debug,
        "log_level": settings.log_level,
        "log_to_file": settings.log_to_file,
        "data_dir": str(settings.data_dir),
        "sessions_dir": str(settings.sessions_dir),
        "exports_dir": str(settings.exports_dir),
        "log_dir": str(settings.log_dir),
        "max_messages_limit": settings.max_messages_limit,
        "connect_timeout": settings.connect_timeout,
        "operation_timeout": settings.operation_timeout,
        "heartbeat_interval": settings.heartbeat_interval,
        "heartbeat_timeout": settings.heartbeat_timeout,
        "heartbeat_max_failures": settings.heartbeat_max_failures,
        "stale_task_threshold_hours": settings.stale_task_threshold_hours,
    }


def get_recent_logs(log_file_path: Path, max_lines: int = 100) -> str:
    """Get recent log entries from the log file.

    Args:
        log_file_path: Path to the log file
        max_lines: Maximum number of recent lines to retrieve (default: 100)

    Returns:
        String containing recent log entries, or error message if unavailable
    """
    if not log_file_path.exists():
        return f"Log file not found: {log_file_path}"

    try:
        with open(log_file_path, encoding="utf-8") as f:
            lines = f.readlines()
            recent_lines = lines[-max_lines:] if len(lines) > max_lines else lines
            return "".join(recent_lines)
    except Exception as e:
        logger.warning(f"Failed to read log file {log_file_path}: {e}")
        return f"Error reading log file: {e}"


def collect_diagnostics(settings: Settings) -> dict[str, Any]:
    """Collect all diagnostic information for troubleshooting.

    Gathers:
    - OS information (platform, version)
    - Python version and implementation
    - Dependency versions (pip freeze)
    - Sanitized configuration (without secrets)
    - Recent logs (last 100 lines)
    - Disk space information

    Args:
        settings: Application settings instance

    Returns:
        Dictionary containing all diagnostic information
    """
    from chatfilter import __version__

    logger.info("Collecting diagnostic information")

    diagnostics = {
        "collected_at": datetime.now(UTC).isoformat(),
        "app_version": __version__,
        "os": get_os_info(),
        "python": get_python_info(),
        "dependencies": get_dependency_versions(),
        "config": sanitize_config(settings),
        "disk_space": {
            "data_dir": get_disk_space(settings.data_dir),
        },
    }

    # Add log file info if logging to file is enabled
    if settings.log_to_file and settings.log_file_path.exists():
        diagnostics["logs"] = {
            "recent_entries": get_recent_logs(settings.log_file_path, max_lines=100),
            "log_file_path": str(settings.log_file_path),
        }
    else:
        diagnostics["logs"] = {
            "message": "File logging not enabled or log file does not exist",
        }

    logger.info("Diagnostic information collected successfully")
    return diagnostics


def export_diagnostics_to_json(settings: Settings) -> str:
    """Export diagnostics to a JSON string.

    Args:
        settings: Application settings instance

    Returns:
        JSON string containing all diagnostic information
    """
    diagnostics = collect_diagnostics(settings)
    return json.dumps(diagnostics, indent=2, ensure_ascii=False)


def export_diagnostics_to_text(settings: Settings) -> str:
    """Export diagnostics to a human-readable text format.

    Args:
        settings: Application settings instance

    Returns:
        Formatted text string containing all diagnostic information
    """
    diagnostics = collect_diagnostics(settings)

    lines = [
        "=" * 80,
        "CHATFILTER DIAGNOSTIC REPORT",
        "=" * 80,
        "",
        f"Generated: {diagnostics['collected_at']}",
        f"App Version: {diagnostics['app_version']}",
        "",
        "=" * 80,
        "SYSTEM INFORMATION",
        "=" * 80,
        "",
        f"OS: {diagnostics['os']['system']} {diagnostics['os']['release']}",
        f"Platform: {diagnostics['os']['platform']}",
        f"Machine: {diagnostics['os']['machine']}",
        "",
        f"Python: {diagnostics['python']['version']}",
        f"Implementation: {diagnostics['python']['implementation']}",
        f"Compiler: {diagnostics['python']['compiler']}",
        "",
        "=" * 80,
        "CONFIGURATION (sanitized)",
        "=" * 80,
        "",
    ]

    for key, value in diagnostics["config"].items():
        lines.append(f"{key}: {value}")

    lines.extend(
        [
            "",
            "=" * 80,
            "DISK SPACE",
            "=" * 80,
            "",
        ]
    )

    disk_info = diagnostics["disk_space"]["data_dir"]
    if "error" in disk_info:
        lines.append(f"Error: {disk_info['error']}")
    else:
        lines.append(f"Data Directory: {diagnostics['config']['data_dir']}")
        lines.append(
            f"Total: {disk_info['total_gb']} GB | "
            f"Used: {disk_info['used_gb']} GB ({disk_info['percent_used']}%) | "
            f"Free: {disk_info['free_gb']} GB"
        )

    lines.extend(
        [
            "",
            "=" * 80,
            "INSTALLED DEPENDENCIES",
            "=" * 80,
            "",
            diagnostics["dependencies"],
            "",
            "=" * 80,
            "RECENT LOGS (last 100 lines)",
            "=" * 80,
            "",
        ]
    )

    if "recent_entries" in diagnostics["logs"]:
        lines.append(diagnostics["logs"]["recent_entries"])
    else:
        lines.append(diagnostics["logs"]["message"])

    lines.extend(
        [
            "",
            "=" * 80,
            "END OF DIAGNOSTIC REPORT",
            "=" * 80,
        ]
    )

    return "\n".join(lines)

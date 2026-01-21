"""Port availability checking and utilities."""

from __future__ import annotations

import logging
import socket
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PortInfo:
    """Information about a process using a port."""

    port: int
    pid: int | None = None
    process_name: str | None = None
    command: str | None = None


def is_port_available(host: str, port: int) -> bool:
    """Check if a port is available for binding.

    Args:
        host: Host address to check
        port: Port number to check

    Returns:
        True if port is available, False if in use
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            return True
    except OSError:
        return False


def find_available_port(
    host: str = "127.0.0.1",
    start_port: int = 8000,
    end_port: int = 9000,
) -> int | None:
    """Find an available port in the given range.

    Args:
        host: Host address to check
        start_port: Starting port number (inclusive)
        end_port: Ending port number (inclusive)

    Returns:
        First available port number, or None if no ports available
    """
    for port in range(start_port, end_port + 1):
        if is_port_available(host, port):
            return port
    return None


def get_port_info(port: int) -> PortInfo | None:
    """Get information about the process using a port.

    Uses lsof on Unix-like systems to find the process using the port.

    Args:
        port: Port number to check

    Returns:
        PortInfo with process details, or None if port is free or info unavailable

    Note:
        This function is Unix/macOS-specific. On Windows, returns minimal info.
    """
    import sys

    if sys.platform == "win32":
        return _get_port_info_windows(port)
    else:
        return _get_port_info_unix(port)


def _get_port_info_unix(port: int) -> PortInfo | None:
    """Get port info on Unix-like systems using lsof."""
    try:
        # Run lsof to find process using the port
        result = subprocess.run(
            ["lsof", "-i", f":{port}", "-t", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=2,
        )

        if result.returncode != 0 or not result.stdout.strip():
            # Port is free or lsof failed
            return None

        pid = int(result.stdout.strip().split()[0])

        # Get process name
        try:
            ps_result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm="],
                capture_output=True,
                text=True,
                timeout=1,
            )
            process_name = ps_result.stdout.strip() if ps_result.returncode == 0 else None
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            process_name = None

        # Get full command
        try:
            ps_cmd_result = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="],
                capture_output=True,
                text=True,
                timeout=1,
            )
            command = ps_cmd_result.stdout.strip() if ps_cmd_result.returncode == 0 else None
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            command = None

        return PortInfo(
            port=port,
            pid=pid,
            process_name=process_name,
            command=command,
        )

    except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError) as e:
        logger.debug(f"Failed to get port info: {e}")
        return None
    except FileNotFoundError:
        # lsof not available
        logger.debug("lsof command not found")
        return None


def _get_port_info_windows(port: int) -> PortInfo | None:
    """Get port info on Windows using netstat."""
    try:
        result = subprocess.run(
            ["netstat", "-ano", "-p", "TCP"],
            capture_output=True,
            text=True,
            timeout=2,
        )

        if result.returncode != 0:
            return None

        # Parse netstat output to find the port
        for line in result.stdout.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                parts = line.split()
                if len(parts) >= 5:
                    pid = int(parts[-1])
                    return PortInfo(port=port, pid=pid)

        return None

    except (subprocess.TimeoutExpired, subprocess.SubprocessError, ValueError) as e:
        logger.debug(f"Failed to get port info on Windows: {e}")
        return None


def format_port_conflict_message(host: str, port: int) -> str:
    """Format a user-friendly message about port conflict.

    Args:
        host: Host address
        port: Port number that's in use

    Returns:
        Formatted error message with suggestions
    """
    message = f"Port {port} is already in use on {host}"

    # Try to get process info
    port_info = get_port_info(port)
    if port_info and port_info.pid:
        message += f"\n  Process: {port_info.process_name or 'unknown'} (PID: {port_info.pid})"
        if port_info.command:
            # Truncate long commands
            cmd = port_info.command
            if len(cmd) > 80:
                cmd = cmd[:77] + "..."
            message += f"\n  Command: {cmd}"

    # Find alternative port
    alt_port = find_available_port(host, port + 1, port + 100)
    if alt_port:
        message += f"\n\n→ Fix: Use port {alt_port} instead (available)"
        message += f"\n  Example: chatfilter --port {alt_port}"
    else:
        message += "\n\n→ Fix: Stop the process using this port or choose a different port"

    # Add hint for finding the process
    import sys

    if sys.platform != "win32":
        message += f"\n  Hint: Run 'lsof -i :{port}' to see details about the process"
    else:
        message += f"\n  Hint: Run 'netstat -ano | findstr :{port}' to see details"

    return message

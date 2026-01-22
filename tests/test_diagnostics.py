"""Tests for diagnostics module."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from chatfilter.diagnostics import (
    collect_diagnostics,
    export_diagnostics_to_json,
    export_diagnostics_to_text,
    get_dependency_versions,
    get_disk_space,
    get_os_info,
    get_python_info,
    get_recent_logs,
    sanitize_config,
)


def test_get_os_info():
    """Test get_os_info returns expected OS information."""
    os_info = get_os_info()

    assert "system" in os_info
    assert "release" in os_info
    assert "version" in os_info
    assert "machine" in os_info
    assert "platform" in os_info

    # Verify all values are strings
    assert all(isinstance(v, str) for v in os_info.values())

    # Verify system is a valid OS name
    assert os_info["system"] in ("Linux", "Darwin", "Windows", "Java")


def test_get_python_info():
    """Test get_python_info returns expected Python runtime information."""
    python_info = get_python_info()

    assert "version" in python_info
    assert "implementation" in python_info
    assert "compiler" in python_info

    # Verify all values are strings
    assert all(isinstance(v, str) for v in python_info.values())

    # Verify version has expected format (e.g., "3.11.0")
    version_parts = python_info["version"].split(".")
    assert len(version_parts) >= 2
    assert all(part.isdigit() for part in version_parts[:2])


@patch("chatfilter.diagnostics.subprocess.run")
def test_get_dependency_versions_success(mock_run):
    """Test get_dependency_versions with successful pip freeze."""
    mock_run.return_value = Mock(
        returncode=0,
        stdout="package1==1.0.0\npackage2==2.0.0\n",
        stderr="",
    )

    result = get_dependency_versions()

    assert "package1==1.0.0" in result
    assert "package2==2.0.0" in result
    mock_run.assert_called_once()


@patch("chatfilter.diagnostics.subprocess.run")
def test_get_dependency_versions_error(mock_run):
    """Test get_dependency_versions with pip error."""
    mock_run.return_value = Mock(
        returncode=1,
        stdout="",
        stderr="pip error message",
    )

    result = get_dependency_versions()

    assert "Error getting dependencies" in result
    assert "exit code 1" in result


@patch("chatfilter.diagnostics.subprocess.run")
def test_get_dependency_versions_timeout(mock_run):
    """Test get_dependency_versions with timeout."""
    mock_run.side_effect = subprocess.TimeoutExpired(cmd="pip freeze", timeout=10)

    result = get_dependency_versions()

    assert "timed out" in result


@patch("chatfilter.diagnostics.subprocess.run")
def test_get_dependency_versions_exception(mock_run):
    """Test get_dependency_versions with unexpected exception."""
    mock_run.side_effect = Exception("Unexpected error")

    result = get_dependency_versions()

    assert "Error getting dependencies" in result
    assert "Unexpected error" in result


def test_get_disk_space_success(isolated_tmp_dir: Path):
    """Test get_disk_space with valid path."""
    disk_space = get_disk_space(isolated_tmp_dir)

    # Verify all expected keys are present
    assert "total_bytes" in disk_space
    assert "used_bytes" in disk_space
    assert "free_bytes" in disk_space
    assert "total_gb" in disk_space
    assert "used_gb" in disk_space
    assert "free_gb" in disk_space
    assert "percent_used" in disk_space

    # Verify values are reasonable
    assert disk_space["total_bytes"] > 0
    assert disk_space["used_bytes"] >= 0
    assert disk_space["free_bytes"] > 0
    assert disk_space["total_gb"] > 0
    assert 0 <= disk_space["percent_used"] <= 100


@patch("chatfilter.diagnostics.shutil.disk_usage")
def test_get_disk_space_error(mock_disk_usage, isolated_tmp_dir: Path):
    """Test get_disk_space with error."""
    mock_disk_usage.side_effect = OSError("Disk error")

    disk_space = get_disk_space(isolated_tmp_dir)

    assert "error" in disk_space
    assert "Disk error" in disk_space["error"]


def test_sanitize_config():
    """Test sanitize_config removes sensitive information."""
    # Create a mock settings object
    mock_settings = MagicMock()
    mock_settings.host = "localhost"
    mock_settings.port = 8000
    mock_settings.debug = True
    mock_settings.log_level = "INFO"
    mock_settings.log_to_file = True
    mock_settings.data_dir = Path("/data")
    mock_settings.sessions_dir = Path("/sessions")
    mock_settings.exports_dir = Path("/exports")
    mock_settings.log_dir = Path("/logs")
    mock_settings.max_messages_limit = 1000
    mock_settings.connect_timeout = 30
    mock_settings.operation_timeout = 60
    mock_settings.heartbeat_interval = 5
    mock_settings.heartbeat_timeout = 15
    mock_settings.heartbeat_max_failures = 3
    mock_settings.stale_task_threshold_hours = 24

    config = sanitize_config(mock_settings)

    # Verify expected keys are present
    assert config["host"] == "localhost"
    assert config["port"] == 8000
    assert config["debug"] is True
    assert config["log_level"] == "INFO"
    # Use str(Path) to get platform-appropriate path separator
    assert config["data_dir"] == str(mock_settings.data_dir)

    # Verify sensitive fields are NOT present (they shouldn't be in the function)
    # The function should only include non-sensitive configuration
    assert "api_id" not in config
    assert "api_hash" not in config
    assert "password" not in config


def test_get_recent_logs_file_exists(isolated_tmp_dir: Path):
    """Test get_recent_logs with existing log file."""
    log_file = isolated_tmp_dir / "test.log"
    log_content = "\n".join([f"Log line {i}" for i in range(150)])
    log_file.write_text(log_content)

    result = get_recent_logs(log_file, max_lines=100)

    # Verify we get the last 100 lines
    lines = result.strip().split("\n")
    assert len(lines) == 100
    assert lines[-1] == "Log line 149"


def test_get_recent_logs_file_not_exists(isolated_tmp_dir: Path):
    """Test get_recent_logs with non-existent log file."""
    log_file = isolated_tmp_dir / "nonexistent.log"

    result = get_recent_logs(log_file)

    assert "Log file not found" in result


def test_get_recent_logs_small_file(isolated_tmp_dir: Path):
    """Test get_recent_logs with file smaller than max_lines."""
    log_file = isolated_tmp_dir / "small.log"
    log_content = "\n".join([f"Log line {i}" for i in range(10)])
    log_file.write_text(log_content)

    result = get_recent_logs(log_file, max_lines=100)

    # Verify we get all lines
    lines = result.strip().split("\n")
    assert len(lines) == 10


@patch("chatfilter.diagnostics.open")
def test_get_recent_logs_read_error(mock_open, isolated_tmp_dir: Path):
    """Test get_recent_logs with read error."""
    log_file = isolated_tmp_dir / "test.log"
    log_file.write_text("test")  # Create the file so exists() returns True

    # Mock open to raise an exception
    mock_open.side_effect = OSError("Permission denied")

    result = get_recent_logs(log_file)

    assert "Error reading log file" in result
    assert "Permission denied" in result


@patch("chatfilter.diagnostics.get_os_info")
@patch("chatfilter.diagnostics.get_python_info")
@patch("chatfilter.diagnostics.get_dependency_versions")
@patch("chatfilter.diagnostics.get_disk_space")
@patch("chatfilter.diagnostics.sanitize_config")
@patch("chatfilter.diagnostics.get_recent_logs")
def test_collect_diagnostics_with_logs(
    mock_get_logs,
    mock_sanitize,
    mock_disk,
    mock_deps,
    mock_python,
    mock_os,
    isolated_tmp_dir: Path,
):
    """Test collect_diagnostics with logging enabled."""
    # Setup mocks
    mock_os.return_value = {"system": "Linux"}
    mock_python.return_value = {"version": "3.11"}
    mock_deps.return_value = "package==1.0.0"
    mock_disk.return_value = {"total_gb": 100}
    mock_sanitize.return_value = {"host": "localhost"}
    mock_get_logs.return_value = "Log content"

    # Create mock settings
    mock_settings = MagicMock()
    mock_settings.data_dir = isolated_tmp_dir
    mock_settings.log_to_file = True
    mock_settings.log_file_path = isolated_tmp_dir / "test.log"
    mock_settings.log_file_path.write_text("test log")

    # Collect diagnostics
    with patch("chatfilter.__version__", "1.0.0"):
        diagnostics = collect_diagnostics(mock_settings)

    # Verify structure
    assert "collected_at" in diagnostics
    assert "app_version" in diagnostics
    assert diagnostics["app_version"] == "1.0.0"
    assert diagnostics["os"] == {"system": "Linux"}
    assert diagnostics["python"] == {"version": "3.11"}
    assert diagnostics["dependencies"] == "package==1.0.0"
    assert diagnostics["config"] == {"host": "localhost"}
    assert diagnostics["disk_space"]["data_dir"] == {"total_gb": 100}
    assert "logs" in diagnostics
    assert diagnostics["logs"]["recent_entries"] == "Log content"


@patch("chatfilter.diagnostics.get_os_info")
@patch("chatfilter.diagnostics.get_python_info")
@patch("chatfilter.diagnostics.get_dependency_versions")
@patch("chatfilter.diagnostics.get_disk_space")
@patch("chatfilter.diagnostics.sanitize_config")
def test_collect_diagnostics_without_logs(
    mock_sanitize,
    mock_disk,
    mock_deps,
    mock_python,
    mock_os,
    isolated_tmp_dir: Path,
):
    """Test collect_diagnostics with logging disabled."""
    # Setup mocks
    mock_os.return_value = {"system": "Linux"}
    mock_python.return_value = {"version": "3.11"}
    mock_deps.return_value = "package==1.0.0"
    mock_disk.return_value = {"total_gb": 100}
    mock_sanitize.return_value = {"host": "localhost"}

    # Create mock settings
    mock_settings = MagicMock()
    mock_settings.data_dir = isolated_tmp_dir
    mock_settings.log_to_file = False
    mock_settings.log_file_path = isolated_tmp_dir / "test.log"

    # Collect diagnostics
    with patch("chatfilter.__version__", "1.0.0"):
        diagnostics = collect_diagnostics(mock_settings)

    # Verify logs message
    assert "logs" in diagnostics
    assert "message" in diagnostics["logs"]
    assert "not enabled" in diagnostics["logs"]["message"]


@patch("chatfilter.diagnostics.collect_diagnostics")
def test_export_diagnostics_to_json(mock_collect):
    """Test export_diagnostics_to_json."""
    mock_collect.return_value = {
        "app_version": "1.0.0",
        "os": {"system": "Linux"},
    }

    mock_settings = MagicMock()
    result = export_diagnostics_to_json(mock_settings)

    # Verify it's valid JSON
    parsed = json.loads(result)
    assert parsed["app_version"] == "1.0.0"
    assert parsed["os"]["system"] == "Linux"

    # Verify JSON is formatted with indentation
    assert "\n" in result


@patch("chatfilter.diagnostics.collect_diagnostics")
def test_export_diagnostics_to_text(mock_collect, isolated_tmp_dir: Path):
    """Test export_diagnostics_to_text."""
    mock_collect.return_value = {
        "collected_at": "2025-01-21T12:00:00Z",
        "app_version": "1.0.0",
        "os": {
            "system": "Linux",
            "release": "5.15.0",
            "platform": "Linux-5.15.0-x86_64",
            "machine": "x86_64",
        },
        "python": {
            "version": "3.11.0",
            "implementation": "CPython",
            "compiler": "GCC 11.2.0",
        },
        "config": {
            "host": "localhost",
            "port": 8000,
            "data_dir": "/data",
        },
        "disk_space": {
            "data_dir": {
                "total_gb": 100.0,
                "used_gb": 50.0,
                "free_gb": 50.0,
                "percent_used": 50.0,
            }
        },
        "dependencies": "package1==1.0.0\npackage2==2.0.0",
        "logs": {
            "recent_entries": "Log line 1\nLog line 2",
        },
    }

    mock_settings = MagicMock()
    result = export_diagnostics_to_text(mock_settings)

    # Verify key sections are present
    assert "CHATFILTER DIAGNOSTIC REPORT" in result
    assert "SYSTEM INFORMATION" in result
    assert "CONFIGURATION" in result
    assert "DISK SPACE" in result
    assert "INSTALLED DEPENDENCIES" in result
    assert "RECENT LOGS" in result

    # Verify specific values
    assert "1.0.0" in result
    assert "Linux" in result
    assert "3.11.0" in result
    assert "localhost" in result
    assert "package1==1.0.0" in result
    assert "Log line 1" in result


@patch("chatfilter.diagnostics.collect_diagnostics")
def test_export_diagnostics_to_text_with_disk_error(mock_collect):
    """Test export_diagnostics_to_text with disk space error."""
    mock_collect.return_value = {
        "collected_at": "2025-01-21T12:00:00Z",
        "app_version": "1.0.0",
        "os": {"system": "Linux", "release": "5.15.0", "platform": "Linux", "machine": "x86_64"},
        "python": {"version": "3.11.0", "implementation": "CPython", "compiler": "GCC"},
        "config": {"data_dir": "/data"},
        "disk_space": {"data_dir": {"error": "Disk error"}},
        "dependencies": "package==1.0.0",
        "logs": {"message": "Logging not enabled"},
    }

    mock_settings = MagicMock()
    result = export_diagnostics_to_text(mock_settings)

    # Verify error is displayed
    assert "Error: Disk error" in result


@patch("chatfilter.diagnostics.collect_diagnostics")
def test_export_diagnostics_to_text_without_logs(mock_collect):
    """Test export_diagnostics_to_text with no log entries."""
    mock_collect.return_value = {
        "collected_at": "2025-01-21T12:00:00Z",
        "app_version": "1.0.0",
        "os": {"system": "Linux", "release": "5.15.0", "platform": "Linux", "machine": "x86_64"},
        "python": {"version": "3.11.0", "implementation": "CPython", "compiler": "GCC"},
        "config": {"data_dir": "/data"},
        "disk_space": {
            "data_dir": {"total_gb": 100.0, "used_gb": 50.0, "free_gb": 50.0, "percent_used": 50.0}
        },
        "dependencies": "",
        "logs": {"message": "File logging not enabled"},
    }

    mock_settings = MagicMock()
    result = export_diagnostics_to_text(mock_settings)

    # Verify message is displayed
    assert "File logging not enabled" in result

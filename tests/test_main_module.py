"""Comprehensive tests for src/chatfilter/main.py module.

Tests cover:
- setup_logging function with various configurations
- main function with different CLI arguments
- Error handling and edge cases
- File logging with rotation
- Module-level logging configuration
- CLI argument parsing
- Configuration validation flows
- Self-test flows
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chatfilter import __version__
from chatfilter.main import main, setup_logging


@pytest.fixture(autouse=True)
def reset_logging() -> Generator[None, None, None]:
    """Reset logging state between tests to prevent interference."""
    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers.copy()
    original_level = root_logger.level

    yield

    # Restore original state
    root_logger.handlers = original_handlers
    root_logger.setLevel(original_level)


@pytest.fixture
def temp_log_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for log files."""
    log_dir = tmp_path / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


@pytest.fixture
def mock_settings():
    """Create a mock Settings object with common defaults."""
    mock_settings_obj = MagicMock()
    mock_settings_obj.host = "127.0.0.1"
    mock_settings_obj.port = 8080
    mock_settings_obj.debug = False
    mock_settings_obj.data_dir = Path("/tmp/chatfilter")
    mock_settings_obj.sessions_dir = Path("/tmp/chatfilter/sessions")
    mock_settings_obj.exports_dir = Path("/tmp/chatfilter/exports")
    mock_settings_obj.log_level = "INFO"
    mock_settings_obj.log_format = "text"
    mock_settings_obj.verbose = False
    mock_settings_obj.log_to_file = False
    mock_settings_obj.log_file_path = None
    mock_settings_obj.log_file_max_bytes = 10485760
    mock_settings_obj.log_file_backup_count = 5
    mock_settings_obj.log_module_levels = None
    mock_settings_obj.validate.return_value = []
    mock_settings_obj.check.return_value = []
    mock_settings_obj.is_first_run.return_value = False
    mock_settings_obj.ensure_data_dirs.return_value = []
    mock_settings_obj.mark_first_run_complete.return_value = None
    mock_settings_obj.print_config.return_value = None
    return mock_settings_obj


@contextmanager
def mock_main_dependencies(mock_settings_obj, capture_uvicorn_call: MagicMock | None = None):
    """Context manager to mock all main() dependencies.

    Mocks configuration and uvicorn to allow tests to run in CI environments.

    Args:
        mock_settings_obj: Mock settings object
        capture_uvicorn_call: Optional MagicMock to capture uvicorn.run call args
    """
    mock_uvicorn = capture_uvicorn_call if capture_uvicorn_call else MagicMock()

    with (
        patch("chatfilter.config.get_settings", return_value=mock_settings_obj),
        patch("chatfilter.config.Settings", return_value=mock_settings_obj),
        patch("chatfilter.config.reset_settings"),
        patch("uvicorn.run", mock_uvicorn),
    ):
        yield mock_uvicorn


# ============================================================================
# Tests for setup_logging function
# ============================================================================


class TestSetupLogging:
    """Test suite for setup_logging function."""

    def test_setup_logging_console_only_default(self) -> None:
        """Test logging setup with console output only (default behavior)."""
        setup_logging(level="INFO", debug=False, log_to_file=False)

        root_logger = logging.getLogger()

        # Should have one handler (console)
        assert len(root_logger.handlers) == 1
        assert isinstance(root_logger.handlers[0], logging.StreamHandler)
        assert root_logger.level == logging.INFO

    def test_setup_logging_debug_mode_overrides_level(self) -> None:
        """Test that debug=True overrides the level parameter to DEBUG."""
        setup_logging(level="INFO", debug=True, log_to_file=False)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_verbose_mode_enables_debug(self) -> None:
        """Test that verbose=True enables DEBUG level."""
        setup_logging(level="INFO", verbose=True, log_to_file=False)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_warning_level(self) -> None:
        """Test logging setup with WARNING level."""
        setup_logging(level="WARNING", debug=False, log_to_file=False)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.WARNING

    def test_setup_logging_error_level(self) -> None:
        """Test logging setup with ERROR level."""
        setup_logging(level="ERROR", debug=False, log_to_file=False)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.ERROR

    def test_setup_logging_invalid_level_falls_back_to_info(self) -> None:
        """Test that invalid log level falls back to INFO."""
        setup_logging(level="INVALID", debug=False, log_to_file=False)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.INFO

    def test_setup_logging_clears_existing_handlers(self) -> None:
        """Test that setup_logging clears existing handlers to avoid duplicates."""
        root_logger = logging.getLogger()
        # Add a dummy handler
        dummy_handler = logging.StreamHandler()
        root_logger.addHandler(dummy_handler)
        initial_count = len(root_logger.handlers)
        assert initial_count >= 1

        setup_logging(level="INFO", debug=False, log_to_file=False)

        # Should only have the new console handler
        assert len(root_logger.handlers) == 1

    def test_setup_logging_with_file_creates_handlers(self, temp_log_dir: Path) -> None:
        """Test logging setup with file handler creates both console and file handlers."""
        log_file = temp_log_dir / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
            log_file_max_bytes=1024,
            log_file_backup_count=3,
        )

        root_logger = logging.getLogger()

        # Should have two handlers (console + file)
        assert len(root_logger.handlers) == 2

    def test_setup_logging_file_handler_configuration(self, temp_log_dir: Path) -> None:
        """Test that file handler is configured with correct rotation settings."""
        from logging.handlers import RotatingFileHandler

        log_file = temp_log_dir / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
            log_file_max_bytes=2048,
            log_file_backup_count=7,
        )

        root_logger = logging.getLogger()

        # Find the file handler
        file_handlers = [h for h in root_logger.handlers if isinstance(h, RotatingFileHandler)]
        assert len(file_handlers) == 1

        file_handler = file_handlers[0]
        assert file_handler.maxBytes == 2048
        assert file_handler.backupCount == 7

    def test_setup_logging_file_creates_log_directory(self, tmp_path: Path) -> None:
        """Test that setup_logging creates parent directories for log file."""
        log_file = tmp_path / "nested" / "dirs" / "test.log"
        assert not log_file.parent.exists()

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        assert log_file.parent.exists()
        assert log_file.parent.is_dir()

    def test_setup_logging_file_writes_to_file(self, temp_log_dir: Path) -> None:
        """Test that file logging actually writes log messages to the file."""
        log_file = temp_log_dir / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        # Write a test log message
        test_logger = logging.getLogger("test")
        test_logger.info("Test message for file logging")

        assert log_file.exists()
        content = log_file.read_text()
        assert "Test message for file logging" in content

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="Unix file permissions not applicable on Windows",
    )
    def test_setup_logging_file_permission_error_graceful_degradation(self, tmp_path: Path) -> None:
        """Test that permission errors on file logging degrade gracefully to console-only."""
        # Create a read-only directory
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        readonly_dir.chmod(0o444)

        log_file = readonly_dir / "test.log"

        try:
            # Should not raise an exception, should fall back to console-only
            setup_logging(
                level="INFO",
                debug=False,
                log_to_file=True,
                log_file_path=log_file,
            )

            root_logger = logging.getLogger()
            # Should only have console handler due to permission error
            assert len(root_logger.handlers) == 1
        finally:
            # Cleanup: restore permissions
            readonly_dir.chmod(0o755)

    def test_setup_logging_json_format(self) -> None:
        """Test logging setup with JSON formatter."""
        setup_logging(level="INFO", debug=False, log_to_file=False, log_format="json")

        root_logger = logging.getLogger()
        handler = root_logger.handlers[0]

        from chatfilter.utils.logging import JSONFormatter

        assert isinstance(handler.formatter, JSONFormatter)

    def test_setup_logging_text_format(self) -> None:
        """Test logging setup with text formatter (default)."""
        setup_logging(level="INFO", debug=False, log_to_file=False, log_format="text")

        root_logger = logging.getLogger()
        handler = root_logger.handlers[0]

        from chatfilter.utils.logging import SanitizingFormatter

        assert isinstance(handler.formatter, SanitizingFormatter)

    def test_setup_logging_adds_filters_to_handlers(self) -> None:
        """Test that setup_logging adds required filters to all handlers."""
        setup_logging(level="INFO", debug=False, log_to_file=False)

        root_logger = logging.getLogger()
        handler = root_logger.handlers[0]

        # Should have filters added
        assert len(handler.filters) == 3

        from chatfilter.utils.logging import ChatContextFilter, CorrelationIDFilter, LogSanitizer

        filter_types = [type(f) for f in handler.filters]
        assert LogSanitizer in filter_types
        assert CorrelationIDFilter in filter_types
        assert ChatContextFilter in filter_types

    def test_setup_logging_module_levels_configuration(self) -> None:
        """Test that module-level log levels are configured correctly."""
        module_levels = {
            "chatfilter.telegram": "DEBUG",
            "chatfilter.web": "WARNING",
        }

        with patch("chatfilter.utils.logging.configure_module_levels") as mock_configure:
            setup_logging(
                level="INFO",
                debug=False,
                log_to_file=False,
                module_levels=module_levels,
            )

            mock_configure.assert_called_once_with(module_levels)

    def test_setup_logging_no_module_levels(self) -> None:
        """Test that module levels are not configured when None."""
        with patch("chatfilter.utils.logging.configure_module_levels") as mock_configure:
            setup_logging(
                level="INFO",
                debug=False,
                log_to_file=False,
                module_levels=None,
            )

            mock_configure.assert_not_called()

    def test_setup_logging_verbose_without_debug_logs_message(self) -> None:
        """Test that verbose mode enables DEBUG level (same as debug)."""
        setup_logging(level="INFO", verbose=True, debug=False, log_to_file=False)

        # Verify that the level is DEBUG (which verbose sets)
        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_debug_and_verbose_both_set_debug_level(self) -> None:
        """Test that when both debug and verbose are True, level is DEBUG."""
        setup_logging(level="INFO", verbose=True, debug=True, log_to_file=False)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_file_with_utf8_encoding(self, temp_log_dir: Path) -> None:
        """Test that file handler uses UTF-8 encoding."""
        from logging.handlers import RotatingFileHandler

        log_file = temp_log_dir / "utf8_test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        root_logger = logging.getLogger()
        file_handlers = [h for h in root_logger.handlers if isinstance(h, RotatingFileHandler)]

        assert len(file_handlers) == 1
        # Check encoding attribute
        assert file_handlers[0].encoding == "utf-8"

    def test_setup_logging_console_outputs_to_stdout(self) -> None:
        """Test that console handler outputs to stdout."""
        setup_logging(level="INFO", debug=False, log_to_file=False)

        root_logger = logging.getLogger()
        console_handler = root_logger.handlers[0]

        assert console_handler.stream == sys.stdout


# ============================================================================
# Tests for main function
# ============================================================================


class TestMain:
    """Test suite for main function."""

    def test_main_version_argument_exits(self, capsys) -> None:
        """Test that --version prints version and exits."""
        with patch.object(sys, "argv", ["chatfilter", "--version"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "ChatFilter" in captured.out
        assert __version__ in captured.out

    def test_main_help_argument_exits(self) -> None:
        """Test that --help prints help and exits."""
        with patch.object(sys, "argv", ["chatfilter", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()

            # argparse exits with 0 for --help
            assert exc_info.value.code == 0

    def test_main_validate_argument_success(self, mock_settings, capsys) -> None:
        """Test --validate argument with valid configuration exits successfully."""
        mock_settings.validate.return_value = []
        mock_settings.check.return_value = []

        with (
            patch.object(sys, "argv", ["chatfilter", "--validate"]),
            mock_main_dependencies(mock_settings),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "Configuration is valid" in captured.out
        mock_settings.print_config.assert_called_once()

    def test_main_validate_argument_with_errors(self, mock_settings, capsys) -> None:
        """Test --validate argument with configuration errors exits with error code."""
        mock_settings.validate.return_value = ["Error: Invalid port", "Error: Bad data dir"]
        mock_settings.check.return_value = []

        with (
            patch.object(sys, "argv", ["chatfilter", "--validate"]),
            mock_main_dependencies(mock_settings),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "Configuration validation failed" in captured.out
        assert "Invalid port" in captured.out
        assert "Bad data dir" in captured.out

    def test_main_validate_argument_with_warnings(self, mock_settings, capsys) -> None:
        """Test --validate argument with warnings but no errors exits successfully."""
        mock_settings.validate.return_value = []
        mock_settings.check.return_value = ["Warning: Using default port", "Warning: Debug mode"]

        with (
            patch.object(sys, "argv", ["chatfilter", "--validate"]),
            mock_main_dependencies(mock_settings),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

            assert exc_info.value.code == 0

        captured = capsys.readouterr()
        assert "Configuration warnings" in captured.out
        assert "Using default port" in captured.out
        assert "Debug mode" in captured.out
        assert "Configuration is valid" in captured.out

    def test_main_check_config_deprecated_still_works(self, mock_settings) -> None:
        """Test that deprecated --check-config still works like --validate."""
        mock_settings.validate.return_value = []
        mock_settings.check.return_value = []

        with (
            patch.object(sys, "argv", ["chatfilter", "--check-config"]),
            mock_main_dependencies(mock_settings),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

            assert exc_info.value.code == 0

    def test_main_self_test_success(self, mock_settings, capsys) -> None:
        """Test --self-test argument with all tests passing exits successfully."""
        mock_self_test = MagicMock()
        mock_self_test.has_failures.return_value = False
        mock_self_test.format_table.return_value = "All tests passed"
        mock_self_test.to_dict.return_value = {"status": "ok"}

        with (
            patch.object(sys, "argv", ["chatfilter", "--self-test"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.self_test.SelfTest", return_value=mock_self_test),
            patch("asyncio.run") as mock_asyncio_run,
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

            assert exc_info.value.code == 0
            mock_asyncio_run.assert_called_once()

        captured = capsys.readouterr()
        assert "RUNNING SELF-TEST DIAGNOSTICS" in captured.out
        assert "All tests passed" in captured.out
        assert "JSON OUTPUT:" in captured.out

    def test_main_self_test_failures(self, mock_settings, capsys) -> None:
        """Test --self-test argument with failures exits with error code."""
        mock_self_test = MagicMock()
        mock_self_test.has_failures.return_value = True
        mock_self_test.format_table.return_value = "Some tests failed"
        mock_self_test.to_dict.return_value = {"status": "failed"}

        with (
            patch.object(sys, "argv", ["chatfilter", "--self-test"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.self_test.SelfTest", return_value=mock_self_test),
            patch("asyncio.run"),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "RUNNING SELF-TEST DIAGNOSTICS" in captured.out

    def test_main_cli_overrides_env_settings(self, mock_settings) -> None:
        """Test that CLI arguments override environment settings."""
        with (
            patch.object(sys, "argv", ["chatfilter", "--host", "0.0.0.0", "--port", "9000"]),
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.config.Settings") as mock_settings_class,
            patch("chatfilter.config.reset_settings"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            patch("uvicorn.run"),
            pytest.raises(SystemExit) as exc_info,
        ):
            mock_settings_class.return_value = mock_settings
            main()

        # Check that Settings was called with CLI overrides
        call_kwargs = mock_settings_class.call_args[1]
        assert call_kwargs["host"] == "0.0.0.0"
        assert call_kwargs["port"] == 9000
        assert exc_info.value.code == 0

    def test_main_calls_setup_logging(self, mock_settings) -> None:
        """Test that main calls setup_logging with correct parameters."""
        mock_settings.log_level = "DEBUG"
        mock_settings.debug = True
        mock_settings.verbose = False
        mock_settings.log_to_file = False
        mock_settings.log_module_levels = {"test": "INFO"}

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.main.setup_logging") as mock_setup_logging,
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        mock_setup_logging.assert_called_once()
        call_kwargs = mock_setup_logging.call_args[1]
        assert call_kwargs["level"] == "DEBUG"
        assert call_kwargs["debug"] is True
        assert call_kwargs["verbose"] is False
        assert exc_info.value.code == 0

    def test_main_validation_failure_before_server_start(self, mock_settings, capsys) -> None:
        """Test that validation errors prevent server from starting."""
        mock_settings.validate.return_value = ["Error: Port in use"]

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings) as mock_uvicorn,
            patch("chatfilter.main.setup_logging"),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

            assert exc_info.value.code == 1
            # uvicorn.run should not be called
            mock_uvicorn.assert_not_called()

        captured = capsys.readouterr()
        assert "Configuration validation failed" in captured.out
        assert "Port in use" in captured.out

    def test_main_readonly_data_dir_auto_relocates(self, mock_settings, capsys) -> None:
        """Test that readonly data directory auto-relocates to safe location."""
        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.main.setup_logging"),
            patch("chatfilter.config._is_path_in_readonly_location") as mock_readonly,
            patch("chatfilter.config._get_default_data_dir") as mock_default_dir,
            pytest.raises(SystemExit) as exc_info,
        ):
            mock_readonly.return_value = (True, "System directory")
            mock_default_dir.return_value = Path("/safe/data/dir")
            main()

        captured = capsys.readouterr()
        assert "NOTICE: Auto-relocating data directory" in captured.out
        assert "System directory" in captured.out
        assert exc_info.value.code == 0

    def test_main_ensure_data_dirs_errors_exit(self, mock_settings, capsys) -> None:
        """Test that errors creating data directories cause exit."""
        mock_settings.ensure_data_dirs.return_value = [
            "Error creating sessions directory",
            "Permission denied for exports",
        ]

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.main.setup_logging"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

            assert exc_info.value.code == 1

        captured = capsys.readouterr()
        assert "ERROR: Failed to create required directories" in captured.out
        assert "Error creating sessions directory" in captured.out
        assert "Permission denied for exports" in captured.out

    def test_main_first_run_shows_welcome_banner(self, mock_settings, capsys) -> None:
        """Test that first run shows welcome banner and setup guide."""
        mock_settings.is_first_run.return_value = True

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.main.setup_logging"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        captured = capsys.readouterr()
        assert "Welcome! This is your first run." in captured.out
        assert "FIRST RUN SETUP GUIDE" in captured.out
        assert "https://my.telegram.org/apps" in captured.out
        assert exc_info.value.code == 0

    def test_main_first_run_marks_complete(self, mock_settings) -> None:
        """Test that first run is marked as complete after successful setup."""
        mock_settings.is_first_run.return_value = True

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.main.setup_logging"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        mock_settings.mark_first_run_complete.assert_called_once()
        assert exc_info.value.code == 0

    def test_main_not_first_run_no_welcome_banner(self, mock_settings, capsys) -> None:
        """Test that subsequent runs don't show the welcome banner."""
        mock_settings.is_first_run.return_value = False

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.main.setup_logging"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        captured = capsys.readouterr()
        assert "Welcome! This is your first run." not in captured.out
        assert "FIRST RUN SETUP GUIDE" not in captured.out
        assert exc_info.value.code == 0

    def test_main_uvicorn_called_with_correct_params(self, mock_settings) -> None:
        """Test that uvicorn.run is called with correct parameters."""
        mock_settings.host = "0.0.0.0"
        mock_settings.port = 9090
        mock_settings.debug = False

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings) as mock_uvicorn_run,
            patch("chatfilter.main.setup_logging"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        mock_uvicorn_run.assert_called_once()
        call_kwargs = mock_uvicorn_run.call_args[1]
        assert call_kwargs["host"] == "0.0.0.0"
        assert call_kwargs["port"] == 9090
        assert call_kwargs["reload"] is False
        assert call_kwargs["log_level"] == "info"
        assert exc_info.value.code == 0

    def test_main_uvicorn_debug_mode_sets_log_level(self, mock_settings) -> None:
        """Test that debug mode sets uvicorn log level to debug and enables reload."""
        mock_settings.debug = True

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings) as mock_uvicorn_run,
            patch("chatfilter.main.setup_logging"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        call_kwargs = mock_uvicorn_run.call_args[1]
        assert call_kwargs["reload"] is True  # Enabled in debug mode
        assert call_kwargs["log_level"] == "debug"
        assert exc_info.value.code == 0

    def test_main_keyboard_interrupt_graceful_shutdown(self, mock_settings, capsys) -> None:
        """Test that KeyboardInterrupt is handled gracefully.

        KeyboardInterrupt comes from uvicorn.run() when user presses Ctrl+C.
        """
        with (
            patch.object(sys, "argv", ["chatfilter"]),
            patch("chatfilter.config.get_settings", return_value=mock_settings),
            patch("chatfilter.config.Settings", return_value=mock_settings),
            patch("chatfilter.config.reset_settings"),
            patch("uvicorn.run", side_effect=KeyboardInterrupt()),
            patch("chatfilter.main.setup_logging"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "Shutting down..." in captured.out

    def test_main_startup_banner_displays_system_info(self, mock_settings, capsys) -> None:
        """Test that startup banner displays correct system information."""
        mock_settings.host = "127.0.0.1"
        mock_settings.port = 8080
        mock_settings.data_dir = Path("/tmp/data")
        mock_settings.sessions_dir = Path("/tmp/data/sessions")
        mock_settings.exports_dir = Path("/tmp/data/exports")
        mock_settings.log_level = "DEBUG"
        mock_settings.log_format = "json"
        mock_settings.verbose = True
        mock_settings.log_to_file = True
        mock_settings.log_file_path = Path("/tmp/data/logs/app.log")

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.main.setup_logging"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit) as exc_info,
        ):
            main()

        captured = capsys.readouterr()
        assert f"ChatFilter v{__version__}" in captured.out
        assert "Server:        http://127.0.0.1:8080" in captured.out
        # Use str(Path) to get platform-appropriate path separator
        assert f"Data dir:      {mock_settings.data_dir}" in captured.out
        assert f"Sessions dir:  {mock_settings.sessions_dir}" in captured.out
        assert f"Exports dir:   {mock_settings.exports_dir}" in captured.out
        assert "Log level:     DEBUG" in captured.out
        assert "Log format:    json" in captured.out
        assert "Verbose:       enabled" in captured.out
        assert f"Log file:      {mock_settings.log_file_path}" in captured.out
        assert exc_info.value.code == 0


# ============================================================================
# Edge cases and integration tests
# ============================================================================


class TestEdgeCases:
    """Test edge cases and unusual scenarios."""

    def test_setup_logging_case_insensitive_level(self) -> None:
        """Test that log level is case-insensitive."""
        for level in ["info", "Info", "INFO", "InFo"]:
            setup_logging(level=level, debug=False, log_to_file=False)
            root_logger = logging.getLogger()
            assert root_logger.level == logging.INFO

    def test_setup_logging_both_debug_and_verbose(self) -> None:
        """Test behavior when both debug and verbose are True."""
        setup_logging(level="INFO", debug=True, verbose=True, log_to_file=False)

        root_logger = logging.getLogger()
        assert root_logger.level == logging.DEBUG

    def test_setup_logging_file_path_with_spaces(self, tmp_path: Path) -> None:
        """Test that log file paths with spaces are handled correctly."""
        log_dir = tmp_path / "path with spaces"
        log_file = log_dir / "test log.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        assert log_file.parent.exists()

    def test_setup_logging_very_long_path(self, tmp_path: Path) -> None:
        """Test that very long file paths are handled correctly."""
        # Create a deeply nested path
        nested_path = tmp_path
        for i in range(10):
            nested_path = nested_path / f"level_{i}"
        log_file = nested_path / "test.log"

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        assert log_file.parent.exists()

    def test_setup_logging_file_already_exists(self, temp_log_dir: Path) -> None:
        """Test that existing log file is appended to."""
        log_file = temp_log_dir / "existing.log"
        log_file.write_text("Existing content\n")

        setup_logging(
            level="INFO",
            debug=False,
            log_to_file=True,
            log_file_path=log_file,
        )

        test_logger = logging.getLogger("test")
        test_logger.info("New message")

        content = log_file.read_text()
        assert "Existing content" in content
        assert "New message" in content

    def test_main_first_run_with_dir_errors_no_mark_complete(self, mock_settings) -> None:
        """Test that first run is not marked complete if directory creation fails."""
        mock_settings.is_first_run.return_value = True
        mock_settings.ensure_data_dirs.return_value = ["Error creating directory"]

        with (
            patch.object(sys, "argv", ["chatfilter"]),
            mock_main_dependencies(mock_settings),
            patch("chatfilter.main.setup_logging"),
            patch(
                "chatfilter.config._is_path_in_readonly_location",
                return_value=(False, None),
            ),
            pytest.raises(SystemExit),
        ):
            main()

        # Should not mark first run complete if there were errors
        mock_settings.mark_first_run_complete.assert_not_called()

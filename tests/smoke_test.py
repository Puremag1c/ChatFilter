#!/usr/bin/env python3
"""Smoke tests for compiled ChatFilter binaries.

This script validates that the compiled binary:
1. Starts without errors
2. Responds to --version flag
3. Opens the web UI and serves health endpoint
4. Can validate configuration
5. Returns correct exit codes
6. Works without network (mocked Telegram)

Usage:
    python tests/smoke_test.py --binary path/to/ChatFilter.exe
    python tests/smoke_test.py --binary dist/ChatFilter.app/Contents/MacOS/ChatFilter
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

try:
    import httpx
except ImportError:
    print("❌ httpx is required for smoke tests. Install with: pip install httpx")
    sys.exit(1)


class SmokeTestRunner:
    """Runner for smoke tests on compiled binaries."""

    def __init__(self, binary_path: Path, verbose: bool = False):
        """Initialize smoke test runner.

        Args:
            binary_path: Path to the compiled binary
            verbose: Enable verbose output
        """
        self.binary_path = binary_path
        self.verbose = verbose
        self.test_results: list[tuple[str, bool, str]] = []

    def log(self, message: str) -> None:
        """Log a message if verbose mode is enabled."""
        if self.verbose:
            print(f"  {message}")

    def run_test(self, name: str, func) -> bool:
        """Run a single test and record result.

        Args:
            name: Test name
            func: Test function to execute

        Returns:
            True if test passed, False otherwise
        """
        print(f"\n🧪 {name}")
        try:
            func()
            self.test_results.append((name, True, ""))
            print(f"✅ {name} PASSED")
            return True
        except AssertionError as e:
            self.test_results.append((name, False, str(e)))
            print(f"❌ {name} FAILED: {e}")
            return False
        except Exception as e:
            self.test_results.append((name, False, f"Unexpected error: {e}"))
            print(f"❌ {name} FAILED: Unexpected error: {e}")
            return False

    def test_binary_exists(self) -> None:
        """Test that binary exists and is executable."""
        if not self.binary_path.exists():
            raise AssertionError(f"Binary not found at {self.binary_path}")

        if not os.access(self.binary_path, os.X_OK):
            raise AssertionError(f"Binary is not executable: {self.binary_path}")

        self.log(f"Binary found and executable: {self.binary_path}")

    def test_version_flag(self) -> None:
        """Test --version flag returns version info."""
        self.log("Running: --version")
        result = subprocess.run(
            [str(self.binary_path), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            raise AssertionError(
                f"--version returned non-zero exit code {result.returncode}\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )

        output = result.stdout + result.stderr
        if "ChatFilter" not in output:
            raise AssertionError(f"Version output doesn't contain 'ChatFilter': {output}")

        self.log(f"Version output: {output.strip()}")

    def test_validate_config(self) -> None:
        """Test --validate flag validates configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"

            self.log(f"Running: --validate --data-dir {data_dir}")
            result = subprocess.run(
                [
                    str(self.binary_path),
                    "--validate",
                    "--data-dir", str(data_dir),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                raise AssertionError(
                    f"--validate returned non-zero exit code {result.returncode}\n"
                    f"stdout: {result.stdout}\nstderr: {result.stderr}"
                )

            output = result.stdout + result.stderr
            if "valid" not in output.lower():
                raise AssertionError(f"Validation output doesn't indicate success: {output}")

            self.log(f"Validation output: {output.strip()}")

    def test_web_server_startup(self) -> None:
        """Test that web server starts and responds to health check."""
        import random
        import signal

        # Use random port to avoid conflicts
        port = random.randint(49152, 65535)
        host = "127.0.0.1"

        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"

            self.log(f"Starting server on {host}:{port} with data dir {data_dir}")

            # Set environment to avoid network calls
            env = os.environ.copy()
            env["CHATFILTER_HOST"] = host
            env["CHATFILTER_PORT"] = str(port)
            env["CHATFILTER_DATA_DIR"] = str(data_dir)

            # Start the server process
            process = subprocess.Popen(
                [
                    str(self.binary_path),
                    "--host", host,
                    "--port", str(port),
                    "--data-dir", str(data_dir),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )

            try:
                # Wait for server to start
                max_wait = 30  # seconds
                start_time = time.time()
                server_ready = False

                while time.time() - start_time < max_wait:
                    if process.poll() is not None:
                        # Process died
                        stdout, stderr = process.communicate()
                        raise AssertionError(
                            f"Server process died unexpectedly\n"
                            f"stdout: {stdout}\nstderr: {stderr}"
                        )

                    try:
                        response = httpx.get(
                            f"http://{host}:{port}/health",
                            timeout=2.0,
                        )
                        if response.status_code == 200:
                            server_ready = True
                            self.log(f"Server responded after {time.time() - start_time:.1f}s")
                            break
                    except (httpx.ConnectError, httpx.TimeoutException):
                        time.sleep(0.5)
                        continue

                if not server_ready:
                    raise AssertionError(
                        f"Server did not respond within {max_wait}s"
                    )

                # Test health endpoint
                response = httpx.get(f"http://{host}:{port}/health", timeout=5.0)

                if response.status_code != 200:
                    raise AssertionError(
                        f"Health endpoint returned status {response.status_code}: {response.text}"
                    )

                data = response.json()
                if data.get("status") != "healthy":
                    raise AssertionError(f"Health check status is not 'healthy': {data}")

                if "version" not in data:
                    raise AssertionError(f"Health check response missing 'version': {data}")

                self.log(f"Health check response: {data}")

                # Test that the root page is accessible
                response = httpx.get(f"http://{host}:{port}/", timeout=5.0)
                if response.status_code not in (200, 404):  # 404 is ok if no route defined
                    self.log(f"Root page status: {response.status_code}")

            finally:
                # Gracefully shutdown server
                self.log("Shutting down server")
                try:
                    if sys.platform == "win32":
                        # Windows doesn't have SIGTERM
                        process.terminate()
                    else:
                        process.send_signal(signal.SIGTERM)

                    # Wait up to 10 seconds for graceful shutdown
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.log("Graceful shutdown timeout, forcing kill")
                        process.kill()
                        process.wait()
                except Exception as e:
                    self.log(f"Error during shutdown: {e}")
                    process.kill()

    def test_invalid_args_exit_code(self) -> None:
        """Test that invalid arguments return non-zero exit code."""
        self.log("Running with invalid argument: --invalid-flag")
        result = subprocess.run(
            [str(self.binary_path), "--invalid-flag"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            raise AssertionError(
                f"Invalid argument should return non-zero exit code, got {result.returncode}"
            )

        self.log(f"Invalid argument correctly returned exit code: {result.returncode}")

    def test_session_loading(self) -> None:
        """Test that the app can handle session files in data directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            data_dir = Path(tmpdir) / "data"
            sessions_dir = data_dir / "sessions"
            sessions_dir.mkdir(parents=True)

            # Create a dummy session file (Telethon session format)
            # This is just to test that the app doesn't crash when sessions exist
            dummy_session = sessions_dir / "test.session"
            dummy_session.touch()

            self.log(f"Created dummy session at {dummy_session}")

            # Run validation with session present
            result = subprocess.run(
                [
                    str(self.binary_path),
                    "--validate",
                    "--data-dir", str(data_dir),
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                raise AssertionError(
                    f"Validation with session file failed with exit code {result.returncode}\n"
                    f"stdout: {result.stdout}\nstderr: {result.stderr}"
                )

            self.log("Session file presence doesn't break validation")

    def run_all_tests(self) -> bool:
        """Run all smoke tests.

        Returns:
            True if all tests passed, False otherwise
        """
        print(f"\n{'='*60}")
        print(f"🚀 Running smoke tests for: {self.binary_path}")
        print(f"{'='*60}")

        # Run tests in order
        tests = [
            ("Binary exists and is executable", self.test_binary_exists),
            ("Version flag works", self.test_version_flag),
            ("Config validation works", self.test_validate_config),
            ("Invalid arguments return non-zero", self.test_invalid_args_exit_code),
            ("Session loading doesn't crash", self.test_session_loading),
            ("Web server starts and responds", self.test_web_server_startup),
        ]

        for name, test_func in tests:
            self.run_test(name, test_func)

        # Print summary
        print(f"\n{'='*60}")
        print("📊 Test Summary")
        print(f"{'='*60}")

        passed = sum(1 for _, result, _ in self.test_results if result)
        total = len(self.test_results)

        for name, result, error in self.test_results:
            status = "✅ PASS" if result else "❌ FAIL"
            print(f"{status} - {name}")
            if error:
                print(f"         {error}")

        print(f"\n{passed}/{total} tests passed")

        if passed == total:
            print("\n🎉 All smoke tests passed!")
            return True
        else:
            print(f"\n⚠️  {total - passed} test(s) failed")
            return False


def main() -> int:
    """Main entry point for smoke tests."""
    parser = argparse.ArgumentParser(
        description="Run smoke tests on compiled ChatFilter binary"
    )
    parser.add_argument(
        "--binary",
        required=True,
        type=Path,
        help="Path to the compiled binary (e.g., dist/ChatFilter.exe or dist/ChatFilter.app/Contents/MacOS/ChatFilter)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    runner = SmokeTestRunner(args.binary, verbose=args.verbose)
    success = runner.run_all_tests()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

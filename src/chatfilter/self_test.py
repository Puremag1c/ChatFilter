"""Startup self-test and diagnostics module.

Validates system readiness before starting the application:
- Network connectivity
- DNS resolution for Telegram
- Port connectivity to Telegram servers
- Write permissions for required directories
- Configuration validation
"""

import asyncio
import socket
import tempfile
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from .config import Settings


class TestStatus(str, Enum):
    """Test result status."""

    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    SKIP = "SKIP"


@dataclass
class TestResult:
    """Result of a single diagnostic test."""

    name: str
    status: TestStatus
    message: str
    details: dict[str, Any] | None = None
    error: str | None = None


class SelfTest:
    """Runs startup self-test diagnostics."""

    def __init__(self, settings: Settings) -> None:
        """Initialize self-test with application settings.

        Args:
            settings: Application configuration settings.
        """
        self.settings = settings
        self.results: list[TestResult] = []

    def _add_result(
        self,
        name: str,
        status: TestStatus,
        message: str,
        details: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        """Add a test result.

        Args:
            name: Test name/identifier.
            status: Test status (PASS/WARN/FAIL/SKIP).
            message: Human-readable result message.
            details: Optional additional details dictionary.
            error: Optional error message for failures.
        """
        self.results.append(
            TestResult(
                name=name,
                status=status,
                message=message,
                details=details,
                error=error,
            )
        )

    async def test_network_connectivity(self) -> None:
        """Test basic network connectivity."""
        test_hosts = [
            ("1.1.1.1", 53),  # Cloudflare DNS
            ("8.8.8.8", 53),  # Google DNS
        ]

        for host, port in test_hosts:
            try:
                # Test with a 3-second timeout
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=3.0,
                )
                writer.close()
                await writer.wait_closed()

                self._add_result(
                    name="network_connectivity",
                    status=TestStatus.PASS,
                    message=f"Network connectivity verified via {host}:{port}",
                    details={"host": host, "port": port},
                )
                return  # Success, no need to try other hosts

            except TimeoutError:
                continue  # Try next host
            except Exception:
                continue  # Try next host

        # All hosts failed
        self._add_result(
            name="network_connectivity",
            status=TestStatus.FAIL,
            message="Unable to establish network connectivity to test hosts",
            details={"tested_hosts": test_hosts},
            error="Connection timeout or refused for all test hosts",
        )

    async def test_dns_resolution(self) -> None:
        """Test DNS resolution for telegram.org."""
        hostname = "telegram.org"

        try:
            loop = asyncio.get_running_loop()
            addresses = await asyncio.wait_for(
                loop.getaddrinfo(hostname, None),
                timeout=5.0,
            )

            if addresses:
                resolved_ips = list({addr[4][0] for addr in addresses})
                self._add_result(
                    name="dns_resolution",
                    status=TestStatus.PASS,
                    message=f"Successfully resolved {hostname}",
                    details={
                        "hostname": hostname,
                        "resolved_ips": resolved_ips,
                        "count": len(resolved_ips),
                    },
                )
            else:
                self._add_result(
                    name="dns_resolution",
                    status=TestStatus.FAIL,
                    message=f"DNS resolution for {hostname} returned no results",
                    details={"hostname": hostname},
                )

        except TimeoutError:
            self._add_result(
                name="dns_resolution",
                status=TestStatus.FAIL,
                message=f"DNS resolution for {hostname} timed out",
                details={"hostname": hostname},
                error="DNS query timeout after 5 seconds",
            )
        except socket.gaierror as e:
            self._add_result(
                name="dns_resolution",
                status=TestStatus.FAIL,
                message=f"DNS resolution for {hostname} failed",
                details={"hostname": hostname},
                error=str(e),
            )
        except Exception as e:
            self._add_result(
                name="dns_resolution",
                status=TestStatus.FAIL,
                message=f"Unexpected error during DNS resolution for {hostname}",
                details={"hostname": hostname},
                error=f"{type(e).__name__}: {e}",
            )

    async def test_telegram_connectivity(self) -> None:
        """Test port connectivity to Telegram servers."""
        telegram_servers = [
            ("149.154.175.50", 443),  # DC2
            ("149.154.167.51", 443),  # DC4
        ]

        successful = []
        failed = []

        for host, port in telegram_servers:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=5.0,
                )
                writer.close()
                await writer.wait_closed()
                successful.append(f"{host}:{port}")

            except TimeoutError:
                failed.append((f"{host}:{port}", "timeout"))
            except Exception as e:
                failed.append((f"{host}:{port}", str(e)))

        if successful:
            self._add_result(
                name="telegram_connectivity",
                status=TestStatus.PASS,
                message=f"Successfully connected to {len(successful)} Telegram server(s)",
                details={
                    "successful": successful,
                    "failed": [f[0] for f in failed] if failed else [],
                },
            )
        else:
            self._add_result(
                name="telegram_connectivity",
                status=TestStatus.FAIL,
                message="Unable to connect to any Telegram servers",
                details={"tested_servers": [f"{h}:{p}" for h, p in telegram_servers]},
                error=f"All servers failed: {failed}",
            )

    def test_write_permissions(self) -> None:
        """Test write permissions for all required directories."""
        directories = [
            ("data_dir", self.settings.data_dir),
            ("config_dir", self.settings.config_dir),
            ("sessions_dir", self.settings.sessions_dir),
            ("exports_dir", self.settings.exports_dir),
        ]

        all_passed = True
        failed_dirs = []

        for name, directory in directories:
            dir_path = Path(directory)

            # Check if directory exists or can be created
            try:
                dir_path.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                all_passed = False
                failed_dirs.append((name, str(directory), f"mkdir failed: {e}"))
                continue

            # Test write permission by creating a temporary file
            try:
                with tempfile.NamedTemporaryFile(dir=directory, delete=True, mode="w") as tmp:
                    tmp.write("test")
                    tmp.flush()
            except Exception as e:
                all_passed = False
                failed_dirs.append((name, str(directory), f"write test failed: {e}"))

        if all_passed:
            self._add_result(
                name="write_permissions",
                status=TestStatus.PASS,
                message=f"Write permissions verified for {len(directories)} directories",
                details={
                    "directories": [{"name": name, "path": str(path)} for name, path in directories]
                },
            )
        else:
            self._add_result(
                name="write_permissions",
                status=TestStatus.FAIL,
                message=f"Write permission failures in {len(failed_dirs)} directories",
                details={
                    "failed_directories": [
                        {"name": name, "path": path, "error": error}
                        for name, path, error in failed_dirs
                    ]
                },
                error=f"Cannot write to: {', '.join(name for name, _, _ in failed_dirs)}",
            )

    def test_port_availability(self) -> None:
        """Test if the configured port is available."""
        host = self.settings.host
        port = self.settings.port

        try:
            # Try to bind to the port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.close()

            self._add_result(
                name="port_availability",
                status=TestStatus.PASS,
                message=f"Port {port} is available on {host}",
                details={"host": host, "port": port},
            )

        except OSError as e:
            if e.errno == 48:  # Address already in use
                self._add_result(
                    name="port_availability",
                    status=TestStatus.FAIL,
                    message=f"Port {port} is already in use on {host}",
                    details={"host": host, "port": port},
                    error="Address already in use",
                )
            else:
                self._add_result(
                    name="port_availability",
                    status=TestStatus.FAIL,
                    message=f"Cannot bind to port {port} on {host}",
                    details={"host": host, "port": port},
                    error=str(e),
                )

    def test_configuration(self) -> None:
        """Validate application configuration."""
        try:
            # Run the built-in validation
            validation_errors = self.settings.validate()

            if not validation_errors:
                self._add_result(
                    name="configuration",
                    status=TestStatus.PASS,
                    message="Configuration validation passed",
                    details={
                        "data_dir": str(self.settings.data_dir),
                        "host": self.settings.host,
                        "port": self.settings.port,
                    },
                )
            else:
                self._add_result(
                    name="configuration",
                    status=TestStatus.FAIL,
                    message=f"Configuration validation failed with {len(validation_errors)} error(s)",
                    details={"errors": validation_errors},
                    error="; ".join(validation_errors),
                )

        except Exception as e:
            self._add_result(
                name="configuration",
                status=TestStatus.FAIL,
                message="Configuration validation raised an exception",
                error=f"{type(e).__name__}: {e}",
            )

    async def run_all_tests(self) -> list[TestResult]:
        """Run all diagnostic tests.

        Returns:
            List of test results.
        """
        self.results = []

        # Configuration validation (synchronous)
        self.test_configuration()

        # Write permissions check (synchronous)
        self.test_write_permissions()

        # Port availability check (synchronous)
        self.test_port_availability()

        # Network tests (asynchronous)
        await self.test_network_connectivity()
        await self.test_dns_resolution()
        await self.test_telegram_connectivity()

        return self.results

    def has_failures(self) -> bool:
        """Check if any tests failed.

        Returns:
            True if any test has FAIL status.
        """
        return any(result.status == TestStatus.FAIL for result in self.results)

    def has_warnings(self) -> bool:
        """Check if any tests have warnings.

        Returns:
            True if any test has WARN status.
        """
        return any(result.status == TestStatus.WARN for result in self.results)

    def to_dict(self) -> dict[str, Any]:
        """Convert results to dictionary format.

        Returns:
            Dictionary with test results and summary.
        """
        return {
            "summary": {
                "total": len(self.results),
                "passed": sum(1 for r in self.results if r.status == TestStatus.PASS),
                "warned": sum(1 for r in self.results if r.status == TestStatus.WARN),
                "failed": sum(1 for r in self.results if r.status == TestStatus.FAIL),
                "skipped": sum(1 for r in self.results if r.status == TestStatus.SKIP),
                "has_failures": self.has_failures(),
                "has_warnings": self.has_warnings(),
            },
            "tests": [
                {
                    "name": result.name,
                    "status": result.status.value,
                    "message": result.message,
                    "details": result.details,
                    "error": result.error,
                }
                for result in self.results
            ],
        }

    def format_table(self) -> str:
        """Format results as a human-readable table.

        Returns:
            Formatted table string.
        """
        lines = []
        lines.append("=" * 80)
        lines.append("SELF-TEST DIAGNOSTICS")
        lines.append("=" * 80)
        lines.append("")

        # Summary
        summary = self.to_dict()["summary"]
        lines.append("Summary:")
        lines.append(f"  Total:   {summary['total']}")
        lines.append(f"  Passed:  {summary['passed']}")
        lines.append(f"  Warned:  {summary['warned']}")
        lines.append(f"  Failed:  {summary['failed']}")
        lines.append(f"  Skipped: {summary['skipped']}")
        lines.append("")

        # Individual test results
        lines.append("-" * 80)
        lines.append(f"{'Test':<30} {'Status':<10} {'Message':<40}")
        lines.append("-" * 80)

        for result in self.results:
            status_symbol = {
                TestStatus.PASS: "✓",
                TestStatus.WARN: "⚠",
                TestStatus.FAIL: "✗",
                TestStatus.SKIP: "○",
            }.get(result.status, "?")

            lines.append(
                f"{result.name:<30} {status_symbol} {result.status.value:<8} {result.message[:40]}"
            )

            if result.error:
                lines.append(f"  Error: {result.error}")

            if result.details:
                # Show key details
                for key, value in result.details.items():
                    if isinstance(value, str | int | float | bool):
                        lines.append(f"  {key}: {value}")

        lines.append("-" * 80)
        lines.append("")

        # Overall status
        if self.has_failures():
            lines.append("STATUS: FAILED ✗")
            lines.append("The application may not function correctly.")
        elif self.has_warnings():
            lines.append("STATUS: PASSED WITH WARNINGS ⚠")
            lines.append("The application should function, but some features may be limited.")
        else:
            lines.append("STATUS: ALL TESTS PASSED ✓")
            lines.append("The application is ready to start.")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)

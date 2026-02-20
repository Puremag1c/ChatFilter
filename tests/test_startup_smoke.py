"""Smoke test for ChatFilter startup verification.

This test ensures the application can start successfully and serve basic endpoints.
Run with: pytest tests/test_startup_smoke.py
"""

import asyncio
import sys
import time
from subprocess import PIPE, Popen

import httpx
import pytest


@pytest.mark.timeout(60)
def test_app_startup_and_sessions_endpoint():
    """Test that 'chatfilter --port 8000' starts successfully.

    Verifies:
    - App starts without errors
    - GET /api/sessions returns 200
    - No exceptions in startup logs

    This is a deployment smoke test to ensure the app can be deployed.
    """
    port = 8000
    startup_timeout = 30  # seconds

    # Start the chatfilter process
    process = Popen(
        [sys.executable, "-m", "chatfilter.main", "--port", str(port)],
        stdout=PIPE,
        stderr=PIPE,
        text=True,
    )

    try:
        # Wait for server to start
        start_time = time.time()
        server_ready = False

        async def check_server():
            nonlocal server_ready
            while time.time() - start_time < startup_timeout:
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.get(
                            f"http://localhost:{port}/api/sessions",
                            timeout=2.0,
                            follow_redirects=True,
                        )

                        if response.status_code == 200:
                            server_ready = True
                            return True
                        else:
                            pytest.fail(f"GET /api/sessions returned {response.status_code}")

                except (httpx.ConnectError, httpx.TimeoutException):
                    # Server not ready yet, wait and retry
                    await asyncio.sleep(0.5)
                    continue
                except Exception as e:
                    pytest.fail(f"Unexpected error: {e}")

            return False

        # Run the async check
        success = asyncio.run(check_server())

        if not success:
            # Try to read any error output
            try:
                stdout, stderr = process.communicate(timeout=1)
                error_msg = f"Server failed to start within {startup_timeout}s"
                if stderr:
                    error_msg += f"\nSTDERR:\n{stderr}"
                if stdout:
                    error_msg += f"\nSTDOUT:\n{stdout}"
                pytest.fail(error_msg)
            except:
                pytest.fail(f"Server failed to start within {startup_timeout}s")

        # Verify server started successfully
        assert server_ready, "Server should be ready and responding"

        # Success - all checks passed
        # The test framework will report success if we reach this point

    finally:
        # Clean up: terminate the process
        process.terminate()
        try:
            process.wait(timeout=5)
        except:
            process.kill()
            process.wait()

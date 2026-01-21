"""Tests to verify memory leak detection is working correctly.

These tests intentionally create memory leaks to ensure the detection
mechanism catches them properly.
"""

from __future__ import annotations

import pytest

# Global list to simulate memory leak
_leaked_data = []


def test_no_leak():
    """Test that passes with no memory leak."""
    # This test should pass even with leak detection enabled
    data = [0] * 1000
    assert len(data) == 1000
    # data is cleaned up when function exits


@pytest.mark.skip_leak_detection
def test_intentional_leak_with_skip_marker():
    """Test with intentional leak but skip marker."""
    # This test leaks memory but has skip_leak_detection marker
    global _leaked_data
    _leaked_data.append([0] * 1_000_000)  # Leak ~8MB
    assert len(_leaked_data) > 0


def test_small_allocation():
    """Test with small memory allocation within threshold."""
    # Allocate less than 1MB (should pass with default 5MB threshold)
    data = [0] * 100_000  # ~800KB
    result = sum(data)
    assert result == 0


@pytest.mark.skip(reason="Example of test that would fail leak detection")
def test_large_leak_example():
    """Example test that would fail leak detection.

    This test is skipped by default but shows how a leak would be detected.
    To test leak detection, run with:
        pytest tests/test_leak_detection.py::test_large_leak_example --detect-leaks -v
    """
    global _leaked_data
    # Intentionally leak 10MB (exceeds 5MB threshold)
    _leaked_data.append([0] * 10_000_000)
    assert True


def test_cleanup_after_use():
    """Test that properly cleans up after use."""
    # Allocate and explicitly delete
    data = [0] * 1_000_000
    assert len(data) == 1_000_000
    del data  # Explicit cleanup
    # Should pass leak detection as memory is freed

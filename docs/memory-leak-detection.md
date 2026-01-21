# Memory Leak Detection

ChatFilter includes comprehensive memory leak detection for tests to ensure long-running analysis tasks don't accumulate memory.

## Quick Start

### Automatic Leak Detection (tracemalloc)

Built-in leak detection using Python's `tracemalloc` module:

```bash
# Enable leak detection for all tests
pytest --detect-leaks

# Enable with environment variable
DETECT_MEMORY_LEAKS=1 pytest

# Configure threshold (default: 5.0 MB)
pytest --detect-leaks --leak-threshold-mb=10.0

# Generate detailed leak reports
pytest --detect-leaks --leak-report
```

### Advanced Profiling (memray)

For detailed memory profiling and flamegraphs:

```bash
# Install memray (included in dev dependencies)
pip install -e ".[dev]"

# Profile a specific test
python -m memray run -o output.bin -m pytest tests/test_memory_stability.py

# Generate HTML report
python -m memray flamegraph output.bin

# Generate summary report
python -m memray summary output.bin

# Live monitoring during test execution
python -m memray run --live -m pytest tests/test_memory_stability.py
```

## Configuration

### Pytest Options

- `--detect-leaks`: Enable memory leak detection
- `--leak-threshold-mb=<float>`: Memory growth threshold in MB (default: 5.0)
- `--leak-report`: Generate detailed allocation report on failure

### Environment Variables

- `DETECT_MEMORY_LEAKS`: Set to `1`, `true`, or `yes` to enable leak detection

### Skip Leak Detection for Specific Tests

Use the `skip_leak_detection` marker for tests that intentionally allocate memory:

```python
import pytest

@pytest.mark.skip_leak_detection
def test_large_data_structure():
    # This test intentionally creates large objects
    large_data = [0] * 10_000_000
    assert len(large_data) == 10_000_000
```

## CI Integration

Memory leak detection is automatically enabled in CI for long-running tests:

```yaml
# In .github/workflows/ci.yml
- name: Run tests with leak detection
  run: pytest --detect-leaks --leak-threshold-mb=10.0
  env:
    DETECT_MEMORY_LEAKS: 1
```

## Understanding Results

### tracemalloc Output

When a leak is detected, you'll see:

```
Memory leak detected: 8.42 MB growth (threshold: 5.00 MB).
Run with --leak-report for details.
```

With `--leak-report`, you get detailed allocation traces:

```
======================================================================
MEMORY LEAK DETECTED: tests/test_memory_stability.py::test_example
Memory growth: 8.42 MB (threshold: 5.00 MB)
======================================================================

Top 10 memory allocations:
  +3.24 MB: /path/to/file.py:123
  +2.15 MB: /path/to/file.py:456
  +1.89 MB: /path/to/file.py:789
  ...
```

### memray Flamegraph

The memray flamegraph shows:
- Memory allocations over time
- Call stacks that allocated memory
- Peak memory usage
- Memory that wasn't freed

## Best Practices

1. **Run leak detection locally** before pushing:
   ```bash
   pytest --detect-leaks tests/test_memory_stability.py
   ```

2. **Use appropriate thresholds**:
   - Unit tests: 1-2 MB
   - Integration tests: 5-10 MB
   - Long-running tests: 10-50 MB

3. **Profile with memray** for deep investigation:
   ```bash
   python -m memray run --live -m pytest tests/test_analysis_router.py -v
   ```

4. **Check for common issues**:
   - Unclosed file handles
   - Cached objects not cleared
   - Circular references preventing garbage collection
   - Event loops not properly cleaned up

## Common Leak Patterns

### Unclosed Resources

```python
# BAD: Resource leak
def test_file_processing():
    f = open("data.txt")
    data = f.read()
    # File never closed!

# GOOD: Proper cleanup
def test_file_processing():
    with open("data.txt") as f:
        data = f.read()
```

### Unbounded Caches

```python
# BAD: Cache grows indefinitely
cache = {}
def get_data(key):
    if key not in cache:
        cache[key] = expensive_operation()
    return cache[key]

# GOOD: Use LRU cache with size limit
from functools import lru_cache

@lru_cache(maxsize=100)
def get_data(key):
    return expensive_operation()
```

### Event Loop Cleanup

```python
# BAD: Tasks not cleaned up
async def test_async_operation():
    task = asyncio.create_task(long_running_op())
    # Task never awaited or cancelled!

# GOOD: Proper cleanup
async def test_async_operation():
    task = asyncio.create_task(long_running_op())
    try:
        result = await asyncio.wait_for(task, timeout=1.0)
    finally:
        if not task.done():
            task.cancel()
```

## Troubleshooting

### False Positives

Some tests may show memory growth that isn't a leak:
- First-time imports loading modules
- Caching that's intentional and bounded
- Lazy initialization of singletons

Use `@pytest.mark.skip_leak_detection` for these cases.

### High Memory Usage Without Leaks

If tests use a lot of memory but don't leak:
- Use `--leak-threshold-mb` to set appropriate threshold
- Add explicit garbage collection: `gc.collect()`
- Clear caches between tests

### CI Failures

If leak detection fails in CI but not locally:
1. Check for test interdependencies
2. Verify cleanup in fixtures
3. Run tests in same order as CI: `pytest --collect-only`
4. Profile with memray in CI (save artifacts)

## References

- [tracemalloc documentation](https://docs.python.org/3/library/tracemalloc.html)
- [memray documentation](https://bloomberg.github.io/memray/)
- [Python Memory Management](https://docs.python.org/3/c-api/memory.html)

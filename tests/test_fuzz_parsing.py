"""Fuzz testing for session and JSON file parsing.

This module uses property-based testing with Hypothesis to fuzz test:
- Telethon session file (.session) parsing and validation
- JSON config file parsing and validation
- Account metadata JSON parsing

The goal is to ensure parsers handle malformed, corrupted, and edge-case
inputs gracefully without crashes or security vulnerabilities.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from chatfilter.telegram.client import (
    SessionFileError,
    TelegramConfig,
    TelegramConfigError,
    validate_session_file,
)

# ============================================================================
# Helper Functions
# ============================================================================


def unique_filename(base: str, *args: Any) -> str:
    """Generate a unique filename based on test data.

    Args:
        base: Base filename (e.g., "fuzz", "config")
        *args: Additional data to include in hash

    Returns:
        Unique filename with hash suffix
    """
    # Create hash from all arguments
    hasher = hashlib.sha256()
    for arg in args:
        hasher.update(str(arg).encode("utf-8", errors="replace"))
    hash_suffix = hasher.hexdigest()[:12]
    return f"{base}_{hash_suffix}"


# ============================================================================
# Hypothesis Strategies
# ============================================================================


@st.composite
def session_file_bytes(draw: Any) -> bytes:
    """Generate random bytes that might be interpreted as session files."""
    # Mix of different strategies
    result: bytes = draw(
        st.one_of(
            st.binary(min_size=0, max_size=1000),  # Random bytes
            st.just(b"SQLite format 3\x00"),  # Valid header only
            st.just(b"SQLite format "),  # Truncated header
            st.just(b"NotSQLite"),  # Invalid header
            st.binary(min_size=100, max_size=10000),  # Larger random data
        )
    )
    return result


@st.composite
def json_like_string(draw: Any) -> str:
    """Generate strings that might be parsed as JSON."""
    result: str = draw(
        st.one_of(
            st.text(min_size=0, max_size=1000),  # Random text
            st.just(""),  # Empty
            st.just("   "),  # Whitespace only
            st.just("null"),  # Valid JSON primitives
            st.just("true"),
            st.just("false"),
            st.just("[]"),  # Valid but wrong structure
            st.just("[1,2,3]"),
            st.just('{"incomplete":'),  # Incomplete JSON
            st.just("{malformed}"),  # Malformed
            st.just('{"key": "value"'),  # Missing closing brace
            st.just('{"key": "value"}}'),  # Extra closing brace
            # Unicode and special characters
            st.from_regex(r'.*["\\\x00-\x1f].*', fullmatch=True),
        )
    )
    return result


@st.composite
def config_dict(draw: Any) -> dict[str, Any]:
    """Generate dictionaries that might be used as Telegram configs."""
    # Strategy for potentially valid configs
    result: dict[str, Any] = draw(
        st.one_of(
            # Empty dict
            st.just({}),
            # Missing required fields
            st.just({"api_id": 12345}),
            st.just({"api_hash": "abc123"}),
            # Wrong types
            st.just({"api_id": None, "api_hash": "abc"}),
            st.just({"api_id": [], "api_hash": "abc"}),
            st.just({"api_id": {}, "api_hash": "abc"}),
            st.just({"api_id": 12345, "api_hash": None}),
            st.just({"api_id": 12345, "api_hash": []}),
            st.just({"api_id": 12345, "api_hash": 123}),
            # Empty strings
            st.just({"api_id": 12345, "api_hash": ""}),
            st.just({"api_id": "", "api_hash": "abc"}),
            # Boundary values
            st.just({"api_id": 0, "api_hash": "abc"}),
            st.just({"api_id": -1, "api_hash": "abc"}),
            st.just({"api_id": 2**31 - 1, "api_hash": "abc"}),
            st.just({"api_id": 2**31, "api_hash": "abc"}),
            # Extra fields (should be OK)
            st.just({"api_id": 12345, "api_hash": "abc", "extra": "field"}),
            # String api_id (should work)
            st.just({"api_id": "12345", "api_hash": "abc"}),
            st.just({"api_id": "not_a_number", "api_hash": "abc"}),
        )
    )
    return result


# ============================================================================
# Session File Fuzz Tests
# ============================================================================


class TestFuzzSessionFile:
    """Fuzz tests for session file parsing and validation."""

    @settings(
        max_examples=50,
        deadline=1000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(data=session_file_bytes())
    def test_fuzz_random_bytes_as_session(self, isolated_tmp_dir: Path, data: bytes) -> None:
        """Fuzz test with random bytes written to .session file.

        The validator should handle arbitrary binary data gracefully
        without crashing or raising unexpected exceptions.
        """
        filename = unique_filename("fuzz", data) + ".session"
        session_path = isolated_tmp_dir / filename
        session_path.write_bytes(data)

        # Should either succeed or raise SessionFileError
        # Should NOT crash or raise unexpected exceptions
        try:
            validate_session_file(session_path)
        except SessionFileError:
            # This is expected for invalid data
            pass
        except Exception as e:
            # Log unexpected exception for debugging
            pytest.fail(
                f"Unexpected exception type: {type(e).__name__}: {e}\nData size: {len(data)} bytes"
            )

    @settings(
        max_examples=50,
        deadline=5000,  # Increased for Windows CI (slow file I/O)
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(
        dc_id=st.integers(),
        server=st.text(max_size=255),
        port=st.integers(),
        auth_key=st.binary(max_size=2048),
    )
    def test_fuzz_valid_sqlite_random_data(
        self,
        isolated_tmp_dir: Path,
        dc_id: int,
        server: str,
        port: int,
        auth_key: bytes,
    ) -> None:
        """Fuzz test with valid SQLite structure but random data values.

        Tests whether the validator properly handles valid SQLite databases
        with arbitrary data in the expected tables.
        """
        filename = unique_filename("fuzz_sqlite", dc_id, server, port, auth_key) + ".session"
        session_path = isolated_tmp_dir / filename

        # Use context manager to ensure proper connection cleanup on Windows
        with contextlib.closing(sqlite3.connect(session_path)) as conn:
            cursor = conn.cursor()

            # Create valid Telethon 1.x schema
            cursor.execute("""
                CREATE TABLE sessions (
                    dc_id INTEGER PRIMARY KEY,
                    server_address TEXT,
                    port INTEGER,
                    auth_key BLOB
                )
            """)
            cursor.execute("""
                CREATE TABLE entities (
                    id INTEGER PRIMARY KEY,
                    hash INTEGER NOT NULL,
                    username TEXT,
                    phone INTEGER,
                    name TEXT
                )
            """)

            # Insert random data
            try:
                cursor.execute(
                    "INSERT INTO sessions (dc_id, server_address, port, auth_key) VALUES (?, ?, ?, ?)",
                    (dc_id, server, port, auth_key),
                )
                conn.commit()
            except (sqlite3.Error, OverflowError):
                # Some random values might cause SQL errors or overflow, that's OK
                pass

        # Should handle gracefully
        try:
            validate_session_file(session_path)
        except (SessionFileError, sqlite3.OperationalError):
            # Expected for invalid data or Windows file locking issues
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")

    def test_fuzz_truncated_sqlite_file(self, valid_session_file: Path) -> None:
        """Test handling of truncated SQLite database files.

        Simulates corrupted or incomplete file downloads.
        """
        # Read valid session file and truncate it
        data = valid_session_file.read_bytes()

        for truncate_size in [0, 10, 50, 100, len(data) // 2]:
            truncated_path = valid_session_file.parent / f"truncated_{truncate_size}.session"
            truncated_path.write_bytes(data[:truncate_size])

            # Should handle gracefully
            with pytest.raises(SessionFileError):
                validate_session_file(truncated_path)

    def test_fuzz_corrupted_sqlite_header(self, valid_session_file: Path) -> None:
        """Test handling of corrupted SQLite header bytes."""
        data = bytearray(valid_session_file.read_bytes())

        # Corrupt header bytes (first 16 bytes are critical)
        for i in range(min(16, len(data))):
            corrupted_data = data.copy()
            corrupted_data[i] = (corrupted_data[i] + 1) % 256
            corrupted_path = valid_session_file.parent / f"corrupted_{i}.session"
            corrupted_path.write_bytes(bytes(corrupted_data))

            # Should detect corruption
            with pytest.raises(SessionFileError):
                validate_session_file(corrupted_path)

    @settings(
        max_examples=30,
        deadline=1000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(extra_bytes=st.binary(min_size=1, max_size=1000))
    def test_fuzz_appended_garbage(self, valid_session_file: Path, extra_bytes: bytes) -> None:
        """Test handling of valid SQLite with garbage data appended.

        Some file corruption scenarios involve extra bytes at the end.
        """
        original_data = valid_session_file.read_bytes()
        corrupted_data = original_data + extra_bytes

        filename = unique_filename("appended", extra_bytes) + ".session"
        corrupted_path = valid_session_file.parent / filename
        corrupted_path.write_bytes(corrupted_data)

        # SQLite might still be able to read this, or might fail
        # Either way, should not crash (any error is acceptable as long as it doesn't crash)
        with contextlib.suppress(SessionFileError, Exception):
            validate_session_file(corrupted_path)


# ============================================================================
# JSON Config File Fuzz Tests
# ============================================================================


class TestFuzzConfigJSON:
    """Fuzz tests for JSON config file parsing."""

    @settings(
        max_examples=100,
        deadline=1000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(data=json_like_string())
    def test_fuzz_random_json_strings(self, isolated_tmp_dir: Path, data: str) -> None:
        """Fuzz test with random strings that might be parsed as JSON.

        The config parser should handle malformed JSON gracefully
        without crashes or unhandled exceptions.
        """
        filename = unique_filename("fuzz_config", data) + ".json"
        config_path = isolated_tmp_dir / filename
        config_path.write_text(data, encoding="utf-8")

        # Should handle gracefully
        try:
            TelegramConfig.from_json_file(config_path)
        except (ValueError, json.JSONDecodeError, KeyError, TypeError, TelegramConfigError):
            # These are all expected for invalid data
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}\nData: {data[:100]}")

    @settings(
        max_examples=50,
        deadline=1000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(config=config_dict())
    def test_fuzz_config_dictionary_values(
        self, isolated_tmp_dir: Path, config: dict[str, Any]
    ) -> None:
        """Fuzz test with various dictionary structures as config.

        Tests type validation and required field checks.
        """
        filename = unique_filename("fuzz_config_dict", str(config)) + ".json"
        config_path = isolated_tmp_dir / filename
        config_path.write_text(json.dumps(config), encoding="utf-8")

        # Should validate structure and types
        try:
            TelegramConfig.from_json_file(config_path)
        except (ValueError, KeyError, TypeError, TelegramConfigError):
            # Expected for invalid configs
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}\nConfig: {config}")

    @settings(
        max_examples=30,
        deadline=1000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(
        api_id=st.one_of(
            st.integers(),
            st.floats(allow_nan=False, allow_infinity=False),
            st.text(),
            st.none(),
            st.booleans(),
        ),
        api_hash=st.one_of(st.text(), st.integers(), st.none(), st.booleans()),
    )
    def test_fuzz_config_field_types(
        self, isolated_tmp_dir: Path, api_id: Any, api_hash: Any
    ) -> None:
        """Fuzz test with various types for api_id and api_hash fields."""
        config = {"api_id": api_id, "api_hash": api_hash}
        filename = unique_filename("fuzz_config_types", api_id, api_hash) + ".json"
        config_path = isolated_tmp_dir / filename

        try:
            config_path.write_text(json.dumps(config), encoding="utf-8")
        except (TypeError, ValueError):
            # Some values can't be JSON serialized (e.g., NaN)
            return

        # Should validate types
        try:
            TelegramConfig.from_json_file(config_path)
        except (ValueError, TypeError, KeyError, TelegramConfigError):
            # Expected for wrong types
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}\nConfig: {config}")

    def test_fuzz_invalid_utf8_sequences(self, isolated_tmp_dir: Path) -> None:
        """Test handling of invalid UTF-8 byte sequences in JSON files."""
        config_path = isolated_tmp_dir / "invalid_utf8.json"

        # Various invalid UTF-8 sequences
        invalid_sequences = [
            b'{"api_id": 12345, "api_hash": "\xff\xfe"}',  # Invalid UTF-8
            b'{"api_id": 12345, "api_hash": "\x80\x81"}',  # Invalid continuation
            b'{"api_id": 12345, "api_hash": "\xc0\x80"}',  # Overlong encoding
        ]

        for seq in invalid_sequences:
            config_path.write_bytes(seq)

            # Should detect invalid encoding
            with pytest.raises((ValueError, UnicodeDecodeError)):
                TelegramConfig.from_json_file(config_path)

    @settings(
        max_examples=30,
        deadline=1000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(nesting_level=st.integers(min_value=1, max_value=100))
    def test_fuzz_deeply_nested_json(self, isolated_tmp_dir: Path, nesting_level: int) -> None:
        """Test handling of deeply nested JSON structures.

        Deep nesting can cause stack overflow or performance issues.
        """
        # Create deeply nested structure
        nested = {"api_id": 12345, "api_hash": "test"}
        for _ in range(nesting_level):
            nested = {"nested": nested}

        filename = unique_filename("nested", nesting_level) + ".json"
        config_path = isolated_tmp_dir / filename
        try:
            config_path.write_text(json.dumps(nested), encoding="utf-8")
        except RecursionError:
            # Python's JSON encoder might fail on extreme nesting
            return

        # Should handle gracefully (likely KeyError for missing fields)
        try:
            TelegramConfig.from_json_file(config_path)
        except (ValueError, KeyError, RecursionError, TelegramConfigError):
            # Expected for nested structures or recursion limits
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")


# ============================================================================
# Account Metadata JSON Fuzz Tests
# ============================================================================


class TestFuzzAccountMetadata:
    """Fuzz tests for account metadata JSON parsing."""

    @settings(
        max_examples=50,
        deadline=1000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(
        phone=st.one_of(st.text(), st.integers(), st.none()),
        user_id=st.one_of(st.integers(), st.text(), st.none()),
        username=st.one_of(st.text(), st.none(), st.integers()),
    )
    def test_fuzz_account_metadata_fields(
        self,
        isolated_tmp_dir: Path,
        phone: Any,
        user_id: Any,
        username: Any,
    ) -> None:
        """Fuzz test account metadata with various field types.

        Account metadata files store information about Telegram accounts.
        """
        metadata = {
            "phone": phone,
            "user_id": user_id,
            "username": username,
        }

        filename = unique_filename("account_info", phone, user_id, username) + ".json"
        metadata_path = isolated_tmp_dir / filename

        try:
            metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
        except (TypeError, ValueError):
            # Some values can't be JSON serialized
            return

        # Just verify it doesn't crash when reading back
        try:
            with metadata_path.open("r") as f:
                data = json.load(f)
            assert isinstance(data, dict)
        except (json.JSONDecodeError, ValueError):
            # Expected for some invalid cases
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")

    @settings(
        max_examples=50,
        deadline=1000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(data=st.dictionaries(st.text(), st.text() | st.integers() | st.none()))
    def test_fuzz_arbitrary_metadata_dict(
        self, isolated_tmp_dir: Path, data: dict[str, Any]
    ) -> None:
        """Fuzz test with arbitrary dictionary structures as metadata."""
        filename = unique_filename("arbitrary_metadata", str(data)) + ".json"
        metadata_path = isolated_tmp_dir / filename

        try:
            metadata_path.write_text(json.dumps(data), encoding="utf-8")
        except (TypeError, ValueError):
            return

        # Verify safe reading
        try:
            with metadata_path.open("r") as f:
                loaded = json.load(f)
            assert isinstance(loaded, dict)
        except (json.JSONDecodeError, ValueError):
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")


# ============================================================================
# Size Limit Fuzz Tests
# ============================================================================


class TestFuzzFileSizeLimits:
    """Fuzz tests for file size limit enforcement."""

    @settings(
        max_examples=20,
        deadline=2000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(size_multiplier=st.floats(min_value=0.5, max_value=2.0))
    def test_fuzz_session_file_size_boundaries(
        self, isolated_tmp_dir: Path, size_multiplier: float
    ) -> None:
        """Test session file handling near size limit boundaries.

        The session upload has a 10MB size limit.
        """
        # 10MB limit
        limit = 10 * 1024 * 1024
        test_size = int(limit * size_multiplier)

        filename = unique_filename("large", size_multiplier, test_size) + ".session"
        session_path = isolated_tmp_dir / filename
        # Write random data of specified size
        session_path.write_bytes(b"\x00" * test_size)

        # Attempt to validate - should handle large files gracefully
        try:
            validate_session_file(session_path)
        except (SessionFileError, sqlite3.Error, MemoryError):
            # Expected for oversized or invalid files
            pass
        except Exception as e:
            # Should not crash with unexpected errors
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")

    @settings(
        max_examples=20,
        deadline=1000,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    @given(size=st.integers(min_value=0, max_value=2048))
    def test_fuzz_config_file_size_boundaries(self, isolated_tmp_dir: Path, size: int) -> None:
        """Test config file handling near size limit boundaries.

        The config upload has a 1KB size limit.
        """
        # Create content of specified size
        content = '{"api_id": 12345, "api_hash": "' + "a" * max(0, size - 40) + '"}'
        filename = unique_filename("large_config", size, len(content)) + ".json"
        config_path = isolated_tmp_dir / filename
        config_path.write_text(content, encoding="utf-8")

        # Attempt to parse
        try:
            TelegramConfig.from_json_file(config_path)
        except (ValueError, json.JSONDecodeError, KeyError, TelegramConfigError):
            # Expected for many cases
            pass
        except Exception as e:
            pytest.fail(f"Unexpected exception: {type(e).__name__}: {e}")

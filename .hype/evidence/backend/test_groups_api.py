"""Tests for link format support in chat parser."""

import pytest


class TestLinkFormatSupport:
    """Test that all link formats from SPEC.md are supported."""

    def test_parser_handles_tme_username(self):
        """Test t.me/username format."""
        from chatfilter.importer.parser import parse_text, ChatListEntry

        entries = parse_text("t.me/test_channel")
        assert len(entries) > 0
        assert entries[0].normalized == "test_channel"
        assert entries[0].entry_type.value == "link"

    def test_parser_handles_tme_plus_hash(self):
        """Test t.me/+hash format (invite link)."""
        from chatfilter.importer.parser import parse_text, ChatListEntry

        entries = parse_text("t.me/+AbCdEfGhIjK")
        assert len(entries) > 0
        assert entries[0].entry_type.value == "link"

    def test_parser_handles_tme_joinchat(self):
        """Test t.me/joinchat/hash format."""
        from chatfilter.importer.parser import parse_text, ChatListEntry

        entries = parse_text("t.me/joinchat/AbCdEfGhIjK")
        assert len(entries) > 0
        assert entries[0].entry_type.value == "link"

    def test_parser_handles_at_username(self):
        """Test @username format."""
        from chatfilter.importer.parser import parse_text, ChatListEntry

        entries = parse_text("@test_channel")
        assert len(entries) > 0
        assert entries[0].normalized == "test_channel"
        assert entries[0].entry_type.value == "username"

    def test_parser_handles_numeric_id(self):
        """Test -100xxxxxxxxxx format."""
        from chatfilter.importer.parser import parse_text, ChatListEntry

        entries = parse_text("-1001234567890")
        assert len(entries) > 0
        assert entries[0].normalized == "-1001234567890"
        assert entries[0].entry_type.value == "id"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

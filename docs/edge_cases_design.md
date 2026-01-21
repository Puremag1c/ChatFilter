# Edge Cases Design: Unique Author Counting

## Overview

This document outlines the design decisions for handling edge cases in unique author counting:
1. Deleted Accounts
2. Forwarded Messages
3. Service Messages

## 1. Deleted Accounts (sender.deleted=True)

### Problem
When a Telegram user deletes their account, `sender.deleted` becomes `True`. The question is: should we count all deleted accounts as one entity, or count each by their unique ID?

### Solution: Count by ID (Each deleted account is unique)

**Rationale:**
- Each deleted account represents a real, distinct user who participated in the chat
- Counting them separately provides more accurate statistics about chat participation
- Grouping all deleted accounts as one would artificially deflate unique_authors count
- Consistent with how we treat regular users (by their ID)

**Implementation:**
- Continue using `author_id` from deleted accounts
- No special handling needed in metrics computation (already works correctly)
- The `deleted` flag is metadata about the user, not a reason to merge them

### Alternative Approaches Considered

**Alternative A: Count all deleted as one "Deleted Account"**
- ❌ Loses information about actual participation
- ❌ Would require extending Message model with `is_deleted` flag
- ❌ Inconsistent with how we handle active users

**Alternative B: Exclude deleted accounts entirely**
- ❌ Would lose message count data
- ❌ Distorts historical analysis of chat activity
- ❌ The messages existed and contributed to the chat

## 2. Forwarded Messages

### Problem
Forwarded messages have both a forwarder (who sent it to this chat) and an original author (who created it). Which should we count for unique_authors?

### Solution: Count the forwarder (sender)

**Rationale:**
- The message appears in *this* chat because the forwarder sent it here
- The forwarder is actively participating in the chat; the original author may not even be a member
- This matches what users see in the Telegram UI (the forwarder is shown as the sender)
- The original author (`fwd_from.from_id`) may be unavailable due to privacy settings
- Consistent with our goal: measure who is actively engaging in this specific chat

**Implementation:**
- No changes needed - current implementation already uses `sender_id`/`from_id`, which is the forwarder
- We can optionally add `is_forwarded` metadata for analytics, but it doesn't affect unique_authors counting

### Alternative Approaches Considered

**Alternative A: Count the original author**
- ❌ Original author might not be in this chat
- ❌ Doesn't reflect who is actually active in this chat
- ❌ fwd_from.from_id may be None (privacy settings, anonymous channels)
- ❌ Complex implementation requiring Message model extension

**Alternative B: Count both (double-count)**
- ❌ Would inflate unique_authors incorrectly
- ❌ One message shouldn't count as two authors

## 3. Service Messages (join/leave/pin)

### Problem
Telegram generates service messages for events like user join, leave, pin message, etc. These are `MessageService` objects with an `action` field. Should they be included in metrics?

### Solution: Filter them out (return None during conversion)

**Rationale:**
- Service messages are system-generated, not authored by users
- Including them would inflate `message_count` with non-content
- They don't represent actual chat activity (no one typed them)
- Cleanest approach: they never enter our analytics pipeline
- Consistent with existing behavior (we already filter deleted/empty messages)

**Implementation:**
- Update `_telethon_message_to_model()` to detect `MessageService` instances
- Return `None` for service messages (same as deleted messages)
- This automatically excludes them from all metrics

**Examples of filtered service messages:**
- `MessageActionChatJoinedByLink`, `MessageActionChatJoinedByRequest` (user joined)
- `MessageActionChatDeleteUser` (user left)
- `MessageActionChatAddUser` (user added)
- `MessageActionPinMessage` (message pinned)
- `MessageActionChatEditTitle`, `MessageActionChatEditPhoto` (chat changes)
- And 50+ other action types

### Alternative Approaches Considered

**Alternative A: Include in message_count but not unique_authors**
- ❌ Complex logic in metrics computation
- ❌ Still inflates message_count incorrectly
- ❌ Inconsistent: why count a message but not its author?

**Alternative B: Include in both counts**
- ❌ Service messages don't have meaningful authors
- ❌ The "author" of a join message is the joiner, but they didn't write anything
- ❌ Would distort activity metrics

**Alternative C: Add is_service flag and make it configurable**
- ❌ Over-engineering for a clear-cut case
- ❌ Adds complexity without clear benefit
- ❌ Users rarely want service messages in chat analysis

## Implementation Plan

### Phase 1: Service Message Filtering (High Priority)
1. Extend `_telethon_message_to_model()` to detect `MessageService`
2. Return `None` for service messages
3. Add tests for various service action types

### Phase 2: Documentation (Medium Priority)
1. Document deleted account behavior (no changes needed, current behavior is correct)
2. Document forwarded message behavior (no changes needed, current behavior is correct)
3. Update metrics.py docstring to mention these edge cases

### Phase 3: Optional Enhancements (Low Priority)
1. Consider adding optional metadata fields to Message model:
   - `is_forwarded: bool` - for analytics
   - `is_deleted_user: bool` - for analytics
2. These don't affect unique_authors counting but may be useful for other analysis

## Summary

| Edge Case | Solution | Changes Needed |
|-----------|----------|----------------|
| Deleted Accounts | Count by ID | None (already correct) |
| Forwarded Messages | Count forwarder | None (already correct) |
| Service Messages | Filter out | Update `_telethon_message_to_model()` |

The only code change needed is filtering service messages. The other edge cases are already handled correctly by the current implementation.

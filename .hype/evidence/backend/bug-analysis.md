# Bug Analysis: test_needs_code_to_connected_success

## Issue
Test `test_needs_code_to_connected_success` fails because mock publish is never called.

## Root Cause
The test patches `chatfilter.web.events.get_event_bus`, but the code imports it as:

```python
from chatfilter.web.events import get_event_bus
```

This means the function is bound to the module namespace at import time. The test needs to patch `chatfilter.web.routers.sessions.get_event_bus` instead.

## Location
- Test: tests/test_connect_flow_states.py:282
- Code: src/chatfilter/web/routers/sessions.py:2725

## Expected Behavior
When `verify_code` successfully authenticates, `_finalize_reconnect_auth` should publish a "connected" event via SSE.

## Actual Behavior
The test patches the wrong import path, so the event bus publish never gets mocked, and no calls are tracked.

## Fix Required
Change test from:
```python
patch("chatfilter.web.events.get_event_bus")
```

To:
```python
patch("chatfilter.web.routers.sessions.get_event_bus")
```

## Severity
**P1** - Test is not testing what it claims to test (mocking error), but the actual code is likely working correctly.

## Evidence
- Debug output shows 0 publish calls: .hype/evidence/backend/debug-execution.txt
- Mock calls show sign_in, get_me, disconnect all work correctly
- Only the event bus publish is not being called because mock isn't applied

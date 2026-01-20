# Session Management & Multi-Tab Support

This document describes the session management system implemented in ChatFilter for supporting multiple browser tabs and maintaining user state across page refreshes.

## Overview

ChatFilter implements a **hybrid session management system** that combines:

1. **Server-side sessions** - Secure cookie-based session tracking with server-side state storage
2. **Client-side tab synchronization** - localStorage-based cross-tab communication

This architecture enables:
- Multiple browser tabs working independently
- State persistence across page refreshes
- Real-time synchronization between tabs (optional)
- Secure session isolation per user

## Architecture

### Server-Side Sessions

#### Components

1. **Session Storage** (`src/chatfilter/web/session.py`)
   - `SessionData`: Container for session-specific data
   - `SessionStore`: Thread-safe in-memory session storage
   - `get_session()`: Dependency injection helper for route handlers

2. **Session Middleware** (`src/chatfilter/web/middleware.py`)
   - `SessionMiddleware`: Automatically manages session cookies on all requests/responses
   - Creates new sessions for first-time visitors
   - Retrieves existing sessions via cookies
   - Sets secure session cookies on responses

3. **Dependencies** (`src/chatfilter/web/dependencies.py`)
   - `get_web_session()`: FastAPI dependency for accessing session in routes
   - `WebSession`: Type alias for session dependency injection

#### Session Data Structure

Each session stores:
- `session_id`: Unique identifier (URL-safe token)
- `created_at`: Timestamp of session creation
- `last_accessed`: Last access timestamp (for TTL)
- `data`: Dictionary of session-specific data
  - `selected_telegram_session`: Currently selected Telegram session
  - `selected_chats`: List of selected chat IDs
  - `current_task_id`: Current analysis task ID
  - Custom user preferences

#### Configuration

```python
# Session configuration in src/chatfilter/web/session.py
SESSION_COOKIE_NAME = "chatfilter_session"
SESSION_TTL = 3600 * 24  # 24 hours
SESSION_CLEANUP_INTERVAL = 3600  # 1 hour
```

#### Security Features

- **HTTPOnly cookies**: Prevents JavaScript access to session IDs
- **SameSite=Lax**: CSRF protection
- **Secure flag**: Should be enabled in production with HTTPS
- **Signed cookies**: Session IDs are cryptographically secure tokens
- **TTL-based expiration**: Sessions expire after 24 hours of inactivity
- **Automatic cleanup**: Expired sessions are removed periodically

### Client-Side Tab Synchronization

#### Components

1. **TabSync Module** (`src/chatfilter/static/js/tab-sync.js`)
   - Event-based cross-tab communication
   - Uses localStorage and storage events
   - Debouncing to prevent excessive updates

#### How It Works

```javascript
// Tab 1: Broadcast event
TabSync.broadcast('session_selected', {
    sessionId: 'my_session',
    timestamp: Date.now()
});

// Tab 2: Listen for event
TabSync.on('session_selected', function(data) {
    console.log('Session selected in another tab:', data.sessionId);
    // Update UI to reflect the change
});
```

#### Storage Events

- When tab 1 modifies localStorage, tabs 2-N receive `storage` events
- Events contain: `key`, `oldValue`, `newValue`, `url`
- TabSync module filters events by prefix and dispatches to handlers

#### Debouncing

- Rapid consecutive updates are debounced (100ms)
- Prevents excessive UI updates and event handler executions

## Usage Guide

### In Route Handlers

Use the `WebSession` dependency to access session data:

```python
from fastapi import APIRouter, Request
from chatfilter.web.dependencies import WebSession

router = APIRouter()

@router.get("/my-route")
async def my_route(
    request: Request,
    session: WebSession
) -> dict:
    # Get session data
    selected_session = session.get("selected_telegram_session")

    # Set session data
    session.set("selected_telegram_session", "new_value")

    # Delete session data
    session.delete("some_key")

    # Clear all session data
    session.clear()

    return {"selected_session": selected_session}
```

### In JavaScript/Templates

Use the TabSync module for cross-tab communication:

```javascript
// Broadcast when user selects a session
document.getElementById('session-select').addEventListener('change', function() {
    TabSync.broadcast('session_selected', {
        sessionId: this.value
    });
});

// Listen for selections from other tabs
TabSync.on('session_selected', function(data) {
    // Update UI to match selection
    document.getElementById('session-select').value = data.sessionId;

    // Trigger HTMX to load data
    htmx.trigger(document.getElementById('session-select'), 'change');

    // Show notification
    ToastManager.info('Session synced from another tab');
});
```

### Example: Chats Page

The chats page demonstrates full integration:

1. **Server-side** (`src/chatfilter/web/routers/chats.py`):
   ```python
   @router.get("/api/chats")
   async def get_chats(
       request: Request,
       web_session: WebSession,
       session_id: str = Query(alias="session-select")
   ):
       # Store selection in user's session
       web_session.set("selected_telegram_session", session_id)

       # Fetch chats and return HTML
       ...
   ```

2. **Client-side** (`src/chatfilter/templates/chats.html`):
   ```javascript
   // Broadcast selection to other tabs
   sessionSelect.addEventListener('change', function() {
       TabSync.broadcast('session_selected', {
           sessionId: this.value
       });
   });

   // Sync from other tabs
   TabSync.on('session_selected', function(data) {
       sessionSelect.value = data.sessionId;
       htmx.trigger(sessionSelect, 'change');
   });
   ```

## Multi-Tab Behavior

### Scenario 1: User Opens Two Tabs

1. **Tab 1**: User visits site
   - Server creates new session with unique ID
   - Session cookie is set: `chatfilter_session=abc123`

2. **Tab 2**: User opens new tab with same domain
   - Browser sends same cookie: `chatfilter_session=abc123`
   - Server retrieves same session data
   - Both tabs share the same server-side session

### Scenario 2: User Selects Session in Tab 1

1. **Tab 1**: User selects "my_session" from dropdown
   - Server stores in session: `selected_telegram_session = "my_session"`
   - JavaScript broadcasts: `TabSync.broadcast('session_selected', {...})`
   - localStorage updated: `chatfilter_sync_session_selected = {...}`

2. **Tab 2**: Receives storage event
   - `storage` event fires with new value
   - TabSync dispatches to registered handlers
   - Handler updates dropdown to "my_session"
   - HTMX triggers request to load chats
   - Shows notification: "Session synced from another tab"

### Scenario 3: Page Refresh

1. **Before refresh**: Session state is stored server-side
2. **After refresh**:
   - Session cookie is sent with request
   - Server retrieves session data
   - Page can restore previous state
   - No data loss

## Production Considerations

### Scaling with Multiple Workers

The current implementation uses **in-memory session storage**, which works for:
- Single-process deployments
- Development environments
- Small-scale production (one worker)

For **multi-worker** deployments (multiple uvicorn workers), use a **shared session backend**:

#### Option 1: Redis

```python
# Install: pip install redis
import redis
from chatfilter.web.session import SessionStore

class RedisSessionStore(SessionStore):
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis = redis.from_url(redis_url)

    def get_session(self, session_id: str):
        data = self.redis.get(f"session:{session_id}")
        if data:
            return json.loads(data)
        return None

    def set_session(self, session_id: str, data: dict):
        self.redis.setex(
            f"session:{session_id}",
            SESSION_TTL,
            json.dumps(data)
        )
```

#### Option 2: Database

Store sessions in SQLite/PostgreSQL with the task queue database.

#### Option 3: External Session Library

Use `starlette-session` or similar with Redis/database backend.

### Security Hardening

For production deployments:

1. **Enable HTTPS**:
   ```python
   # In src/chatfilter/web/session.py
   response.set_cookie(
       secure=True,  # Only send over HTTPS
       ...
   )
   ```

2. **Set SameSite=Strict** (if no cross-site requests needed):
   ```python
   response.set_cookie(
       samesite="strict",
       ...
   )
   ```

3. **Add CSRF protection** for state-changing operations

4. **Rate limit** session creation to prevent DoS

5. **Monitor** session store size and implement cleanup

### Performance Optimization

1. **Session cleanup**: Runs automatically every hour
   ```python
   store.cleanup_expired()  # Manual cleanup
   ```

2. **Lazy loading**: Sessions are only loaded when accessed

3. **Debouncing**: Tab sync events are debounced (100ms)

4. **Cache headers**: Set appropriate cache headers for static assets

## Testing

### Manual Testing

1. **Single tab**:
   - Select a session, verify it persists across page refresh
   - Check that selection is stored in session cookie

2. **Multiple tabs**:
   - Open 2 tabs
   - Select session in Tab 1
   - Verify Tab 2 updates automatically
   - Check browser console for sync messages

3. **Session expiration**:
   - Wait 24 hours or manually expire session
   - Verify new session is created on next request

### Automated Testing

```python
# Example test for session management
from chatfilter.web.session import SessionStore

def test_session_creation():
    store = SessionStore()
    session = store.create_session()

    assert session.session_id is not None
    assert len(session.session_id) > 20
    assert session.data == {}

def test_session_data_storage():
    store = SessionStore()
    session = store.create_session()

    session.set("key", "value")
    assert session.get("key") == "value"

    retrieved = store.get_session(session.session_id)
    assert retrieved.get("key") == "value"
```

## Troubleshooting

### Issue: State not persisting across refreshes

**Cause**: Session cookie not being set or not sent by browser

**Solution**:
1. Check browser dev tools → Application → Cookies
2. Verify `chatfilter_session` cookie exists
3. Check cookie domain and path settings
4. Ensure cookies are enabled in browser

### Issue: Tabs not syncing

**Cause**: localStorage not working or storage events not firing

**Solution**:
1. Check browser console for TabSync initialization messages
2. Verify localStorage is enabled (not in private browsing)
3. Check that both tabs are on same domain (storage events don't cross domains)
4. Look for JavaScript errors in console

### Issue: Memory leak from sessions

**Cause**: Sessions not being cleaned up

**Solution**:
1. Check session cleanup is running: `store.get_session_count()`
2. Manually trigger cleanup: `store.cleanup_expired()`
3. Consider reducing `SESSION_TTL` for shorter-lived sessions
4. Monitor memory usage and implement limits

## Future Enhancements

Potential improvements to the session system:

1. **WebSocket-based sync**: Real-time bidirectional communication (more reliable than localStorage)
2. **Session migration**: Move sessions between storage backends
3. **Session analytics**: Track session duration, page views, etc.
4. **Persistent sessions**: "Remember me" functionality
5. **Multi-device sync**: Sync state across devices (requires backend changes)
6. **Conflict resolution**: Handle simultaneous updates from multiple tabs
7. **Session replay**: Record and replay user interactions for debugging

## References

- [MDN: Web Storage API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Storage_API)
- [MDN: Storage Event](https://developer.mozilla.org/en-US/docs/Web/API/Window/storage_event)
- [FastAPI: Dependencies](https://fastapi.tiangolo.com/tutorial/dependencies/)
- [Starlette: Sessions](https://www.starlette.io/middleware/#sessionmiddleware)

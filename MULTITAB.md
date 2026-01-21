# Multi-Tab Support Documentation

## Overview

ChatFilter now fully supports multiple browser tabs with comprehensive conflict prevention and state synchronization. This document describes the multi-tab architecture, features, and testing procedures.

## Architecture

### Components

The multi-tab support system consists of 5 JavaScript modules that work together:

1. **tab-sync.js** - Cross-tab communication using localStorage
2. **tab-activity.js** - Tab visibility and activity state tracking
3. **request-dedup.js** - Request deduplication to prevent duplicate API calls
4. **optimistic-lock.js** - Optimistic locking for critical operations
5. **conflict-warnings.js** - User warnings for potential conflicts

### Component Details

#### 1. TabSync (tab-sync.js)

**Purpose**: Enable cross-tab communication using localStorage and storage events.

**Features**:
- Broadcast events to all tabs
- Listen for events from other tabs
- Automatic debouncing (100ms)
- Namespace prefixed keys (`chatfilter_sync_`)

**API**:
```javascript
TabSync.broadcast('event_type', data)  // Send event to other tabs
TabSync.on('event_type', handler)      // Listen for events
TabSync.off('event_type', handler)     // Remove listener
TabSync.get('event_type')              // Get current value
TabSync.clear()                        // Clear all sync data
```

#### 2. TabActivity (tab-activity.js)

**Purpose**: Track tab visibility, focus, and activity state.

**States**:
- `ACTIVE` - Tab is visible and focused
- `VISIBLE` - Tab is visible but not focused
- `HIDDEN` - Tab is hidden
- `INACTIVE` - Tab has been inactive for >1 minute

**Features**:
- Tracks user activity (mouse, keyboard, scroll, touch)
- Inactivity timeout (1 minute)
- Heartbeat broadcasting (every 5 seconds)
- Unique tab ID generation

**API**:
```javascript
TabActivity.getState()              // Get current state
TabActivity.isActive()              // Is tab active?
TabActivity.isVisible()             // Is tab visible?
TabActivity.isHidden()              // Is tab hidden?
TabActivity.isInactive()            // Is tab inactive?
TabActivity.getTabId()              // Get unique tab ID
TabActivity.onStateChange(callback) // Listen for state changes
```

#### 3. RequestDedup (request-dedup.js)

**Purpose**: Prevent duplicate API requests across tabs.

**Features**:
- Tracks in-flight requests by unique key (method + URL + params)
- Request timeout (30 seconds)
- Automatic HTMX integration
- Toast notifications for blocked requests

**How it works**:
1. Before HTMX request, check if duplicate is in flight
2. If duplicate found in this tab or another, cancel request
3. Show toast notification explaining why request was blocked
4. When request completes, remove from tracking

**API**:
```javascript
RequestDedup.getRequestKey(method, url, params)  // Generate request key
RequestDedup.isRequestInFlight(key)              // Check if in flight
RequestDedup.markRequestStarted(key, tabId)      // Mark as started
RequestDedup.markRequestCompleted(key, success)  // Mark as completed
```

#### 4. OptimisticLock (optimistic-lock.js)

**Purpose**: Prevent race conditions for critical operations (delete, cancel, etc.).

**Features**:
- Lock timeout (30 seconds)
- Automatic HTMX integration via `data-lock` attribute
- Cross-tab lock coordination
- Toast notifications for denied locks

**How it works**:
1. Before critical operation, try to acquire lock
2. If lock held by another tab, deny operation and show warning
3. When operation completes (success or failure), release lock
4. Locks expire after 30 seconds

**Usage**:
```html
<!-- Add data-lock attribute to buttons -->
<button hx-delete="/api/sessions/123"
        data-lock="session:123:delete">
    Delete
</button>
```

**API**:
```javascript
OptimisticLock.tryAcquireLock(type, id, operation)  // Try to acquire
OptimisticLock.releaseLock(type, id, operation)     // Release lock
OptimisticLock.isLockedByOtherTab(type, id, op)     // Check if locked
OptimisticLock.getLockInfo(type, id, operation)     // Get lock info
```

#### 5. ConflictWarnings (conflict-warnings.js)

**Purpose**: Warn users about potential multi-tab conflicts.

**Features**:
- Tab count warning (>5 tabs)
- Stale state warning (inactive >5 minutes)
- Concurrent operation notifications
- Unsaved changes warning on page close

**Warnings**:
- **Too Many Tabs**: Shows warning when 5+ tabs are open
- **Stale State**: When tab becomes active after 5+ minutes of inactivity
- **Concurrent Operations**: Info toast when another tab performs critical operation
- **Unsaved Changes**: Browser confirmation when closing tab with unsaved checkbox selections

**API**:
```javascript
ConflictWarnings.showWarning(message, options)  // Custom warning
ConflictWarnings.checkTabCount()                // Check tab count now
ConflictWarnings.checkStaleState()              // Check stale state now
ConflictWarnings.getActiveTabCount()            // Get number of tabs
ConflictWarnings.configure(options)             // Update config
```

## Synchronized Features

### Session Selection
When a user selects a Telegram session in one tab, all other tabs automatically sync to that selection and reload their chat lists.

**Implementation**: [chats.html:L126-145](src/chatfilter/templates/chats.html#L126-145)

### Telegram Connection Status
When Telegram connection status changes in one tab, all tabs immediately check their own status and update their UI.

**Implementation**: [base.html:L497-530](src/chatfilter/templates/base.html#L497-530)

### Critical Operations
The following operations are protected with optimistic locking:
- Session deletion (`data-lock="session:ID:delete"`)
- Analysis cancellation (programmatic lock acquisition)

## Testing Multi-Tab Support

### Manual Testing Checklist

#### Basic Functionality
- [ ] Open 2 tabs with the application
- [ ] Verify both tabs load without errors
- [ ] Check browser console for initialization messages

#### Request Deduplication
- [ ] Open 2 tabs on the Chats page
- [ ] Select same session in both tabs
- [ ] Click "Start Analysis" in both tabs quickly
- [ ] Verify only one analysis starts
- [ ] Verify second tab shows toast: "Request is already being processed in another tab"

#### Session Deletion Lock
- [ ] Open 2 tabs on the Sessions page
- [ ] Click Delete on same session in both tabs quickly
- [ ] Verify only one delete proceeds
- [ ] Verify second tab shows toast: "This operation is being performed in another tab"

#### Analysis Cancellation Lock
- [ ] Open 2 tabs and start an analysis
- [ ] Click Cancel in both tabs quickly
- [ ] Verify only one cancel proceeds
- [ ] Verify second tab shows toast: "Cancellation is already in progress in another tab"

#### Session Selection Sync
- [ ] Open 2 tabs on the Chats page
- [ ] Select different sessions in each tab
- [ ] Change session in Tab 1
- [ ] Verify Tab 2 automatically switches to same session and reloads chats
- [ ] Verify toast in Tab 2: "Session selection synced from another tab"

#### Telegram Status Sync
- [ ] Open 2 tabs
- [ ] Monitor status indicator in both tabs
- [ ] When status changes in one tab, verify other tab updates within 5 seconds

#### Tab Count Warning
- [ ] Open 5+ tabs with the application
- [ ] Verify warning toast appears: "You have X tabs open. This may cause performance issues and conflicts."

#### Stale State Warning
- [ ] Open a tab and leave it inactive for 5+ minutes (or modify STALE_STATE_THRESHOLD for testing)
- [ ] Focus the tab
- [ ] Verify warning toast: "You've been away for a while. The page state may be outdated."
- [ ] Click "Reload Page" and verify page reloads

#### Unsaved Changes Warning
- [ ] Open Chats page
- [ ] Check some chat checkboxes
- [ ] Try to close the tab
- [ ] Verify browser shows "Leave site?" confirmation

### Automated Testing

To create automated tests, consider testing:

1. **TabSync messaging**
   - Simulate localStorage changes
   - Verify event handlers are called
   - Verify debouncing works

2. **Request deduplication**
   - Mock HTMX requests
   - Verify duplicate detection
   - Verify timeout cleanup

3. **Optimistic locking**
   - Test lock acquisition/release
   - Test lock expiration
   - Test cross-tab coordination

4. **Tab activity tracking**
   - Mock visibility change events
   - Mock focus/blur events
   - Verify state transitions

## Edge Cases Handled

### Page Refresh
- Active analysis progress recovered via initial status check
- In-flight requests tracked in memory are cleared (by design)
- Locks held by refreshed tab timeout after 30 seconds

### Tab Close
- Heartbeat stops
- Other tabs detect absence after 1 minute
- Locks expire after 30 seconds
- Unsaved changes prompt shown if applicable

### Network Issues
- Request deduplication continues to work (localStorage-based)
- Optimistic locks continue to work (localStorage-based)
- Tab activity tracking continues to work (localStorage-based)

### Browser Refresh
- Tab ID regenerated (new tab identity)
- Session cookie preserved (server-side session continues)
- Sync state cleared (clean slate)

### Server Restart
- In-memory sessions lost
- Client reconnects automatically
- Request deduplication resets
- Optimistic locks reset

## Configuration

All modules are configured with sensible defaults, but can be customized:

```javascript
// Customize conflict warnings
ConflictWarnings.configure({
    enableTabCountWarning: true,
    enableStaleStateWarning: true,
    enableConcurrentOpWarning: true,
    maxTabs: 5
});
```

## Browser Support

- **Modern browsers**: Full support (Chrome, Firefox, Safari, Edge)
- **IE11**: Not supported (uses modern JavaScript features)
- **Private/Incognito mode**: Full support (localStorage works within session)

## Performance Considerations

- **localStorage**: Synchronous API, but fast for small data
- **Debouncing**: 100ms debounce prevents excessive events
- **Heartbeat**: 5-second interval is lightweight
- **Cleanup**: Automatic cleanup prevents memory leaks

## Known Limitations

1. **Same-origin only**: Only works across tabs on same domain
2. **localStorage limit**: 5-10MB per origin (more than sufficient)
3. **No shared workers**: Uses localStorage instead of SharedWorker for better compatibility
4. **Server-side coordination**: Not implemented (not needed for current use cases)

## Future Enhancements

Potential improvements for future versions:

1. **Leader election**: Designate one tab as leader for coordinating operations
2. **Shared WebSocket**: Single WebSocket connection shared across tabs
3. **Persistent locks**: Store locks in database for server restart recovery
4. **Conflict resolution UI**: Visual indicator showing which tab owns what operation
5. **Tab list view**: Show all open tabs and their current page/state

## Troubleshooting

### Problem: Tabs not syncing
**Solution**: Check browser console for errors. Verify localStorage is enabled.

### Problem: Too many lock warnings
**Solution**: Increase LOCK_TIMEOUT or reduce concurrent operations.

### Problem: Stale state warnings too frequent
**Solution**: Increase STALE_STATE_THRESHOLD in conflict-warnings.js.

### Problem: Request deduplication too aggressive
**Solution**: Adjust REQUEST_TIMEOUT in request-dedup.js.

## Related Files

- [tab-sync.js](src/chatfilter/static/js/tab-sync.js) - Cross-tab messaging
- [tab-activity.js](src/chatfilter/static/js/tab-activity.js) - Activity tracking
- [request-dedup.js](src/chatfilter/static/js/request-dedup.js) - Request dedup
- [optimistic-lock.js](src/chatfilter/static/js/optimistic-lock.js) - Locking
- [conflict-warnings.js](src/chatfilter/static/js/conflict-warnings.js) - Warnings
- [base.html](src/chatfilter/templates/base.html) - Script loading
- [sessions_list.html](src/chatfilter/templates/partials/sessions_list.html) - Delete buttons with locks
- [analysis_progress.html](src/chatfilter/templates/partials/analysis_progress.html) - Cancel with lock

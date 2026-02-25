# Diagnosis: SSE event.detail format in htmx:sseMessage

## Investigation

### Source: sse.js line 152
```javascript
api.triggerEvent(elt, "htmx:sseMessage", event);
```

Where `event` is the raw MessageEvent from EventSource.

### How triggerEvent works (htmx API)
```javascript
api.triggerEvent(element, eventName, detail)
```
Creates a CustomEvent where the third parameter becomes `event.detail`.

### Result
When `htmx:sseMessage` fires, `event.detail` contains the **raw MessageEvent** with:
- `event.detail.type` — SSE event type (e.g., "message", "init", "ping")
- `event.detail.data` — raw string data from server
- `event.detail.lastEventId` — event ID if present
- `event.detail.origin` — source origin

### Current listener code (group_card.html:297-316)
```javascript
document.body.addEventListener('htmx:sseMessage', function(event) {
    if (!event || !event.detail) return;
    
    const sseEvent = event.detail;  // This IS the MessageEvent
    
    if (sseEvent.type === 'ping') {
        return;
    }
    
    const data = JSON.parse(sseEvent.data);
    if (data.group_id !== groupId) return;
    // ... process data
});
```

## Conclusion

✅ **The listener code is CORRECT**
- `event.detail` correctly contains the MessageEvent
- `sseEvent.type` correctly accesses the SSE event type
- `sseEvent.data` correctly accesses the raw data string
- Parser works as expected: `JSON.parse(sseEvent.data)`

**The format is exactly what the listener expects. No changes needed to data parsing logic.**

## Related Issues

The actual problem is NOT data format — it's stale DOM references and listener leaks:
- ChatFilter-6j8: DOM elements cached at script init become stale after refreshGroups()
- ChatFilter-y19: Multiple listeners accumulate without cleanup

The data parsing is working correctly. The bug is in DOM manipulation, not event structure.

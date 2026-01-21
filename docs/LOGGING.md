# ChatFilter Logging Guide

This guide explains how to use ChatFilter's logging system for debugging and troubleshooting.

## Log Formats

ChatFilter supports two log formats:

### Text Format (Default)

Human-readable format suitable for console viewing:

```
2026-01-21 10:30:45 [INFO] [abc123def456] [chat:-] chatfilter.web.app: Request started
2026-01-21 10:30:45 [INFO] [abc123def456] [chat:12345] chatfilter.telegram.client: Fetching messages
2026-01-21 10:30:46 [INFO] [abc123def456] [chat:-] chatfilter.web.app: Request completed
```

Format breakdown:
- `2026-01-21 10:30:45` - Timestamp (YYYY-MM-DD HH:MM:SS)
- `[INFO]` - Log level (DEBUG, INFO, WARNING, ERROR)
- `[abc123def456]` - Correlation ID (tracks request through system)
- `[chat:12345]` - Chat ID context (for Telegram operations)
- `chatfilter.web.app` - Logger name (module path)
- Message text

### JSON Format

Structured format for log aggregators (ELK, Datadog, CloudWatch, Splunk):

```json
{"timestamp": "2026-01-21T10:30:45.123456+00:00", "level": "INFO", "logger": "chatfilter.web.app", "message": "Request started", "correlation_id": "abc123def456", "method": "GET", "path": "/api/chats"}
```

Enable with `--log-format json` or `CHATFILTER_LOG_FORMAT=json`.

## Command Line Options

```bash
# Set log level
chatfilter --log-level DEBUG

# Enable verbose mode (detailed operation logs)
chatfilter --verbose
chatfilter -v

# Use JSON format for log aggregation
chatfilter --log-format json

# Combine options
chatfilter --verbose --log-format json --log-level DEBUG
```

## Environment Variables

```bash
# Log level (DEBUG, INFO, WARNING, ERROR)
export CHATFILTER_LOG_LEVEL=DEBUG

# Log format (text or json)
export CHATFILTER_LOG_FORMAT=json

# Verbose mode
export CHATFILTER_VERBOSE=true

# Per-module log levels (JSON format)
export CHATFILTER_LOG_MODULE_LEVELS='{"chatfilter.telegram": "DEBUG", "chatfilter.web": "WARNING"}'
```

## Log Levels

| Level   | Use Case |
|---------|----------|
| DEBUG   | Detailed debugging information, timing metrics |
| INFO    | General operational information |
| WARNING | Potential issues that don't stop operation |
| ERROR   | Errors that affect operation |

## Verbose Mode

Verbose mode (`-v` or `--verbose`) enables:

1. **Detailed timing metrics** - Duration of key operations
2. **Request body logging** - POST/PUT/PATCH request bodies (sanitized)
3. **Operation-level logging** - More granular log messages

All sensitive data is automatically sanitized (see Security section).

## Per-Module Log Levels

Configure different log levels for different parts of the application:

```python
# In settings or environment
log_module_levels = {
    "chatfilter.telegram": "DEBUG",    # Detailed Telegram operations
    "chatfilter.web": "WARNING",        # Only warnings from web layer
    "chatfilter.analyzer": "INFO",      # Normal logging for analyzer
}
```

## Log File Configuration

Logs are written to a rotating log file by default:

| Setting | Default | Description |
|---------|---------|-------------|
| `log_to_file` | `true` | Enable file logging |
| `log_file_max_bytes` | 10 MB | Max size before rotation |
| `log_file_backup_count` | 5 | Number of backup files |

Log file location:
- **macOS**: `~/Library/Logs/ChatFilter/chatfilter.log`
- **Linux**: `~/.local/state/chatfilter/log/chatfilter.log`
- **Windows**: `%LOCALAPPDATA%/ChatFilter/Logs/chatfilter.log`

## Security: Log Sanitization

ChatFilter automatically sanitizes sensitive data from logs:

| Data Type | Replacement |
|-----------|-------------|
| Session tokens | `***SESSION_TOKEN***` |
| Bot tokens | `***BOT_TOKEN***` |
| API keys/hashes | `***TOKEN***` |
| Phone numbers | `***PHONE***` |
| IP addresses | `***IP***` |
| Passwords | `***PASSWORD***` |
| Secret keys | `***SECRET***` |
| Auth headers | `***AUTH***` |
| Credit cards | `***CARD***` |
| Email addresses | `***@domain.com` |
| AWS keys | `***AWS_KEY***` |
| Hex secrets | `***HEX_SECRET***` |

Exception tracebacks are also sanitized.

## Sharing Logs for Troubleshooting

When sharing logs for troubleshooting:

1. **Collect logs**: Copy from log file location (above) or console
2. **Include correlation ID**: Look for `[abc123...]` in the log
3. **Provide context**: What operation were you performing?
4. **Check sanitization**: While automatic, review logs before sharing

Example log excerpt to share:

```
2026-01-21 10:30:45 [ERROR] [abc123def456] [chat:12345] chatfilter.telegram.client: Failed to fetch messages
Traceback (most recent call last):
  File "chatfilter/telegram/client.py", line 100, in fetch_messages
    ...
TimeoutError: Connection timed out
```

## Timing Metrics

In verbose mode, operations include timing information:

```json
{"timestamp": "...", "level": "DEBUG", "message": "fetch_messages completed", "operation": "fetch_messages", "duration_ms": 1234.56, "success": true}
```

Use this to identify slow operations.

## Chat Context Tracking

Telegram operations include chat ID context:

```
[chat:12345] Fetching messages from chat
[chat:12345] Processing 500 messages
[chat:-] Chat context cleared
```

This helps correlate logs for specific chat operations.

## Troubleshooting Common Issues

### "No logs appearing"

1. Check log level isn't too restrictive
2. Verify log file path is writable
3. Try `--log-level DEBUG` for more output

### "Logs too verbose"

1. Use `--log-level WARNING` to reduce output
2. Configure per-module levels to silence specific modules

### "Can't find specific request"

1. Look for correlation ID in error message
2. Search logs for that correlation ID
3. All log entries for that request will share the ID

### "Need to debug Telegram operations"

```bash
# Enable debug just for Telegram module
CHATFILTER_LOG_MODULE_LEVELS='{"chatfilter.telegram": "DEBUG"}' chatfilter
```

## Integration with Log Aggregators

For production deployments, use JSON format with your log aggregator:

```bash
# Run with JSON logging
chatfilter --log-format json 2>&1 | your-log-shipper
```

Example fields available for filtering/alerting:
- `level`: Log level for filtering errors
- `correlation_id`: Track requests across services
- `chat_id`: Filter by Telegram chat
- `duration_ms`: Alert on slow operations
- `status_code`: Track HTTP response codes

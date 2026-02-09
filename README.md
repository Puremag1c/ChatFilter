# ChatFilter

Telegram chat filtering and analysis tool with web interface.

## Quick Start

### Prerequisites

- Python 3.11 or higher
- pip or uv package manager

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ChatFilter.git
cd ChatFilter

# Install package (choose one)
pip install -e .        # using pip
uv pip install -e .     # using uv (faster)

# Run application
chatfilter
```

The server will start at `http://127.0.0.1:8000` by default.

## Configuration

### Command Line Options

```bash
chatfilter --help
```

Available options:
- `--host HOST` - Server host (default: 127.0.0.1, env: `CHATFILTER_HOST`)
- `--port PORT` - Server port (default: 8000, env: `CHATFILTER_PORT`)
- `--debug` - Enable debug mode (env: `CHATFILTER_DEBUG`)
- `--data-dir PATH` - Data directory path (env: `CHATFILTER_DATA_DIR`)
- `--log-level LEVEL` - Logging level: DEBUG, INFO, WARNING, ERROR (env: `CHATFILTER_LOG_LEVEL`)
- `--check-config` - Validate configuration and exit
- `--version` - Show version and exit

### Environment Variables

Create a `.env` file in your data directory:

```bash
CHATFILTER_HOST=127.0.0.1
CHATFILTER_PORT=8000
CHATFILTER_DEBUG=false
CHATFILTER_LOG_LEVEL=INFO
```

### CORS Configuration (Separated Frontend/Backend)

If you're running the frontend separately from the backend API, you need to configure CORS (Cross-Origin Resource Sharing) to allow cross-origin requests.

**Default Allowed Origins:**

The application includes default CORS origins for common development scenarios:
- `http://localhost:8000`, `http://127.0.0.1:8000` (backend)
- `http://localhost:3000`, `http://127.0.0.1:3000` (React, Next.js)
- `http://localhost:5173`, `http://127.0.0.1:5173` (Vite)
- `http://localhost:4200`, `http://127.0.0.1:4200` (Angular)

**Environment Variable:**

Set `CHATFILTER_CORS_ORIGINS` to a comma-separated list of allowed origins:

```bash
CHATFILTER_CORS_ORIGINS=http://localhost:3000,https://myapp.com
```

**Security Notes:**

- **Allowed Methods:** Only `GET`, `POST`, and `DELETE` are permitted (not `PUT`, `PATCH`)
- **Allowed Headers:** Limited to `Content-Type`, `Accept`, `Accept-Language`, `Content-Language`
- **Credentials:** Enabled (`allow_credentials=True`) for cookie-based authentication
- **Production:** Always restrict origins to your specific domain(s) in production:
  ```bash
  CHATFILTER_CORS_ORIGINS=https://yourdomain.com
  ```

**Programmatic Configuration:**

You can also configure CORS programmatically when creating the app:

```python
from chatfilter.web.app import create_app

app = create_app(cors_origins=["https://yourdomain.com"])
```

### Network and Firewall Configuration

ChatFilter connects to Telegram servers using the MTProto protocol. If you're running ChatFilter in a corporate environment with firewall restrictions, you may need to:

- Allow outbound connections to Telegram servers (port 443)
- Configure proxy settings to bypass firewall restrictions
- Whitelist Telegram domains and IP ranges

For detailed information about network requirements, firewall configuration, and proxy setup, see [Network and Firewall Documentation](docs/NETWORK_AND_FIREWALL.md).

**Quick Proxy Setup:**

If direct connection to Telegram is blocked, you can configure a SOCKS5 or HTTP proxy:

1. Start ChatFilter and open the web interface
2. Navigate to **Proxies** in the navigation menu
3. Click **Add Proxy** and configure your proxy details (name, host, port, type)
4. Assign the proxy to your session(s)

Proxies are automatically health-checked and disabled if they become unavailable.

### Examples

Run on custom port:
```bash
chatfilter --port 9000
```

Run in debug mode:
```bash
chatfilter --debug
```

Bind to all interfaces:
```bash
chatfilter --host 0.0.0.0 --port 8080
```

## Usage

1. **Start the server** (see Running the Application above)
2. **Open web interface** at `http://127.0.0.1:8000`
3. **Upload Telegram session file** (`.session` file from Telethon)
4. **Select chats** to analyze
5. **Export results** to Excel or other formats

### Getting a Telegram Session File

To use ChatFilter, you need a Telegram session file:

1. Install Telethon: `pip install telethon`
2. Create a session using the [Telegram API](https://my.telegram.org/apps)
3. Use the session file with ChatFilter

See the web interface onboarding for detailed instructions.

## Development

### Install with Development Dependencies

```bash
pip install -e ".[dev]"    # or: uv pip install -e ".[dev]"
```

### Run Tests

```bash
pytest                                      # full test suite
pytest --cov=chatfilter --cov-report=html   # with coverage
pytest tests/test_filter.py                 # specific file
```

### Code Quality

```bash
ruff check .              # linting
ruff check --fix .        # auto-fix
mypy src/                 # type checking
```

### Internationalization (i18n)

ChatFilter uses Babel for internationalization. The workflow consists of three steps:

**1. Extract translatable strings from source code:**
```bash
pybabel extract -F babel.cfg -o src/chatfilter/i18n/messages.pot src/chatfilter
```

This extracts strings from Python files (`.py`) and Jinja2 templates (`.html`) according to `babel.cfg` configuration.

**2. Update or initialize locale-specific .po files:**
```bash
# Initialize new locale (first time only)
pybabel init -i src/chatfilter/i18n/messages.pot -d src/chatfilter/i18n/locales -l ru

# Update existing locale with new strings
pybabel update -i src/chatfilter/i18n/messages.pot -d src/chatfilter/i18n/locales
```

Then manually translate strings in `src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.po` (or other locales).

**3. Compile .po files to binary .mo format:**
```bash
msgfmt -c -v -o src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.mo \
              src/chatfilter/i18n/locales/ru/LC_MESSAGES/messages.po
```

The `-c` flag checks for errors, `-v` provides verbose output. The compiled `.mo` files are used at runtime.

**Verification:**
- `pybabel extract` should complete without errors
- `messages.po` should contain all translatable strings from templates
- `msgfmt` should compile without warnings

### Project Structure

```
ChatFilter/
├── src/chatfilter/       # Main package source code
│   ├── main.py          # Entry point
│   ├── filter/          # Chat filtering logic
│   ├── web/             # FastAPI web application
│   └── session/         # Telegram session management
├── tests/               # Test suite
└── pyproject.toml       # Project configuration
```

## License

MIT

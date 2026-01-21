# ChatFilter

Telegram chat filtering and analysis tool with web interface.

## Quick Start

### Download Pre-built Binaries

Download the latest build for your platform from GitHub Actions artifacts:

- **Windows**: Download `ChatFilter-Windows-exe.zip`, extract `ChatFilter.exe`
- **macOS**: Download `ChatFilter-macOS-app.zip`, extract and open `ChatFilter.app`

#### Windows SmartScreen Warning

When running `ChatFilter.exe` for the first time, Windows SmartScreen may show a warning: **"Windows protected your PC"**.

This happens because the executable is not code-signed (code signing certificates cost hundreds of dollars annually). The application is completely safe - all source code is open and auditable in this repository.

**To run the application:**

1. Click **"More info"** on the SmartScreen warning dialog
2. Click **"Run anyway"** button that appears
3. The application will start normally

You only need to do this once. Windows will remember your choice for future runs.

**Why is this safe?**
- All source code is public and can be reviewed
- The executable is built automatically via GitHub Actions (see [build-windows.yml](.github/workflows/build-windows.yml))
- No telemetry or network calls except to Telegram API
- Open-source under MIT license

**Signed Builds:**
The Windows builds support optional code signing with Standard or EV Code Signing certificates. Official builds from GitHub Actions with proper secrets configured can be code-signed to prevent SmartScreen warnings entirely. However, code signing certificates cost $150-500 annually, so unsigned builds are provided by default.

**For maintainers:** See [docs/WINDOWS_CODESIGN_SETUP.md](docs/WINDOWS_CODESIGN_SETUP.md) for setup instructions.

#### macOS Gatekeeper Warning

When opening `ChatFilter.app` for the first time, macOS Gatekeeper may block the application if it's not properly signed and notarized. You might see errors like:
- **"ChatFilter.app cannot be opened because the developer cannot be verified"**
- **"ChatFilter.app is damaged and can't be opened"**

This is a security feature of macOS, not an indication that the app is actually malicious. All source code is open and auditable in this repository.

**Solution 1: Use System Preferences (Recommended)**

1. Try to open `ChatFilter.app` (it will be blocked)
2. Open **System Preferences** → **Security & Privacy** → **General** tab
3. You should see a message: *"ChatFilter.app was blocked from use because it is not from an identified developer"*
4. Click the **"Open Anyway"** button
5. Confirm by clicking **"Open"** in the dialog
6. The application will start normally

You only need to do this once. macOS will remember your choice for future runs.

**Solution 2: Remove Quarantine Attribute (Alternative)**

If the System Preferences method doesn't work, you can remove the quarantine attribute using Terminal:

```bash
xattr -cr /path/to/ChatFilter.app
```

Then open the app normally by double-clicking it.

**Why is this safe?**
- All source code is public and can be reviewed
- The executable is built automatically via GitHub Actions (see [.github/workflows/build-macos.yml](.github/workflows/build-macos.yml))
- No telemetry or network calls except to Telegram API
- Open-source under MIT license

**Signed Builds:**
The macOS builds support automatic code signing and notarization through Apple Developer Program. Official builds from GitHub Actions with proper secrets configured will be fully signed and notarized, preventing Gatekeeper warnings entirely.

**For maintainers:** See [docs/MACOS_CODESIGN_SETUP.md](docs/MACOS_CODESIGN_SETUP.md) for setup instructions.

### Running the Application

**Windows:**
```cmd
ChatFilter.exe
```

**macOS:**
```bash
./ChatFilter.app/Contents/MacOS/ChatFilter
```

**From Source (any platform):**
```bash
chatfilter
```

The server will start at `http://127.0.0.1:8000` by default.

## Installation from Source

### Prerequisites

- Python 3.11 or higher
- pip package manager

### Install

```bash
# Clone repository
git clone https://github.com/yourusername/ChatFilter.git
cd ChatFilter

# Install package
pip install -e .

# Run application
chatfilter
```

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
2. Navigate to **Settings** → **Proxy**
3. Configure your proxy details (host, port, type)
4. Save and test the connection

Or edit `data/config/proxy.json` directly:
```json
{
  "enabled": true,
  "proxy_type": "socks5",
  "host": "proxy.example.com",
  "port": 1080
}
```

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

### Building from Source

Complete instructions for developers who want to build, test, and contribute to ChatFilter.

#### Prerequisites

- Python 3.11 or higher
- Git
- pip package manager

#### Clone Repository

```bash
git clone https://github.com/yourusername/ChatFilter.git
cd ChatFilter
```

#### Install with Development Dependencies

Install the package in editable mode with all development tools:

```bash
pip install -e ".[dev]"
```

This installs:
- The main package dependencies (Telethon, FastAPI, etc.)
- Development tools: pytest, ruff, mypy
- Test utilities: pytest-asyncio, pytest-cov, pytest-timeout

#### Run the Application

After installation, run the application directly:

```bash
chatfilter
```

Or with custom options:

```bash
chatfilter --debug --port 9000
```

See [Command Line Options](#command-line-options) section for all available options.

#### Run Tests

Run the full test suite:

```bash
pytest
```

Run tests with coverage report:

```bash
pytest --cov=chatfilter --cov-report=html
```

Run specific test file or test:

```bash
pytest tests/test_filter.py
pytest tests/test_filter.py::test_specific_function
```

#### Code Quality

**Linting:**

Check code style with Ruff:

```bash
ruff check .
```

Auto-fix issues:

```bash
ruff check --fix .
```

**Type Checking:**

Run MyPy type checker:

```bash
mypy src/
```

**Run All Checks:**

```bash
ruff check . && mypy src/ && pytest
```

#### Build Executable

Build standalone executable with PyInstaller:

```bash
pip install pyinstaller
pyinstaller chatfilter.spec
```

The executable will be in the `dist/` directory:
- **Windows**: `dist/ChatFilter.exe`
- **macOS**: `dist/ChatFilter.app`
- **Linux**: `dist/ChatFilter`

#### Project Structure

```
ChatFilter/
├── src/chatfilter/       # Main package source code
│   ├── main.py          # Entry point
│   ├── filter/          # Chat filtering logic
│   ├── web/             # FastAPI web application
│   └── session/         # Telegram session management
├── tests/               # Test suite
├── pyproject.toml       # Project configuration
└── chatfilter.spec      # PyInstaller build spec
```

## License

MIT

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

#### macOS Code Signing

The macOS builds support automatic code signing and notarization through Apple Developer Program. This prevents Gatekeeper warnings and ensures a smooth user experience.

**For maintainers:** See [docs/MACOS_CODESIGN_SETUP.md](docs/MACOS_CODESIGN_SETUP.md) for setup instructions.

**For users:** Official builds from GitHub Actions with proper secrets configured will be fully signed and notarized. Community builds without signing credentials will require manual approval through System Preferences → Security & Privacy.

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

### Install with dev dependencies

```bash
pip install -e ".[dev]"
```

### Run tests

```bash
pytest
```

### Code quality

```bash
# Linting
ruff check .

# Type checking
mypy src/
```

### Build executable

```bash
pip install pyinstaller
pyinstaller chatfilter.spec
```

The executable will be in the `dist/` directory.

## License

MIT

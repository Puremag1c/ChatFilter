# ChatFilter

Telegram chat filtering and analysis tool with web interface.

## Quick Start

### Download Pre-built Binaries

Download the latest build for your platform from GitHub Actions artifacts:

- **Windows**: Download `ChatFilter-Windows-exe.zip`, extract `ChatFilter.exe`
- **macOS**: Download `ChatFilter-macOS-app.zip`, extract and open `ChatFilter.app`

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

# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for ChatFilter.

This spec file bundles the ChatFilter application with all required dependencies,
data files, and hidden imports needed for Telegram client functionality.

Build with: pyinstaller chatfilter.spec

RUNTIME PATH RESOLUTION:
- The application uses chatfilter.utils.paths.get_base_path() for PyInstaller-safe
  path resolution (handles sys._MEIPASS in frozen mode)
- Data files (templates, static, certificates) are extracted to sys._MEIPASS/chatfilter/
- User data (sessions, configs, databases) uses platformdirs for the appropriate
  user data directory (NOT bundled in the executable)

CODE SIGNING (Windows):
- Code signing happens POST-BUILD using SignTool in GitHub Actions workflow
- See .github/workflows/build-windows.yml for signing implementation
- See docs/WINDOWS_CODESIGN_SETUP.md for certificate setup instructions
- Signing requires: WINDOWS_CERTIFICATE, WINDOWS_CERTIFICATE_PASSWORD, WINDOWS_CODESIGN_NAME secrets
"""

from PyInstaller.utils.hooks import collect_data_files, collect_submodules
import os
from pathlib import Path

block_cipher = None

# Application metadata
APP_NAME = 'ChatFilter'
MAIN_SCRIPT = 'src/chatfilter/main.py'

# Read version from chatfilter/__init__.py to stay in sync with pyproject.toml
def get_version():
    """Extract version from chatfilter/__init__.py."""
    init_path = Path('src/chatfilter/__init__.py')
    if init_path.exists():
        content = init_path.read_text()
        for line in content.splitlines():
            if line.startswith('__version__'):
                # Parse: __version__ = "0.4.5"
                return line.split('=')[1].strip().strip('"\'')
    return '0.0.0'

APP_VERSION = get_version()

# Collect all chatfilter submodules (loaded dynamically by uvicorn)
hiddenimports = collect_submodules('chatfilter')

# Add external dependencies that use dynamic imports
hiddenimports += [
    # Telethon and crypto dependencies (critical for Telegram client)
    'telethon',
    'telethon.crypto',
    'telethon.crypto.aes',
    'telethon.crypto.rsa',
    'telethon.crypto.factorization',
    'telethon.extensions',
    'telethon.extensions.html',
    'telethon.extensions.markdown',
    'telethon.tl',
    'telethon.tl.types',
    'telethon.tl.functions',
    'telethon.tl.custom',

    # Cryptography backends
    'cryptg',  # Fast crypto for Telethon

    # FastAPI and Uvicorn
    'uvicorn',
    'uvicorn.logging',
    'uvicorn.loops',
    'uvicorn.loops.auto',
    'uvicorn.protocols',
    'uvicorn.protocols.http',
    'uvicorn.protocols.http.auto',
    'uvicorn.protocols.websockets',
    'uvicorn.protocols.websockets.auto',
    'uvicorn.lifespan',
    'uvicorn.lifespan.on',

    # ASGI and web server
    'fastapi',
    'starlette',
    'starlette.middleware',
    'starlette.middleware.cors',
    'starlette.routing',

    # HTTP client with connectors
    'httpx',
    'httpx._transports',
    'httpx._transports.default',
    'aiohttp',
    'aiohttp.connector',

    # Pydantic for validation
    'pydantic',
    'pydantic_core',
    'pydantic_settings',
    'pydantic_settings.sources',

    # Excel support
    'openpyxl',
    'openpyxl.cell',
    'openpyxl.styles',

    # SOCKS proxy support
    'socks',
    'socksio',

    # SSL/TLS certificates (critical for HTTPS)
    'certifi',
    'ssl',

    # Platform directories (user data paths)
    'platformdirs',

    # Templating engine (required by starlette Jinja2Templates)
    'jinja2',
    'markupsafe',

    # Standard library that may not be auto-detected
    'asyncio',
    'pathlib',
    'tempfile',
    'csv',

    # System tray support
    'pystray',
    'pystray._base',
    'pystray._darwin',  # macOS backend
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',

    # macOS pyobjc (required for pystray on macOS)
    'AppKit',
    'Foundation',
    'objc',
    'PyObjCTools',
    'PyObjCTools.Conversion',
]

# Collect data files from dependencies
datas = []

# Include CA certificates bundle for HTTPS
datas += collect_data_files('certifi')

# Include application templates and static files
src_path = Path('src/chatfilter')
if src_path.exists():
    # Templates directory
    templates_src = src_path / 'templates'
    if templates_src.exists():
        datas.append((str(templates_src), 'chatfilter/templates'))

    # Static files (CSS, JS, images)
    static_src = src_path / 'static'
    if static_src.exists():
        datas.append((str(static_src), 'chatfilter/static'))

# Analysis: scan and analyze the Python code
a = Analysis(
    [MAIN_SCRIPT],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude dev/test dependencies to reduce size
        'pytest',
        'pytest_asyncio',
        'pytest_cov',
        'mypy',
        'ruff',
        # Exclude GUI toolkits not used
        'tkinter',
        'PyQt5',
        'PySide2',
        # Exclude unused stdlib modules
        'curses',
        'readline',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# PYZ: Python zip archive of pure Python modules
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher,
)

# EXE: executable
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # onedir mode (faster startup than onefile)
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX disabled: reduces antivirus false positives
    console=False,  # GUI application (tray icon, no console window)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,  # Code signing done post-build (see .github/workflows/build-windows.yml)
    entitlements_file=None,
    version='file_version_info.txt',  # Windows version metadata (increases legitimacy)
    icon='src/chatfilter/static/images/logo.ico',  # Windows application icon
)

# COLLECT: collect all files into distribution directory
coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,  # UPX disabled: reduces antivirus false positives
    upx_exclude=[],
    name=APP_NAME,
)

# Platform-specific configurations
import sys
if sys.platform == 'darwin':
    # macOS: create .app bundle
    app = BUNDLE(
        coll,
        name=f'{APP_NAME}.app',
        icon='src/chatfilter/static/images/logo.icns',  # macOS application icon
        bundle_identifier=f'com.chatfilter.{APP_NAME.lower()}',
        info_plist={
            'NSPrincipalClass': 'NSApplication',
            'CFBundleShortVersionString': APP_VERSION,
            'CFBundleVersion': APP_VERSION,
            # High resolution display support
            'NSHighResolutionCapable': True,
            # LSUIElement=False: show app in Dock (required for menu bar interaction on some macOS versions)
            # Set to True if you want menu-bar-only app without Dock icon
            'LSUIElement': False,
            # Enable system status bar (menu bar) access
            'NSSystemStatusBarUsageDescription': 'ChatFilter uses the menu bar for quick access and status display.',
        },
    )

ChatFilter - Portable Windows Version
========================================

Thank you for downloading ChatFilter Portable!

This is a standalone version that requires NO INSTALLATION. Simply extract and run.

QUICK START
-----------

1. Extract the entire ZIP file to a folder of your choice
   Example: C:\Tools\ChatFilter\

2. Run ChatFilter.exe from the extracted folder
   - Double-click ChatFilter.exe, or
   - Open Command Prompt in the folder and run: ChatFilter.exe

3. On first run, Windows may show a SmartScreen warning
   - Click "More info"
   - Click "Run anyway"
   (This is normal for unsigned applications)

4. Create a .env file in the same folder as ChatFilter.exe with your settings:
   API_ID=your_telegram_api_id
   API_HASH=your_telegram_api_hash
   SESSION_NAME=my_account

   See .env.example for all available options.

5. Start the application:
   ChatFilter.exe

6. Open your browser to: http://127.0.0.1:8000


COMMAND LINE OPTIONS
--------------------

View all options:
  ChatFilter.exe --help

Check configuration:
  ChatFilter.exe --validate

Start on custom port:
  ChatFilter.exe --port 9000

Show version:
  ChatFilter.exe --version


SYSTEM REQUIREMENTS
-------------------

- Windows 10 or later (64-bit)
- 200 MB free disk space
- Internet connection for Telegram access
- Web browser (Chrome, Firefox, Edge, etc.)


PORTABLE MODE BENEFITS
----------------------

- No installation required
- No admin rights needed
- Run from USB drive
- Easy to test and evaluate
- Clean removal (just delete the folder)
- Multiple versions side-by-side


WHERE DATA IS STORED
--------------------

Session files and user data are stored in:
  %APPDATA%\ChatFilter\

To make it fully portable (store data in the same folder):
  Set this in your .env file:
  USER_DATA_DIR=./data

Then all session files will be stored in the "data" subfolder
next to ChatFilter.exe.


ANTIVIRUS WARNINGS
------------------

Some antivirus software may flag this application. This is a false positive
common with PyInstaller-built executables. ChatFilter is open source and safe.

To verify authenticity:
1. Check the SHA256 checksum (included in download)
2. Review the source code: https://github.com/your-org/ChatFilter
3. Submit to VirusTotal if concerned

If your antivirus blocks the file, you may need to:
- Add an exception for ChatFilter.exe
- Temporarily disable real-time protection during first run


UPDATING
--------

To update to a new version:
1. Download the new portable ZIP
2. Extract to a new folder (or backup and replace)
3. Copy your .env file to the new folder
4. Session files in %APPDATA% will work automatically


TROUBLESHOOTING
---------------

"ChatFilter.exe is not recognized..."
  → Make sure you're running from the correct folder
  → Use full path: C:\path\to\ChatFilter\ChatFilter.exe

"Failed to load configuration..."
  → Create a .env file in the same folder as ChatFilter.exe
  → See .env.example for required settings

"Missing templates/static files..."
  → Make sure the entire ZIP was extracted
  → The _internal folder must be present

Application won't start:
  → Check Windows Event Viewer for details
  → Run from Command Prompt to see error messages
  → Ensure Windows 10+ and all updates installed

Web interface won't load:
  → Check if port 8000 is already in use
  → Try a different port: ChatFilter.exe --port 9000
  → Check firewall settings


SUPPORT
-------

Documentation: https://github.com/your-org/ChatFilter/blob/main/README.md
Issues: https://github.com/your-org/ChatFilter/issues
Security: See SECURITY.md in the repository


LICENSE
-------

This software is provided under the MIT License.
See LICENSE file in the repository for full terms.


DISCLAIMER
----------

This is an unofficial Telegram client tool. Use at your own risk.
Ensure compliance with Telegram's Terms of Service when using this application.


---
ChatFilter Portable v0.1.0
Generated: 2026-01-21

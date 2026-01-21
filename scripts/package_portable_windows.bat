@echo off
REM Package ChatFilter as portable Windows ZIP distribution
REM This script creates a portable ZIP file with the built application and documentation
REM
REM Prerequisites:
REM   - ChatFilter must be built first (run build.bat)
REM   - dist/ChatFilter/ directory must exist
REM
REM Usage: package_portable_windows.bat [--build] [--version X.Y.Z]
REM   --build     : Run build.bat before packaging
REM   --version   : Override version (default: read from pyproject.toml or use 0.1.0)

setlocal enabledelayedexpansion

echo ChatFilter Portable Packaging Script
echo ======================================
echo.

REM Parse arguments
set BUILD_FIRST=0
set VERSION=

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--build" (
    set BUILD_FIRST=1
    shift
    goto parse_args
)
if /i "%~1"=="--version" (
    set VERSION=%~2
    shift
    shift
    goto parse_args
)
shift
goto parse_args
:args_done

REM Auto-detect version if not specified
if "%VERSION%"=="" (
    echo Detecting version from pyproject.toml...
    for /f "tokens=2 delims=^= " %%a in ('findstr /C:"version = " pyproject.toml 2^>nul') do (
        set VERSION=%%a
        set VERSION=!VERSION:"=!
        set VERSION=!VERSION:'=!
        goto version_found
    )
    echo Warning: Could not detect version, using default 0.1.0
    set VERSION=0.1.0
)
:version_found
echo Version: %VERSION%
echo.

REM Build if requested
if %BUILD_FIRST%==1 (
    echo Building application first...
    call build.bat
    if errorlevel 1 (
        echo ERROR: Build failed
        exit /b 1
    )
    echo.
)

REM Verify build exists
if not exist "dist\ChatFilter\ChatFilter.exe" (
    echo ERROR: dist\ChatFilter\ChatFilter.exe not found
    echo Run build.bat first or use --build flag
    exit /b 1
)

REM Create output directory for packages
if not exist "packages" mkdir packages

REM Set output filename
set PACKAGE_NAME=ChatFilter-Windows-Portable-v%VERSION%
set ZIP_FILE=packages\%PACKAGE_NAME%.zip
set CHECKSUM_FILE=packages\%PACKAGE_NAME%.zip.sha256

echo Preparing portable package...
echo Target: %ZIP_FILE%
echo.

REM Copy README.portable.txt to dist folder
echo Copying README.portable.txt...
if exist "README.portable.txt" (
    copy /Y "README.portable.txt" "dist\ChatFilter\README.txt" >nul
    if errorlevel 1 (
        echo ERROR: Failed to copy README.portable.txt
        exit /b 1
    )
) else (
    echo ERROR: README.portable.txt not found in project root
    exit /b 1
)

REM Copy .env.example if it exists
if exist ".env.example" (
    echo Copying .env.example...
    copy /Y ".env.example" "dist\ChatFilter\.env.example" >nul
)

REM Create ZIP archive
echo Creating ZIP archive...

REM Check if PowerShell is available for compression
where powershell >nul 2>&1
if errorlevel 1 (
    echo ERROR: PowerShell not found
    echo PowerShell is required for ZIP creation
    exit /b 1
)

REM Remove old ZIP if exists
if exist "%ZIP_FILE%" del /q "%ZIP_FILE%"

REM Use PowerShell to create ZIP with compression
powershell -NoProfile -Command "Compress-Archive -Path 'dist\ChatFilter\*' -DestinationPath '%ZIP_FILE%' -CompressionLevel Optimal" 2>nul
if errorlevel 1 (
    echo ERROR: Failed to create ZIP archive
    exit /b 1
)

REM Verify ZIP was created
if not exist "%ZIP_FILE%" (
    echo ERROR: ZIP file was not created
    exit /b 1
)

REM Get ZIP file size
for %%A in ("%ZIP_FILE%") do set SIZE=%%~zA
set /a SIZE_MB=%SIZE% / 1048576
echo ZIP created: %SIZE_MB% MB
echo.

REM Generate SHA256 checksum
echo Generating SHA256 checksum...
powershell -NoProfile -Command "$hash = (Get-FileHash -Algorithm SHA256 '%ZIP_FILE%').Hash.ToLower(); $filename = Split-Path '%ZIP_FILE%' -Leaf; \"$hash  $filename\" | Out-File -Encoding ASCII '%CHECKSUM_FILE%'" 2>nul
if errorlevel 1 (
    echo Warning: Failed to generate checksum
) else (
    echo Checksum saved: %CHECKSUM_FILE%
    type "%CHECKSUM_FILE%"
    echo.
)

REM Success summary
echo ======================================
echo Portable package created successfully!
echo ======================================
echo.
echo Package: %ZIP_FILE%
echo Size: %SIZE_MB% MB
echo Checksum: %CHECKSUM_FILE%
echo.
echo Contents:
echo   - ChatFilter.exe         (Main executable)
echo   - _internal\             (Dependencies)
echo   - README.txt             (Usage instructions)
echo   - .env.example           (Configuration template)
echo.
echo DISTRIBUTION CHECKLIST:
echo [ ] Test ZIP extraction
echo [ ] Test ChatFilter.exe runs without Python
echo [ ] Verify README.txt is readable
echo [ ] Check .env.example is present
echo [ ] Verify SHA256 checksum matches
echo [ ] Test on clean Windows 10/11 system
echo [ ] Upload to GitHub Releases
echo [ ] Update download links in documentation
echo.

REM Cleanup: Remove copied files from dist
echo Cleaning up...
del /q "dist\ChatFilter\README.txt" 2>nul
del /q "dist\ChatFilter\.env.example" 2>nul

echo Done!

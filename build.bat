@echo off
REM Build script for ChatFilter using PyInstaller (Windows)
REM Usage: build.bat [clean]

setlocal enabledelayedexpansion

echo ChatFilter Build Script (Windows)
echo ================================
echo.

REM Clean build if requested
if "%1"=="clean" (
    echo Cleaning build artifacts...
    if exist build rmdir /s /q build
    if exist dist rmdir /s /q dist
    if exist *.spec.bak del /q *.spec.bak
    echo Done.
    exit /b 0
)

REM Check if running in virtual environment
if not defined VIRTUAL_ENV (
    echo WARNING: Not running in a virtual environment
    echo It's recommended to use a virtual environment for building.
    set /p CONTINUE="Continue anyway? (y/N): "
    if /i not "!CONTINUE!"=="y" exit /b 1
)

REM Check if PyInstaller is installed
where pyinstaller >nul 2>&1
if errorlevel 1 (
    echo ERROR: PyInstaller not found
    echo Install build requirements with:
    echo   pip install -r requirements-build.txt
    exit /b 1
)

REM Verify spec file exists
if not exist chatfilter.spec (
    echo ERROR: chatfilter.spec not found
    exit /b 1
)

REM Check Python version
python --version
echo.

REM Build with PyInstaller
echo Building with PyInstaller...
pyinstaller chatfilter.spec --clean --noconfirm

REM Check build result
if exist dist\ChatFilter (
    echo.
    echo Build successful!
    echo.
    echo Distribution directory: dist\ChatFilter\
    echo.

    REM Show directory contents
    dir dist\ChatFilter\ChatFilter.exe 2>nul
    if errorlevel 0 (
        echo.
        echo To run the application:
        echo   dist\ChatFilter\ChatFilter.exe --help
    )

    echo.
    echo IMPORTANT: Test on a clean system without Python installed
    echo to verify all dependencies are bundled correctly.
) else (
    echo ERROR: Build failed - check errors above
    exit /b 1
)

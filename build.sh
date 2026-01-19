#!/bin/bash
# Build script for ChatFilter using PyInstaller
# Usage: ./build.sh [clean]

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}ChatFilter Build Script${NC}"
echo "================================"

# Clean build if requested
if [ "$1" == "clean" ]; then
    echo -e "${YELLOW}Cleaning build artifacts...${NC}"
    rm -rf build/ dist/ *.spec.bak
    echo -e "${GREEN}✓ Clean complete${NC}"
    exit 0
fi

# Check if running in virtual environment
if [ -z "$VIRTUAL_ENV" ]; then
    echo -e "${YELLOW}⚠ Warning: Not running in a virtual environment${NC}"
    echo "It's recommended to use a virtual environment for building."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Check if PyInstaller is installed
if ! command -v pyinstaller &> /dev/null; then
    echo -e "${RED}✗ PyInstaller not found${NC}"
    echo "Install build requirements with:"
    echo "  pip install -r requirements-build.txt"
    exit 1
fi

# Verify spec file exists
if [ ! -f "chatfilter.spec" ]; then
    echo -e "${RED}✗ chatfilter.spec not found${NC}"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "Python version: $PYTHON_VERSION"
if [[ $(echo "$PYTHON_VERSION < 3.11" | bc -l) -eq 1 ]]; then
    echo -e "${RED}✗ Python 3.11+ required${NC}"
    exit 1
fi

# Show platform info
echo "Platform: $(uname -s)"
echo "Architecture: $(uname -m)"
echo ""

# Build with PyInstaller
echo -e "${GREEN}Building with PyInstaller...${NC}"
pyinstaller chatfilter.spec --clean --noconfirm

# Check build result
if [ -d "dist/ChatFilter" ]; then
    echo ""
    echo -e "${GREEN}✓ Build successful!${NC}"
    echo ""
    echo "Distribution directory: dist/ChatFilter/"
    echo ""

    # Show binary size
    if [ -f "dist/ChatFilter/ChatFilter" ]; then
        SIZE=$(du -sh dist/ChatFilter/ | cut -f1)
        echo "Bundle size: $SIZE"
        echo ""
        echo "To run the application:"
        echo "  ./dist/ChatFilter/ChatFilter --help"
    fi

    # Test on clean system reminder
    echo ""
    echo -e "${YELLOW}⚠ IMPORTANT: Test on a clean system without Python installed${NC}"
    echo "  to verify all dependencies are bundled correctly."
else
    echo -e "${RED}✗ Build failed - check errors above${NC}"
    exit 1
fi

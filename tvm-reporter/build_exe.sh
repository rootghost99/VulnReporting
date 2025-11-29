#!/bin/bash
# TVM Reporter - Build Executable Script

echo "=========================================="
echo "  TVM Reporter - Build Executable"
echo "=========================================="
echo ""

cd "$(dirname "$0")"

# Check if pyinstaller is installed
if ! python -c "import PyInstaller" 2>/dev/null; then
    echo "Installing PyInstaller..."
    pip install pyinstaller
fi

# Check if eel is installed
if ! python -c "import eel" 2>/dev/null; then
    echo "Installing Eel..."
    pip install eel
fi

echo "Building executable..."
echo ""

python desktop/build.py

echo ""
echo "Build complete! Check desktop/dist/ for the executable."

@echo off
REM TVM Reporter - Build Executable Script

echo ==========================================
echo   TVM Reporter - Build Executable
echo ==========================================
echo.

cd /d "%~dp0"

REM Check and install dependencies
echo Checking dependencies...
pip install pyinstaller eel --quiet

echo Building executable...
echo.

python desktop\build.py

echo.
echo Build complete! Check desktop\dist\ for the executable.
pause

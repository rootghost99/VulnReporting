@echo off
REM TVM Reporter - Build Executable Script

echo ==========================================
echo   TVM Reporter - Build Executable
echo ==========================================
echo.

cd /d "%~dp0"

REM Try to find Python
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set PYTHON_CMD=py
    goto :found_python
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set PYTHON_CMD=python
    goto :found_python
)

echo ERROR: Python not found!
echo.
echo Please install Python from https://www.python.org/downloads/
echo During installation, make sure to check "Add Python to PATH"
echo.
echo Alternatively, if Python is installed:
echo   1. Go to Settings ^> Apps ^> Advanced app settings ^> App execution aliases
echo   2. Turn OFF the "python.exe" and "python3.exe" App Installer entries
echo.
pause
exit /b 1

:found_python
echo Found Python: %PYTHON_CMD%
echo.

REM Check and install dependencies
echo Installing dependencies...
%PYTHON_CMD% -m pip install pyinstaller eel --quiet --upgrade

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Failed to install dependencies.
    echo Try running: %PYTHON_CMD% -m pip install pyinstaller eel
    pause
    exit /b 1
)

echo.
echo Building executable...
echo.

%PYTHON_CMD% desktop\build.py

echo.
if exist desktop\dist\TVM-Reporter.exe (
    echo ==========================================
    echo   BUILD SUCCESSFUL!
    echo ==========================================
    echo.
    echo Executable: desktop\dist\TVM-Reporter.exe
) else (
    echo Build may have completed. Check desktop\dist\ for the executable.
)
echo.
pause

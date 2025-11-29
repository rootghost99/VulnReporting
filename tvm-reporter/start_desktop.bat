@echo off
REM TVM Reporter Desktop Application Launcher

echo ==========================================
echo   TVM Reporter - Desktop Application
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
pause
exit /b 1

:found_python
echo Starting desktop application...
echo.

%PYTHON_CMD% desktop\main.py

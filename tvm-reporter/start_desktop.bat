@echo off
REM TVM Reporter Desktop Application Launcher

echo ==========================================
echo   TVM Reporter - Desktop Application
echo ==========================================
echo.
echo Starting desktop application...
echo.

cd /d "%~dp0"
python desktop\main.py

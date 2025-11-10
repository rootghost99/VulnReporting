@echo off
REM TVM Reporter Web Interface Launcher

echo ==========================================
echo   TVM Reporter - Web Interface
echo ==========================================
echo.
echo Starting web interface...
echo The browser will open automatically.
echo.
echo Press Ctrl+C to stop the server
echo.

cd /d "%~dp0"
streamlit run web_app.py

@echo off
chcp 65001 > nul
title Discord Badge Spoofer - GUI
echo ======================================================
echo    ⚡ Discord Badge Spoofer - Starting GUI
echo ======================================================
echo.
echo Starting local server and opening browser automatically...
echo You can stop the application at any time with Ctrl+C.
echo.

python gui.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Failed to start application. Make sure Python is installed and in PATH.
    pause
)

@echo off
title WinSentry Application
cd /d "%~dp0"

if exist "%~dp0WinSentry.exe" (
    echo Starting WinSentry Executable...
    start "" "%~dp0WinSentry.exe"
    exit /b
)

where python >nul 2>&1
if %errorlevel% equ 0 (
    echo Starting WinSentry Application...
    python app.py
) else (
    echo Launching WinSentry Scanner...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0WinSentry.ps1"
    pause
)

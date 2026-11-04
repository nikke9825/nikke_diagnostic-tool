@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0NikkeLauncherCleanup.ps1"
pause

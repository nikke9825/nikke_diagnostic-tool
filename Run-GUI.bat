@echo off
chcp 65001 >nul
powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0NikkeLauncherCleanupGUI.ps1"

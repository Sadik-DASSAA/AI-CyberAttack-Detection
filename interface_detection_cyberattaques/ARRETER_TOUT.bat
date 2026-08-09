@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title Supervision des cyberattaques - Arret complet

net session >nul 2>&1
if errorlevel 1 (
    echo Demande des droits administrateur...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass ^
    -File "%~dp0arreter_tout.ps1"

set "CODE_SORTIE=%ERRORLEVEL%"
echo.
pause
exit /b %CODE_SORTIE%


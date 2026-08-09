@echo off
setlocal
chcp 65001 >nul
cd /d "%~dp0"
title Supervision des cyberattaques - Lancement complet

net session >nul 2>&1
if errorlevel 1 (
    echo Demande des droits administrateur...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
        "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass ^
    -File "%~dp0demarrer_tout.ps1"

set "CODE_SORTIE=%ERRORLEVEL%"
echo.
if not "%CODE_SORTIE%"=="0" (
    echo [ERREUR] Le lancement complet n'a pas abouti.
    echo Lisez le message affiche juste au-dessus.
) else (
    echo Le site complet reste actif apres la fermeture de cette fenetre.
    echo Pour tout arreter, double-cliquez sur ARRETER_TOUT.bat.
)
echo.
pause
exit /b %CODE_SORTIE%


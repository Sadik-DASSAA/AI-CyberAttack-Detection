@echo off
setlocal
cd /d "%~dp0"

fltmc >nul 2>&1
if not "%errorlevel%"=="0" (
    echo Demande des droits administrateur...
    powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0corriger_https.ps1"
set "SCA_RESULT=%errorlevel%"

echo.
if "%SCA_RESULT%"=="0" (
    echo Correctif termine. Fermez completement Chrome puis rouvrez https://localhost/SCA/
) else (
    echo Le correctif a echoue. Photographiez cette fenetre et envoyez-la.
)
echo.
pause
exit /b %SCA_RESULT%

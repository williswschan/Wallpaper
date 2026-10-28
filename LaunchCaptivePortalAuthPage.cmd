@echo off
setlocal
set "ScriptPath=%~dp0LaunchCaptivePortalAuthPage.ps1"
if not exist "%ScriptPath%" (
    echo [ERROR] LaunchCaptivePortalAuthPage.ps1 was not found next to this file.
    pause
    exit /b 1
)
start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%ScriptPath%"
exit /b 0

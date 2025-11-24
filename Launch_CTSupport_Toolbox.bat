@echo off
setlocal

rem ============================================================
rem   COMPU-TEK TECHNICIAN TOOLBOX LAUNCHER (PowerShell Edition)
rem ============================================================

:: Get this script’s directory (handles USB, network, etc.)
set "ScriptDir=%~dp0"
set "MainScript=%ScriptDir%CTSupport_Toolbox.ps1"

:: Verify the PowerShell script exists
if not exist "%MainScript%" (
    echo [ERROR] Could not find PowerShell script:
    echo         "%MainScript%"
    pause
    exit /b
)

:: Launch a NEW elevated PowerShell window
echo Launching CT-Support Toolbox as Administrator...
powershell -NoLogo -Command ^
    "Start-Process PowerShell -ArgumentList '-ExecutionPolicy Bypass','-File \"%MainScript%\"' -Verb RunAs"

endlocal
exit /b

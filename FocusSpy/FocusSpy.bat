@echo off
rem Startet FocusSpy als Administrator (fuer vollstaendige Prozessinfos)
net session >nul 2>&1
if %errorlevel% neq 0 (
  powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0FocusSpy.ps1"
pause

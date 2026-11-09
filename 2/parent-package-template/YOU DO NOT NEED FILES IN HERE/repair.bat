@echo off
setlocal EnableExtensions
title @M Family Safety Guard - Repair this PC
net session >nul 2>&1
if not "%errorlevel%"=="0" (
  echo Administrator permission is required. Requesting elevation...
  powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b 0
)
set "TARGET=%ProgramFiles%\M Family Safety Guard"
if not exist "%TARGET%\agent.py" (echo [X] @M Family Safety Guard is not installed in "%TARGET%". Run install.bat instead.& pause & exit /b 1)
set "PY="
if exist "%TARGET%\python.txt" set /p PY=<"%TARGET%\python.txt"
REM python.txt can start with an invisible UTF-8 marker that breaks set /p; re-read it with PowerShell, which ignores the marker
if exist "%TARGET%\python.txt" for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "(Get-Content -LiteralPath '%TARGET%\python.txt' -Raw).Trim()"`) do set "PY=%%A"
if not defined PY (echo [X] python.txt is missing - run install.bat again.& pause & exit /b 1)
echo.
echo  Repairing @M Family Safety Guard on this PC.
echo  Only the program's own settings are touched. Your internet connection,
echo  files and other programs are left alone.
echo.
pushd "%TARGET%"
"%PY%" agent.py --repair-now
set "RC=%ERRORLEVEL%"
popd
echo.
if "%RC%"=="0" (echo [OK] Repair finished. Check that this device shows ONLINE in the dashboard.) else (echo [!] Some repair steps failed - see the lines above. If it keeps failing, run install.bat again.)
pause
exit /b %RC%

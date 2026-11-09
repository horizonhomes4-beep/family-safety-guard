@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Family Safety Guard - Installer
color 0B
cd /d "%~dp0"
echo.
echo  ==================================================================
echo    FAMILY SAFETY GUARD - INSTALLER
echo  ==================================================================
echo.
if not exist "%~dp0program-DO-NOT-OPEN\install.ps1" goto NOTEXTRACTED
echo  This takes about 5 to 10 minutes and needs the internet.
echo  Please do NOT close this window and do NOT turn off the laptop.
echo.
net session >nul 2>&1
if "%errorlevel%"=="0" goto RUNINSTALL
echo  Windows will now ask: "Do you want to allow this app to make changes?"
echo  Please click YES. If it asks for a password, type the password of
echo  the laptop owner (administrator).
echo.
set "SELF=%~f0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%SELF:'=''%' -Verb RunAs"
if errorlevel 1 goto NOADMIN
exit /b 0

:RUNINSTALL
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0program-DO-NOT-OPEN\install.ps1"
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" goto FAILED
color 0A
echo  ==================================================================
echo    SUCCESS - Family Safety Guard is installed on this laptop.
echo.
echo    Please tell the person who sent you this package that it
echo    finished. You may then close this window.
echo.
echo    Last step: delete this whole folder and the ZIP file you
echo    downloaded, then empty the Recycle Bin.
echo  ==================================================================
echo.
pause
exit /b 0

:FAILED
color 0C
echo  ==================================================================
echo    THE INSTALLATION DID NOT FINISH. This laptop is NOT protected yet.
echo.
echo    Please take a photo of this screen and send it to the person
echo    who sent you this package. They will tell you what to do.
echo  ==================================================================
echo.
pause
exit /b 1

:NOADMIN
color 0C
echo.
echo  Permission was not given, so nothing was installed.
echo  Please double-click the installer again and click YES when Windows asks.
echo.
pause
exit /b 1

:NOTEXTRACTED
color 0C
echo  The installer cannot find its files.
echo.
echo  This usually happens when the installer is opened from INSIDE the ZIP.
echo  Please close this window, then:
echo    1. Right-click the ZIP file and choose  Extract All...
echo    2. Click  Extract
echo    3. Open the new folder and double-click the installer again.
echo.
pause
exit /b 1

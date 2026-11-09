@echo off
title Make a package for a parent
cd /d "%~dp0"
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\make-parent-package.ps1"
echo.
pause

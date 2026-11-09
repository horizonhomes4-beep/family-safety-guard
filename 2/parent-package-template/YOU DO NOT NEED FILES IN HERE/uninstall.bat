@echo off
setlocal EnableExtensions
net session >nul 2>&1 || (echo [X] Run this file as Administrator. & pause & exit /b 1)
set "TARGET=%ProgramFiles%\M Family Safety Guard"
set "K=HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MFamilySafetyGuard"

REM When run from inside the install folder, re-run from %TEMP% so the folder can be deleted.
if /i "%~dp0"=="%TARGET%\" if not "%~1"=="--relaunched" (
  copy /y "%~f0" "%TEMP%\pg_uninstall.bat" >nul
  call "%TEMP%\pg_uninstall.bat" --relaunched
  exit /b %errorlevel%
)

if not exist "%TARGET%" (
  echo @M Family Safety Guard folder not found - checking for leftovers only.
)
echo Stopping tasks and agent...
schtasks /delete /tn MFamilySafetyGuard-Watchdog /f >nul 2>&1
schtasks /end /tn MFamilySafetyGuard-Notice >nul 2>&1
schtasks /delete /tn MFamilySafetyGuard-Notice /f >nul 2>&1
schtasks /delete /tn ParentGuardWatchdog /f >nul 2>&1
schtasks /end /tn MFamilySafetyGuard-Agent >nul 2>&1
schtasks /delete /tn MFamilySafetyGuard-Agent /f >nul 2>&1
schtasks /end /tn ParentGuardAgent >nul 2>&1
schtasks /delete /tn ParentGuardAgent /f >nul 2>&1
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object {$_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -like '*M Family Safety Guard*agent.py*'} | ForEach-Object {Stop-Process -Id $_.ProcessId -Force}" >nul 2>&1
timeout /t 2 /nobreak >nul

REM Restore hosts file, DNS, browser policies (needs the installed agent + python path)
set "PY="
if exist "%TARGET%\python.txt" set /p PY=<"%TARGET%\python.txt"
REM python.txt can start with an invisible UTF-8 marker that breaks set /p; re-read it with PowerShell, which ignores the marker
if exist "%TARGET%\python.txt" for /f "usebackq delims=" %%A in (`powershell -NoProfile -Command "(Get-Content -LiteralPath '%TARGET%\python.txt' -Raw).Trim()"`) do set "PY=%%A"
if defined PY if exist "%TARGET%\agent.py" (
  pushd "%TARGET%"
  "%PY%" agent.py --uninstall
  popd
) else (
  echo [!] Could not run the agent cleanup. Hosts file, DNS and browser policies may need manual reset.
)

REM Safety net: give back internet if any adapter still points at ParentGuard's local filter
powershell -NoProfile -Command "Get-DnsClientServerAddress | Where-Object {$_.ServerAddresses -contains '127.0.0.1' -or $_.ServerAddresses -contains '::1'} | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses }" >nul 2>&1
ipconfig /flushdns >nul 2>&1
netsh advfirewall firewall delete rule name=MFamilySafetyGuard-BlockDoT >nul 2>&1
for /d %%D in ("%ProgramFiles%\M Family Safety Guard.backup-*") do rmdir /s /q "%%D" >nul 2>&1
reg delete "%K%" /f >nul 2>&1
rmdir /s /q "%TARGET%" >nul 2>&1
rmdir /s /q "%ProgramData%\MFamilySafetyGuard" >nul 2>&1

echo.
echo Verifying removal...
set "BAD="
schtasks /query /tn MFamilySafetyGuard-Agent >nul 2>&1 && (echo [X] Task MFamilySafetyGuard-Agent still exists & set "BAD=1")
schtasks /query /tn MFamilySafetyGuard-Watchdog >nul 2>&1 && (echo [X] Task MFamilySafetyGuard-Watchdog still exists & set "BAD=1")
schtasks /query /tn MFamilySafetyGuard-Notice >nul 2>&1 && (echo [X] Task MFamilySafetyGuard-Notice still exists & set "BAD=1")
schtasks /query /tn ParentGuardAgent >nul 2>&1 && (echo [X] Legacy task ParentGuardAgent still exists & set "BAD=1")
schtasks /query /tn ParentGuardWatchdog >nul 2>&1 && (echo [X] Legacy task ParentGuardWatchdog still exists & set "BAD=1")
reg query "%K%" >nul 2>&1 && (echo [X] Control Panel entry still exists & set "BAD=1")
if exist "%TARGET%" (echo [X] Folder still exists: %TARGET% & set "BAD=1")
for /d %%D in ("%ProgramFiles%\M Family Safety Guard.backup-*") do (echo [X] Backup folder still exists: %%D & set "BAD=1")
powershell -NoProfile -Command "if (Get-CimInstance Win32_Process | Where-Object {$_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -like '*M Family Safety Guard*agent.py*'}) {exit 1}" >nul 2>&1 || (echo [X] An agent process is still running & set "BAD=1")
findstr /c:"PARENTGUARD BEGIN" "%SystemRoot%\System32\drivers\etc\hosts" >nul 2>&1 && (echo [X] Hosts file still contains ParentGuard entries & set "BAD=1")

if defined BAD (echo. & echo UNINSTALL INCOMPLETE - see the items above. & pause & exit /b 2)
echo [OK] @M Family Safety Guard fully removed.
pause
exit /b 0

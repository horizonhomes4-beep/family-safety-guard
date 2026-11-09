#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
# Version is read from agent.py so installer and agent can never disagree.
$Version = [regex]::Match((Get-Content (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'agent.py') -Raw),'(?m)^VERSION\s*=\s*"([^"]+)"').Groups[1].Value
if (-not $Version) { $Version = '0.0.0' }
$TaskAgent = 'MFamilySafetyGuard-Agent'
$TaskWatchdog = 'MFamilySafetyGuard-Watchdog'
$Target = Join-Path $env:ProgramFiles 'M Family Safety Guard'
$Source = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path $env:TEMP 'MFamilySafetyGuard-install.log'
$Backup = $null
$InstallTouched = $false
$TranscriptStarted = $false
function Info([string]$m) { Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Good([string]$m) { Write-Host "[ OK ] $m" -ForegroundColor Green }
function Warn([string]$m) { Write-Host "[WARN] $m" -ForegroundColor Yellow }
function StopInstall([string]$m) { throw $m }
function Remove-GuardTask([string]$Name) {
  # Uses ScheduledTasks cmdlets; schtasks.exe stderr is fatal under $ErrorActionPreference='Stop' in PS 5.1.
  try {
    $t = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($t) {
      Stop-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
      Unregister-ScheduledTask -TaskName $Name -Confirm:$false -ErrorAction SilentlyContinue
    }
  } catch { }
}
function Stop-GuardAgent {
  try {
    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
      Where-Object { $_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -like '*M Family Safety Guard*agent.py*' } |
      ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
  } catch { }
}
function Find-Python {
  $candidates = @()
  $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
  if ($launcher) {
    foreach ($v in @('-3.12','-3.11','-3.10')) {
      try {
        $candidate = (& $launcher.Source $v -c 'import sys;print(sys.executable)' 2>$null | Select-Object -First 1)
        if ($LASTEXITCODE -eq 0 -and $candidate -and (Test-Path $candidate)) { $candidates += $candidate }
      } catch { }
    }
  }
  foreach ($name in @('python.exe','python3.exe')) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -notmatch 'WindowsApps') {
      try {
        $candidate = (& $cmd.Source -c 'import sys;print(sys.executable)' 2>$null | Select-Object -First 1)
        if ($LASTEXITCODE -eq 0 -and $candidate -and (Test-Path $candidate)) { $candidates += $candidate }
      } catch { }
    }
  }
  # Fallback: standard machine-wide install folders (does not depend on PATH being refreshed).
  foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if (-not $root) { continue }
    foreach ($v in @('Python312','Python311','Python310')) {
      $p = Join-Path $root "$v\python.exe"
      if (Test-Path $p) { $candidates += $p }
    }
  }
  foreach ($candidate in ($candidates | Select-Object -Unique)) {
    try {
      # NOTE: no double quotes inside -c code; Windows PowerShell 5.1 strips them when calling native programs.
      $info = (& $candidate -c 'import sys;print(sys.version_info[0],sys.version_info[1],sys.maxsize>2**32)' 2>$null | Select-Object -First 1)
      $parts = ([string]$info).Trim() -split '\s+'
      $ver = [version]('{0}.{1}' -f $parts[0],$parts[1])
      if ($ver -ge [version]'3.10' -and $ver -lt [version]'3.13' -and $parts[2] -eq 'True') {
        # SYSTEM scheduled tasks need a machine-wide interpreter, not a per-user AppData runtime.
        if ($candidate -like "$env:ProgramFiles\*" -or $candidate -like "${env:ProgramFiles(x86)}\*") { return $candidate }
      }
    } catch { }
  }
  return $null
}
try {
  Start-Transcript -Path $Log -Append | Out-Null
  $TranscriptStarted = $true
  Write-Host "`n@M FAMILY SAFETY GUARD - WINDOWS CLIENT v$Version`n" -ForegroundColor Cyan
  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { StopInstall 'Administrator rights are required. Run install.bat and approve the Windows prompt.' }

  $os = Get-CimInstance Win32_OperatingSystem
  if (-not [Environment]::Is64BitOperatingSystem -or [int]$os.BuildNumber -lt 10240) { StopInstall 'A supported 64-bit Windows 10/11 computer is required.' }
  Good ("Operating system: {0}, build {1}, 64-bit" -f $os.Caption,$os.BuildNumber)

  foreach ($f in @('agent.py','policy_rules.py','notice_client.py','blocklists.py','dnsfilter.py','webhistory.py','config.json','requirements.txt','uninstall.bat','repair.bat')) {
    if (-not (Test-Path (Join-Path $Source $f) -PathType Leaf)) { StopInstall "Required installation file is missing: $f. Extract the complete ZIP archive." }
  }
  $cfg = Get-Content (Join-Path $Source 'config.json') -Raw | ConvertFrom-Json
  foreach ($field in @('projectId','apiKey','deviceId','deviceKey')) {
    $value = [string]$cfg.$field
    if ([string]::IsNullOrWhiteSpace($value) -or $value -match 'PASTE_FROM_ADMIN|YOUR_|CHANGE_ME|REPLACE_') { StopInstall "This package is not ready: the settings file for this laptop is empty. Please contact the person who sent you this package." }
  }
  if ([string]$cfg.projectId -notmatch '^[a-z][a-z0-9-]{4,}[a-z0-9]$' -or $cfg.deviceKey.Length -lt 16 -or $cfg.deviceId.Length -lt 6) { StopInstall 'The Firebase project/device credentials do not meet the required format.' }
  Good ("Device configuration validated: {0}" -f $cfg.deviceId)

  $python = Find-Python
  if (-not $python) {
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget) {
      Info 'No supported machine-wide Python runtime found. Trying Windows Package Manager first...'
      try {
        & $winget.Source install --id Python.Python.3.12 --exact --source winget --scope machine --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) {
          $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
          $python = Find-Python
        } else {
          Warn "Windows Package Manager could not install Python (exit code $LASTEXITCODE). Trying the official python.org installer instead."
        }
      } catch {
        Warn ("Windows Package Manager failed: " + $_.Exception.Message + ". Trying the official python.org installer instead.")
      }
    } else {
      Warn 'Windows Package Manager is unavailable. Trying the official python.org installer instead.'
    }
  }
  if (-not $python) {
    # Do not make installation depend on the Microsoft Store/winget source database.
    # Python 3.12.10 is an official 64-bit python.org maintenance release.
    $pythonInstaller = Join-Path $env:TEMP 'MFamilySafetyGuard-python-3.12.10-amd64.exe'
    $pythonUrl = 'https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe'
    Info 'Downloading the official 64-bit Python 3.12 installer directly from python.org...'
    try {
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller -UseBasicParsing
      $sig = Get-AuthenticodeSignature -FilePath $pythonInstaller
      if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
        StopInstall 'The downloaded Python installer signature could not be verified as Python Software Foundation. Delete the installer and retry on a trusted network.'
      }
      Info 'Installing Python 3.12 for all users (quiet installation)...'
      $proc = Start-Process -FilePath $pythonInstaller -ArgumentList @('/quiet','InstallAllUsers=1','PrependPath=1','Include_launcher=1','Include_test=0','TargetDir=' + (Join-Path $env:ProgramFiles 'Python312')) -Wait -PassThru
      if ($proc.ExitCode -notin @(0,3010)) {
        StopInstall "The official Python installer returned exit code $($proc.ExitCode). Install Python manually from https://www.python.org/downloads/windows/ and select Install for all users."
      }
      $env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')
      $python = Find-Python
    } catch {
      StopInstall ("Automatic Python installation failed: " + $_.Exception.Message + ". Install 64-bit Python 3.10, 3.11 or 3.12 from https://www.python.org/downloads/windows/ and select Install for all users, then run install.bat again.")
    } finally {
      Remove-Item $pythonInstaller -Force -ErrorAction SilentlyContinue
    }
  }
  if (-not $python) { StopInstall 'Python installation completed but no supported machine-wide 64-bit Python runtime could be detected. Restart Windows and run install.bat again as Administrator.' }
  $pyInfo = & $python -c 'import sys;print(sys.version.split()[0],sys.executable)'
  Good "Python runtime: $pyInfo"

  if (Test-Path $Target) {
    $Backup = "$Target.backup-$(Get-Date -Format yyyyMMdd-HHmmss)"
    Copy-Item $Target $Backup -Recurse -Force
    Good "Previous installation backed up: $Backup"
  }
  $InstallTouched = $true
  New-Item $Target -ItemType Directory -Force | Out-Null
  foreach ($f in @('agent.py','policy_rules.py','notice_client.py','blocklists.py','dnsfilter.py','webhistory.py','config.json','requirements.txt','uninstall.bat','repair.bat','install.ps1')) { Copy-Item (Join-Path $Source $f) (Join-Path $Target $f) -Force }
  Set-Content (Join-Path $Target 'python.txt') $python -Encoding UTF8
  # Windows PowerShell 5.1 writes a hidden UTF-8 marker that breaks `set /p` in repair.bat and uninstall.bat; write the file again without it
  [IO.File]::WriteAllText((Join-Path $Target 'python.txt'), $python, (New-Object System.Text.UTF8Encoding($false)))
  Remove-Item (Join-Path $Target 'health.json') -Force -ErrorAction SilentlyContinue
  Good 'Application files staged'

  & icacls.exe $Target /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)RX' | Out-Null
  if ($LASTEXITCODE -ne 0) { StopInstall 'Could not apply installation folder permissions.' }
  & icacls.exe (Join-Path $Target 'config.json') /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
  if ($LASTEXITCODE -ne 0) { StopInstall 'Could not protect device credentials.' }
  Good 'Installation and device configuration ACLs applied'

  # Drop folder for the pop-up's requests (more time / allow site). Children may add files; only admins own it.
  $ReqDir = Join-Path $env:ProgramData 'MFamilySafetyGuard\requests'
  New-Item $ReqDir -ItemType Directory -Force | Out-Null
  & icacls.exe $ReqDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' 'Users:(OI)(CI)M' | Out-Null
  if ($LASTEXITCODE -ne 0) { Warn 'Could not set permissions on the request folder; child requests may not be delivered.' } else { Good 'Child request folder prepared' }

  Info 'Installing isolated Python dependencies...'
  & $python -m pip install --disable-pip-version-check --upgrade --target (Join-Path $Target 'packages') -r (Join-Path $Target 'requirements.txt')
  if ($LASTEXITCODE -ne 0) { StopInstall 'Dependency installation failed. Check internet access and retry.' }
  & $python -c "import sys;sys.path.insert(0,r'$Target\packages');import requests;print('requests',requests.__version__)"
  if ($LASTEXITCODE -ne 0) { StopInstall 'Dependency verification failed.' }
  Good 'Dependencies installed and verified'

  Info 'Checking Firebase sign-in, device registration, policy read and status write...'
  Push-Location $Target
  try { & $python (Join-Path $Target 'agent.py') --check; if ($LASTEXITCODE -ne 0) { StopInstall 'Firebase preflight failed. Check Anonymous Authentication, Firestore rules, device record and device key.' } }
  finally { Pop-Location }
  Good 'Firebase preflight passed'

  foreach ($task in @($TaskAgent,$TaskWatchdog,'MFamilySafetyGuard-Notice','ParentGuardAgent','ParentGuardWatchdog')) { Remove-GuardTask $task }
  $pythonw = Join-Path (Split-Path $python) 'pythonw.exe'
  if (-not (Test-Path $pythonw)) { $pythonw = $python }
  $agentAction = New-ScheduledTaskAction -Execute $pythonw -Argument ('"{0}"' -f (Join-Path $Target 'agent.py')) -WorkingDirectory $Target
  $startup = New-ScheduledTaskTrigger -AtStartup
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
  $system = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  Register-ScheduledTask -TaskName $TaskAgent -Action $agentAction -Trigger $startup -Settings $settings -Principal $system -Description '@M Family Safety Guard Windows child-device client' -Force | Out-Null
  $watchAction = New-ScheduledTaskAction -Execute $python -Argument ('"{0}" --watchdog' -f (Join-Path $Target 'agent.py')) -WorkingDirectory $Target
  $watchTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
  Register-ScheduledTask -TaskName $TaskWatchdog -Action $watchAction -Trigger $watchTrigger -Settings $settings -Principal $system -Description '@M Family Safety Guard agent health watchdog' -Force | Out-Null
  # The enforcement agent runs as SYSTEM (session 0), so a separate task must
  # run inside each signed-in user's interactive desktop to display the notice.
  # NOTE: New-ScheduledTaskPrincipal -GroupId cannot be combined with -LogonType (that mix caused
  # "Parameter set cannot be resolved using the specified named parameters"). S-1-5-32-545 = BUILTIN\Users,
  # so the notice window starts in every user's own desktop session at sign-in.
  try {
    $noticeAction = New-ScheduledTaskAction -Execute $pythonw -Argument ('"{0}"' -f (Join-Path $Target 'notice_client.py')) -WorkingDirectory $Target
    $noticeTrigger = New-ScheduledTaskTrigger -AtLogOn
    $interactive = New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-545' -RunLevel Limited
    $noticeSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'MFamilySafetyGuard-Notice' -Action $noticeAction -Trigger $noticeTrigger -Settings $noticeSettings -Principal $interactive -Description '@M Family Safety Guard full-screen user notice' -Force | Out-Null
    Good 'SYSTEM agent, watchdog and interactive-user notice tasks registered'
  } catch {
    # Protection must still install; only the pop-up window is affected.
    Warn ('Notice pop-up task could not be registered: ' + $_.Exception.Message)
    Good 'SYSTEM agent and watchdog tasks registered (pop-up notice NOT active)'
  }

  $uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MFamilySafetyGuard'
  New-Item -Path $uninstallKey -Force | Out-Null
  $regValues = @(
    @('DisplayName','@M Family Safety Guard','String'),
    @('DisplayVersion',$Version,'String'),
    @('Publisher','@M Family Safety Guard','String'),
    @('InstallLocation',$Target,'String'),
    @('UninstallString',('"{0}"' -f (Join-Path $Target 'uninstall.bat')),'String'),
    @('NoModify',1,'DWord'),
    @('NoRepair',1,'DWord')
  )
  foreach ($rv in $regValues) { New-ItemProperty -Path $uninstallKey -Name $rv[0] -Value $rv[1] -PropertyType $rv[2] -Force | Out-Null }
  Good 'Apps & Features entry registered'

  Remove-Item (Join-Path $Target 'health.json') -Force -ErrorAction SilentlyContinue
  # Start the notice helper in the setup user's current desktop immediately;
  # the AtLogOn task starts it automatically for subsequent Windows sign-ins.
  Start-Process -FilePath $pythonw -ArgumentList ('"{0}"' -f (Join-Path $Target 'notice_client.py')) -WorkingDirectory $Target -WindowStyle Hidden
  Start-ScheduledTask -TaskName $TaskAgent
  Info 'Waiting up to 120 seconds for the SYSTEM agent to authenticate and fetch the live Firebase policy...'
  $healthy = $false
  for ($i=0; $i -lt 24; $i++) {
    Start-Sleep -Seconds 5
    $healthPath = Join-Path $Target 'health.json'
    if (Test-Path $healthPath) {
      try {
        $health = Get-Content $healthPath -Raw | ConvertFrom-Json
        if ($health.ok -eq $true -and $health.version -eq $Version -and $health.phase -in @('policy-sync','cycle-complete') -and [int64]$health.at -ge [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()-150) { $healthy = $true; break }
        if ($health.error) { Warn $health.error }
      } catch { }
    }
  }
  if (-not $healthy) {
    if (Test-Path (Join-Path $Target 'agent.log')) { Get-Content (Join-Path $Target 'agent.log') -Tail 25 | ForEach-Object { Write-Host $_ } }
    StopInstall 'The background agent did not produce a fresh successful heartbeat. This installation is not verified.'
  }
  $taskState = (Get-ScheduledTask -TaskName $TaskAgent).State
  Good "SYSTEM agent policy-sync heartbeat verified. Agent task state: $taskState"
  if ($Backup -and (Test-Path $Backup)) { Remove-Item $Backup -Recurse -Force -ErrorAction SilentlyContinue }
  Write-Host "`n======================================================================" -ForegroundColor Green
  Write-Host ' INSTALLATION AND LIVE CONNECTION VERIFICATION SUCCEEDED' -ForegroundColor Green
  Write-Host " Product: @M Family Safety Guard v$Version"
  Write-Host " Installed: $Target"
  Write-Host ' Next: tell the person who sent you this package that it finished, so they can confirm this laptop shows ONLINE.'
  Write-Host ' Device-wide controls affect every interactive user session on this PC. Local administrators can bypass endpoint restrictions.'
  Write-Host ' Uninstall: Windows Apps & Features or the installed uninstall.bat'
  Write-Host " Installer log: $Log"
  Write-Host '======================================================================' -ForegroundColor Green
  Stop-Transcript | Out-Null
  exit 0
}
catch {
  Write-Host "`n[INSTALL ERROR] $($_.Exception.Message)" -ForegroundColor Red
  if ($InstallTouched) {
    Warn 'Rolling back the incomplete installation attempt...'
    foreach ($task in @($TaskAgent,$TaskWatchdog,'MFamilySafetyGuard-Notice')) { Remove-GuardTask $task }
    Stop-GuardAgent
    Start-Sleep -Seconds 2
    Remove-Item -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MFamilySafetyGuard' -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $Target) { Remove-Item $Target -Recurse -Force -ErrorAction SilentlyContinue }
    if ($Backup -and (Test-Path $Backup)) { Move-Item $Backup $Target -Force; Good 'Previous installation restored from backup.' }
  }
  Write-Host "Installer diagnostic log: $Log" -ForegroundColor Yellow
  if ($TranscriptStarted) { try { Stop-Transcript | Out-Null } catch { } }
  exit 1
}

# pg-check.ps1 - lists everything the Family Safety Guard installer / agent leaves on this PC.
# Run as Administrator:  powershell -NoProfile -ExecutionPolicy Bypass -File .\pg-check.ps1 -Label before
# It only READS. It changes nothing. Result is shown on screen and saved next to this script as pg-check-<label>.txt
param([string]$Label = "check")

$ErrorActionPreference = 'SilentlyContinue'
$script:left = 0
$script:out = New-Object System.Collections.Generic.List[string]

function Say($text) { $script:out.Add([string]$text); Write-Host $text }
function Check($name, $found, $detail) {
    if ($found) {
        $script:left++
        if ($detail) { Say ("[PRESENT] " + $name + "  ->  " + $detail) } else { Say ("[PRESENT] " + $name) }
    } else {
        Say ("[clean]   " + $name)
    }
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$pf = $env:ProgramFiles
$target = Join-Path $pf 'M Family Safety Guard'
$data = Join-Path $env:ProgramData 'MFamilySafetyGuard'

Say ("=== Family Safety Guard footprint: " + $Label + " ===")
Say ("Time: " + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
if (-not $isAdmin) { Say "WARNING: not running as Administrator - some checks may be wrong. Open Command Prompt as administrator." }
$agentFile = Join-Path $target 'agent.py'
if (Test-Path $agentFile) { Say ("Agent file: " + (Select-String -Path $agentFile -Pattern '^VERSION = ' | Select-Object -First 1).Line) }
Say ""
Say "--- Files and folders ---"
Check "Install folder" (Test-Path $target) $target
$backups = @(Get-ChildItem -LiteralPath $pf -Directory -Filter 'M Family Safety Guard.backup-*')
Check "Backup folders" ($backups.Count -gt 0) (($backups | ForEach-Object { $_.Name }) -join ', ')
Check "Data folder (requests / notices)" (Test-Path $data) $data
$tmpFiles = @(Get-ChildItem -LiteralPath (Join-Path $env:SystemRoot 'Temp') -Filter 'mfsg-*')
Check "Temp scripts in Windows\Temp" ($tmpFiles.Count -gt 0) (($tmpFiles | ForEach-Object { $_.Name }) -join ', ')

Say ""
Say "--- Tasks, programs and processes ---"
$tasks = @(Get-ScheduledTask | Where-Object { $_.TaskName -like 'MFamilySafetyGuard-*' -or $_.TaskName -like 'ParentGuard*' -or $_.TaskName -like 'MFSG-*' })
Check "Scheduled tasks" ($tasks.Count -gt 0) (($tasks | ForEach-Object { $_.TaskName + '=' + $_.State }) -join ', ')
Check "Apps and Features entry" (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MFamilySafetyGuard') ""
$procs = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^pythonw?\.exe$' -and $_.CommandLine -like '*M Family Safety Guard*' })
Check "Running agent / helper processes" ($procs.Count -gt 0) (($procs | ForEach-Object { 'PID ' + $_.ProcessId }) -join ', ')

Say ""
Say "--- Network and filtering ---"
$hostsFile = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$hostsHit = $false
if (Test-Path -LiteralPath $hostsFile) { $hostsHit = [bool](Select-String -LiteralPath $hostsFile -Pattern 'PARENTGUARD' -Quiet) }
Check "Blocklist entries in the hosts file" $hostsHit $hostsFile
$fw = @(Get-NetFirewallRule -DisplayName 'MFamilySafetyGuard-BlockDoT')
Check "Firewall rule MFamilySafetyGuard-BlockDoT" ($fw.Count -gt 0) ""
$loop = @(Get-DnsClientServerAddress -AddressFamily IPv4, IPv6 | Where-Object { $_.ServerAddresses -contains '127.0.0.1' -or $_.ServerAddresses -contains '::1' })
Check "Adapters still pointing DNS at the local filter" ($loop.Count -gt 0) (($loop | ForEach-Object { $_.InterfaceAlias }) -join ', ')
$wifi = Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -eq 'Wi-Fi' }
if ($wifi) { Say ("(info) Wi-Fi DNS right now: " + ($wifi.ServerAddresses -join ', ')) }
try { Resolve-DnsName example.com -ErrorAction Stop | Out-Null; Say "(info) Name lookup: OK" } catch { Say "(info) Name lookup: FAILED" }

Say ""
Say "--- Browser policies written by the agent ---"
$names = 'ForceGoogleSafeSearch','ForceYouTubeRestrict','ForceBingSafeSearch','DnsOverHttpsMode','BuiltInDnsClientEnabled','IncognitoModeAvailability','InPrivateModeAvailability','BrowserGuestModeEnabled','AllowDeletingBrowserHistory','NetworkPredictionOptions','TorDisabled','DisablePrivateBrowsing','Enabled','Locked'
$found = @()
foreach ($k in 'Google\Chrome','Microsoft\Edge','BraveSoftware\Brave','Mozilla\Firefox','Mozilla\Firefox\DNSOverHTTPS') {
    $p = 'HKLM:\SOFTWARE\Policies\' + $k
    if (Test-Path $p) {
        $item = Get-ItemProperty -Path $p
        foreach ($n in $names) { if ($null -ne $item.$n) { $found += ($k + ' ' + $n + '=' + $item.$n) } }
    }
}
Check "Browser policy values (safe search, private mode, DNS-over-HTTPS)" ($found.Count -gt 0) ""
foreach ($f in $found) { Say ("            " + $f) }

Say ""
Say "--- For information only (not counted) ---"
$py = @(Get-ChildItem -LiteralPath $pf -Directory -Filter 'Python3*')
if ($py.Count -gt 0) { Say ("Python installed machine-wide: " + (($py | ForEach-Object { $_.Name }) -join ', ') + "  (a normal program; Remove does not uninstall it)") } else { Say "No machine-wide Python found" }

Say ""
if ($script:left -eq 0) { Say "RESULT: CLEAN - nothing from Family Safety Guard was found." } else { Say ("RESULT: " + $script:left + " item(s) present.") }

$dir = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
$file = Join-Path $dir ("pg-check-" + $Label + ".txt")
$script:out | Set-Content -Path $file -Encoding UTF8
Write-Host ("Saved to: " + $file)

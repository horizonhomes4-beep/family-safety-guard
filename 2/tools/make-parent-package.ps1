#Requires -Version 5.1
# Builds a ready-to-send ZIP for ONE child laptop.
# Input : the config.json copied from the Admin dashboard (clipboard or file).
# Output: READY-TO-SEND\FamilySafetyGuard-<ChildName>.zip
$ErrorActionPreference = 'Stop'
$Here     = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root     = Split-Path -Parent $Here
$Template = Join-Path $Root 'parent-package-template'
$OutDir   = Join-Path $Root 'READY-TO-SEND'
$ReadmeName  = '1 - READ ME FIRST.txt'
$ProgramName = 'program-DO-NOT-OPEN'

function Read-Config([string]$text) {
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }
  try { $c = $text | ConvertFrom-Json } catch { return $null }
  foreach ($f in 'projectId','apiKey','deviceId','deviceKey') {
    $v = [string]$c.$f
    if ([string]::IsNullOrWhiteSpace($v) -or $v -match 'PASTE_FROM_ADMIN|YOUR_|CHANGE_ME|REPLACE_') { return $null }
  }
  return $c
}

try {
  Write-Host ''
  Write-Host '  ===============================================' -ForegroundColor Cyan
  Write-Host '   Make a package for a parent (one child laptop)' -ForegroundColor Cyan
  Write-Host '  ===============================================' -ForegroundColor Cyan
  Write-Host ''

  foreach ($need in @($ReadmeName, '2 - DOUBLE-CLICK TO INSTALL.bat', "$ProgramName\install.ps1", "$ProgramName\agent.py")) {
    if (-not (Test-Path -LiteralPath (Join-Path $Template $need))) { throw "The parent-package-template folder is incomplete (missing: $need)." }
  }

  $name = (Read-Host '  Type the child''s first name (example: Amara)').Trim()
  if (-not $name) { throw 'No name was typed.' }

  $cfg = $null
  try { $cfg = Read-Config (Get-Clipboard -Raw) } catch { }
  if ($cfg) {
    Write-Host '  Found the copied config.json on the clipboard.' -ForegroundColor Green
  } else {
    Write-Host '  No copied config.json found on the clipboard.' -ForegroundColor Yellow
    Write-Host '  (In the Admin dashboard open the child and click "Copy config.json".)'
    $p = (Read-Host '  Or drag a saved config.json file onto this window and press Enter').Trim().Trim('"')
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { throw 'No config.json was provided.' }
    $cfg = Read-Config ([IO.File]::ReadAllText($p))
    if (-not $cfg) { throw 'That file is not a valid, complete config.json.' }
  }
  Write-Host ('  Device ID : ' + $cfg.deviceId)
  Write-Host ('  For child : ' + $name)
  Write-Host ''
  $ok = Read-Host '  Is this the right child? Press Enter to continue, or type N to cancel'
  if ($ok -match '^[nN]') { Write-Host '  Cancelled.'; exit 0 }

  $safe = (($name -replace '[^\p{L}\p{N} _-]', '').Trim()) -replace '\s+', '-'
  if (-not $safe) { $safe = 'Child' }
  $folderName = "FamilySafetyGuard-$safe"

  $stageRoot = Join-Path $env:TEMP ('fsg-build-' + [guid]::NewGuid().ToString('N'))
  $stage = Join-Path $stageRoot $folderName
  New-Item -ItemType Directory -Path $stage -Force | Out-Null
  Copy-Item -Path (Join-Path $Template '*') -Destination $stage -Recurse -Force

  # 1) this child's config.json
  $json = [ordered]@{ projectId = [string]$cfg.projectId; apiKey = [string]$cfg.apiKey; deviceId = [string]$cfg.deviceId; deviceKey = [string]$cfg.deviceKey } | ConvertTo-Json
  [IO.File]::WriteAllText((Join-Path $stage "$ProgramName\config.json"), $json, (New-Object Text.UTF8Encoding($false)))

  # 2) child's name in the parent's instructions
  $readme = Join-Path $stage $ReadmeName
  $txt = [IO.File]::ReadAllText($readme).Replace('{{CHILD_NAME}}', $name)
  [IO.File]::WriteAllText($readme, $txt, (New-Object Text.UTF8Encoding($true)))

  # 3) zip it
  New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
  $zip = Join-Path $OutDir "$folderName.zip"
  if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
  Compress-Archive -LiteralPath $stage -DestinationPath $zip -CompressionLevel Optimal
  Remove-Item -LiteralPath $stageRoot -Recurse -Force
  if (-not (Test-Path -LiteralPath $zip)) { throw 'The ZIP file was not created.' }

  Write-Host ''
  Write-Host '  ===============================================' -ForegroundColor Green
  Write-Host '   DONE. Send this file to the parent:' -ForegroundColor Green
  Write-Host ('   ' + $zip) -ForegroundColor Green
  Write-Host '  ===============================================' -ForegroundColor Green
  Write-Host '  Send it privately (restricted Drive/OneDrive link or WhatsApp document).'
  Write-Host '  It contains this child''s secret key - never post it publicly.'
  Start-Process explorer.exe -ArgumentList ('"{0}"' -f $OutDir)
}
catch {
  Write-Host ''
  Write-Host ('  [X] ' + $_.Exception.Message) -ForegroundColor Red
  exit 1
}

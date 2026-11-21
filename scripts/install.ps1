<#
Installs NetGuard. Run from YOUR OWN account in an elevated PowerShell (Run as administrator):
    powershell -ExecutionPolicy Bypass -File scripts\install.ps1
Options:
    -NoGate    install the firewall part only (no launch checks / Gatekeeper)
Turns outbound Block on LAST, after every allow rule and the watcher are in place.
Undo with scripts\uninstall.ps1, or `netguard off` for an instant allow-all.
#>
param([switch]$NoGate)
$ErrorActionPreference = 'Continue'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this from an elevated PowerShell (Run as administrator).'
}
$root = Split-Path $PSScriptRoot -Parent
$ng = 'C:\ProgramData\NetGuard'
$user = "$env:USERDOMAIN\$env:USERNAME"

# 1. Build (if needed) and install files, locked down: only SYSTEM and Administrators can change them.
if (-not (Test-Path (Join-Path $root 'build\gatekeeper.exe'))) { & (Join-Path $PSScriptRoot 'build.ps1') }
New-Item -ItemType Directory -Force -Path $ng | Out-Null
Get-Process gatekeeper -ErrorAction SilentlyContinue | Stop-Process -Force
Copy-Item (Join-Path $PSScriptRoot 'watcher.ps1'), (Join-Path $PSScriptRoot 'netguard.ps1'), (Join-Path $root 'build\gatekeeper.exe'), (Join-Path $root 'build\ngstub.exe') -Destination $ng -Force
Set-Content -LiteralPath (Join-Path $ng 'netguard.cmd') -Value '@powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0netguard.ps1" %*' -Encoding ASCII
icacls $ng /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
"files installed in $ng (users: read-only)"

# 2. Allow list from config\allowlist.txt.
$paths = foreach ($line in Get-Content (Join-Path $root 'config\allowlist.txt')) {
  $l = $line.Trim(); if (-not $l -or $l.StartsWith('#')) { continue }
  $p = [Environment]::ExpandEnvironmentVariables($l)
  Get-ChildItem -Path $p -ErrorAction SilentlyContinue | ForEach-Object FullName
}
Get-NetFirewallRule -DisplayName 'NetGuard:*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$approved = @()
foreach ($p in ($paths | Sort-Object -Unique)) {
  $name = [System.IO.Path]::GetFileName($p)
  New-NetFirewallRule -DisplayName "NetGuard: $name" -Group 'NetGuard' -Direction Outbound -Program $p -Action Allow | Out-Null
  $s = Get-AuthenticodeSignature -LiteralPath $p
  $signer = if ($s.Status -eq 'Valid') { $s.SignerCertificate.Subject -replace '^CN="?([^",]+)"?.*', '$1' } else { '' }
  $approved += [pscustomobject]@{ path = $p; name = $name; signer = $signer; approvedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm'); how = 'initial' }
}
New-NetFirewallRule -DisplayName 'NetGuard: Microsoft Defender (service)' -Group 'NetGuard' -Direction Outbound -Service 'WinDefend' -Action Allow | Out-Null
New-NetFirewallRule -DisplayName 'NetGuard: System' -Group 'NetGuard' -Direction Outbound -Program 'System' -Action Allow | Out-Null
$approved | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $ng 'approved.json') -Encoding UTF8
if (-not (Test-Path (Join-Path $ng 'blocked.json'))) { '[]' | Set-Content -LiteralPath (Join-Path $ng 'blocked.json') -Encoding UTF8 }
"allow rules: $(@(Get-NetFirewallRule -DisplayName 'NetGuard:*').Count)"

# 3. Log blocked connections (Filtering Platform Connection, failures) for the watcher.
auditpol /set /subcategory:'{0CCE9226-69AE-11D9-BED3-505054503030}' /failure:enable | Out-Null
"blocked-connection auditing: on"

# 4. Watcher (SYSTEM, at startup and every 2 minutes).
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ng\watcher.ps1`""
$t1 = New-ScheduledTaskTrigger -AtStartup
$t2 = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
Register-ScheduledTask -TaskName 'NetGuard Watcher' -Action $action -Trigger $t1, $t2 -Principal $principal -Settings $settings -Description 'NetGuard: keeps outbound blocked by default and records blocked programs.' -Force | Out-Null
"watcher task: registered"

# 5. Gatekeeper (your session, elevated so normal programs can't close it or click its window).
if (-not $NoGate) {
  $action = New-ScheduledTaskAction -Execute "$ng\gatekeeper.exe"
  $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
  $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -MultipleInstances IgnoreNew -Priority 4
  Register-ScheduledTask -TaskName 'NetGuard Gatekeeper' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'NetGuard: checks how allowed programs are used and asks you about suspicious use.' -Force | Out-Null
  Start-ScheduledTask -TaskName 'NetGuard Gatekeeper'
  "gatekeeper task: registered for $user"
}

# 6. `netguard` command on PATH (machine PATH, admin-only to change).
$mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($mp -notlike "*$ng*") { [Environment]::SetEnvironmentVariable('Path', "$mp;$ng", 'Machine') }
"netguard on PATH (open a new terminal)"

# 7. Disk map, launch checks, then LAST: block outbound by default on every profile.
& "$ng\netguard.ps1" refreshmap
if (-not $NoGate) { & "$ng\netguard.ps1" gate on }
Remove-Item -LiteralPath (Join-Path $ng 'disabled.flag') -Force -ErrorAction SilentlyContinue
Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Block
Get-NetFirewallProfile | ForEach-Object { "profile $($_.Name): firewall on=$($_.Enabled) outbound=$($_.DefaultOutboundAction)" }
Start-ScheduledTask -TaskName 'NetGuard Watcher'
''
'NetGuard is on. Programs that try to connect will show up in:  netguard blocked'

<#
Removes NetGuard completely. Run in an elevated PowerShell:
    powershell -ExecutionPolicy Bypass -File scripts\uninstall.ps1
Options:
    -KeepAudit   leave blocked-connection auditing on (it is turned off by default)
#>
param([switch]$KeepAudit)
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw 'Run this from an elevated PowerShell (Run as administrator).'
}
$ng = 'C:\ProgramData\NetGuard'

# Outbound back to the Windows default first, so nothing breaks half-way.
Set-NetFirewallProfile -All -DefaultOutboundAction Allow
'outbound: allowed again (Windows default)'

# Launch checks (IFEO entries) and the BITS/WebDAV block rules.
$roots = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
foreach ($r in $roots) {
  Get-ChildItem $r -ErrorAction SilentlyContinue | ForEach-Object {
    Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | Where-Object PSChildName -like 'NetGuard-*' | Remove-Item -Recurse -Force
    if (-not (Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue)) { Remove-ItemProperty $_.PSPath -Name UseFilter -ErrorAction SilentlyContinue }
  }
}
'launch checks: removed'

foreach ($t in 'NetGuard Watcher', 'NetGuard Gatekeeper') { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue }
Get-Process gatekeeper -ErrorAction SilentlyContinue | Stop-Process -Force
'tasks: removed'

Get-NetFirewallRule -DisplayName 'NetGuard:*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Get-NetFirewallRule -DisplayName 'NetGuard-Block:*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
'firewall rules: removed'

if (-not $KeepAudit) { auditpol /set /subcategory:'{0CCE9226-69AE-11D9-BED3-505054503030}' /failure:disable | Out-Null; 'blocked-connection auditing: off' }

$mp = [Environment]::GetEnvironmentVariable('Path', 'Machine')
[Environment]::SetEnvironmentVariable('Path', (($mp -split ';') | Where-Object { $_ -and $_ -ne $ng }) -join ';', 'Machine')
Start-Sleep 1
Remove-Item -LiteralPath $ng -Recurse -Force -ErrorAction SilentlyContinue
'files: removed'
'NetGuard uninstalled.'

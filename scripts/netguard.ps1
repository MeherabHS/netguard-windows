<#
NetGuard - nothing leaves this PC unless you approve it.
Windows Firewall blocks all outbound traffic by default; approved programs get an
allow rule. Every change asks for administrator approval (UAC), so a program running
as you cannot quietly approve itself.

  netguard status            protection state and counts
  netguard blocked           programs that tried to connect and were blocked (numbered)
  netguard approve <n|name|path>   allow a program (number from `blocked`, part of its name, or full path)
  netguard allowed           programs allowed by NetGuard
  netguard revoke <name|path>      remove an approval
  netguard refreshmap        re-read drive letters (after adding/removing a drive)
  netguard gate on / off     check each launch of curl/ssh/git/node/gh/python first (off = emergency switch)
  netguard gatelog           what the Gatekeeper paused and what you decided
  netguard trust <folder>    let unsigned programs in this folder start allowed tools silently
  netguard off / on          emergency switch: allow / block all outbound

From WSL:  powershell.exe -File 'C:\ProgramData\NetGuard\netguard.ps1' blocked
#>
param([string]$Command = 'status', [string]$Target = '')
$ng = 'C:\ProgramData\NetGuard'
$blockedPath = Join-Path $ng 'blocked.json'; $approvedPath = Join-Path $ng 'approved.json'
# PS 5.1 returns a JSON array as ONE object; re-enumerate so callers get the items.
function Read-Json($p) { if (Test-Path -LiteralPath $p) { try { $o = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json; return @($o | ForEach-Object { $_ }) } catch { } } return @() }
function Is-Admin { ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
function Elevate([string]$cmd, [string]$arg) {
  Start-Process powershell.exe -Verb RunAs -Wait -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $cmd `"$arg`""
}
function Signer($path) {
  if (-not (Test-Path -LiteralPath $path)) { return '' }
  $s = Get-AuthenticodeSignature -LiteralPath $path
  if ($s.Status -eq 'Valid') { return ($s.SignerCertificate.Subject -replace '^CN="?([^",]+)"?.*', '$1') }
  return ''
}

switch ($Command.ToLower()) {
  'status' {
    Get-NetFirewallProfile | ForEach-Object { "{0,-8} firewall on: {1}  outbound default: {2}" -f $_.Name, $_.Enabled, $_.DefaultOutboundAction }
    "disabled by 'netguard off': $(Test-Path -LiteralPath (Join-Path $ng 'disabled.flag'))"
    "NetGuard allow rules: $(@(Get-NetFirewallRule -DisplayName 'NetGuard:*' -ErrorAction SilentlyContinue).Count)"
    "programs blocked so far: $(@(Read-Json $blockedPath).Count)  (see: netguard blocked)"
    $st = @(Read-Json (Join-Path $ng 'state.json')) | Select-Object -First 1
    if ($st) { "watcher last run: $($st.lastRun)  (runs every 2 minutes as SYSTEM)" } else { 'watcher has not run yet' }
    if (-not (Test-Path -LiteralPath (Join-Path $ng 'devmap.json'))) { "disk map missing - run: netguard refreshmap" }
    "gatekeeper running: $([bool](Get-Process gatekeeper -ErrorAction SilentlyContinue))  (checks how allowed programs are used)"
  }
  'blocked' {
    $i = 0
    Read-Json $blockedPath | ForEach-Object { $i++; "{0,3}. {1,-28} x{2,-5} last {3}  -> {4}`n      {5}  [{6}]" -f $i, $_.name, $_.count, $_.last, $_.lastDest, $_.path, $(if ($_.signer) { "signed: $($_.signer)" } else { 'NOT signed' }) }
    if ($i -eq 0) { 'nothing blocked yet' }
  }
  'allowed' {
    Get-NetFirewallRule -DisplayName 'NetGuard:*' -ErrorAction SilentlyContinue | ForEach-Object { $a = $_ | Get-NetFirewallApplicationFilter; $s = $_ | Get-NetFirewallServiceFilter; "{0}`n      {1}" -f $_.DisplayName, $(if ($a.Program -and $a.Program -ne 'Any') { $a.Program } else { "service: $($s.Service)" }) }
  }
  'approve' {
    if (-not $Target) { 'usage: netguard approve <number|name|path>'; break }
    $list = Read-Json $blockedPath; $path = $null
    if ($Target -match '^\d+$' -and [int]$Target -ge 1 -and [int]$Target -le $list.Count) { $path = $list[[int]$Target - 1].path }
    elseif (Test-Path -LiteralPath $Target) { $path = (Resolve-Path -LiteralPath $Target).Path }
    else { $m = @($list | Where-Object { $_.name -like "*$Target*" -or $_.path -like "*$Target*" }); if ($m.Count -eq 1) { $path = $m[0].path } elseif ($m.Count -gt 1) { "several matches - use the number from 'netguard blocked':"; $m | ForEach-Object { "  $($_.path)" }; break } }
    if (-not $path) { "no blocked program matches '$Target' (see: netguard blocked)"; break }
    if (-not (Is-Admin)) { "approving: $path"; "signature: $(if ($s = Signer $path) { $s } else { 'NOT signed - only approve if you trust it' })"; Elevate 'approve' $path; break }
    $name = [System.IO.Path]::GetFileName($path)
    New-NetFirewallRule -DisplayName "NetGuard: $name" -Group 'NetGuard' -Direction Outbound -Program $path -Action Allow | Out-Null
    $approved = @(Read-Json $approvedPath) + [pscustomobject]@{ path = $path; name = $name; signer = (Signer $path); approvedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm'); how = 'approved' }
    $approved | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $approvedPath -Encoding UTF8
    @(Read-Json $blockedPath | Where-Object { $_.path -ne $path }) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $blockedPath -Encoding UTF8
    "approved: $path"
  }
  'revoke' {
    if (-not $Target) { 'usage: netguard revoke <name|path>'; break }
    if (-not (Is-Admin)) { Elevate 'revoke' $Target; break }
    $rules = @(Get-NetFirewallRule -DisplayName 'NetGuard:*' -ErrorAction SilentlyContinue | Where-Object { $a = $_ | Get-NetFirewallApplicationFilter; $_.DisplayName -like "*$Target*" -or $a.Program -like "*$Target*" })
    $rules | Remove-NetFirewallRule
    @(Read-Json $approvedPath | Where-Object { $_.path -notlike "*$Target*" -and $_.name -notlike "*$Target*" }) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $approvedPath -Encoding UTF8
    "revoked $($rules.Count) rule(s)"
  }
  'refreshmap' {
    # Saves \Device\HarddiskVolumeN -> drive letter, used by the watcher to show real paths.
    if (-not (Is-Admin)) { Elevate 'refreshmap' ''; break }
    Add-Type -Namespace NetGuard -Name Dos -MemberDefinition '[DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern uint QueryDosDevice(string lpDeviceName, System.Text.StringBuilder lpTargetPath, int ucchMax);'
    $map = foreach ($drv in [System.IO.DriveInfo]::GetDrives()) { $l = $drv.Name.TrimEnd('\'); $sb = New-Object System.Text.StringBuilder 512; if ([NetGuard.Dos]::QueryDosDevice($l, $sb, 512) -gt 0) { [pscustomobject]@{ device = $sb.ToString(); letter = $l } } }
    @($map) | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ng 'devmap.json') -Encoding UTF8
    "disk map saved: $(@($map).Count) drives"
  }
  'gate' {
    # on: route allowed data-sending tools through ngstub.exe so the Gatekeeper checks each launch first.
    if ($Target -notin 'on', 'off') { 'usage: netguard gate on|off'; break }
    if (-not (Is-Admin)) { Elevate 'gate' $Target; break }
    $roots = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    foreach ($r in $roots) { Get-ChildItem $r -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue | Where-Object PSChildName -like 'NetGuard-*' | Remove-Item -Recurse -Force; if (-not (Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue)) { Remove-ItemProperty $_.PSPath -Name UseFilter -ErrorAction SilentlyContinue } } }
    Get-NetFirewallRule -DisplayName 'NetGuard-Block:*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    if ($Target -eq 'off') { 'Gatekeeper launch checks OFF (tools start without asking; firewall still blocks unknown programs)'; break }
    $gated = 'curl.exe', 'ssh.exe', 'git-remote-https.exe', 'node.exe', 'gh.exe', 'python.exe', 'pythonw.exe'
    $paths = Get-NetFirewallRule -DisplayName 'NetGuard:*' | Get-NetFirewallApplicationFilter | ForEach-Object Program | Where-Object { $_ -and (Split-Path $_ -Leaf) -in $gated -and (Test-Path -LiteralPath $_) } | Sort-Object -Unique
    $i = 0
    foreach ($p in $paths) {
      $i++; $leaf = Split-Path $p -Leaf
      foreach ($r in $roots) {
        $k = Join-Path $r $leaf; if (-not (Test-Path $k)) { New-Item $k -Force | Out-Null }
        Set-ItemProperty $k -Name UseFilter -Value 1 -Type DWord
        $f = New-Item (Join-Path $k "NetGuard-$i") -Force
        Set-ItemProperty $f.PSPath -Name FilterFullPath -Value $p
        Set-ItemProperty $f.PSPath -Name Debugger -Value "`"$ng\ngstub.exe`" `"--image=$p`""
      }
      "gated: $p"
    }
    # BITS and WebDAV run inside svchost (allowed), so a script could send data through them unseen.
    New-NetFirewallRule -DisplayName 'NetGuard-Block: BITS transfers' -Direction Outbound -Service BITS -Action Block | Out-Null
    New-NetFirewallRule -DisplayName 'NetGuard-Block: WebDAV client' -Direction Outbound -Service WebClient -Action Block | Out-Null
    'blocked: BITS and WebDAV background transfers'
  }
  'gatelog' {
    $g = Join-Path $ng 'gate.log'
    if (Test-Path -LiteralPath $g) { Get-Content -LiteralPath $g -Tail 40 } else { 'nothing paused yet' }
  }
  'trust' {
    if (-not $Target) { 'usage: netguard trust <folder>'; break }
    if (-not (Is-Admin)) { Elevate 'trust' $Target; break }
    $f = (Resolve-Path -LiteralPath $Target -ErrorAction SilentlyContinue).Path; if (-not $f) { $f = $Target }
    if ((Test-Path -LiteralPath $f -PathType Container) -and -not $f.EndsWith([string][char]92)) { $f += [char]92 }
    Add-Content -LiteralPath (Join-Path $ng 'gate-trust.txt') -Value $f
    "trusted: $f"
  }
  'off' {
    if (-not (Is-Admin)) { Elevate 'off' ''; break }
    New-Item -ItemType File -Force -Path (Join-Path $ng 'disabled.flag') | Out-Null
    Set-NetFirewallProfile -All -DefaultOutboundAction Allow
    'NetGuard OFF: all outbound allowed until `netguard on`'
  }
  'on' {
    if (-not (Is-Admin)) { Elevate 'on' ''; break }
    Remove-Item -LiteralPath (Join-Path $ng 'disabled.flag') -Force -ErrorAction SilentlyContinue
    Set-NetFirewallProfile -All -Enabled True -DefaultOutboundAction Block
    'NetGuard ON: outbound blocked except approved programs'
  }
  default { Get-Content -LiteralPath $PSCommandPath -TotalCount 21 | Select-Object -Skip 1 }
}


# NetGuard watcher - runs as SYSTEM every 2 minutes (scheduled task "NetGuard Watcher").
# Kept deliberately light (target well under 100 MB): no firewall/eventing modules and
# no C# compilation on the normal path - registry reads, wevtutil and netsh only.
#  1. Keeps Windows Firewall blocking outbound by default (unless `netguard off`).
#  2. Records every program whose outbound connection was blocked (Security event 5157)
#     into blocked.json, for review with `netguard blocked` / `netguard approve`.
#  3. When an approved program updates into a new folder (same file name, same valid
#     publisher signature), allows the new path automatically.
$ErrorActionPreference = 'SilentlyContinue'
$ng = 'C:\ProgramData\NetGuard'
$logFile = Join-Path $ng 'watcher.log'
function Log($m) { Add-Content -LiteralPath $logFile -Value ("{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $m) }
# PS 5.1 returns a JSON array as ONE object; re-enumerate so callers get the items.
function Read-Json($p) { if (Test-Path -LiteralPath $p) { try { $o = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json; return @($o | ForEach-Object { $_ }) } catch { } } return @() }

# --- 1. enforce (registry check; netsh only when something must be fixed) ---
if (-not (Test-Path -LiteralPath (Join-Path $ng 'disabled.flag'))) {
  $bad = $false
  foreach ($p in 'DomainProfile', 'StandardProfile', 'PublicProfile') {
    $v = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\$p"
    if ($v.EnableFirewall -ne 1 -or $v.DefaultOutboundAction -ne 1) { $bad = $true }
  }
  if ($bad) {
    & netsh.exe advfirewall set allprofiles state on | Out-Null
    & netsh.exe advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
    Log 're-enforced outbound Block on all profiles'
  }
}

# --- device path -> drive letter (map saved by `netguard refreshmap`) -------
$devMap = @{}
foreach ($m in (Read-Json (Join-Path $ng 'devmap.json'))) { $devMap[$m.device.ToLower()] = $m.letter }
function To-DosPath($p) {
  if (-not $p) { return $p }
  foreach ($k in $devMap.Keys) { if ($p.ToLower().StartsWith($k + '\')) { return $devMap[$k] + $p.Substring($k.Length) } }
  return $p
}
function Signer($path) {
  if (-not (Test-Path -LiteralPath $path)) { return '' }
  $s = Get-AuthenticodeSignature -LiteralPath $path
  if ($s.Status -eq 'Valid') { return ($s.SignerCertificate.Subject -replace '^CN="?([^",]+)"?.*', '$1') }
  return ''
}

# --- 2. collect blocked outbound attempts (wevtutil, newer than last run) ----
$statePath = Join-Path $ng 'state.json'; $blockedPath = Join-Path $ng 'blocked.json'; $approvedPath = Join-Path $ng 'approved.json'
$state = @(Read-Json $statePath) | Select-Object -First 1
$lastId = if ($state) { [long]$state.lastRecordId } else { 0 }
if ($lastId -eq 0) {
  # First run: start from the newest event instead of the whole log history.
  $newest = (& wevtutil.exe qe Security /q:'*[System[(EventID=5157)]]' /f:xml /c:1 /rd:true) -join ''
  if ($newest -match '<EventRecordID>(\d+)</EventRecordID>') { $lastId = [long]$Matches[1] - 200 }
}
$blocked = @{}
foreach ($e in (Read-Json $blockedPath)) { $blocked[$e.path.ToLower()] = $e }
$approved = @(Read-Json $approvedPath)
$raw = (& wevtutil.exe qe Security "/q:*[System[(EventID=5157) and (EventRecordID>$lastId)]]" /f:xml /c:1000) -join ''
$maxId = $lastId
foreach ($chunk in ($raw -split '</Event>')) {
  if ($chunk -notmatch '<EventRecordID>(\d+)</EventRecordID>') { continue }
  $id = [long]$Matches[1]; if ($id -gt $maxId) { $maxId = $id }
  if ($chunk -notmatch "Name='Direction'>%%14593<") { continue }                 # outbound only
  if ($chunk -notmatch "Name='Application'>([^<]+)<") { continue }
  $path = To-DosPath $Matches[1]
  if ($path -eq 'System') { continue }
  $dest = if ($chunk -match "Name='DestAddress'>([^<]*)<") { $Matches[1] } else { '' }
  $port = if ($chunk -match "Name='DestPort'>([^<]*)<") { $Matches[1] } else { '' }
  $when = if ($chunk -match "SystemTime='([^']+)'") { ([datetime]$Matches[1]).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } else { (Get-Date).ToString('yyyy-MM-dd HH:mm') }
  $key = $path.ToLower()
  if ($blocked.ContainsKey($key)) {
    $b = $blocked[$key]; $b.count = [int]$b.count + 1; $b.last = $when; $b.lastDest = "${dest}:$port"
  } else {
    $blocked[$key] = [pscustomobject]@{ path = $path; name = [System.IO.Path]::GetFileName($path); signer = (Signer $path); count = 1; first = $when; last = $when; lastDest = "${dest}:$port" }
  }
}

# --- 3. follow updates of approved apps (netsh: no firewall module needed) ---
foreach ($key in @($blocked.Keys)) {
  $b = $blocked[$key]
  if (-not $b.signer) { continue }
  $match = $approved | Where-Object { $_.name -ieq $b.name -and $_.signer -and $_.signer -eq $b.signer } | Select-Object -First 1
  if ($match -and (Signer $b.path) -eq $match.signer) {
    & netsh.exe advfirewall firewall add rule name="NetGuard: $($b.name) (auto-updated)" dir=out action=allow program="$($b.path)" enable=yes | Out-Null
    $approved += [pscustomobject]@{ path = $b.path; name = $b.name; signer = $b.signer; approvedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm'); how = 'auto-update' }
    $blocked.Remove($key); Log "auto-allowed updated app $($b.path) (signer $($b.signer))"
  }
}

$approved | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $approvedPath -Encoding UTF8
@($blocked.Values | Sort-Object last -Descending) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $blockedPath -Encoding UTF8
[pscustomobject]@{ lastRecordId = $maxId; lastRun = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8

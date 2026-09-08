[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [string]$ReportPath
)
$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
if (-not $ReportPath) { $ReportPath = Join-Path $package 'dependency-audit.txt' }

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio vswhere.exe was not found' }
$installation = (& $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $installation) { throw 'MSVC x64 tools were not found' }
$dumpbin = Get-ChildItem -LiteralPath (Join-Path $installation 'VC\Tools\MSVC') -Directory |
    Sort-Object Name -Descending |
    ForEach-Object { Join-Path $_.FullName 'bin\Hostx64\x64\dumpbin.exe' } |
    Where-Object { Test-Path -LiteralPath $_ } |
    Select-Object -First 1
if (-not $dumpbin) { throw 'dumpbin.exe was not found' }

$binaries = Get-ChildItem -LiteralPath $package -Recurse -File | Where-Object Extension -in '.exe','.dll'
$forbidden = 'MSCOREE\.DLL|HOSTFXR\.DLL|HOSTPOLICY\.DLL|CORECLR\.DLL|WEBVIEW2LOADER\.DLL|VCRUNTIME\d*\.DLL|MSVCP\d*\.DLL|CONCRT\d*\.DLL|UCRTBASE\.DLL'
$lines = @(
    'NativeDNS portable PE dependency audit'
    "Package: $package"
    "Tool: $dumpbin"
    "Generated UTC: $([DateTime]::UtcNow.ToString('s'))Z"
    ''
)
foreach ($binary in $binaries) {
    $output = & $dumpbin /DEPENDENTS $binary.FullName 2>&1
    if ($LASTEXITCODE -ne 0) { throw "dumpbin failed for $($binary.FullName)" }
    $dependencies = @($output | ForEach-Object { if ($_ -match '^\s+([A-Za-z0-9_.-]+\.dll)\s*$') { $Matches[1].ToUpperInvariant() } } | Sort-Object -Unique)
    $relative = $binary.FullName.Substring($package.TrimEnd([IO.Path]::DirectorySeparatorChar).Length + 1)
    $lines += "[$relative]"
    $lines += ($dependencies | ForEach-Object { "  $_" })
    $lines += ''
    $bad = @($dependencies | Where-Object { $_ -match $forbidden })
    if ($bad) { throw "Forbidden managed/WebView/dynamic MSVC runtime dependency in $relative`: $($bad -join ', ')" }
    $headers = (& $dumpbin /HEADERS $binary.FullName 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "dumpbin header inspection failed for $($binary.FullName)" }
    if ($headers -notmatch '(?m)^\s+8664 machine \(x64\)') { throw "$relative is not an x64 PE image" }
    if ($headers -notmatch '(?m)^\s+0 \[\s*0\] RVA \[size\] of COM Descriptor Directory') { throw "$relative contains a CLR COM descriptor" }
    $subsystem = if ($headers -match '(?m)^\s+\d+ subsystem \(([^)]+)\)') { $Matches[1] } else { 'unknown' }
    $lines += "  PE: x64; subsystem=$subsystem; CLR descriptor=absent"
    $lines += ''
}
$lines += 'RESULT: PASS - all images are x64 with no CLR descriptor and no .NET, WebView2, or dynamic MSVC/UCRT dependency imports.'
[IO.File]::WriteAllLines($ReportPath,$lines,[Text.UTF8Encoding]::new($false))
Write-Output $ReportPath

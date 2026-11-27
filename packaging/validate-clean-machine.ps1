[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [string]$ConfigPath,
    [string]$HostName = 'iana.org',
    [switch]$NetworkProbes
)
$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
if (-not [Environment]::Is64BitOperatingSystem -or [Environment]::OSVersion.Version.Major -lt 10) { throw 'Windows 10/11 x64 is required' }
foreach ($line in Get-Content -LiteralPath (Join-Path $package 'docs/SHA256SUMS.txt')) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Invalid hash manifest line: $line" }
    $expected = $Matches[1]
    $file = Join-Path $package $Matches[2]
    if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw "Package hash mismatch: $file" }
}
$driver = Join-Path $package 'bin/drivers/WinDivert64.sys'
if ((Get-AuthenticodeSignature -LiteralPath $driver).Status -ne 'Valid') { throw 'WinDivert driver signature is not valid' }
& (Join-Path $PSScriptRoot 'smoke-portable.ps1') -PackageDirectory $package
if ($NetworkProbes) {
    if (-not $ConfigPath) { throw 'Supply -ConfigPath for network probes' }
    $probe = Start-Process -FilePath (Join-Path $package 'NativeDNS.exe') -ArgumentList '--collect','--quiet','--host',$HostName,'--config',('"' + [IO.Path]::GetFullPath($ConfigPath) + '"') -WindowStyle Hidden -Wait -PassThru
    if ($probe.ExitCode) { throw 'Diagnostic collection failed' }
}
Write-Output 'Clean-machine package validation: PASS; privileged interception was not exercised.'

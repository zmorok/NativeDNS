[CmdletBinding()]
param(
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release',
    [string]$BuildDirectory = 'build/msvc',
    [string]$OutputDirectory = 'build/package',
    [switch]$SkipBuild,
    [switch]$SkipArchive
)
$ErrorActionPreference = 'Stop'
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
function Get-Sha256Hex([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
        finally { $algorithm.Dispose() }
    }
    finally { $stream.Dispose() }
}
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$build = [IO.Path]::GetFullPath((Join-Path $root $BuildDirectory))
$output = [IO.Path]::GetFullPath((Join-Path $root $OutputDirectory))
$stage = Join-Path $output "NativeDNS-0.4.0-windows-x64-portable"
$outputPrefix = $output.TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $stage.StartsWith($outputPrefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Refusing to clean a staging path outside the package output directory' }
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

if (-not $SkipBuild) {
    cmake --build $build --config $Configuration
    if ($LASTEXITCODE -ne 0) { throw 'NativeDNS build failed' }
}
cmake --install $build --config $Configuration --prefix $stage
if ($LASTEXITCODE -ne 0) { throw 'NativeDNS install failed' }

$required = @(
    'NativeDNS.exe','NativeDNS.xml','validate-clean-machine.ps1','validation-transparent.xml','WinDivert.dll','WinDivert64.sys',
    'README.md','THIRD_PARTY_NOTICES.md','licenses/WinDivert.txt',
    'licenses/curl.txt','licenses/libsodium.txt','licenses/nghttp2.txt','docs/BUILD.md',
    'docs/CONFIG_FORMAT.md','docs/MIGRATION_YOGADNS.md','docs/DEPENDENCIES.md',
    'docs/PROGRESS.md','docs/TEST_REPORT.md',
    'tools/nativednsctl.exe'
)
foreach ($relative in $required) {
    $candidate = Join-Path $stage $relative
    if (-not (Test-Path -LiteralPath $candidate)) { throw "Package is missing $relative" }
}

& (Join-Path $PSScriptRoot 'audit-pe.ps1') -PackageDirectory $stage | Out-Null
$hashes = Get-ChildItem -LiteralPath $stage -Recurse -File | Sort-Object FullName | ForEach-Object {
    $relative = $_.FullName.Substring($stage.TrimEnd([IO.Path]::DirectorySeparatorChar).Length + 1)
    '{0}  {1}' -f (Get-Sha256Hex $_.FullName),$relative.Replace('\','/')
}
[IO.File]::WriteAllLines((Join-Path $stage 'SHA256SUMS.txt'),$hashes,[Text.UTF8Encoding]::new($false))

Write-Output $stage
if (-not $SkipArchive) {
    $archive = "$stage.zip"
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
    Compress-Archive -LiteralPath $stage -DestinationPath $archive -CompressionLevel Optimal
    $archiveHash = Get-Sha256Hex $archive
    [IO.File]::WriteAllText("$archive.sha256","$archiveHash  $([IO.Path]::GetFileName($archive))`n",[Text.UTF8Encoding]::new($false))
    Write-Output $archive
}

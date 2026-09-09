[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Debug','Release')][string]$Configuration,
    [ValidateSet('standalone','portable','installer','all')][string]$Target = 'all'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$build = Join-Path $root 'build\msvc'
$artifactRoot = Join-Path $root ("build\artifacts\{0}" -f $Configuration)
$portableOutput = Join-Path $artifactRoot 'portable'
$standalone = Join-Path $artifactRoot 'standalone'
$installerOutput = Join-Path $artifactRoot 'installer'
$preset = $Configuration.ToLowerInvariant()

function Invoke-Checked([string]$Description, [scriptblock]$Command) {
    Write-Host "`n== $Description ==" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) { throw "$Description failed with exit code $LASTEXITCODE" }
}

function Reset-OwnedDirectory([string]$Path, [string]$Parent) {
    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullParent = [IO.Path]::GetFullPath($Parent).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($fullParent,[StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean a path outside $Parent"
    }
    if (Test-Path -LiteralPath $fullPath) { Remove-Item -LiteralPath $fullPath -Recurse -Force }
    New-Item -ItemType Directory -Path $fullPath -Force | Out-Null
}

function Get-Sha256Hex([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    try {
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { return ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-','').ToLowerInvariant() }
        finally { $algorithm.Dispose() }
    }
    finally { $stream.Dispose() }
}

Invoke-Checked 'Configure NativeDNS' { cmake --preset msvc }
Invoke-Checked "Build $Configuration" { cmake --build --preset $preset }
Invoke-Checked "Test $Configuration" { ctest --preset $preset }

if ($Target -in @('standalone','all')) {
    Write-Host "`n== Create minimal standalone folder ==" -ForegroundColor Cyan
    Reset-OwnedDirectory -Path $standalone -Parent $artifactRoot
    $files = @(
        @{ Source = "build\msvc\NativeDNS.GUI\$Configuration\NativeDNS.exe"; Destination = 'NativeDNS.exe' },
        @{ Source = "build\msvc\NativeDNS.GUI\$Configuration\WinDivert.dll"; Destination = 'WinDivert.dll' },
        @{ Source = "build\msvc\NativeDNS.GUI\$Configuration\WinDivert64.sys"; Destination = 'WinDivert64.sys' },
        @{ Source = 'THIRD_PARTY_NOTICES.md'; Destination = 'THIRD_PARTY_NOTICES.md' }
    )
    foreach ($file in $files) {
        $source = Join-Path $root $file.Source
        if (-not (Test-Path -LiteralPath $source)) { throw "Standalone input is missing: $source" }
        Copy-Item -LiteralPath $source -Destination (Join-Path $standalone $file.Destination)
    }
    & (Join-Path $PSScriptRoot 'audit-pe.ps1') -PackageDirectory $standalone | Out-Null
    Write-Host "Standalone: $standalone" -ForegroundColor Green
}

$needsPortableStage = $Target -in @('portable','installer','all')
$portableStage = Join-Path $portableOutput 'NativeDNS-0.1.0-windows-x64-portable'
if ($needsPortableStage) {
    $portableArguments = @{
        Configuration = $Configuration
        BuildDirectory = 'build/msvc'
        OutputDirectory = "build\artifacts\$Configuration\portable"
        SkipBuild = $true
    }
    if ($Target -eq 'installer') { $portableArguments.SkipArchive = $true }
    & (Join-Path $PSScriptRoot 'build-portable.ps1') @portableArguments
    if ($LASTEXITCODE -ne 0) { throw 'Portable staging failed' }
}

if ($Target -in @('installer','all')) {
    Write-Host "`n== Build Windows installer ==" -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $installerOutput -Force | Out-Null
    $isccCandidates = @(
        (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
    )
    $isccCommand = Get-Command iscc.exe -ErrorAction SilentlyContinue
    $iscc = if ($isccCommand) { $isccCommand.Source } else { $isccCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1 }
    if (-not $iscc) { throw 'Inno Setup 6 was not found. Install it or add ISCC.exe to PATH to build the installer target.' }
    Invoke-Checked 'Compile installer' {
        & $iscc "/DStageDir=$portableStage" "/DOutputDir=$installerOutput" "/DConfiguration=$Configuration" (Join-Path $PSScriptRoot 'NativeDNS.iss')
    }
    $configurationSuffix = if ($Configuration -eq 'Debug') { '-debug' } else { '' }
    $installer = Join-Path $installerOutput "NativeDNS-0.1.0-windows-x64-setup$configurationSuffix.exe"
    if (-not (Test-Path -LiteralPath $installer)) { throw "Installer output is missing: $installer" }
    $installerHash = Get-Sha256Hex $installer
    [IO.File]::WriteAllText("$installer.sha256","$installerHash  $([IO.Path]::GetFileName($installer))`n",[Text.UTF8Encoding]::new($false))
    Write-Host "Installer: $installerOutput" -ForegroundColor Green
}

Write-Host "`nCompleted $Configuration target: $Target" -ForegroundColor Green
Write-Host "Artifacts: $artifactRoot"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Debug','Release')][string]$Configuration,
    [ValidateSet('standalone','portable','installer','all')][string]$Target = 'all'
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

$versionFile = Join-Path $root 'VERSION'
if (-not (Test-Path -LiteralPath $versionFile)) {
    throw "VERSION file is missing: $versionFile"
}

$version = (Get-Content -LiteralPath $versionFile -Raw).Trim()
if ($version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Invalid NativeDNS version in VERSION: '$version'"
}

Write-Host "NativeDNS version: $version" -ForegroundColor DarkGray

$preset = "windows-$($Configuration.ToLowerInvariant())"
& cmake --preset $preset
if ($LASTEXITCODE) { throw 'Configure failed' }
& cmake --build --preset $preset --parallel
if ($LASTEXITCODE) { throw 'Build failed' }
& ctest --preset $preset
if ($LASTEXITCODE) { throw 'Tests failed' }
$arguments = @{
    Configuration = $Configuration
    BuildDirectory = "build/windows/$preset"
    OutputDirectory = "out/windows/$($Configuration.ToLowerInvariant())"
    SkipBuild = $true
    SkipArchive = ($Target -in @('standalone','installer'))
}
& (Join-Path $PSScriptRoot 'build-portable.ps1') @arguments
$stage = Join-Path $root "$($arguments.OutputDirectory)/NativeDNS-$version-windows-x64-portable"
if ($Target -in @('installer','all')) {
    $iscc = $env:INNO_SETUP_ISCC
    if (-not $iscc) { $iscc = Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6/ISCC.exe' }
    if (-not (Test-Path -LiteralPath $iscc)) { throw 'Set INNO_SETUP_ISCC to Inno Setup 6 ISCC.exe' }
    & $iscc "/DStageDir=$stage" "/DOutputDir=$(Join-Path $root 'out/packages')" "/DConfiguration=$Configuration" "/DAppVersion=$version" (Join-Path $PSScriptRoot 'NativeDNS.iss')
    if ($LASTEXITCODE) { throw 'Installer build failed' }
}
Write-Output $stage

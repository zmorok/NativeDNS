[CmdletBinding()]
param(
    [switch]$Configure
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

Write-Host "VERSION file: $version" -ForegroundColor Cyan
Write-Host "Windows portable: NativeDNS-$version-windows-x64-portable.zip"
Write-Host "Windows installer: NativeDNS-$version-windows-x64-setup.exe"
Write-Host "Linux portable: NativeDNS-$version-linux-x64-portable.tar.gz"
Write-Host "Linux AppImage: NativeDNS-$version-linux-x64.AppImage"

$checks = @(
    @{
        Path = 'CMakeLists.txt'
        Patterns = @(
            'file\(STRINGS "\$\{NATIVEDNS_VERSION_FILE\}" NATIVEDNS_VERSION',
            'project\(NativeDNS VERSION \$\{NATIVEDNS_VERSION\}',
            'NativeDNS version: \$\{PROJECT_VERSION\}'
        )
    },
    @{
        Path = 'NativeDNS.Core\CMakeLists.txt'
        Patterns = @(
            'configure_file\(',
            'src/version\.hpp\.in',
            'version\.hpp'
        )
    },
    @{
        Path = 'NativeDNS.Core\src\core_api.cpp'
        Patterns = @(
            '#include "version\.hpp"',
            'return nd::build::version;'
        )
    },
    @{
        Path = 'NativeDNS.Core\src\version.hpp.in'
        Patterns = @(
            '@PROJECT_VERSION@'
        )
    },
    @{
        Path = 'scripts\windows\build-windows.bat'
        Patterns = @(
            'VERSION_FILE=%ROOT%\\VERSION',
            'NativeDNS-%VERSION%-windows-x64',
            '/DAppVersion="%VERSION%"'
        )
    },
    @{
        Path = 'packaging\NativeDNS.iss'
        Patterns = @(
            'AppVersion=\{#AppVersion\}',
            'NativeDNS-\{#AppVersion\}-windows-x64-setup'
        )
    },
    @{
        Path = 'packaging\build-artifacts.ps1'
        Patterns = @(
            'NativeDNS-\$version-windows-x64-portable',
            '/DAppVersion=\$version',
            'NativeDNS-\$version-windows-x64-setup'
        )
    },
    @{
        Path = 'packaging\build-portable.ps1'
        Patterns = @(
            'NativeDNS-\$version-windows-x64-portable'
        )
    },
    @{
        Path = 'scripts\linux\build-linux.sh'
        Patterns = @(
            'VERSION_FILE="\$ROOT/VERSION"',
            'NativeDNS version \$VERSION'
        )
    },
    @{
        Path = 'scripts\linux\package-portable.sh'
        Patterns = @(
            'NativeDNS-\$\{VERSION\}-linux-x64'
        )
    },
    @{
        Path = 'scripts\linux\package-appimage.sh'
        Patterns = @(
            'NativeDNS-\$\{VERSION\}-linux-x64'
        )
    }
)

foreach ($check in $checks) {
    $path = Join-Path $root $check.Path

    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required file is missing: $($check.Path)"
    }

    $content = Get-Content -LiteralPath $path -Raw

    foreach ($pattern in $check.Patterns) {
        if ($content -notmatch $pattern) {
            throw "Version wiring check failed for $($check.Path): pattern not found: $pattern"
        }
    }

    Write-Host "OK: $($check.Path)" -ForegroundColor Green
}

$legacyPatterns = @(
    'AppVersion=\d+\.\d+\.\d+',
    'NativeDNS-\d+\.\d+\.\d+-windows-x64',
    'NativeDNS-\d+\.\d+\.\d+-linux-x64',
    'VERSION="\d+\.\d+\.\d+"',
    'return "\d+\.\d+\.\d+"'
)

$versionFiles = @(
    'CMakeLists.txt',
    'NativeDNS.Core\src\core_api.cpp',
    'packaging\NativeDNS.iss',
    'packaging\build-artifacts.ps1',
    'packaging\build-portable.ps1',
    'scripts\windows\build-windows.bat',
    'scripts\linux\build-linux.sh',
    'scripts\linux\package-portable.sh',
    'scripts\linux\package-appimage.sh'
)

foreach ($relative in $versionFiles) {
    $path = Join-Path $root $relative
    $content = Get-Content -LiteralPath $path -Raw

    foreach ($pattern in $legacyPatterns) {
        if ($content -match $pattern) {
            throw "Hardcoded version found in ${relative}: $($Matches[0])"
        }
    }
}

Write-Host "No hardcoded release version remains in build/package files." -ForegroundColor Green

if ($Configure) {
    $cmake = Get-Command cmake -ErrorAction Stop

    Write-Host ""
    Write-Host "=== Running CMake configure ===" -ForegroundColor Cyan

    & $cmake.Source --preset windows-release
    if ($LASTEXITCODE -ne 0) {
        throw "CMake configure failed with exit code $LASTEXITCODE"
    }

    $generatedHeader = Join-Path $root 'build\windows\windows-release\NativeDNS.Core\generated\version.hpp'

    if (-not (Test-Path -LiteralPath $generatedHeader)) {
        throw "Generated version header is missing: $generatedHeader"
    }

    $generated = Get-Content -LiteralPath $generatedHeader -Raw

    if ($generated -notmatch [regex]::Escape('"' + $version + '"')) {
        throw "Generated version header does not contain '$version'"
    }

    Write-Host "Generated C++ version header: $version" -ForegroundColor Green
}

Write-Host ""
Write-Host "Version wiring check passed." -ForegroundColor Green

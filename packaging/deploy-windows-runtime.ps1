[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$PackageDirectory,
    [ValidateSet('Debug','Release')][string]$Configuration = 'Release',
    [string]$QtBinDirectory = $(if ($env:QT_ROOT) { Join-Path $env:QT_ROOT 'bin' })
)
$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$deploy = if ($QtBinDirectory) { Join-Path $QtBinDirectory 'windeployqt.exe' } else { (Get-Command windeployqt.exe -ErrorAction Stop).Source }
$library = Join-Path $package 'app\lib'
New-Item -ItemType Directory -Path $library -Force | Out-Null
& $deploy "--$($Configuration.ToLowerInvariant())" --no-translations --compiler-runtime --dir $library --libdir $library --plugindir $package (Join-Path $package 'app\bin\NativeDNS.GUI.exe')
if ($LASTEXITCODE) { throw 'Qt runtime deployment failed' }
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$visualStudio = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1
if (-not $visualStudio) { throw 'MSVC redistributable runtime directory was not found' }
$redist = Get-ChildItem -LiteralPath (Join-Path $visualStudio 'VC\Redist\MSVC') -Directory |
    Where-Object Name -match '^\d+\.\d+\.\d+$' | Sort-Object { [version]$_.Name } -Descending | Select-Object -First 1
$patterns = @('x64\Microsoft.VC*.CRT')
if ($Configuration -eq 'Debug') { $patterns += 'debug_nonredist\x64\Microsoft.VC*.DebugCRT' }
foreach ($pattern in $patterns) {
    $crt = Get-ChildItem -Path (Join-Path $redist.FullName $pattern) -Directory | Select-Object -First 1
    if (-not $crt) { throw "MSVC runtime $pattern was not found under $redist" }
    Get-ChildItem -LiteralPath $crt.FullName -Filter '*.dll' -File | Copy-Item -Destination $library -Force
}
if ($Configuration -eq 'Debug') {
    $sdk = (Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows Kits\Installed Roots').KitsRoot10
    $ucrt = Get-ChildItem -Path (Join-Path $sdk 'bin\10.*') -Directory | Sort-Object Name -Descending |
        ForEach-Object { Join-Path $_.FullName 'x64\ucrt\ucrtbased.dll' } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $ucrt) { throw 'Debug UCRT was not found in the Windows SDK' }
    Copy-Item -LiteralPath $ucrt -Destination $library -Force
}
# A single shared CRT/Qt directory is inherited by every worker launched by
# the static root bootstrap, including elevated CoreHost and CLI processes.
foreach ($relative in 'NativeDNS.exe','NativeDNS.Debug.exe','app\bin\NativeDNS.GUI.exe','app\bin\NativeDNS.CoreHost.exe','app\bin\NativeDNS.Diagnostics.exe','app\lib\Qt6Core.dll','app\drivers\windivert\WinDivert64.sys','platforms\qwindows.dll') {
    if ($Configuration -eq 'Debug') { $relative = $relative.Replace('Qt6Core.dll','Qt6Cored.dll').Replace('qwindows.dll','qwindowsd.dll') }
    if (-not (Test-Path -LiteralPath (Join-Path $package $relative) -PathType Leaf)) { throw "Incomplete package: $relative" }
}

[CmdletBinding()]
param([Parameter(Mandatory)][string]$PackageDirectory)
$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
$application = Join-Path $package 'NativeDNS.exe'
$control = Join-Path $package 'tools\nativednsctl.exe'
$config = Join-Path $package 'NativeDNS.xml'

& $control rules list $config | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Packaged CLI could not parse NativeDNS.xml' }

if (-not ('NativeDnsSmokeWindow' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NativeDnsSmokeWindow {
    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wparam, IntPtr lparam);
}
'@
}

$process = Start-Process -FilePath $application -WorkingDirectory $package -PassThru
try {
    $window = [IntPtr]::Zero
    for ($attempt = 0; $attempt -lt 50; $attempt++) {
        Start-Sleep -Milliseconds 100
        $process.Refresh()
        if ($process.HasExited) { throw "Packaged GUI exited early with $($process.ExitCode)" }
        if ($process.MainWindowHandle -ne [IntPtr]::Zero) { $window = $process.MainWindowHandle; break }
    }
    if ($window -eq [IntPtr]::Zero) { throw 'Packaged GUI did not create its main Win32 window' }
    # WM_COMMAND / File > Exit. This exercises the same shutdown path as the menu.
    if (-not [NativeDnsSmokeWindow]::PostMessage($window,0x0111,[IntPtr]104,[IntPtr]::Zero)) { throw 'Could not post GUI Exit command' }
    if (-not $process.WaitForExit(5000)) { throw 'Packaged GUI did not exit within five seconds' }
    if ($process.ExitCode -ne 0) { throw "Packaged GUI returned $($process.ExitCode)" }
    Write-Output 'Portable GUI/CLI smoke test passed.'
}
finally {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
}

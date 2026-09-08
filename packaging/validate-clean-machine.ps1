[CmdletBinding()]
param([switch]$TestInterception)
$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$application = Join-Path $package 'NativeDNS.exe'
$control = Join-Path $package 'tools\nativednsctl.exe'
$config = Join-Path $package 'NativeDNS.xml'

if (-not [Environment]::Is64BitOperatingSystem) { throw 'NativeDNS requires x64 Windows' }
$os = [Environment]::OSVersion.Version
if ($os.Major -lt 10) { throw "Windows 10 or later is required; detected $os" }
Write-Output "OS: Windows build $($os.Build), x64"

foreach ($line in Get-Content -LiteralPath (Join-Path $package 'SHA256SUMS.txt')) {
    if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "Invalid SHA256SUMS line: $line" }
    $file = Join-Path $package $Matches[2]
    if (-not (Test-Path -LiteralPath $file)) { throw "Missing package file: $($Matches[2])" }
    $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $Matches[1]) { throw "SHA-256 mismatch: $($Matches[2])" }
}
Write-Output 'Package SHA-256 manifest: PASS'

$signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $package 'WinDivert64.sys')
if ($signature.Status -ne 'Valid') { throw "WinDivert driver signature is $($signature.Status)" }
Write-Output 'WinDivert64.sys signature: PASS'

& $control rules list $config | Out-Host
if ($LASTEXITCODE) { throw 'Starter configuration validation failed' }
foreach ($server in 1,2,3,4) {
    & $control servers test $config $server | Out-Host
    if ($LASTEXITCODE) { throw "Live server test $server failed" }
}
& $control probe udp 1.1.1.1 iana.org 53 | Out-Host
if ($LASTEXITCODE) { throw 'Live Plain UDP test failed' }
& $control probe tcp 208.67.222.222 iana.org 5353 | Out-Host
if ($LASTEXITCODE) { throw 'Live Plain TCP test failed' }

if (-not ('NativeDnsCleanWindow' -as [type])) {
    Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class NativeDnsCleanWindow {
    [DllImport("user32.dll")]
    public static extern bool PostMessage(IntPtr window, uint message, IntPtr wparam, IntPtr lparam);
}
'@
}
$gui = Start-Process -FilePath $application -WorkingDirectory $package -PassThru
try {
    for ($attempt=0; $attempt -lt 50 -and $gui.MainWindowHandle -eq [IntPtr]::Zero; $attempt++) { Start-Sleep -Milliseconds 100; $gui.Refresh() }
    if ($gui.HasExited -or $gui.MainWindowHandle -eq [IntPtr]::Zero) { throw 'NativeDNS GUI did not open' }
    if (-not [NativeDnsCleanWindow]::PostMessage($gui.MainWindowHandle,0x0111,[IntPtr]104,[IntPtr]::Zero)) { throw 'Could not request GUI exit' }
    if (-not $gui.WaitForExit(5000) -or $gui.ExitCode) { throw 'NativeDNS GUI did not exit cleanly' }
    Write-Output 'Native Win32 GUI launch/exit: PASS'
}
finally { if (-not $gui.HasExited) { Stop-Process -Id $gui.Id -Force } }

if ($TestInterception) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw '-TestInterception requires an elevated PowerShell window' }
    & $control windivert-check $config | Out-Host
    if ($LASTEXITCODE) { throw 'Elevated WinDivert load check failed' }
    $routingConfig = Join-Path $package 'validation-transparent.xml'
    & $control rules list $routingConfig | Out-Host
    if ($LASTEXITCODE) { throw 'Transparent-routing fixture is invalid' }
    $hostProcess = Start-Process -FilePath $application -WorkingDirectory $package -ArgumentList '--core-host-windivert',('"'+$routingConfig+'"'),'5353' -PassThru
    try {
        $ready = $false
        for ($attempt=0; $attempt -lt 50; $attempt++) {
            Start-Sleep -Milliseconds 100
            & $control core status *> $null
            if ($LASTEXITCODE -eq 0) { $ready=$true; break }
            if ($hostProcess.HasExited) { throw "Transparent Core exited early with $($hostProcess.ExitCode)" }
        }
        if (-not $ready) { throw 'Transparent Core did not become ready' }
        foreach ($probe in @(
            @('udp','1.1.1.1','iana.org','53'),
            @('udp','1.1.1.1','api.openai.com','53'),
            @('udp','1.1.1.1','blocked.example','53'),
            @('udp','1.1.1.1','example.org','53'),
            @('udp','1.1.1.1','example.net','53'),
            @('tcp','208.67.222.222','iana.org','5353'),
            @('tcp','208.67.222.222','api.openai.com','5353'),
            @('tcp','208.67.222.222','blocked.example','5353'),
            @('tcp','208.67.222.222','example.org','5353'),
            @('tcp','208.67.222.222','example.net','5353')
        )) {
            & $control probe @probe | Out-Host
            if ($LASTEXITCODE) { throw "Transparent $($probe[0]) probe for $($probe[2]) failed" }
        }
        $logs = (& $control core logs 0 0) -join "`n"
        foreach ($rule in 'Selected plain','Selected secure','Blocked','Bypass','Default') {
            if ($logs -notmatch "rule=$([regex]::Escape($rule))") { throw "No transparent routing evidence for rule $rule" }
        }
        Write-Output 'Transparent UDP/TCP Process/Block/Bypass/Default routing: PASS'
    }
    finally {
        & $control core shutdown *> $null
        if (-not $hostProcess.WaitForExit(5000)) { Stop-Process -Id $hostProcess.Id -Force }
    }
}
Write-Output 'CLEAN_MACHINE_VALIDATION: PASS'

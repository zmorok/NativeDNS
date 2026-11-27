[CmdletBinding()]
param([Parameter(Mandatory)][string]$PackageDirectory)
$ErrorActionPreference = 'Stop'
$package = (Resolve-Path -LiteralPath $PackageDirectory).Path
# Initializes Qt/platform paths without acquiring the GUI singleton, opening
# windows, touching autostart or starting interception.
function Test-Entry([string]$Executable, [string]$Arguments, [string]$Expected) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = Join-Path $package $Executable
    $info.Arguments = $Arguments
    $info.WorkingDirectory = [IO.Path]::GetTempPath()
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(15000)) { $process.Kill(); throw "Package entry timed out: $Executable" }
        $text = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0 -or $text -notmatch $Expected) { throw "Package entry failed: $Executable exit=$($process.ExitCode) $text" }
        Write-Output $text.Trim()
    } finally { $process.Dispose() }
}
Test-Entry 'NativeDNS.exe' '--layout-check --quiet' 'diagnostics=0'
Test-Entry 'NativeDNS.exe' '--diagnostics --layout-check --quiet' 'diagnostics=1'
Test-Entry 'NativeDNS.exe' '--core-host --layout-check --quiet' 'driver=.*bin[/\\]drivers'
Write-Output 'Portable GUI normal/Debug and CoreHost module loading: PASS'

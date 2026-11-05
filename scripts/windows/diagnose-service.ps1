[CmdletBinding()]
param(
    [string]$HostName = 'gemini.google.com',
    [string]$PackageDirectory = $PSScriptRoot,
    [string]$ConfigPath = (Join-Path $env:LOCALAPPDATA 'NativeDNS\NativeDNS.xml'),
    [string]$OriginalResolver = '1.1.1.1',
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
if ([Uri]::CheckHostName($HostName) -ne [UriHostNameType]::Dns -or $HostName -match '[^\x21-\x7e]') {
    throw 'HostName must be an ASCII DNS hostname'
}
$control = Join-Path $PackageDirectory 'tools\nativednsctl.exe'
if (-not (Test-Path -LiteralPath $control -PathType Leaf)) { throw "CLI was not found: $control" }
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Config was not found: $ConfigPath" }
if (-not $OutputPath) {
    $directory = Join-Path $PackageDirectory 'logs'
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $OutputPath = Join-Path $directory ('service-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.log')
}
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
$lines = New-Object 'System.Collections.Generic.List[string]'
$utf8 = New-Object Text.UTF8Encoding($true)
function Add-Line([string]$Text) {
    $lines.Add($Text)
    Write-Host $Text
    [IO.File]::WriteAllText($OutputPath, ($lines -join [Environment]::NewLine) + [Environment]::NewLine, $utf8)
}
function Quote-Argument([string]$Value) {
    $quoted = New-Object Text.StringBuilder
    [void]$quoted.Append([char]34)
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq [char]92) { $slashes++; continue }
        if ($character -eq [char]34) { [void]$quoted.Append([char]92, $slashes * 2 + 1) }
        else { [void]$quoted.Append([char]92, $slashes) }
        [void]$quoted.Append($character)
        $slashes = 0
    }
    [void]$quoted.Append([char]92, $slashes * 2)
    [void]$quoted.Append([char]34)
    return $quoted.ToString()
}
function Invoke-Native([string]$Executable, [string[]]$NativeArguments) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = [IO.Path]::GetFullPath($Executable)
    $info.Arguments = ($NativeArguments | ForEach-Object { Quote-Argument $_ }) -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = $utf8
    $info.StandardErrorEncoding = $utf8
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(20000)) {
            $process.Kill()
            $process.WaitForExit()
            Add-Line 'ERROR: diagnostic command exceeded twenty seconds'
        }
        $result = [PSCustomObject]@{ ExitCode = $process.ExitCode; StdOut = $stdout.GetAwaiter().GetResult(); StdErr = $stderr.GetAwaiter().GetResult() }
        Add-Line ('exit_code=' + $result.ExitCode)
        if ($result.StdOut) { Add-Line $result.StdOut.TrimEnd() }
        if ($result.StdErr) { Add-Line $result.StdErr.TrimEnd() }
        return $result
    } finally { $process.Dispose() }
}
Add-Line ('NativeDNS service diagnostics; time=' + (Get-Date -Format o) + ' host=' + $HostName)
Add-Line 'This reads DNS settings and performs DNS/HTTPS probes. Network settings and browser profiles are not changed.'
Add-Line 'HTTPS reachability does not verify service account or region eligibility.'
Add-Line '=== CoreHost status ==='
[void](Invoke-Native $control @('core', 'status'))
Add-Line '=== Configuration and system DNS inspection ==='
[void](Invoke-Native $control @('diagnose', $ConfigPath, $HostName))
Add-Line '=== WinDivert driver services and NativeDNS processes ==='
try {
    $drivers = @(Get-CimInstance Win32_SystemDriver -Filter "Name LIKE '%WinDivert%'" |
        Select-Object Name, State, StartMode, PathName)
    Add-Line (($drivers | Format-List | Out-String).TrimEnd())
    if (-not $drivers.Count) { Add-Line 'No WinDivert driver service was found.' }
    Add-Line ((Get-Process NativeDNS, NativeDNSCoreHost -ErrorAction SilentlyContinue |
        Select-Object ProcessName, Id, Path | Format-List | Out-String).TrimEnd())
    $source = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System\WinDivert' -ErrorAction SilentlyContinue
    if ($source -and $source.EventMessageFile) { Add-Line ('Event Log WinDivert message resource=' + $source.EventMessageFile) }
} catch { Add-Line ('Driver inspection unavailable: ' + $_.Exception.Message) }
Add-Line '=== Edge DNS configuration ==='
foreach ($hive in @('HKCU:', 'HKLM:')) {
    $policy = Get-ItemProperty -LiteralPath (Join-Path $hive 'SOFTWARE\Policies\Microsoft\Edge') -ErrorAction SilentlyContinue
    if ($policy -and $policy.PSObject.Properties['DnsOverHttpsMode']) { Add-Line ($hive + ' Edge DnsOverHttpsMode=' + $policy.DnsOverHttpsMode) }
}
$edgeState = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Local State'
try {
    if (Test-Path -LiteralPath $edgeState -PathType Leaf) {
        if ((Get-Item -LiteralPath $edgeState).Length -gt 16MB) { throw 'Edge Local State exceeds the inspection limit' }
        $settings = [IO.File]::ReadAllText($edgeState, $utf8) | ConvertFrom-Json
        $dns = $settings.dns_over_https
        if ($dns -and $dns.mode) { Add-Line ('Edge Local State DNS mode=' + $dns.mode + ' templates_configured=' + [bool]$dns.templates) }
        else { Add-Line 'Edge Local State has no explicit DNS mode; this is not proof that Secure DNS is disabled.' }
    } else { Add-Line 'Edge Local State was not found for this Windows user.' }
} catch { Add-Line ('Edge DNS preference inspection unavailable: ' + $_.Exception.Message) }
Add-Line '=== Windows resolver result (may use OS encryption and cache) ==='
try {
    $lookup = [Net.Dns]::GetHostAddressesAsync($HostName)
    if (-not $lookup.Wait(10000)) { throw 'Windows resolver lookup exceeded ten seconds' }
    foreach ($address in $lookup.GetAwaiter().GetResult()) { Add-Line ('OS address=' + $address.IPAddressToString) }
} catch {
    $resolverFailure = $_.Exception.GetBaseException()
    Add-Line ('OS lookup failed: type=' + $resolverFailure.GetType().FullName + ' message=' + $resolverFailure.Message)
    if ($resolverFailure -is [Net.Sockets.SocketException]) {
        Add-Line ('OS socket_error=' + $resolverFailure.SocketErrorCode + ' native_error=' + $resolverFailure.NativeErrorCode)
    }
}
$probeAddresses = New-Object 'System.Collections.Generic.List[string]'
foreach ($type in @('A', 'AAAA', 'HTTPS')) {
    Add-Line ('=== NativeDNS configured route; DNS type=' + $type + ' ===')
    $resolveArguments = @('resolve', $ConfigPath, $HostName, $OriginalResolver)
    if ($type -ne 'A') { $resolveArguments += @('--type', $type) }
    $answer = Invoke-Native $control $resolveArguments
    if ($answer.ExitCode -eq 2 -and ($answer.StdOut + $answer.StdErr) -match 'Usage:') {
        Add-Line 'This older CLI supports A queries only. AAAA/HTTPS DNS probes were skipped; the A-answer TLS/HTTP check will still run.'
        break
    }
    if ($answer.ExitCode -eq 0 -and $type -ne 'HTTPS') {
        $summary = @($answer.StdOut -split '\r?\n' | Where-Object { $_ -match '^rule=.*action=process rcode=0 ' })
        if ($summary.Count) {
            foreach ($word in ($summary[-1] -split ' ')) {
                $parsed = $null
                if ([Net.IPAddress]::TryParse($word, [ref]$parsed) -and -not [Net.IPAddress]::IsLoopback($parsed) -and $word -ne '0.0.0.0' -and $word -ne '::') {
                    $probeAddresses.Add($parsed.IPAddressToString)
                    break
                }
            }
        }
    }
}
$curl = Join-Path $env:SystemRoot 'System32\curl.exe'
if (Test-Path -LiteralPath $curl -PathType Leaf) {
    foreach ($address in ($probeAddresses | Select-Object -Unique)) {
        Add-Line ('=== HTTPS TLS/HTTP probe using NativeDNS answer ' + $address + ' ===')
        $destination = if ($address.Contains(':')) { '[' + $address + ']' } else { $address }
        [void](Invoke-Native $curl @('--silent', '--show-error', '--head', '--output', 'NUL', '--connect-timeout', '8', '--max-time', '15', '--noproxy', '*',
            '--resolve', ($HostName + ':443:' + $destination), '--write-out', 'remote_ip=%{remote_ip} http_code=%{http_code} ssl_verify_result=%{ssl_verify_result}\n', ('https://' + $HostName + '/')))
    }
} else { Add-Line 'Windows curl.exe was not found; HTTPS transport checks were skipped.' }
Add-Line ('Saved diagnostics: ' + $OutputPath)

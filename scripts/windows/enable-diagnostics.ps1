[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $env:LOCALAPPDATA 'NativeDNS\NativeDNS.xml'),
    [ValidatePattern('^HKCU:\\Software\\')]
    [string]$SettingsRegistryPath = 'HKCU:\Software\NativeDNS\NativeDNS\ui'
)
$ErrorActionPreference = 'Stop'
if ($SettingsRegistryPath -eq 'HKCU:\Software\NativeDNS\NativeDNS\ui' -and
    (Get-Process NativeDNS -ErrorAction SilentlyContinue)) {
    throw 'Close NativeDNS using Exit, then run this script again. No files have been changed.'
}
$ConfigPath = (Resolve-Path -LiteralPath $ConfigPath).Path
$readerSettings = New-Object Xml.XmlReaderSettings
$readerSettings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
$readerSettings.XmlResolver = $null
$reader = [Xml.XmlReader]::Create($ConfigPath, $readerSettings)
$document = New-Object Xml.XmlDocument
$document.PreserveWhitespace = $true
$document.XmlResolver = $null
try { $document.Load($reader) } finally { $reader.Dispose() }
if ($document.DocumentElement.Name -ne 'NativeDNS' -or
    $document.DocumentElement.GetAttribute('schemaVersion') -ne '1') {
    throw 'Expected a NativeDNS schemaVersion=1 working configuration'
}
$logging = $document.DocumentElement.SelectSingleNode('Logging')
if (-not $logging) {
    $logging = $document.CreateElement('Logging')
    [void]$document.DocumentElement.AppendChild($logging)
}
$logging.SetAttribute('screen', '3')
$logging.SetAttribute('file', '3')
$logging.SetAttribute('enabled', '1')
$suffix = [Guid]::NewGuid().ToString('N')
$temporary = $ConfigPath + '.diagnostics-' + $suffix + '.tmp'
$backup = $ConfigPath + '.diagnostics-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + $suffix + '.bak'
$writerSettings = New-Object Xml.XmlWriterSettings
$writerSettings.Encoding = New-Object Text.UTF8Encoding($false)
$writerSettings.NewLineHandling = [Xml.NewLineHandling]::Entitize
$writer = [Xml.XmlWriter]::Create($temporary, $writerSettings)
try { $document.Save($writer) } finally { $writer.Dispose() }
try { [IO.File]::Replace($temporary, $ConfigPath, $backup) }
finally { if (Test-Path -LiteralPath $temporary) { [IO.File]::Delete($temporary) } }
New-Item -Path $SettingsRegistryPath -Force | Out-Null
New-ItemProperty -LiteralPath $SettingsRegistryPath -Name logActions -PropertyType MultiString -Value @('process') -Force | Out-Null
New-ItemProperty -LiteralPath $SettingsRegistryPath -Name logCommands -PropertyType String -Value 'none' -Force | Out-Null
New-ItemProperty -LiteralPath $SettingsRegistryPath -Name logErrors -PropertyType String -Value 'with' -Force | Out-Null
Write-Host 'Enabled: screen=Debug, file=Debug, file recording=on.'
Write-Host 'GUI: Process queries; lifecycle/service commands hidden; query failures retained.'
Write-Host 'The file log retains all diagnostic events, including Bypass and service events.'
Write-Host ('Config backup: ' + $backup)
Write-Host 'Start NativeDNS normally. Re-importing a config with other logging settings requires applying this preset again.'

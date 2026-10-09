[CmdletBinding()]
param(
    [string]$ReleaseRef = 'HEAD',
    [string]$PreviousRef,
    [string]$OutputPath = 'out/release/update.json'
)

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path

function Invoke-ReleaseGit {
    param([string[]]$Arguments)
    $result = & git -C $repoRoot @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Git failed: $($Arguments -join ' ')" }
    return $result
}

# Resolve input refs before using them in ranges or object paths.
$releaseCommit = Invoke-ReleaseGit @('rev-parse', '--verify', '--end-of-options', "$ReleaseRef^{commit}")
$releaseVersion = ((Invoke-ReleaseGit @('show', "${releaseCommit}:VERSION")) -join '').Trim()
if ($releaseVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
    throw "Invalid release VERSION: $releaseVersion"
}
foreach ($segment in $releaseVersion.Split('.')) {
    $parsed = 0
    if (-not [int]::TryParse($segment, [ref]$parsed)) { throw 'Release version component is too large.' }
}
if (-not $PreviousRef) {
    $previousTags = @(Invoke-ReleaseGit @('tag', '--merged', $releaseCommit, '--list', 'v*') |
        Where-Object { $_ -match '^v\d+\.\d+\.\d+$' -and [version]$_.Substring(1) -lt [version]$releaseVersion } |
        Sort-Object { [version]$_.Substring(1) } -Descending)
    if ($previousTags.Count) { $PreviousRef = $previousTags[0] }
}
$range = $releaseCommit
if ($PreviousRef) {
    $previousCommit = Invoke-ReleaseGit @('rev-parse', '--verify', '--end-of-options', "$PreviousRef^{commit}")
    Invoke-ReleaseGit @('merge-base', '--is-ancestor', $previousCommit, $releaseCommit) | Out-Null
    $range = "${previousCommit}..${releaseCommit}"
}

$notes = Get-Content -LiteralPath (Join-Path $repoRoot 'packaging/release-notes.json') -Raw -Encoding UTF8 |
    ConvertFrom-Json
$changes = @()
$usedCategories = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
foreach ($line in @(Invoke-ReleaseGit @('log', '--no-merges', '--reverse', '--format=%H%x09%s', $range))) {
    $parts = $line -split "`t", 2
    if ($parts.Count -ne 2 -or $parts[0] -notmatch '^[0-9a-f]{40}$') { throw 'Invalid Git log entry.' }
    if ($parts[1] -match '^Prepare NativeDNS .* release$') { continue }
    $text = [ordered]@{ en = $parts[1] }
    $override = $notes.PSObject.Properties[$parts[0]]
    if ($override) {
        if ($override.Value.en) { $text.en = [string]$override.Value.en }
        if ($override.Value.ru) { $text['ru'] = [string]$override.Value.ru }
    }
    foreach ($value in $text.Values) {
        if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 4096) { throw 'Invalid release note text.' }
    }
    $change = [ordered]@{ commit = $parts[0]; text = $text }
    if ($override -and $override.Value.category) {
        $change['category'] = [string]$override.Value.category
        $usedCategories.Add($change.category) | Out-Null
    }
    $changes += $change
}
if ($changes.Count -gt 256) { throw 'A release can contain at most 256 change entries.' }
$manifest = [ordered]@{
    schema_version = 1
    version = $releaseVersion
    release_url = "https://github.com/zmorok/NativeDNS/releases/tag/v$releaseVersion"
    whats_new = @($changes)
}
$categories = @()
foreach ($category in @($notes.categories)) {
    if (-not $category) { continue }
    if ($category.id -cnotmatch '^[a-z][a-z0-9_]{0,63}$' -or
        $categories.id -ccontains $category.id) { throw 'Invalid or duplicate release category.' }
    $text = [ordered]@{ en = [string]$category.text.en }
    if ($category.text.ru) { $text['ru'] = [string]$category.text.ru }
    foreach ($value in $text.Values) {
        if ([string]::IsNullOrWhiteSpace($value) -or $value.Length -gt 4096) {
            throw 'Invalid release category text.'
        }
    }
    $categories += [ordered]@{ id = [string]$category.id; text = $text }
}
if ($categories.Count -gt 16) { throw 'A release can contain at most 16 categories.' }
foreach ($id in $usedCategories) {
    if ($categories.id -cnotcontains $id) { throw "Unknown release category: $id" }
}
$categories = @($categories | Where-Object { $usedCategories.Contains($_.id) })
if ($categories.Count) { $manifest['categories'] = $categories }
$json = ConvertTo-Json -InputObject $manifest -Depth 6
$encoding = [System.Text.UTF8Encoding]::new($false)
if ($encoding.GetByteCount($json) -gt 524288) { throw 'Update manifest exceeds 512 KiB.' }
$destination = [System.IO.Path]::GetFullPath($OutputPath, $repoRoot)
[System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($destination)) | Out-Null
[System.IO.File]::WriteAllText($destination, $json + "`n", $encoding)
Write-Host "Prepared $destination for NativeDNS $releaseVersion ($($changes.Count) changes)."

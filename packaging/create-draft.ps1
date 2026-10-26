[CmdletBinding()]
param([Parameter(Mandatory)][string]$Tag, [Parameter(Mandatory)][string]$Directory)
$ErrorActionPreference = 'Stop'
if ($Tag -notmatch '^v\d+\.\d+\.\d+$') { throw 'Use a matching existing vMAJOR.MINOR.PATCH tag.' }
$directoryPath = (Resolve-Path -LiteralPath $Directory).Path
$release = Get-Content -LiteralPath (Join-Path $directoryPath 'release.json') -Raw | ConvertFrom-Json
if ($release.source_dirty -or "v$($release.version)" -ne $Tag) { throw 'Draft source must be clean and match its tag.' }
# Existing drafts can be refreshed only for the same verified source commit.
$existing = & gh release list --limit 1000 --json tagName | ConvertFrom-Json
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect existing releases.' }
$refreshDraft = [bool]($existing | Where-Object { $_.tagName -eq $Tag })
if ($refreshDraft) {
    $previous = & gh release view $Tag --json isDraft,assets | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or -not $previous.isDraft) { throw 'Published releases are immutable in this workflow.' }
    $previousDirectory = Join-Path $directoryPath ('previous-' + [guid]::NewGuid().ToString('N'))
    & gh release download $Tag --pattern release.json --dir $previousDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Cannot verify the existing draft source.' }
    $previousManifest = Get-Content -LiteralPath (Join-Path $previousDirectory 'release.json') -Raw | ConvertFrom-Json
    if ($previousManifest.source_commit -ne $release.source_commit) { throw 'The draft belongs to a different source commit.' }
}
$modeNote = if ($release.signing_mode -eq 'preview') {
    'Preview build: the EXE is unsigned. The MSIX uses the included self-signed development certificate and requires explicit certificate trust before installation. It is not a production-trusted or Store-certified installer.'
} else { 'Installers are signed using the configured production certificate. This is a sideload MSIX, not a Microsoft Store submission.' }
$notes = @"
Network Packet Sniffer $($release.version) for Windows x64.

Both installers bundle Python 3.14.7, Tcl/Tk, the application, a source archive, and third-party notices. Python, uv, Wireshark, and Npcap installation are not required. Capture uses built-in Pktmon and requires administrator privileges.

$modeNote

Original author: Faraz Hussain. Licensed under Apache-2.0; preserve LICENSE and NOTICE attribution when redistributing.

Source commit: $($release.source_commit)
Source snapshot SHA-256: $($release.source_tree_sha256)
Verify downloaded files against SHA256SUMS.txt and release.json. The source archive describes the exact build inputs.
"@
$notesFile = Join-Path $directoryPath 'release-notes.md'
[IO.File]::WriteAllText($notesFile, $notes, [Text.UTF8Encoding]::new($false))
$files = @($release.assets | ForEach-Object { Join-Path $directoryPath $_.name })
$files += @((Join-Path $directoryPath 'release.json'), (Join-Path $directoryPath 'SHA256SUMS.txt'))
if ($refreshDraft) {
    & gh release upload $Tag --clobber @files
    if ($LASTEXITCODE -ne 0) { throw 'Draft asset refresh failed.' }
    $newNames = @($files | ForEach-Object { Split-Path $_ -Leaf })
    foreach ($oldAsset in $previous.assets) {
        if ($oldAsset.name -notin $newNames) {
            & gh release delete-asset $Tag $oldAsset.name --yes
            if ($LASTEXITCODE -ne 0) { throw 'Obsolete draft asset cleanup failed.' }
        }
    }
    & gh release edit $Tag --draft=true --prerelease=true --title "Network Packet Sniffer $($release.version)" --notes-file $notesFile
} else {
    & gh release create $Tag --verify-tag --draft --prerelease --title "Network Packet Sniffer $($release.version)" --notes-file $notesFile @files
}
if ($LASTEXITCODE -ne 0) { throw 'Draft release creation/update failed.' }

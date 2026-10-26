[CmdletBinding()]
param([Parameter(Mandatory)][string]$Tag, [bool]$Prerelease = $true)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($Tag -notmatch '^v?\d+\.\d+\.\d+$') { throw 'Enter an existing vMAJOR.MINOR.PATCH release tag.' }
if (-not $Tag.StartsWith('v')) { $Tag = 'v' + $Tag }
$root = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $root
$directory = Join-Path $root ('packaged-releases/publish-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$release = & gh release view $Tag --json isDraft,tagName,targetCommitish | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $release.isDraft) { throw 'The selected release must exist and remain a draft.' }
& gh release download $Tag --dir $directory
if ($LASTEXITCODE -ne 0) { throw 'Release download failed.' }
$arguments = @('run', '--locked', '--no-dev', 'python', '-m', 'release_tools.release', 'verify', '--directory', $directory, '--tag', $Tag)
if (-not $Prerelease) { $arguments += '--stable' }
& uv @arguments
if ($LASTEXITCODE -ne 0) { throw 'Release checksum, signing-mode, or source verification failed.' }
$manifest = Get-Content -LiteralPath (Join-Path $directory 'release.json') -Raw | ConvertFrom-Json
if ($manifest.signing_mode -eq 'certificate') {
    $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
    $signtool = Get-ChildItem -LiteralPath $sdk -Directory | Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object { [version]$_.Name } -Descending | ForEach-Object { Join-Path $_.FullName 'x64/signtool.exe' } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if (-not $signtool) { throw 'Windows SDK SignTool is required to verify production signatures.' }
    foreach ($asset in ($manifest.assets | Where-Object { $_.name -match '\.(exe|msix)$' })) {
        & $signtool verify /pa /all (Join-Path $directory $asset.name)
        if ($LASTEXITCODE -ne 0) { throw 'Production signature verification failed.' }
    }
}
# Recheck the state immediately before publishing; never create tags implicitly.
$draft = & gh release view $Tag --json isDraft | ConvertFrom-Json
if ($LASTEXITCODE -ne 0 -or -not $draft.isDraft) { throw 'Draft state changed during verification.' }
$previewValue = if ($Prerelease) { 'true' } else { 'false' }
& gh release edit $Tag --draft=false "--prerelease=$previewValue"
if ($LASTEXITCODE -ne 0) { throw 'Release publication failed.' }

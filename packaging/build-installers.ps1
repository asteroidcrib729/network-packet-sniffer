[CmdletBinding()]
param(
    [ValidateSet('Preview', 'Certificate')][string]$SigningMode = 'Preview',
    [string]$Publisher = 'CN=Faraz Hussain',
    [string]$PfxPath,
    [string]$Uv = 'uv',
    [string]$Iscc
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $root

function Invoke-Native([string]$File, [string[]]$Parameters) {
    $command = Get-Command $File -CommandType Application -ErrorAction Stop
    $previousPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5 treats redirected native progress on stderr as
        # errors. Preserve the output and use the actual process exit status.
        $ErrorActionPreference = 'Continue'
        & $command.Source @Parameters 2>&1 | ForEach-Object { $_.ToString() }
        $nativeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($nativeExit -ne 0) { throw "$File failed ($nativeExit)." }
}
function Find-SdkTool([string]$Name) {
    $sdk = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits/10/bin'
    foreach ($directory in (Get-ChildItem -LiteralPath $sdk -Directory | Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } | Sort-Object { [version]$_.Name } -Descending)) {
        $candidate = Join-Path $directory.FullName "x64/$Name"
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    throw "$Name is required. Install the Windows SDK signing and MSIX packaging tools."
}
if ($SigningMode -eq 'Certificate' -and (-not $PfxPath -or -not $env:WINDOWS_SIGNING_PASSWORD)) {
    throw 'Certificate mode requires PfxPath and WINDOWS_SIGNING_PASSWORD. No preview fallback is allowed.'
}
if (-not $Iscc) { $Iscc = & (Join-Path $PSScriptRoot 'bootstrap-inno.ps1') }
$makeappx = Find-SdkTool 'makeappx.exe'
$signtool = Find-SdkTool 'signtool.exe'
Invoke-Native $Uv @('sync', '--locked', '--group', 'packaging', '--python', '3.14.7')
$python = Join-Path $root '.venv/Scripts/python.exe'
Invoke-Native $python @('-c', "import struct,sys; assert tuple(sys.version_info)==(3,14,7,'final',0); assert struct.calcsize('P')==8; assert sys.platform=='win32'")
$version = (& $python -c 'from release_tools.prepare import version; print(version())').Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot read project version.' }
$releaseRoot = Join-Path $root 'packaged-releases'
$build = Join-Path $releaseRoot ('.build/' + [guid]::NewGuid().ToString('N'))
$output = Join-Path $releaseRoot $version
$prepared = Join-Path $build 'prepared'
$assets = Join-Path $build 'Assets'
New-Item -ItemType Directory -Path $build, $output, $assets -Force | Out-Null
Invoke-Native $python @('-m', 'release_tools.prepare', $prepared)
$preparedInfoPath = Join-Path $prepared 'build-info.json'
$preparedInfo = Get-Content -LiteralPath $preparedInfoPath -Raw | ConvertFrom-Json
$uvVersion = (& $Uv --version).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot record the uv version.' }
$innoVersion = (& $Iscc --version).Trim()
if ($LASTEXITCODE -ne 0 -or $innoVersion -notmatch '^\d+\.\d+\.\d+$') { throw 'Cannot record the Inno Setup compiler version.' }
$preparedInfo.build_tools | Add-Member -NotePropertyName 'uv' -NotePropertyValue $uvVersion
$preparedInfo.build_tools | Add-Member -NotePropertyName 'inno_setup' -NotePropertyValue $innoVersion
[IO.File]::WriteAllText($preparedInfoPath, ($preparedInfo | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))

# Minimal generated package artwork: no image library or source image asset.
Add-Type -AssemblyName System.Drawing
foreach ($size in @(44, 50, 150, 256)) {
    $bitmap = [Drawing.Bitmap]::new($size, $size)
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([Drawing.ColorTranslator]::FromHtml('#101720'))
    $pen = [Drawing.Pen]::new([Drawing.ColorTranslator]::FromHtml('#4dd3df'), [single]($size / 24))
    $brush = [Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#e7f0ff'))
    $points = @(@(0.25, 0.65), @(0.5, 0.3), @(0.76, 0.65))
    try {
        foreach ($pair in @(@(0,1), @(1,2), @(0,2))) {
            $a, $b = $points[$pair[0]], $points[$pair[1]]
            $graphics.DrawLine($pen, [single]($a[0]*$size), [single]($a[1]*$size), [single]($b[0]*$size), [single]($b[1]*$size))
        }
        foreach ($point in $points) {
            $graphics.FillEllipse($brush, [single](($point[0]-0.08)*$size), [single](($point[1]-0.08)*$size), [single]($size*0.16), [single]($size*0.16))
        }
        $bitmap.Save((Join-Path $assets "Logo$size.png"), [Drawing.Imaging.ImageFormat]::Png)
    } finally { $pen.Dispose(); $brush.Dispose(); $graphics.Dispose(); $bitmap.Dispose() }
}
$icon = Join-Path $assets 'app.ico'
$png = [IO.File]::ReadAllBytes((Join-Path $assets 'Logo256.png'))
$writer = [IO.BinaryWriter]::new([IO.File]::Create($icon))
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]1)
    $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0)
    $writer.Write([uint16]1); $writer.Write([uint16]32); $writer.Write([uint32]$png.Length); $writer.Write([uint32]22); $writer.Write($png)
} finally { $writer.Dispose() }

$originalPath = $env:PATH
$originalConfig = $env:PYINSTALLER_CONFIG_DIR
$basePython = (& $python -c 'import sys; print(sys.base_prefix)').Trim()
if ($LASTEXITCODE -ne 0) { throw 'Cannot locate the exact Python runtime.' }
try {
    # Avoid unrelated PATH DLLs and keep the build cache inside ignored output.
    $env:PATH = @($basePython, (Join-Path $basePython 'DLLs'), (Join-Path $root '.venv/Scripts'), (Join-Path $env:SystemRoot 'System32'), $env:SystemRoot) -join ';'
    $env:PYINSTALLER_CONFIG_DIR = Join-Path $build 'pyinstaller-cache'
    Invoke-Native $python @(
    '-m', 'PyInstaller', '--noconfirm', '--clean', '--onedir', '--windowed', '--uac-admin', '--noupx',
    '--name', 'NetworkPacketSniffer', '--paths', (Join-Path $root 'src'),
    '--icon', $icon, '--version-file', (Join-Path $prepared 'version-resource.txt'),
    '--distpath', (Join-Path $build 'dist'), '--workpath', (Join-Path $build 'work'), '--specpath', $build,
    (Join-Path $root 'src/network_packet_sniffer/launcher.py')
    )
} finally { $env:PATH = $originalPath; $env:PYINSTALLER_CONFIG_DIR = $originalConfig }
$payload = Join-Path $build 'dist/NetworkPacketSniffer'
Invoke-Native $python @('-m', 'release_tools.inspect_bundle', (Join-Path $build 'work/NetworkPacketSniffer/Analysis-00.toc'), (Join-Path $payload 'NetworkPacketSniffer.exe'))
foreach ($name in @('LICENSE', 'NOTICE', 'README.md', 'THIRD_PARTY_NOTICES.txt', 'build-info.json', 'licenses', "NetworkPacketSniffer-$version-source.zip")) {
    Copy-Item -LiteralPath (Join-Path $prepared $name) -Destination $payload -Recurse -Force
}
$previewCertificate = $null
$certificateAsset = $null
try {
    if ($SigningMode -eq 'Preview') {
        $previewCertificate = New-SelfSignedCertificate -Type Custom -Subject $Publisher -CertStoreLocation 'Cert:\CurrentUser\My' -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 -KeyUsage DigitalSignature -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddYears(1) -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={critical}{text}ca=0')
        $certificateAsset = "NetworkPacketSniffer-$version-preview.cer"
        Export-Certificate -Cert $previewCertificate -FilePath (Join-Path $output $certificateAsset) | Out-Null
    }
    function Sign-File([string]$Path) {
        if ($SigningMode -eq 'Preview') {
            Invoke-Native $signtool @('sign', '/fd', 'SHA256', '/s', 'My', '/sha1', $previewCertificate.Thumbprint, $Path)
        } else {
            Invoke-Native $signtool @('sign', '/fd', 'SHA256', '/f', $PfxPath, '/p', $env:WINDOWS_SIGNING_PASSWORD, '/tr', 'https://timestamp.digicert.com', '/td', 'SHA256', $Path)
            Invoke-Native $signtool @('verify', '/pa', '/all', $Path)
        }
    }
    # Preview EXEs remain unsigned. The signed preview MSIX needs explicit trust.
    if ($SigningMode -eq 'Certificate') { Sign-File (Join-Path $payload 'NetworkPacketSniffer.exe') }
    Invoke-Native $Iscc @("/DAppVersion=$version", "/DPayloadDir=$payload", "/DReleaseDir=$output", "/DIconFile=$icon", (Join-Path $PSScriptRoot 'installer.iss'))
    $exe = Join-Path $output "NetworkPacketSniffer-$version-x64-setup.exe"
    if ($SigningMode -eq 'Certificate') { Sign-File $exe }

    $stage = Join-Path $build 'msix'
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Copy-Item -LiteralPath $payload -Destination (Join-Path $stage 'app') -Recurse
    Copy-Item -LiteralPath $assets -Destination (Join-Path $stage 'Assets') -Recurse
    $publisherXml = [Security.SecurityElement]::Escape($Publisher)
    $manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities" IgnorableNamespaces="uap rescap">
  <Identity Name="FarazHussain.NetworkPacketSniffer" Publisher="$publisherXml" Version="$version.0" ProcessorArchitecture="x64" />
  <Properties><DisplayName>Network Packet Sniffer</DisplayName><PublisherDisplayName>Faraz Hussain</PublisherDisplayName><Description>Live Windows packet summaries with attributed reputation alerts.</Description><Logo>Assets\Logo50.png</Logo></Properties>
  <Resources><Resource Language="en-us" /></Resources>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.26100.0" /></Dependencies>
  <Applications><Application Id="App" Executable="app\NetworkPacketSniffer.exe" EntryPoint="Windows.FullTrustApplication"><uap:VisualElements DisplayName="Network Packet Sniffer" Description="Live Windows packet summaries" BackgroundColor="#101720" Square150x150Logo="Assets\Logo150.png" Square44x44Logo="Assets\Logo44.png" /></Application></Applications>
  <Capabilities><rescap:Capability Name="runFullTrust" /><rescap:Capability Name="allowElevation" /></Capabilities>
</Package>
"@
    [IO.File]::WriteAllText((Join-Path $stage 'AppxManifest.xml'), $manifest, [Text.UTF8Encoding]::new($false))
    $msix = Join-Path $output "NetworkPacketSniffer-$version-x64.msix"
    Invoke-Native $makeappx @('pack', '/d', $stage, '/p', $msix, '/o')
    Sign-File $msix
    $signature = Get-AuthenticodeSignature -LiteralPath $msix
    if (-not $signature.SignerCertificate -or $signature.SignerCertificate.Subject -ne $Publisher) {
        throw 'The MSIX signer does not match the requested publisher.'
    }
    $signerThumbprint = $signature.SignerCertificate.Thumbprint
    Copy-Item -LiteralPath (Join-Path $prepared "NetworkPacketSniffer-$version-source.zip") -Destination $output -Force
    foreach ($name in @('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.txt')) { Copy-Item -LiteralPath (Join-Path $prepared $name) -Destination $output -Force }
    $info = Get-Content -LiteralPath (Join-Path $prepared 'build-info.json') -Raw | ConvertFrom-Json
    $assetNames = @("NetworkPacketSniffer-$version-x64-setup.exe", "NetworkPacketSniffer-$version-x64.msix", "NetworkPacketSniffer-$version-source.zip", 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.txt')
    if ($certificateAsset) { $assetNames += $certificateAsset }
    $records = foreach ($name in $assetNames) {
        $file = Get-Item -LiteralPath (Join-Path $output $name)
        [ordered]@{name=$name; size=$file.Length; sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()}
    }
    $release = [ordered]@{
        version=$version; python='3.14.7'; architecture='x64'; license='Apache-2.0'; publisher=$Publisher
        source_commit=$info.source_commit; source_dirty=$info.source_dirty; source_tree_sha256=$info.source_tree_sha256
        signing_mode=$SigningMode.ToLowerInvariant(); msix_signer_thumbprint=$signerThumbprint
        build_tools=$info.build_tools; tk=$info.tk; openssl=$info.openssl; zlib=$info.zlib
        windows_sdk=(Split-Path (Split-Path (Split-Path $makeappx -Parent) -Parent) -Leaf)
        assets=@($records)
    }
    [IO.File]::WriteAllText((Join-Path $output 'release.json'), ($release | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    $sums = foreach ($name in ($assetNames + 'release.json')) { '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $output $name)).Hash.ToLowerInvariant(), $name }
    [IO.File]::WriteAllLines((Join-Path $output 'SHA256SUMS.txt'), [string[]]$sums, [Text.UTF8Encoding]::new($false))
    Invoke-Native $python @('-m', 'release_tools.release', 'verify', '--directory', $output)
    Write-Output "Installers and checksums: $output"
} finally {
    if ($previewCertificate) { Remove-Item -LiteralPath ("Cert:\CurrentUser\My\" + $previewCertificate.Thumbprint) -DeleteKey -Force }
}

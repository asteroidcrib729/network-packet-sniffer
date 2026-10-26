[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$tools = Join-Path $root 'packaged-releases/.tools'
$compiler = Join-Path $tools 'InnoSetup/ISCC.exe'
if (-not (Test-Path -LiteralPath $compiler)) {
    New-Item -ItemType Directory -Path $tools -Force | Out-Null
    $installer = Join-Path $tools 'innosetup-7.1.0-x64.exe'
    Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/jrsoftware/issrc/releases/download/is-7_1_0/innosetup-7.1.0-x64.exe' -OutFile $installer
    $expected = '0362a383ed217d4c4239b5933866dd96d3eb2102737da92f80f6057a4b40df2f'
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $installer).Hash -ne $expected) {
        throw 'Inno Setup download checksum mismatch.'
    }
    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Pyrsys B.V.') {
        throw 'Inno Setup publisher verification failed.'
    }
    $destination = Join-Path $tools 'InnoSetup'
    $process = Start-Process -FilePath $installer -WindowStyle Hidden -Wait -PassThru -ArgumentList @(
        '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', '/NOICONS', ('/DIR="' + $destination + '"')
    )
    if ($process.ExitCode -ne 0) { throw "Inno Setup installation failed ($($process.ExitCode))." }
}
if (-not (Test-Path -LiteralPath $compiler)) { throw 'ISCC.exe was not installed.' }
Write-Output $compiler

[CmdletBinding()]
param([Parameter(Mandatory)][string]$ReleaseDirectory, [switch]$InstallExe)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $root
$releasePath = (Resolve-Path -LiteralPath $ReleaseDirectory).Path
$allowedRoot = [IO.Path]::GetFullPath((Join-Path $root 'packaged-releases'))
if (-not $releasePath.StartsWith($allowedRoot + [IO.Path]::DirectorySeparatorChar)) { throw 'Tests must use packaged-releases.' }
if ($InstallExe -and -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run EXE installation smoke tests from an administrator PowerShell so they can close the elevated test GUI.'
}
$python = Join-Path $root '.venv/Scripts/python.exe'
& $python -m release_tools.release verify --directory $releasePath
if ($LASTEXITCODE -ne 0) { throw 'Artifact verification failed.' }
$release = Get-Content -LiteralPath (Join-Path $releasePath 'release.json') -Raw | ConvertFrom-Json
$prefix = "NetworkPacketSniffer-$($release.version)"
$msix = Join-Path $releasePath "$prefix-x64.msix"
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($msix)
try {
    $names = @($archive.Entries | ForEach-Object { $_.FullName })
    foreach ($required in @('AppxManifest.xml', 'AppxSignature.p7x', 'app/NetworkPacketSniffer.exe', 'app/_internal/python314.dll', 'app/LICENSE', 'app/NOTICE', "app/$prefix-source.zip")) {
        if ($required -notin $names) { throw "MSIX is missing $required" }
    }
    if ($names | Where-Object { $_ -match '(^|/)(cache|logs|\.env|watchlist\.txt)(/|$)|\.(pfx|p12)$' }) { throw 'Private or obsolete data found in MSIX.' }
    $reader = [IO.StreamReader]::new($archive.GetEntry('AppxManifest.xml').Open())
    try { [xml]$manifest = $reader.ReadToEnd() } finally { $reader.Dispose() }
    if ($manifest.Package.Identity.Version -ne "$($release.version).0") { throw 'MSIX version mismatch.' }
    if ($manifest.Package.Capabilities.Capability.Name -notcontains 'allowElevation') { throw 'MSIX elevation capability missing.' }
    # Check the CMS signature without installing or trusting the development cert.
    Add-Type -AssemblyName System.Security
    $signatureStream = $archive.GetEntry('AppxSignature.p7x').Open()
    $signatureBytes = [IO.MemoryStream]::new()
    try { $signatureStream.CopyTo($signatureBytes); $signatureData = $signatureBytes.ToArray() }
    finally { $signatureStream.Dispose(); $signatureBytes.Dispose() }
    if ([Text.Encoding]::ASCII.GetString($signatureData, 0, 4) -ne 'PKCX') { throw 'Invalid MSIX signature header.' }
    $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
    $cms.Decode([byte[]]$signatureData[4..($signatureData.Length-1)])
    $cms.CheckSignature($true)
} finally { $archive.Dispose() }
$signer = Get-AuthenticodeSignature -LiteralPath $msix
if ($signer.SignerCertificate.Thumbprint -ne $release.msix_signer_thumbprint) { throw 'Unexpected MSIX signer.' }
$results = [ordered]@{version=$release.version; msix_structure=$true; msix_signer=$signer.SignerCertificate.Thumbprint; msix_trust_status=[string]$signer.Status; msix_installed=$false}
if ($InstallExe) {
    foreach ($registryRoot in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (Test-Path -LiteralPath (Join-Path $registryRoot 'FarazHussain.NetworkPacketSniffer_is1')) {
            throw 'An EXE installation already exists. Use a clean test machine to avoid replacing its uninstall registration.'
        }
    }
    Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class SnifferWindowTest {
    private delegate bool EnumCallback(IntPtr window, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumCallback callback, IntPtr state);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowText(IntPtr window, StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr window, uint message, IntPtr wparam, IntPtr lparam);
    public static IntPtr Find(int process) {
        IntPtr result = IntPtr.Zero;
        EnumWindows((window, state) => {
            uint owner; GetWindowThreadProcessId(window, out owner);
            var text = new StringBuilder(256); GetWindowText(window, text, text.Capacity);
            if (owner == process && text.ToString() == "Network Packet Sniffer") result = window;
            return true;
        }, IntPtr.Zero);
        return result;
    }
}
'@
    $install = Join-Path $allowedRoot ('.validation/' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $install -Force | Out-Null
    $setup = Join-Path $releasePath "$prefix-x64-setup.exe"
    $setupProcess = Start-Process -FilePath $setup -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/NOICONS', '/SP-', ('/DIR="' + $install + '"'))
    if ($setupProcess.ExitCode -ne 0) { throw 'EXE installation failed.' }
    $application = Join-Path $install 'NetworkPacketSniffer.exe'
    $process = $null
    try {
        if (-not (Test-Path -LiteralPath (Join-Path $install '_internal/python314.dll'))) { throw 'Bundled Python missing.' }
        if (-not (Test-Path -LiteralPath (Join-Path $install "$prefix-source.zip"))) { throw 'Bundled source missing.' }
        $process = Start-Process -FilePath $application -Verb RunAs -WindowStyle Hidden -PassThru
        $deadline = (Get-Date).AddSeconds(25)
        $window = [IntPtr]::Zero
        while ((Get-Date) -lt $deadline -and -not $process.HasExited) {
            $window = [SnifferWindowTest]::Find($process.Id)
            if ($window -ne [IntPtr]::Zero) { break }
            Start-Sleep -Milliseconds 100
        }
        if ($window -eq [IntPtr]::Zero) { throw 'Installed application did not create its Tk window.' }
        $results.exe_install = $true
        $results.windowed_gui = $true
        [SnifferWindowTest]::PostMessage($window, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        if (-not $process.WaitForExit(30000)) { throw 'Installed GUI did not close cleanly.' }
        if ($process.ExitCode -ne 0) { throw "Installed GUI exited with $($process.ExitCode)." }
        $results.gui_exit = $process.ExitCode
    } finally {
        if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force }
        $uninstaller = Join-Path $install 'unins000.exe'
        if (Test-Path -LiteralPath $uninstaller) {
            $uninstall = Start-Process -FilePath $uninstaller -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART')
            if ($uninstall.ExitCode -ne 0) { throw 'Test uninstall failed.' }
        }
    }
    if (Test-Path -LiteralPath $application) { throw 'Uninstall left the application executable behind.' }
    $results.exe_uninstall = $true
}
$resultPath = Join-Path $allowedRoot 'installer-test-results.json'
[IO.File]::WriteAllText($resultPath, ($results | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
$results | ConvertTo-Json

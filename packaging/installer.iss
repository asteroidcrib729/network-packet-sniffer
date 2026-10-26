#ifndef AppVersion
  #error AppVersion is required
#endif

[Setup]
AppId=FarazHussain.NetworkPacketSniffer
AppName=Network Packet Sniffer
AppVersion={#AppVersion}
AppPublisher=Faraz Hussain
AppPublisherURL=https://github.com/asteroidcrib729/network-packet-sniffer
AppSupportURL=https://github.com/asteroidcrib729/network-packet-sniffer/issues
AppCopyright=Copyright 2023-2026 Faraz Hussain
DefaultDirName={autopf}\Network Packet Sniffer
DefaultGroupName=Network Packet Sniffer
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\NetworkPacketSniffer.exe
ArchitecturesAllowed=x64os
ArchitecturesInstallIn64BitMode=x64os
MinVersion=10.0.19041
PrivilegesRequired=admin
WizardStyle=modern dark
LicenseFile={#PayloadDir}\LICENSE
InfoAfterFile={#PayloadDir}\NOTICE
SetupIconFile={#IconFile}
OutputDir={#ReleaseDir}
OutputBaseFilename=NetworkPacketSniffer-{#AppVersion}-x64-setup
Compression=lzma2
SolidCompression=yes
CloseApplications=yes
RestartApplications=no
Uninstallable=yes

[Files]
Source: "{#PayloadDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\Network Packet Sniffer"; Filename: "{app}\NetworkPacketSniffer.exe"

[Run]
Filename: "{app}\NetworkPacketSniffer.exe"; Description: "Open Network Packet Sniffer"; Flags: postinstall nowait skipifsilent

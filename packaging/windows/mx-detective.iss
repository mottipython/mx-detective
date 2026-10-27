; Per-user installer for mx-detective, built by the release workflow:
;   iscc /DAppVersion=1.2.0 /DExeDir=dist packaging\windows\mx-detective.iss
; Silent install for scripts and RMM tools: mx-detective-setup-windows-x86_64.exe /VERYSILENT /NORESTART

#ifndef AppVersion
  #error Pass /DAppVersion=X.Y.Z
#endif
#ifndef ExeDir
  #define ExeDir "dist"
#endif

[Setup]
AppId={{6F1D8E0C-3B7A-4C52-9E41-5D2A7B0C9A18}
AppName=MX Detective
AppVersion={#AppVersion}
AppPublisher=mottipython
AppPublisherURL=https://github.com/mottipython/mx-detective
AppSupportURL=https://github.com/mottipython/mx-detective/issues
DefaultDirName={autopf}\mx-detective
DefaultGroupName=MX Detective
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline
OutputDir=..\..\dist
OutputBaseFilename=mx-detective-setup-windows-x86_64
SetupIconFile=mx-detective.ico
UninstallDisplayIcon={app}\mx-detective.exe
UninstallDisplayName=MX Detective
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE
WizardStyle=modern
CloseApplications=yes

[Tasks]
Name: addtopath; Description: "Add mx-detective to my PATH (for PowerShell and cmd)"
Name: desktopicon; Description: "Create a desktop shortcut"; Flags: unchecked

[Files]
Source: "{#ExeDir}\mx-detective-windows-x86_64.exe"; DestName: "mx-detective.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "mx-detective.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\MX Detective"; Filename: "{app}\mx-detective.exe"; Parameters: "--gui"; IconFilename: "{app}\mx-detective.ico"
Name: "{autodesktop}\MX Detective"; Filename: "{app}\mx-detective.exe"; Parameters: "--gui"; IconFilename: "{app}\mx-detective.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Tasks: addtopath; Check: NeedsPath

[Run]
Filename: "{app}\mx-detective.exe"; Parameters: "--gui"; Description: "Open MX Detective"; Flags: nowait postinstall skipifsilent

[Code]
function NeedsPath: Boolean;
var
  Path: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', Path) then Path := '';
  Result := Pos(';' + Lowercase(ExpandConstant('{app}')) + ';', ';' + Lowercase(Path) + ';') = 0;
end;

procedure CurUninstallStepChanged(Step: TUninstallStep);
var
  Path, Dir: string;
  P: Integer;
begin
  if (Step <> usPostUninstall) or not RegQueryStringValue(HKCU, 'Environment', 'Path', Path) then Exit;
  Dir := ExpandConstant('{app}');
  Path := ';' + Path + ';';
  P := Pos(';' + Lowercase(Dir) + ';', Lowercase(Path));
  if P = 0 then Exit;
  Delete(Path, P, Length(Dir) + 1);
  Path := Copy(Path, 2, Length(Path) - 2);
  RegWriteExpandStringValue(HKCU, 'Environment', 'Path', Path);
end;

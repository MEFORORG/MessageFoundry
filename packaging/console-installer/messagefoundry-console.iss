; MessageFoundry admin console — Windows installer (Inno Setup) — ADR 0032 Phase B, BACKLOG #39.
;
; Wraps the PyInstaller --onedir output (dist/messagefoundry-console/) into a single setup .exe that:
;   - installs PER-USER by default (no elevation), with an opt-in all-users (per-machine) mode,
;   - creates Desktop + Start-Menu shortcuts to the frozen messagefoundry-console.exe (same app.ico),
;   - registers a real Add/Remove Programs uninstall entry,
;   - bundles the LGPL/GPL/AGPL license texts + the THIRD-PARTY-NOTICES written offer (LGPL compliance),
;   - injects AppVersion from __version__ (single-sourced; never hard-coded here).
;
; Build (from the repo root, AFTER PyInstaller produced dist/messagefoundry-console/):
;   ISCC.exe /DAppVersion=0.2.10 packaging\console-installer\messagefoundry-console.iss
; AppVersion comes from messagefoundry/__init__.py __version__ (the CI leg reads it and passes
; /DAppVersion=...); a local build that omits the define falls back to 0.0.0-dev so ISCC still runs.
;
; Authenticode signing of THIS installer .exe (and the inner messagefoundry-console.exe) is done
; OUTSIDE Inno Setup by signtool in the CI leg — gated on the signing cert secret being present, so an
; unsigned installer is still produced until the owner provisions the cert (ADR 0032 §(c)).

#ifndef AppVersion
  #define AppVersion "0.0.0-dev"
#endif

#define AppName "MessageFoundry Console"
#define AppPublisher "MessageFoundry Organization"
#define AppExeName "messagefoundry-console.exe"
#define AppURL "https://messagefoundry.org/"

; Repo root relative to THIS .iss (packaging\console-installer\ -> ..\..). SourceDir anchors every
; relative [Files] Source path below at the repo root so the script is invariant to ISCC's CWD.
#define RepoRoot "..\.."

[Setup]
; A STABLE AppId GUID is what binds upgrades + the uninstall entry across versions — never regenerate it.
AppId={{8F3C6A21-7B4E-4D9A-9C2F-1E5A0B7D6C84}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
VersionInfoVersion={#AppVersion}

; PER-USER by default (no UAC elevation, matching Phase A's shortcut posture). The user may opt into a
; machine-wide install (writes Program Files + All-Users shortcuts, prompts for elevation) by running
; the setup with /ALLUSERS, or via the install-scope dialog Inno shows when both are allowed.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=commandline dialog

; {autopf} resolves to Program Files for an all-users install and to the per-user local app dir for a
; per-user install, so one DefaultDirName serves both scopes.
DefaultDirName={autopf}\MessageFoundry Console
DefaultGroupName=MessageFoundry
DisableProgramGroupPage=yes
DisableDirPage=auto

; The bundled console is Windows-x64 only (the PyInstaller freeze + Qt6 DLLs are x64). Refuse to run on
; non-x64 / 32-bit Windows rather than install a binary that cannot launch.
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; Output: a single setup exe named with the injected version, written to dist/ alongside the freeze.
OutputDir={#RepoRoot}\dist
OutputBaseFilename=messagefoundry-console-setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#AppName}
; The Add/Remove Programs icon == the app badge (extracted from the installed exe).
UninstallDisplayIcon={app}\{#AppExeName}

; Show the combined license on a wizard page so the user sees the AGPL (app) + LGPL/GPL (Qt) terms
; before installing. Inno Setup's LicenseFile control renders ONLY plain text or RTF (NOT Markdown), so
; the wizard page points at the plain-text THIRD-PARTY-NOTICES.txt — pointing it at the .md would show
; raw `#`/`**`/`<...>` markup on the one screen end users actually read. The same obligations also ship
; as files NEXT TO the binary (the .md authoritative copy + the .txt + the full license texts under
; licenses\, see [Files]) so the LGPL source-offer travels with the binary, not just on the wizard page.
LicenseFile={#RepoRoot}\packaging\console-installer\THIRD-PARTY-NOTICES.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
; Desktop shortcut is opt-in via the standard "Create a desktop shortcut" checkbox (checked by default
; for an app launcher). The Start-Menu shortcut is always created (see [Icons]).
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: checkedonce

[Files]
; The entire PyInstaller --onedir output (the frozen exe + Qt6 DLLs + plugins + the bundled
; app.ico/auth data). recursesubdirs+createallsubdirs preserves the Qt plugin tree
; (platforms\qwindows.dll, styles\, etc.) the windowed app needs at launch.
Source: "{#RepoRoot}\dist\messagefoundry-console\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

; LGPL/GPL/AGPL compliance: ship the written offer + every relevant license text NEXT TO the binary so
; the obligation travels with the installed app, not just the wheel (ADR 0032 §(e), AC-B7). The three
; license texts live under packaging/console-installer/licenses/ (vendored alongside this script).
Source: "{#RepoRoot}\packaging\console-installer\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoRoot}\packaging\console-installer\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#RepoRoot}\packaging\console-installer\licenses\*"; DestDir: "{app}\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs
; The project's own AGPL text + attribution NOTICE (already shipped in the wheel) ride along too.
Source: "{#RepoRoot}\LICENSE"; DestDir: "{app}\licenses"; DestName: "LICENSE-MessageFoundry-AGPL-3.0.txt"; Flags: ignoreversion
Source: "{#RepoRoot}\NOTICE"; DestDir: "{app}\licenses"; DestName: "NOTICE-MessageFoundry.txt"; Flags: ignoreversion

[Icons]
; Start-Menu shortcut (always) + optional Desktop shortcut (the desktopicon task). The icon is the
; frozen exe's own embedded badge (set via the PyInstaller spec's icon=app.ico), so IconFilename can
; just point at the exe.
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Comment: "Open the MessageFoundry admin console"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Comment: "Open the MessageFoundry admin console"; Tasks: desktopicon

[Run]
; Offer to launch the console at the end of setup (no /url -> defaults to the local engine at
; 127.0.0.1:8765 and prompts for sign-in, exactly like the shortcut).
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; The frozen Qt app writes nothing into {app} at runtime (settings live in the registry/keyring), so
; the standard uninstall removes everything it installed; this line sweeps the install dir if empty.
Type: dirifempty; Name: "{app}"

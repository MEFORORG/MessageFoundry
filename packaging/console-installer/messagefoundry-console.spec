# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
#
# PyInstaller spec for the frozen, zero-Python MessageFoundry admin console (ADR 0032 Phase B,
# BACKLOG #39). Produces a WINDOWED, single-FOLDER (--onedir) PySide6 application that the Inno Setup
# script (messagefoundry-console.iss) wraps into an installer.
#
# This is a PyInstaller spec file: PyInstaller exec()s it with `Analysis`, `PYZ`, `EXE`, `COLLECT`,
# `SPLASH`, etc. already in the namespace, so it is NOT a normally-importable module (no SPDX-relevant
# imports of its own — ruff/mypy do not see it; it carries the SPDX header by project convention).
#
# Build:   pyinstaller --noconfirm --clean packaging/console-installer/messagefoundry-console.spec
# Output:  dist/messagefoundry-console/  (a folder containing messagefoundry-console.exe + Qt DLLs)
#
# Why --onedir (not --onefile): the loose Qt6 DLLs stay discrete, user-replaceable files in the
# install folder, which is what satisfies the PySide6/Qt LGPL-3.0 *relink* expectation (ADR 0032 §(e),
# THIRD-PARTY-NOTICES.md). --onefile would bury Qt in a self-extracting temp dir (slower start, more
# AV heuristic noise, and a worse relink story). DO NOT switch this to --onefile.

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files

# ---------------------------------------------------------------------------------------------------
# Resolve the console package's shipped resources (the app.ico badge) so the freeze carries the exact
# bytes the wheel ships. SPECPATH is the dir holding this .spec (packaging/console-installer/); the
# repo root is two levels up. `messagefoundry/console/resources/app.ico` is the multi-resolution badge
# `_app_icon()` loads at runtime (console/__main__.py) AND the Windows exe icon below.
# ---------------------------------------------------------------------------------------------------
REPO_ROOT = Path(SPECPATH).resolve().parents[1]  # noqa: F821 (SPECPATH injected by PyInstaller)
APP_ICON = REPO_ROOT / "messagefoundry" / "console" / "resources" / "app.ico"
LAUNCHER = REPO_ROOT / "packaging" / "console-installer" / "console_launcher.py"

if not APP_ICON.is_file():
    raise SystemExit(f"app.ico not found at {APP_ICON} — the console badge must exist before freezing")

# Bundle the console's shipped resource trees so every runtime asset the wheel carries resolves inside
# the freeze (AC-B5). collect_data_files walks the package's non-.py data files; its `includes` is a
# WHITELIST, so each tree the console reads at runtime must be named explicitly:
#   - resources/*  -> app.ico + app.svg, loaded by _app_icon() via
#                     importlib.resources.files('messagefoundry.console')/'resources'/'app.ico'.
#   - icons/*      -> the left-nav line icons + the header logo-lockup.svg, loaded by console/shell.py
#                     via Path(__file__).parent/'icons'/... (QIcon per nav item + QSvgWidget for the
#                     brand lockup). These live OUTSIDE resources/, so the resources/* glob misses them;
#                     omitting this drops every nav icon + the header brand in the frozen build (the wheel
#                     ships them, so the breakage is frozen-only and the app.ico-only smoke would not catch
#                     it — hence both are collected here).
datas = collect_data_files("messagefoundry.console", includes=["resources/*", "icons/*"])

# ---------------------------------------------------------------------------------------------------
# hiddenimports: the console resolves a few back-ends lazily (keyring's Windows backend, the TLS
# truststore) that PyInstaller's static analysis can miss. Name them so the freeze includes them.
#   - keyring.backends.Windows  -> the OS-keyring token cache (_load_token/_save_token rely on the
#                                   Windows Credential Manager backend; keyring discovers it via entry
#                                   points, which PyInstaller does not follow without the hook below).
#   - win32* (pywin32)          -> keyring's Windows backend imports win32cred at runtime.
# PySide6's own hook already pulls the Qt plugins (platforms/qwindows.dll, styles) + shiboken6, so the
# windows platform plugin does NOT need to be hidden-imported here.
# ---------------------------------------------------------------------------------------------------
hiddenimports = [
    "keyring.backends.Windows",
    "win32ctypes.core",  # keyring>=24 uses pywin32-ctypes (win32ctypes), not classic pywin32
]

# ---------------------------------------------------------------------------------------------------
# excludes: slim the ~150 MB bundle by dropping Qt modules and engine-only deps the console NEVER
# imports. The console is API-only (CLAUDE.md §10): it imports PySide6 (widgets/gui/core), httpx,
# keyring, truststore, and the PURE parsing/ + api/ pydantic models — and nothing from pipeline/,
# transports/, store/, config-runtime, or the heavy optional connector stacks.
#
# AC-B6 (ADR 0032): QtWebEngine, QtMultimedia, and Qt3D MUST be excluded. The rest are belt-and-braces
# trims of large Qt subsystems the console's widgets never touch.
# ---------------------------------------------------------------------------------------------------
excludes = [
    # --- Qt subsystems the console never uses (AC-B6 names the first three explicitly) ---
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebEngineQuick",
    "PySide6.QtWebChannel",
    "PySide6.QtWebSockets",
    "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets",
    "PySide6.Qt3DCore",
    "PySide6.Qt3DRender",
    "PySide6.Qt3DInput",
    "PySide6.Qt3DLogic",
    "PySide6.Qt3DAnimation",
    "PySide6.Qt3DExtras",
    "PySide6.QtCharts",
    "PySide6.QtDataVisualization",
    "PySide6.QtGraphs",
    "PySide6.QtQuick",
    "PySide6.QtQuick3D",
    "PySide6.QtQuickWidgets",
    "PySide6.QtQml",
    "PySide6.QtPdf",
    "PySide6.QtPdfWidgets",
    "PySide6.QtBluetooth",
    "PySide6.QtNfc",
    "PySide6.QtPositioning",
    "PySide6.QtLocation",
    "PySide6.QtSensors",
    "PySide6.QtSerialPort",
    "PySide6.QtSerialBus",
    "PySide6.QtTest",
    "PySide6.QtDesigner",
    "PySide6.QtHelp",
    "PySide6.QtUiTools",
    "PySide6.QtOpenGL",
    "PySide6.QtOpenGLWidgets",
    # --- Engine-only / heavy deps the console never imports (API-only client, CLAUDE.md §10) ---
    "fastapi",
    "starlette",
    "uvicorn",
    "aiosqlite",
    "aioodbc",
    "asyncpg",
    "hl7apy",
    "cryptography",
    "argon2",
    "ldap3",
    "pyspnego",
    "pynetdicom",
    "pydicom",
    "lxml",
    "xmlschema",
    "signxml",
    "pyx12",
    "fhir",
    "fhirpathpy",
    "paramiko",
    "opentelemetry",
    "prometheus_client",
    # Scientific stacks PySide6's optional addons can drag — the console uses none of them.
    "numpy",
    "scipy",
    "matplotlib",
    "PIL",
    "tkinter",
]


block_cipher = None

a = Analysis(  # noqa: F821 (Analysis injected by PyInstaller)
    [str(LAUNCHER)],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)  # noqa: F821 (PYZ injected by PyInstaller)

exe = EXE(  # noqa: F821 (EXE injected by PyInstaller)
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,  # --onedir: binaries are collected by COLLECT below, not embedded here
    name="messagefoundry-console",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX-packed DLLs trip AV heuristics + can corrupt Qt plugins; leave Qt DLLs intact
    console=False,  # WINDOWED: no flashing console window (matches Phase A's pythonw gui-script)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,  # Windows Authenticode is applied post-build by signtool in CI, not here
    entitlements_file=None,
    icon=str(APP_ICON),  # the exe's file icon == the window/taskbar/shortcut badge
)

coll = COLLECT(  # noqa: F821 (COLLECT injected by PyInstaller)
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="messagefoundry-console",  # -> dist/messagefoundry-console/ (the --onedir output folder)
)

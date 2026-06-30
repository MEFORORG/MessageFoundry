# MessageFoundry Console — Third-Party Notices & License Information

This document accompanies the **frozen, standalone MessageFoundry admin console** installer (ADR 0032
Phase B). It states the licensing of the bundled third-party components and the obligations that travel
with this binary. It is installed next to the application (`<install-dir>\THIRD-PARTY-NOTICES.md`) and
shown on the installer's license page, so the obligations travel with the binary — not just with the
source distribution.

---

## 1. The MessageFoundry Console (this application)

- **License:** GNU Affero General Public License, version 3 or later (**AGPL-3.0-or-later**).
- **Copyright:** (C) 2026 MessageFoundry Organization and contributors.
- **Corresponding source:** the complete source of the console (and the rest of MessageFoundry) is
  published at <https://github.com/MEFORORG/MessageFoundry>. The full AGPL-3.0 text is bundled with this
  installer at `licenses\LICENSE-MessageFoundry-AGPL-3.0.txt`, and the project's attribution NOTICE at
  `licenses\NOTICE-MessageFoundry.txt`.
- **AGPL §13 (network use):** this installer ships the console **client** only. The engine — the
  network-accessible service AGPL §13 concerns — is **not** part of this installer (it is deployed
  separately as a Windows service; see `docs/SERVICE.md`). Running this desktop client does not itself
  trigger a §13 source-offer beyond what the published source already satisfies.

## 2. Qt 6 via PySide6 (the GUI toolkit) — LGPL-3.0

The console's graphical interface is built with **PySide6** (the official Qt for Python bindings) and
links dynamically against the **Qt 6** libraries. These are bundled, as loose DLLs, inside this
installer's application folder.

- **Component:** PySide6 + the Qt 6 runtime libraries (and the `shiboken6` binding runtime).
- **Pinned version (this build): PySide6 / Qt `6.11.1`** (`shiboken6 6.11.1`). This is the version
  pinned in the project's hash-locked `requirements.lock`; keep this line in lockstep with that pin —
  the written offer below is accurate only for the Qt version actually bundled.
- **License of Qt-via-PySide6 as used here: GNU Lesser General Public License, version 3
  (LGPL-3.0).** PySide6 and the Qt Essentials/Add-ons modules used by the console are available under
  the LGPL-3.0; MessageFoundry uses them under that license (not under the Qt Company commercial
  license and not under GPL). The LGPL-3.0 is a set of additional permissions layered on top of the
  GPL-3.0, so **both** the LGPL-3.0 and the GPL-3.0 texts apply; both are bundled (see §4).

### 2.1 Your LGPL rights for this bundled Qt — relinking

The LGPL-3.0 guarantees you the ability to **modify the Qt library and relink this application against
your modified or replacement copy.** This build is structured to make that practical:

- The Qt 6 DLLs and the PySide6 / shiboken6 binaries are shipped as **discrete, replaceable files** in
  the installation folder (the freeze uses PyInstaller's single-**folder** layout precisely so the Qt
  DLLs are not buried in a single-file self-extractor and not statically linked). You may replace a
  bundled Qt DLL with your own **compatible** build (same Qt 6 major/minor ABI) and the application will
  load it.
- The application is **dynamically linked** to Qt; Qt is **not** statically linked into the executable.

### 2.2 Obtaining the corresponding source for Qt (written offer)

The **complete corresponding source code** for the bundled Qt 6 / PySide6 libraries, version
**6.11.1**, corresponding to the binaries in this installer, is available as follows:

- **PySide6 / shiboken6 source:** the Qt for Python project,
  <https://download.qt.io/official_releases/QtForPython/> (the `pyside-setup` source archive for the
  matching version) and the upstream repository <https://code.qt.io/cgit/pyside/pyside-setup.git/>.
- **Qt 6 source:** the Qt Project, <https://download.qt.io/archive/qt/> (the matching `6.11` source
  release) and <https://code.qt.io/cgit/qt/qt5.git/> (the Qt 6 super-module).

**Written offer.** For a period of three (3) years from your receipt of this installer, the
MessageFoundry Organization will, on request, provide the complete corresponding source code for the
bundled LGPL-3.0 Qt / PySide6 libraries (version 6.11.1) on a physical medium for a charge no more than
the cost of physically performing the distribution, or will direct you to the upstream download
locations above (which are the same sources from which this build was assembled). Direct requests via
the project's repository: <https://github.com/MEFORORG/MessageFoundry>.

## 3. Other bundled runtime components

The freeze also bundles a small number of permissively-licensed Python runtime dependencies the console
uses to reach the engine and cache its sign-in token. None impose copyleft obligations on this binary:

- **httpx** — the HTTP client to the engine API (BSD-3-Clause).
- **keyring** + **pywin32-ctypes / win32ctypes** — OS-keyring (Windows Credential Manager) token cache
  (MIT / BSD-style).
- **truststore** — verifies the engine's TLS certificate against the OS trust store (MIT).
- **certifi / idna / sniffio / h11 / anyio / httpcore** — httpx's transitive stack (MPL-2.0 for certifi;
  BSD/MIT/ISC for the rest).
- **pydantic** + **pydantic-core** — the API response models the console deserializes (MIT).
- the **Python 3.14 runtime** itself, embedded by PyInstaller (PSF License).

These are listed for transparency; their full license texts ship in their respective upstream
distributions and in the project's generated CycloneDX SBOM (attached to each release). Authoritative,
per-component licensing for the entire dependency tree is the SBOM; this section is a human-readable
summary of what the *frozen console* carries.

## 4. Bundled license texts

The following full license texts are installed under `<install-dir>\licenses\`:

- `LGPL-3.0.txt` — GNU Lesser General Public License v3.0 (applies to Qt-via-PySide6, §2).
- `GPL-3.0.txt` — GNU General Public License v3.0 (the base license the LGPL-3.0 extends, §2).
- `LICENSE-MessageFoundry-AGPL-3.0.txt` — the console's own AGPL-3.0-or-later text (§1).
- `NOTICE-MessageFoundry.txt` — the project's attribution NOTICE (§1).

---

*Maintenance note (do not let this drift): when the bundled PySide6/Qt pin changes in
`requirements.lock`, update the version in §2 and the written offer in §2.2 in the same change. This
NOTICE is accurate only for the Qt version actually frozen into the installer.*

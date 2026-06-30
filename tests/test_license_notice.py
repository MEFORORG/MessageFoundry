# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""LGPL-compliance regression tests for the frozen console installer (ADR 0032 Phase B, AC-B7).

The frozen console bundles LGPL-3.0 Qt (via PySide6) inside an AGPL-3.0 application. The installer must
ship the LGPL-3.0 + GPL-3.0 + AGPL-3.0-or-later license texts and a NOTICE that names PySide6/Qt as
LGPL with a written offer for the Qt corresponding source. These assert the static packaging assets;
the live `[Files]` install of them is verified on the Windows runner / by the manual checklist.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_PKG_DIR = _REPO_ROOT / "packaging" / "console-installer"
_NOTICES = _PKG_DIR / "THIRD-PARTY-NOTICES.md"
_LICENSES = _PKG_DIR / "licenses"
_ISS = _PKG_DIR / "messagefoundry-console.iss"


def test_installer_ships_lgpl_gpl_agpl_and_written_offer() -> None:
    """AC-B7: the LGPL-3.0, GPL-3.0, and AGPL-3.0-or-later texts are bundled, and the NOTICE names
    PySide6/Qt as LGPL with a written offer for the Qt corresponding source."""
    # 1. The three license texts exist (LGPL + GPL bundled here; AGPL is the repo LICENSE the .iss adds).
    lgpl = (_LICENSES / "LGPL-3.0.txt").read_text(encoding="utf-8")
    gpl = (_LICENSES / "GPL-3.0.txt").read_text(encoding="utf-8")
    assert "GNU LESSER GENERAL PUBLIC LICENSE" in lgpl
    assert "GNU GENERAL PUBLIC LICENSE" in gpl
    assert (
        (_REPO_ROOT / "LICENSE")
        .read_text(encoding="utf-8")
        .startswith("                    GNU AFFERO GENERAL PUBLIC LICENSE")
    ), "repo LICENSE is not the AGPL-3.0 text the installer bundles as the app license"

    # 2. The NOTICE names PySide6/Qt as LGPL and carries a written offer + a pinned version.
    notices = _NOTICES.read_text(encoding="utf-8")
    assert "PySide6" in notices and "Qt" in notices
    assert "LGPL-3.0" in notices, "NOTICE does not identify Qt-via-PySide6 as LGPL-3.0"
    assert "AGPL-3.0-or-later" in notices, "NOTICE does not state the app's own AGPL license"
    assert "Written offer" in notices or "written offer" in notices, "NOTICE has no written offer"
    assert "6.11.1" in notices, "NOTICE does not pin the bundled PySide6/Qt version"
    # The relinking ability is the surviving LGPL obligation for a frozen binary — it must be stated.
    assert "relink" in notices.lower(), "NOTICE does not state the LGPL relinking ability"


def test_iss_bundles_the_license_texts() -> None:
    """The .iss installs the NOTICE + the licenses/ dir + the repo AGPL LICENSE/NOTICE next to the app,
    and shows the combined license on a wizard page (so the obligation travels with the binary)."""
    iss = _ISS.read_text(encoding="utf-8")
    assert "THIRD-PARTY-NOTICES.md" in iss, ".iss does not bundle the third-party notices"
    assert "licenses\\*" in iss, ".iss does not bundle the licenses/ dir"
    assert "LICENSE" in iss and "NOTICE" in iss, ".iss does not bundle the repo AGPL LICENSE/NOTICE"
    assert "LicenseFile=" in iss, ".iss has no license wizard page"


def test_notice_version_matches_locked_pyside6_pin() -> None:
    """Belt-and-braces: the PySide6/Qt version the NOTICE pins must match the requirements.lock pin, so
    the LGPL written offer can never silently drift from the version actually frozen."""
    lock = _REPO_ROOT / "requirements.lock"
    if not lock.exists():  # installed layout without the lock alongside — nothing to compare
        import pytest

        pytest.skip("requirements.lock not alongside the tests")
    locked = lock.read_text(encoding="utf-8")
    # Find the pinned pyside6 version (e.g. `pyside6==6.11.1 \`).
    import re

    m = re.search(r"^pyside6==([0-9][^\s\\]*)", locked, re.MULTILINE)
    assert m is not None, "could not find the pyside6 pin in requirements.lock"
    pinned = m.group(1)
    notices = _NOTICES.read_text(encoding="utf-8")
    assert pinned in notices, (
        f"THIRD-PARTY-NOTICES pins a different PySide6 version than requirements.lock ({pinned}); "
        "update the NOTICE written offer to the frozen version"
    )

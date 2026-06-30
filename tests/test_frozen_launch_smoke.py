# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Frozen-exe launch smoke tests for the console installer (ADR 0032 Phase B, AC-B4 / AC-B5).

These exercise the ACTUAL frozen `messagefoundry-console.exe` and so run ONLY on the Windows CI leg
(the `release-console-installer` job in `.github/workflows/release.yml`) after PyInstaller has produced
the bundle — a frozen GUI exe cannot be exercised in the headless pytest suite. They are skipped
everywhere the freeze is absent (local dev, the normal CI matrix), which is the documented design: the
static workflow/spec/license assertions in test_release_console_installer.py / test_license_notice.py
cover what the headless suite can prove; THESE close the runtime-launch gap on the runner.

The CI leg points the suite at the freeze via MEFOR_FROZEN_CONSOLE_DIR=dist/messagefoundry-console.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

_FROZEN_DIR_ENV = "MEFOR_FROZEN_CONSOLE_DIR"


def _frozen_exe() -> Path:
    """Resolve the frozen console exe, or skip when no freeze is present (off the Windows CI leg)."""
    raw = os.environ.get(_FROZEN_DIR_ENV)
    if not raw:
        pytest.skip(
            f"{_FROZEN_DIR_ENV} unset — frozen-exe smoke runs only on the Windows installer CI leg"
        )
    exe = Path(raw) / "messagefoundry-console.exe"
    if not exe.is_file():
        pytest.skip(f"frozen console exe not found at {exe}")
    return exe


def test_frozen_exe_opens_offline() -> None:
    """AC-B4: launched with the engine unreachable, the frozen exe opens its window and surfaces the
    connection error rather than crashing.

    With `--url` pointed at a closed port, `_authenticate()` treats the unreachable probe as "proceed"
    (ApiError.status is None -> the sign-in dialog is skipped), the window opens, and `client.health()`
    fails into `window._show_error("Cannot reach engine: …")`. We assert the process STAYS UP (a crash
    on the offline path would exit non-zero immediately) and then terminate it — there is no headless
    way to read the GUI, so liveness is the proxy for "opened without crashing".
    """
    exe = _frozen_exe()
    # An almost-certainly-closed loopback port so the health probe fails fast but the window still opens.
    proc = subprocess.Popen(  # noqa: S603 (trusted, fixed argv — the frozen exe we just built)
        [str(exe), "--url", "http://127.0.0.1:1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        # If the offline path crashed, the process would have exited within a couple of seconds with a
        # non-zero code. Give the Qt app time to start and run its health probe, then assert it is alive.
        time.sleep(8)
        assert proc.poll() is None, (
            "frozen console exited on the offline launch path (it must open the window and show the "
            f"connection error instead): returncode={proc.returncode}"
        )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_frozen_exe_loads_app_icon() -> None:
    """AC-B5: the freeze layout carries the bundled app.ico so `_app_icon()` resolves it.

    The freeze must place `messagefoundry/console/resources/app.ico` where
    `importlib.resources.files('messagefoundry.console')/'resources'/'app.ico'` finds it. We assert the
    .ico is present in the bundle's `_internal` data tree (PyInstaller's --onedir data root) so the
    icon-resolution path the window relies on cannot silently lose the badge.
    """
    exe = _frozen_exe()
    bundle = exe.parent
    # PyInstaller >=6 puts collected data under <bundle>/_internal/; older layouts put it alongside.
    candidates = list(bundle.rglob("app.ico"))
    matches = [
        p for p in candidates if p.parent.name == "resources" and "console" in str(p).lower()
    ]
    assert matches, (
        "the bundled app.ico is not in the freeze's messagefoundry/console/resources tree — "
        "_app_icon() would lose the badge in the frozen layout"
    )


def test_frozen_exe_bundles_nav_icons() -> None:
    """AC-B5 (extended): the freeze carries the console's `icons/` tree (left-nav line icons + the header
    logo-lockup) that `console/shell.py` loads from `Path(__file__).parent/'icons'`.

    The `collect_data_files(..., includes=[...])` whitelist must name `icons/*` as well as `resources/*`;
    if it only collected `resources/*`, every nav icon would render blank and the header would fall back
    to the plain-text wordmark in the frozen build (the wheel ships them, so the breakage is frozen-only
    and the app.ico-only check above would not catch it). Assert a representative nav SVG + the lockup
    land in the freeze's `messagefoundry/console/icons` tree so this cannot regress.
    """
    exe = _frozen_exe()
    bundle = exe.parent
    for asset in ("connections.svg", "logo-lockup.svg"):
        hits = [
            p
            for p in bundle.rglob(asset)
            if p.parent.name == "icons" and "console" in str(p).lower()
        ]
        assert hits, (
            f"{asset} is not in the freeze's messagefoundry/console/icons tree — the spec's "
            "collect_data_files must include icons/* or the frozen console loses its nav icons/brand"
        )

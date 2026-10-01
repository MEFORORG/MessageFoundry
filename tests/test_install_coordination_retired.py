# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A RETIRED wiring row is stripped on every install and never added back (BACKLOG #1215).

The urgent mail tier (``scripts/hooks/mail-watch.ps1``) is retired from installation: the 2026-08-06
"NOT WIRED" decision recorded in ADR 0161 stands. Its row is kept in ``$WIRING`` and marked
``Retired = $true`` rather than deleted, because the installer strips installed hooks only by walking
``$WIRING`` and matching each row's marker. Deleting the row would leave every copy already installed
in a config root in place, and invisible to ``-Status``, which also walks only ``$WIRING``.

So the row must still be stripped and still be reported, and it must never be added. Each test below
runs the real installer against a fixture settings file, never a real config root.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "coord" / "install-coordination.ps1"
WATCH_REL = "scripts/hooks/mail-watch.ps1"

# Below pyproject.toml's --timeout=60 so a hung subprocess fails this test by name.
TIMEOUT = 45

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="install-coordination.ps1 needs pwsh on Windows",
)

_SRC = INSTALLER.read_text(encoding="utf-8")


def _marker(name: str) -> str:
    """Parse a marker out of the installer, so the test follows the shipped value."""
    m = re.search(rf"^\${name}\s*=\s*\"([^\"]+)\"", _SRC, re.MULTILINE)
    assert m, f"could not find ${name} in {INSTALLER}"
    return m.group(1)


WAKE_MARKER = _marker("WAKE_MARKER")
MAIL_MARKER = _marker("MAIL_MARKER")

# The shape a previous install wrote: the wake shim on Stop, async and rewake both set. Only the
# marker line matters to the installer's strip predicate; the rest mirrors a real entry.
_INSTALLED_WAKE_ENTRY: dict[str, Any] = {
    "hooks": [
        {
            "type": "command",
            "command": f"# {WAKE_MARKER}\n& '{WATCH_REL}'; exit $LASTEXITCODE",
            "shell": "powershell",
            "timeout": 1200,
            "statusMessage": "Watching for urgent mail",
            "async": True,
            "asyncRewake": True,
        }
    ]
}
_FOREIGN_STOP_ENTRY: dict[str, Any] = {
    "hooks": [{"type": "command", "command": "echo foreign-stop", "shell": "powershell"}]
}


def _run(settings: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALLER),
            "-SettingsPath",
            str(settings),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def _load(settings: Path) -> dict[str, Any]:
    # utf-8-sig: Set-Content -Encoding UTF8 writes a BOM under Windows PowerShell 5.1.
    parsed: dict[str, Any] = json.loads(settings.read_text(encoding="utf-8-sig"))
    return parsed


def _commands(d: dict[str, Any]) -> list[str]:
    return [
        str(h.get("command") or "")
        for groups in (d.get("hooks") or {}).values()
        for g in groups or []
        for h in g.get("hooks") or []
    ]


def _wake_count(d: dict[str, Any]) -> int:
    return sum(WAKE_MARKER in c for c in _commands(d))


@pytest.fixture
def installed(tmp_path: Path) -> Path:
    """A settings file as a pre-retirement install left it: the wake row live, beside a foreign hook."""
    p = tmp_path / "settings.json"
    p.write_text(
        json.dumps({"hooks": {"Stop": [_FOREIGN_STOP_ENTRY, _INSTALLED_WAKE_ENTRY]}}),
        encoding="utf-8",
    )
    return p


def _status_line(out: str) -> str:
    lines = [ln for ln in out.splitlines() if WATCH_REL in ln]
    assert len(lines) == 1, f"expected one -Status line for {WATCH_REL}, got {lines}:\n{out}"
    return lines[0]


def test_the_watch_row_is_kept_and_marked_retired() -> None:
    """Kept, so strip and -Status still find it; retired, so install never adds it."""
    rows = [ln for ln in _SRC.splitlines() if re.search(r"^\s*@\{.*Script\s*=", ln)]
    watch = [ln for ln in rows if WATCH_REL in ln]
    assert len(watch) == 1, f"expected one $WIRING row for {WATCH_REL}, found {watch}"
    assert re.search(r"Retired\s*=\s*\$true", watch[0]), watch[0]
    others = [ln for ln in rows if WATCH_REL not in ln]
    assert others, "parsed no other $WIRING rows -- the row regex has drifted from the source"
    assert not [ln for ln in others if "Retired" in ln], "only the urgent tier is retired"


def test_the_fixture_really_carries_an_installed_wake_row(installed: Path) -> None:
    """Positive control: a strip test over a file with nothing to strip proves nothing."""
    assert _wake_count(_load(installed)) == 1


def test_install_strips_an_installed_retired_row(installed: Path) -> None:
    rc, out = _run(installed)
    assert rc == 0, out
    d = _load(installed)
    assert _wake_count(d) == 0, f"the retired wake row survived an install:\n{out}"
    assert "echo foreign-stop" in _commands(d), "the strip took a foreign Stop hook with it"
    assert [c for c in _commands(d) if MAIL_MARKER in c], "the drain was not installed"


def test_a_second_install_does_not_add_it_back(installed: Path) -> None:
    for _ in range(2):
        rc, out = _run(installed)
        assert rc == 0, out
    assert _wake_count(_load(installed)) == 0


def test_a_fresh_install_never_adds_the_retired_row(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    rc, out = _run(settings)
    assert rc == 0, out
    assert _wake_count(_load(settings)) == 0


def test_a_script_filter_naming_the_retired_row_strips_it(installed: Path) -> None:
    """`-Script mail-watch` selects the row, so it is a valid request: strip, exit 0, add nothing."""
    rc, out = _run(installed, "-Script", "mail-watch")
    assert rc == 0, out
    assert _wake_count(_load(installed)) == 0


def test_uninstall_still_finds_the_retired_row(installed: Path) -> None:
    rc, out = _run(installed, "-Uninstall")
    assert rc == 0, out
    assert _wake_count(_load(installed)) == 0


def test_status_names_a_retired_row_that_is_still_installed(installed: Path) -> None:
    rc, out = _run(installed, "-Status")
    assert rc == 0, out
    line = _status_line(out)
    assert "RETIRED" in line, line
    assert "STILL INSTALLED" in line, line


def test_status_names_a_retired_row_once_it_is_stripped(installed: Path) -> None:
    rc, out = _run(installed)
    assert rc == 0, out
    rc, out = _run(installed, "-Status")
    assert rc == 0, out
    line = _status_line(out)
    assert "RETIRED" in line, line
    assert "STILL INSTALLED" not in line, line

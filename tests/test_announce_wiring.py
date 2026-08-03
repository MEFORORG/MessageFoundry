# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the WIRING of the announce hook -- the anti-no-op class.

``test_announce_hook.py`` pins what the hook says. This module pins something the repo had no test
for at all: **does the thing that gets INSTALLED reach a script that EXISTS, and does it say so when
it does not?**

That gap is not hypothetical. Measured 2026-08-01: a ``UserPromptSubmit`` entry installed at user
level by a *different* repo probed ``scripts/hooks/announce.ps1``, resolved nothing in this checkout,
wrote nothing, printed nothing and exited 0 -- byte-identical to a healthy hook with no peers. It had
been wired and inert for weeks and nothing reported it. A hook whose success and whose total failure
look the same from the outside is the defect class this module exists to close.

Two tests here are deliberate negative controls and were written to FAIL first:
``test_every_wired_script_exists_in_this_checkout`` (red until the script lands) and
``test_the_announce_shim_says_so_when_the_script_is_missing`` (red until the shim gained a notice).
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
ANNOUNCE_REL = "scripts/hooks/announce-session.ps1"

# Below pyproject.toml's --timeout=60 (and CI's 120) so a hung subprocess fails THIS test by name
# instead of taking the leg down through --timeout-method=thread with no attribution.
TIMEOUT = 45

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="install-coordination.ps1 needs pwsh on Windows",
)

_SRC = INSTALLER.read_text(encoding="utf-8")


def _marker(name: str) -> str:
    """Parse a marker out of the installer source.

    Never hardcode these: a test carrying its own copy of the string cannot detect the code drifting
    away from it, which is the failure it is supposed to guard.
    """
    m = re.search(rf"\${name}\s*=\s*\"([^\"]+)\"", _SRC)
    assert m, f"could not find ${name} in {INSTALLER}"
    return m.group(1)


COORD_MARKER = _marker("MARKER")
ANNOUNCE_MARKER = _marker("ANNOUNCE_MARKER")


def run_installer(settings: Path, *args: str) -> str:
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
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


@pytest.fixture
def settings(tmp_path: Path) -> Path:
    """Mirrors the REAL user settings file: UserPromptSubmit already holds two FOREIGN entries.

    Verified 2026-08-01 -- an unmarked waiting-flag cleanup, and another repo's announce shim carrying
    its own marker. Both must survive install and uninstall untouched.
    """
    p = tmp_path / "settings.json"
    p.write_text(
        json.dumps(
            {
                "theme": "dark",
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo other"}]}
                    ],
                    "UserPromptSubmit": [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": '$f="$env:TEMP\\claude-waiting.flag";Remove-Item $f',
                                    "shell": "powershell",
                                    "async": True,
                                }
                            ]
                        },
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "# mefor-web-announce\n& 'scripts/hooks/announce.ps1'",
                                    "shell": "powershell",
                                    "timeout": 20,
                                }
                            ]
                        },
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    return p


def load(settings: Path) -> dict[str, Any]:
    # utf-8-sig deliberately: Set-Content -Encoding UTF8 emits a BOM under Windows PowerShell 5.1 and
    # none under pwsh 7, so a plain utf-8 read fails on one of the two hosts.
    parsed: dict[str, Any] = json.loads(settings.read_text(encoding="utf-8-sig"))
    return parsed


def _cmds(d: dict[str, Any], event: str) -> list[str]:
    return [g["hooks"][0]["command"] for g in d["hooks"].get(event, [])]


def _announce_cmd(d: dict[str, Any]) -> str:
    hits = [c for c in _cmds(d, "UserPromptSubmit") if ANNOUNCE_MARKER in c]
    assert len(hits) == 1, f"expected exactly one announce entry, got {len(hits)}"
    return hits[0]


def _git_init(repo: Path) -> None:
    for args in (
        ["init", "-q"],
        ["config", "user.email", "t@example.invalid"],
        ["config", "user.name", "t"],
    ):
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)
    (repo / "f.txt").write_text("x", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "f.txt"], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(repo), "commit", "-qm", "init"], check=True, capture_output=True
    )


# --------------------------------------------------------------------------------------------------
# The negative control. Written FIRST, and red until announce-session.ps1 landed.
# --------------------------------------------------------------------------------------------------


def test_every_wired_script_exists_in_this_checkout() -> None:
    """Every script the installer wires must actually be in the repo.

    Nothing asserted this for ANY hook before now, and its absence is exactly why a shim could look
    installed and resolve nothing for weeks. Prints every path it checked, so a green result is
    evidence of what was scanned rather than a bare dot.
    """
    scripts = re.findall(r"Script\s*=\s*\"([^\"]+)\"", _SRC)
    assert scripts, (
        "parsed no Script entries out of $WIRING -- the regex has drifted from the source"
    )
    missing = []
    for rel in scripts:
        target = ROOT / rel
        print(f"wired script: {rel} -> {'OK' if target.is_file() else 'MISSING'}")
        if not target.is_file():
            missing.append(rel)
    assert not missing, f"wired but absent from this checkout: {missing}"


# --------------------------------------------------------------------------------------------------
# Marker separation -- the property standing between a one-line $WIRING edit and deleting a hook
# that belongs to another repo.
# --------------------------------------------------------------------------------------------------


def test_the_two_markers_cannot_strip_each_other() -> None:
    """Test-IsOurs is a SUBSTRING match, so containment in EITHER direction is a silent deletion."""
    print(f"coord marker={COORD_MARKER!r} announce marker={ANNOUNCE_MARKER!r}")
    assert COORD_MARKER not in ANNOUNCE_MARKER
    assert ANNOUNCE_MARKER not in COORD_MARKER


def test_the_announce_marker_is_not_the_website_marker() -> None:
    """That entry lives in the SAME user settings file on this machine (verified 2026-08-01)."""
    foreign = "mefor-web-announce"
    assert ANNOUNCE_MARKER not in foreign
    assert foreign not in ANNOUNCE_MARKER


def test_the_announce_script_path_differs_from_the_website_shims_path() -> None:
    """Sharing the path would put this repo's coordination under a hook entry another repo owns and
    can uninstall -- and would cost a second ~0.5 s pwsh spawn on every prompt in every repo."""
    assert ANNOUNCE_REL != "scripts/hooks/announce.ps1"


def test_install_wires_user_prompt_submit_to_announce(settings: Path) -> None:
    run_installer(settings)
    cmd = _announce_cmd(load(settings))
    assert ANNOUNCE_REL in cmd


def test_coexistence_with_the_two_foreign_userpromptsubmit_entries(settings: Path) -> None:
    """THE LOAD-BEARING ONE: the foreign entries survive install AND uninstall, byte-identical."""
    before = _cmds(load(settings), "UserPromptSubmit")
    assert len(before) == 2

    run_installer(settings)
    after = _cmds(load(settings), "UserPromptSubmit")
    for c in before:
        assert c in after, "install dropped a foreign UserPromptSubmit entry"
    assert len([c for c in after if ANNOUNCE_MARKER in c]) == 1
    assert load(settings)["theme"] == "dark"

    run_installer(settings, "-Uninstall")
    final = _cmds(load(settings), "UserPromptSubmit")
    assert [c for c in final if ANNOUNCE_MARKER in c] == []
    for c in before:
        assert c in final, "uninstall took a foreign UserPromptSubmit entry with it"


def test_the_two_original_hooks_are_still_wired_and_unchanged(settings: Path) -> None:
    """session-context.ps1 and collision_gate.ps1 have no -CommonDir parameter, and PowerShell errors
    on an unexpected one -- which is why the announce shim is a SEPARATE builder."""
    run_installer(settings)
    d = load(settings)
    assert "SessionStart" in d["hooks"]
    assert "Edit|Write|MultiEdit|NotebookEdit" in [
        g.get("matcher") for g in d["hooks"]["PreToolUse"]
    ]
    for c in _cmds(d, "SessionStart"):
        assert COORD_MARKER in c
        assert ANNOUNCE_MARKER not in c
        assert "-CommonDir" not in c


def test_reinstall_is_byte_identical_with_three_rows(settings: Path) -> None:
    run_installer(settings)
    first = load(settings)
    run_installer(settings)
    assert first == load(settings)


def test_userpromptsubmit_entry_has_no_matcher_key(settings: Path) -> None:
    run_installer(settings)
    ours = [
        g
        for g in load(settings)["hooks"]["UserPromptSubmit"]
        if ANNOUNCE_MARKER in g["hooks"][0]["command"]
    ]
    assert "matcher" not in ours[0]


def test_status_reports_the_announce_row(settings: Path) -> None:
    assert "missing" in run_installer(settings, "-Status")
    run_installer(settings)
    out = run_installer(settings, "-Status")
    assert "INSTALLED" in out
    assert ANNOUNCE_REL in out


def test_only_removes_announce_without_disarming_the_gate(settings: Path) -> None:
    """Without -Only, the 2am remedy for a misbehaving announce hook is a full -Uninstall that takes
    the collision gate and the SessionStart banner with it."""
    run_installer(settings)
    run_installer(settings, "-Only", "UserPromptSubmit", "-Uninstall")
    d = load(settings)
    assert [c for c in _cmds(d, "UserPromptSubmit") if ANNOUNCE_MARKER in c] == []
    assert "SessionStart" in d["hooks"], "-Only took the banner with it"
    assert "Edit|Write|MultiEdit|NotebookEdit" in [
        g.get("matcher") for g in d["hooks"]["PreToolUse"]
    ]


def test_installed_timeout_is_sane() -> None:
    """This timeout is the hook's ONLY time bound -- the peer lookup runs in-process by design -- so
    it must exceed presence.ps1's measured ~1.0 s while staying short enough that a hang at prompt
    submit is not felt as a hang."""
    row = re.search(r"Event\s*=\s*\"UserPromptSubmit\".*?Timeout\s*=\s*(\d+)", _SRC, re.S)
    assert row, "could not parse the announce row's Timeout"
    assert 10 <= int(row.group(1)) <= 30


# --------------------------------------------------------------------------------------------------
# Shim resolution -- what the installed one-liner actually does.
# --------------------------------------------------------------------------------------------------


def _extract_shim(settings: Path, tmp_path: Path) -> Path:
    p = tmp_path / "shim.ps1"
    p.write_text(_announce_cmd(load(settings)), encoding="utf-8")
    return p


def _run_shim(shim: Path, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(shim)],
        cwd=str(cwd),
        input=json.dumps({"session_id": "x", "hook_event_name": "UserPromptSubmit"}),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


def _fixture_primary(tmp_path: Path, *, with_announce: bool, with_presence: bool = True) -> Path:
    primary = tmp_path / "primary"
    primary.mkdir()
    _git_init(primary)
    if with_presence:
        (primary / "scripts" / "coord").mkdir(parents=True)
        (primary / "scripts" / "coord" / "presence.ps1").write_text("exit 0\n", encoding="utf-8")
    if with_announce:
        (primary / "scripts" / "hooks").mkdir(parents=True)
        (primary / "scripts" / "hooks" / "announce-session.ps1").write_text(
            "param([string]$CommonDir)\nWrite-Output 'PRIMARY-ANNOUNCE-RAN'\n", encoding="utf-8"
        )
    return primary


def _linked_worktree(primary: Path, tmp_path: Path) -> Path:
    wt = tmp_path / "old-branch-wt"
    subprocess.run(
        ["git", "-C", str(primary), "worktree", "add", "-q", "-b", "old", str(wt)],
        check=True,
        capture_output=True,
        text=True,
    )
    return wt


def test_the_announce_shim_runs_the_primary_checkouts_script(
    settings: Path, tmp_path: Path
) -> None:
    """Coordination is infrastructure and must be uniform, so the shim resolves the PRIMARY checkout
    (which tracks main) rather than whatever branch the caller happens to be on."""
    primary = _fixture_primary(tmp_path, with_announce=True)
    wt = _linked_worktree(primary, tmp_path)
    assert not (wt / "scripts" / "hooks" / "announce-session.ps1").exists()
    run_installer(settings)
    proc = _run_shim(_extract_shim(settings, tmp_path), wt)
    assert "PRIMARY-ANNOUNCE-RAN" in proc.stdout, f"{proc.stdout!r} {proc.stderr!r}"


def test_the_announce_shim_says_so_when_the_script_is_missing(
    settings: Path, tmp_path: Path
) -> None:
    """THE OTHER NEGATIVE CONTROL, and the fix for the historical bug's defining property.

    Every receipt, marker and visible line the hook writes lives INSIDE the script -- strictly
    downstream of the resolution failure that IS the bug. This notice is the one surface that still
    resolves when the script does not.
    """
    primary = _fixture_primary(tmp_path, with_announce=False)
    wt = _linked_worktree(primary, tmp_path)
    run_installer(settings)
    proc = _run_shim(_extract_shim(settings, tmp_path), wt)
    assert proc.returncode == 0
    assert "announce-session.ps1 is missing" in proc.stdout, (
        f"silent resolution failure: {proc.stdout!r}"
    )
    assert "Announcing yourself" in proc.stdout


def test_the_announce_shim_is_silent_in_a_repo_that_is_not_messagefoundry(
    settings: Path, tmp_path: Path
) -> None:
    """The missing-script notice is gated on presence.ps1 for exactly this reason: the entry is
    user-global and fires in every unrelated project on the machine."""
    primary = _fixture_primary(tmp_path, with_announce=False, with_presence=False)
    run_installer(settings)
    proc = _run_shim(_extract_shim(settings, tmp_path), primary)
    assert proc.returncode == 0
    assert proc.stdout.strip() == "", f"notice leaked into a foreign repo: {proc.stdout!r}"


def test_the_installed_announce_shim_is_inert_outside_a_git_repo(
    settings: Path, tmp_path: Path
) -> None:
    run_installer(settings)
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    proc = _run_shim(_extract_shim(settings, tmp_path), outside)
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""

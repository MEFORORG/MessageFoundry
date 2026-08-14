# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Installing the machine-global worktree gate must leave a record of who wrote it (BACKLOG #1247).

This exists because it went wrong and could not be diagnosed. The installed gate's content changed on
this box while three sessions ran against it, and afterwards nobody could say who wrote it. The change
was benign, which is not the point: an unattributable write to a shared safety control is the same
class of event whichever direction it moves the file.

WHAT THESE TESTS DELIBERATELY DO NOT DO IS RUN THE INSTALLER. `install-gate.ps1` writes into
``~/.claude``, a machine-global location shared by every session on this box, and installing it is the
owner's action by design. A suite that had to install the gate to test the receipt would be a suite
that installs the gate. So the behaviour lives in ``scripts/worktree/_gate_receipt.ps1``, which
defines functions and nothing else and can be dot-sourced against a temp directory -- and the WIRING,
which cannot be tested that way, is pinned statically below.

THE SPLIT IS THE DESIGN, and it is worth naming because each half is blind to the other's failure:
the behavioural tests would still pass if the installer never called any of these functions, and the
static test would still pass if every function were wrong. Neither is sufficient; both are cheap.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "worktree" / "_gate_receipt.ps1"
INSTALLER = ROOT / "scripts" / "worktree" / "install-gate.ps1"

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")


def run_ps(body: str) -> str:
    """Dot-source the receipt helper and run `body`. Never touches the real gate."""
    script = f". '{HELPER.as_posix()}'\n{body}"
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, f"pwsh failed: {r.returncode}\nSTDOUT:{r.stdout}\nSTDERR:{r.stderr}"
    return r.stdout.strip()


# A deliberately trivial injected hash. The REAL hash (Get-GateHash) folds CRLF and is covered by
# tests/test_gate_installed_parity.py; re-testing it here would test that file twice and this one not
# at all. What is under test is the receipt state machine, so the hash only has to be a function of
# content. That the installer passes the real one is pinned by the static test at the bottom.
HASH_FN = "{ param($p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }"


@pytest.fixture
def gate(tmp_path: Path) -> Path:
    p = tmp_path / "worktree_gate.ps1"
    p.write_text("# pretend gate v1\n", encoding="utf-8")
    return p


def test_absent_when_no_gate_is_installed(tmp_path: Path) -> None:
    missing = tmp_path / "worktree_gate.ps1"
    out = run_ps(f"Get-GateProvenance '{missing.as_posix()}' {HASH_FN}")
    assert out == "ABSENT"


def test_unrecorded_when_a_gate_exists_with_no_receipt(gate: Path) -> None:
    """The normal state of every gate installed before this change -- and it must NOT be fatal.

    Refusing here would block the very re-install that adopts the mechanism, which would make the fix
    for an unattributable write into a reason nobody can install the gate at all.
    """
    out = run_ps(f"Get-GateProvenance '{gate.as_posix()}' {HASH_FN}")
    assert out == "UNRECORDED"


def test_verified_after_a_receipt_is_written(gate: Path) -> None:
    out = run_ps(
        f"$null = Write-GateReceipt -GatePath '{gate.as_posix()}' -SourcePath '{gate.as_posix()}' "
        f"-RepoRoot '{ROOT.as_posix()}' -HashFn {HASH_FN}\n"
        f"Get-GateProvenance '{gate.as_posix()}' {HASH_FN}"
    )
    assert out == "VERIFIED"


def test_modified_when_something_writes_the_gate_behind_the_receipt(gate: Path) -> None:
    """The defect this item exists for: a write nobody can attribute.

    This is the assertion that has to be able to fail. If Get-GateProvenance stopped comparing, every
    other test here would still pass -- ABSENT, UNRECORDED and VERIFIED are all reachable without a
    working comparison.
    """
    out = run_ps(
        f"$null = Write-GateReceipt -GatePath '{gate.as_posix()}' -SourcePath '{gate.as_posix()}' "
        f"-RepoRoot '{ROOT.as_posix()}' -HashFn {HASH_FN}\n"
        f"Set-Content -LiteralPath '{gate.as_posix()}' -Value '# someone else wrote this'\n"
        f"Get-GateProvenance '{gate.as_posix()}' {HASH_FN}"
    )
    assert out == "MODIFIED"


def test_the_receipt_timestamp_is_taken_at_write_time_not_inherited(gate: Path) -> None:
    """The mtime is the trap, not the gap.

    Copy-Item carries the SOURCE's LastWriteTime, so an installed gate's mtime reflects whichever
    checkout installed it. A correct stale-gate report was once RETRACTED on the strength of one, and
    the retraction reached three sessions and the owner before a baseline hash reproved it. So the
    receipt's timestamp must not be derived from any file -- here the gate is backdated years and the
    receipt must disagree with it.
    """
    out = run_ps(
        f"$g = '{gate.as_posix()}'\n"
        f"(Get-Item -LiteralPath $g).LastWriteTimeUtc = [DateTime]::new(2001,1,1)\n"
        f"$p = Write-GateReceipt -GatePath $g -SourcePath $g -RepoRoot '{ROOT.as_posix()}' -HashFn {HASH_FN}\n"
        f"Get-Content -LiteralPath $p -Raw"
    )
    receipt = json.loads(out)
    assert not receipt["written_at_utc"].startswith("2001"), (
        "the receipt inherited the file's mtime, which is exactly the defect it replaces"
    )
    assert receipt["written_at_utc"].endswith("Z"), "timestamp must be explicit UTC"


def test_the_replaced_bytes_are_recoverable(gate: Path) -> None:
    """A bad install must be reversible; the backup is byte-exact on purpose."""
    out = run_ps(
        f"$b = Backup-GateBeforeWrite '{gate.as_posix()}'\n"
        f"Set-Content -LiteralPath '{gate.as_posix()}' -Value '# overwritten'\n"
        f"Get-Content -LiteralPath $b -Raw"
    )
    assert "pretend gate v1" in out


def test_a_corrupt_receipt_reads_as_absent_rather_than_throwing(gate: Path) -> None:
    """Both states have the same safe response -- do not claim provenance -- and throwing would make
    an unreadable receipt harder to recover from than a missing one."""
    receipt = gate.parent / "worktree_gate.install-receipt.json"
    receipt.write_text("{not json at all", encoding="utf-8")
    out = run_ps(f"Get-GateProvenance '{gate.as_posix()}' {HASH_FN}")
    assert out == "UNRECORDED"


# --------------------------------------------------------------------------- the wiring


def test_the_installer_actually_calls_the_receipt_machinery() -> None:
    """The behavioural tests above are blind to an installer that never calls any of this.

    That is not hypothetical here: the sibling defect this file's neighbours exist for was a rule that
    worked in isolation and was never wired, so it was dead code the moment it shipped.
    """
    text = INSTALLER.read_text(encoding="utf-8")
    for call in ("Get-GateProvenance", "Backup-GateBeforeWrite", "Write-GateReceipt"):
        assert call in text, f"install-gate.ps1 never calls {call}"
    assert "_gate_receipt.ps1" in text, "installer does not dot-source the receipt helper"
    # The real hash, not a local one -- a second digest basis would let the receipt and
    # tests/test_gate_installed_parity.py disagree about one file.
    assert "${function:Get-GateHash}" in text, "installer must pass the real Get-GateHash"


def test_a_mismatched_gate_stops_the_install_by_default() -> None:
    """An overwrite destroys the only evidence that anything happened, so it must not be the default."""
    text = INSTALLER.read_text(encoding="utf-8")
    assert "OverwriteUnverifiedGate" in text, "no explicit flag exists to override a mismatch"
    assert 'MODIFIED" -and -not $OverwriteUnverifiedGate' in text, (
        "the refusal is not gated on MODIFIED plus the absence of the override"
    )


def test_the_fix_does_not_repair_mtime() -> None:
    """Explicitly rejected by the item: a corrected timestamp is still one mutable field asserting a
    fact nothing corroborates. The record has to be the receipt, not a better-looking mtime."""
    text = INSTALLER.read_text(encoding="utf-8") + HELPER.read_text(encoding="utf-8")
    assert "LastWriteTime =" not in text and "LastWriteTimeUtc =" not in text, (
        "something assigns a file timestamp; #1247 forbids fixing this by touching mtime"
    )

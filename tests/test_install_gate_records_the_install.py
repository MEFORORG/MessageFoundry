# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Installing the gate must leave a record, and the record must not lie about WHEN (BACKLOG #1247).

Three things were missing, all measured at zero on origin/main against a positive control of three
`Copy-Item` calls: the gate script was overwritten with no backup, nothing recorded that an install
had happened, and the installed copy's timestamp was inherited rather than set.

THE TIMESTAMP IS THE LOAD-BEARING ONE. `Copy-Item` carries the SOURCE file's LastWriteTime, so the
installed gate reported a time from whichever checkout it came from -- routinely days old. A correct
stale-gate report was once RETRACTED on the strength of that timestamp ("nothing wrote it today")
and the retraction propagated. **An inherited mtime is worse than a missing one because it reads as
evidence**: a file with no timestamp gets questioned, a file with a confident wrong one gets believed.

THE NEAR-MISS THIS ROW WAS WRITTEN TO WARN ABOUT, recorded because it caught the builder too:
`Write-Settings` has backed up settings.json for a long time, and #1375 added a backup for the
ALLOWLIST. Reading `Copy-Item ... .bak` in this file therefore makes the absence around the GATE
SCRIPT easy to read as presence. They are three different files.

AND THIS DOCSTRING WAS ITSELF AN INSTANCE OF IT. The sentence above shipped while #1375 was unbuilt
and the allowlist writer was a bare `Set-Content` with no backup at all, so it asserted a backup that
did not exist -- in the very paragraph warning against reading one file's `.bak` as another's. It is
true now because #1375 landed the code, not because it was ever true when written. Backups for the
allowlist are covered by tests/test_install_gate_allowlist_merge.py; this file covers the gate script.

WHY THESE TESTS EXECUTE THE REGION RATHER THAN ASSERT ITS SHAPE. The install path cannot be run from
a session -- install-gate.ps1 refuses inside Claude Code, by design, keyed on the session rather than
the target -- so a whole-script run is unavailable. The escape hatch that answer invites is a static
test that pins call-site SHAPE, and on the sibling item every such test was eventually escaped by a
rename or a respelling. So these cut the real region out of the real file and RUN it against a
fixture, then read the consequence off the filesystem.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / "scripts" / "worktree" / "install-gate.ps1"

# The region under test: from the backup that now precedes the copy, through the receipt write.
_START = "$GateSrc = Join-Path $RepoRoot"
_END = 'Set-Content -LiteralPath "$GateDst.receipt.json" -Value $receipt -Encoding utf8'


def _region() -> str:
    text = INSTALLER.read_text(encoding="utf-8")
    i = text.index(_START)
    j = text.index(_END) + len(_END)
    return text[i:j]


def _function(name: str) -> str:
    """The source of one helper the region calls, so the fixture runs the REAL implementation."""
    text = INSTALLER.read_text(encoding="utf-8")
    start = text.index(f"function {name}")
    depth, k = 0, text.index("{", start)
    for pos in range(k, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start : pos + 1]
    raise AssertionError(f"unbalanced braces reading {name}")


def _run(home: Path, source_age_days: int = 6) -> dict[str, object]:
    """Run the real region against a fixture and read the consequences off disk."""
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")

    repo_root = home / "repo"
    (repo_root / "scripts" / "hooks").mkdir(parents=True)
    src = repo_root / "scripts" / "hooks" / "worktree_gate.ps1"
    src.write_text('$GateVersion = "2026.01.01.1"\n# new gate\n', encoding="utf-8")

    hooks = home / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    dst = hooks / "worktree_gate.ps1"
    dst.write_text("# THE GATE THAT WAS ALREADY INSTALLED\n", encoding="utf-8")

    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"$RepoRoot = '{repo_root.as_posix()}'",
            f"$GateDst  = '{dst.as_posix()}'",
            "$ConfigDir = @('c:/fixture/.claude')",
            _function("Get-GateVersion"),
            _function("Get-GateHash"),
            # Back-date the SOURCE, which is what a checkout does. Copy-Item carries this forward.
            f"(Get-Item -LiteralPath (Join-Path $RepoRoot 'scripts/hooks/worktree_gate.ps1'))"
            f".LastWriteTimeUtc = (Get-Date).ToUniversalTime().AddDays(-{source_age_days})",
            _region(),
        ]
    )
    runner = home / "run.ps1"
    runner.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(runner)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert proc.returncode == 0, f"the region failed to run:\n{proc.stdout}\n{proc.stderr}"
    return {
        "src": src,
        "dst": dst,
        "bak": Path(f"{dst}.bak"),
        "receipt": Path(f"{dst}.receipt.json"),
    }


def test_the_previous_gate_is_backed_up_before_it_is_overwritten(tmp_path: Path) -> None:
    r = _run(tmp_path)
    bak = r["bak"]
    assert bak.exists(), "the gate was overwritten with no backup, which is the #1247 defect"
    assert "ALREADY INSTALLED" in bak.read_text(encoding="utf-8"), (
        "the .bak exists but does not hold the PREVIOUS gate, so it is not a recovery point"
    )


def test_the_installed_gate_reports_when_it_was_INSTALLED_not_when_its_source_was_written(
    tmp_path: Path,
) -> None:
    """The defect that made a correct report get retracted.

    Copy-Item carries the source mtime, so the installed copy inherited a stale one and read as
    evidence that nothing had written it today.
    """
    r = _run(tmp_path, source_age_days=6)
    src_mtime = Path(r["src"]).stat().st_mtime
    dst_mtime = Path(r["dst"]).stat().st_mtime
    now = time.time()

    # CONTROL FIRST: the source really is old, so a pass cannot come from a fixture that forgot to
    # back-date it. Without this the assertion below is satisfied by doing nothing at all.
    assert now - src_mtime > 5 * 86400, (
        "fixture did not back-date the source; the test proves nothing"
    )

    assert dst_mtime > src_mtime + 86400, (
        "the installed gate INHERITED its source's timestamp. That is the #1247 defect: it reads as "
        f"evidence about when the gate was installed and it is wrong by {(dst_mtime - src_mtime) / 86400:.1f} days."
    )
    assert abs(now - dst_mtime) < 300, "the installed mtime is not the install time"


def test_the_install_leaves_a_receipt_whose_hash_matches_what_was_installed(tmp_path: Path) -> None:
    """A LIMIT OF THIS TEST, STATED RATHER THAN LEFT FOR SOMEBODY TO DISCOVER.

    Mutating the source to read `Get-GateHash $GateSrc` instead of `$GateDst` leaves all four tests
    GREEN, and no fixture can change that: immediately after `Copy-Item` the two files are
    byte-identical, so hashing either gives the same digest. The rule "the receipt describes what
    was INSTALLED" is untestable at this point by construction, not by oversight.

    It is recorded because the mutation is harmless TODAY and would stop being harmless the moment
    the copy became conditional, or the installed file were post-processed. Found by mutating the
    call site of this very test rather than by reading it.
    """
    r = _run(tmp_path)
    receipt = Path(r["receipt"])
    assert receipt.exists(), "nothing recorded that an install happened"
    data = json.loads(receipt.read_text(encoding="utf-8"))

    stamped = datetime.fromisoformat(str(data["installedAtUtc"]).replace("Z", "+00:00"))
    age = abs((datetime.now(UTC) - stamped).total_seconds())
    assert age < 300, f"the receipt's installedAtUtc is not the install time (off by {age:.0f}s)"

    # MIRROR Get-GateHash's basis, which is a CONTENT hash and not a byte hash: it drops the CR of
    # each CRLF pair before hashing. That is deliberate -- git's clean filter stores LF while
    # core.autocrlf checks out CRLF, and Copy-Item translates nothing, so a byte hash made every
    # Windows checkout read as STALE. Hashing raw bytes here would fail against correct code.
    folded = Path(r["dst"]).read_bytes().replace(b"\r\n", b"\n")
    on_disk = hashlib.sha256(folded).hexdigest()
    assert str(data["gateSha256"]).lower() == on_disk.lower(), (
        "the receipt's hash does not match the file it claims to describe, so it is not checkable"
    )


def test_the_receipt_says_it_is_not_attestation(tmp_path: Path) -> None:
    """A record in an unprotected location must not read as proof.

    Gate rule 1a protects ~/.claude/hooks/ by EXACT FILENAME and refuses to key on the parent
    directory, so this sibling is writable by a session. Shipping it without saying so would replace
    one confident wrong answer (the inherited mtime) with another.
    """
    data = json.loads(Path(_run(tmp_path)["receipt"]).read_text(encoding="utf-8"))
    note = str(data.get("note", "")).lower()
    assert "not attestation" in note and "not protected" in note, data.get("note")

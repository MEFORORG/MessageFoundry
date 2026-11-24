# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
from typing import Any, Literal

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALLER = REPO / "scripts" / "worktree" / "install-gate.ps1"

# The region under test: from the backup that now precedes the copy, through the receipt write.
_START = "$GateSrc = Join-Path $RepoRoot"
_END = 'Set-Content -LiteralPath "$GateDst.receipt.json" -Value $receipt -Encoding utf8'

# The receipt guard that precedes the allowlist write (BACKLOG #1247's last limb): from the check to
# the comment that opens the allowlist read below it.
_GUARD_START = "$guardSha = Get-GateHash $GateDst"
_GUARD_END = "# READ AND MERGE BEFORE ANYTHING ON THIS BOX CHANGES"

_INSTALLED_GATE = "# THE GATE THAT WAS ALREADY INSTALLED\n"


def _region() -> str:
    text = INSTALLER.read_text(encoding="utf-8")
    i = text.index(_START)
    j = text.index(_END) + len(_END)
    return text[i:j]


def _guard() -> str:
    text = INSTALLER.read_text(encoding="utf-8")
    assert text.count(_GUARD_START) == 1, "the receipt guard must appear exactly once"
    return text[text.index(_GUARD_START) : text.index(_GUARD_END)]


def _content_sha(data: bytes) -> str:
    """Get-GateHash's basis: SHA-256 over the bytes with each CRLF folded to LF, upper-case hex."""
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest().upper()


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


def _run(
    home: Path,
    source_age_days: int = 6,
    *,
    receipt: Literal["match", "mismatch", "garbage", "nohash", "none", "nogate"] = "match",
    override: bool = False,
    expect_ok: bool = True,
) -> dict[str, Any]:
    """Run the real guard and region against a fixture and read the consequences off disk.

    ``receipt`` is the state of the installed gate's receipt: ``match`` (what this installer leaves),
    ``mismatch`` (the gate changed after its install), ``garbage`` (unreadable JSON), ``nohash`` (JSON
    with no gate hash), ``none`` (a gate with no receipt) or ``nogate`` (nothing installed at all).
    """
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")

    repo_root = home / "repo"
    (repo_root / "scripts" / "hooks").mkdir(parents=True)
    src = repo_root / "scripts" / "hooks" / "worktree_gate.ps1"
    src.write_text('$GateVersion = "2026.01.01.1"\n# new gate\n', encoding="utf-8")
    # The shell entry's pinned dispatcher is copied in the same region.
    dispatch_src = repo_root / "scripts" / "hooks" / "shell-guard-dispatch.ps1"
    dispatch_src.write_text("# the dispatcher\n", encoding="utf-8")

    hooks = home / ".claude" / "hooks"
    hooks.mkdir(parents=True)
    dst = hooks / "worktree_gate.ps1"
    receipt_path = Path(f"{dst}.receipt.json")
    if receipt != "nogate":
        dst.write_bytes(_INSTALLED_GATE.encode("utf-8"))
    recorded = {
        "match": _content_sha(dst.read_bytes()) if receipt != "nogate" else "",
        "mismatch": _content_sha(b"# some other gate\n"),
    }
    if receipt in recorded:
        receipt_path.write_text(json.dumps({"gateSha256": recorded[receipt]}), encoding="utf-8")
    elif receipt == "garbage":
        receipt_path.write_text("{ not json", encoding="utf-8")
    elif receipt == "nohash":
        receipt_path.write_text(json.dumps({"note": "no hash"}), encoding="utf-8")

    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"$RepoRoot = '{repo_root.as_posix()}'",
            f"$GateDst  = '{dst.as_posix()}'",
            f"$sourceDispatch = '{dispatch_src.as_posix()}'",
            f"$DispatchDst = '{(hooks / 'shell-guard-dispatch.ps1').as_posix()}'",
            "$ConfigDir = @('c:/fixture/.claude')",
            f"$OverwriteUnexplained = ${'true' if override else 'false'}",
            f"$checkedSha = '{_content_sha(src.read_bytes())}'",
            _function("Get-GateVersion"),
            _function("Get-GateHash"),
            _function("Get-UnexplainedGate"),
            _guard(),
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
    if expect_ok:
        assert proc.returncode == 0, f"the region failed to run:\n{proc.stdout}\n{proc.stderr}"
    return {
        "proc": proc,
        "src": src,
        "dst": dst,
        "bak": Path(f"{dst}.bak"),
        "receipt": Path(f"{dst}.receipt.json"),
        "dispatch_src": dispatch_src,
        "dispatch_dst": hooks / "shell-guard-dispatch.ps1",
    }


def test_the_install_pins_the_dispatcher_beside_the_gate(tmp_path: Path) -> None:
    """The shell entry trusts a proof only from a project dispatcher identical to this copy, so an
    install that skipped it would leave every shell call running the gate in its own pwsh."""
    r = _run(tmp_path)
    assert r["dispatch_dst"].read_bytes() == r["dispatch_src"].read_bytes()
    receipt = json.loads(r["receipt"].read_text(encoding="utf-8-sig"))
    assert receipt["dispatchSha256"], receipt


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

    Mutating the source to read `Get-GateHash $GateSrc` instead of `$GateDst` leaves every test in
    this file GREEN, and no fixture can change that: immediately after `Copy-Item` the two files are
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
    assert str(data["gateSha256"]).upper() == _content_sha(Path(r["dst"]).read_bytes()), (
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


# ------------------------------------------------------------- the installed gate matches its receipt


def _refused(r: dict[str, Any], receipt_before: bytes | None = None) -> str:
    proc = r["proc"]
    both = str(proc.stdout) + str(proc.stderr)
    assert proc.returncode != 0, f"the install was not refused:\n{both}"
    assert "Refusing to overwrite the installed gate" in both, both
    assert "-OverwriteUnexplained" in both, "the refusal must name the override"
    # Nothing on the box changed: the gate is byte-identical, and no backup or new receipt appeared.
    assert r["dst"].read_bytes() == _INSTALLED_GATE.encode("utf-8")
    assert not r["bak"].exists(), "a refusal must not have reached the backup"
    assert not r["dispatch_dst"].exists(), "a refusal must not have reached the copy"
    if receipt_before is not None:
        assert r["receipt"].read_bytes() == receipt_before, "a refusal must not rewrite the receipt"
    return both


def test_a_gate_that_matches_its_receipt_installs(tmp_path: Path) -> None:
    """Control: the refusals below are a reading of the fixture, not of every install."""
    r = _run(tmp_path, receipt="match")
    assert r["dst"].read_bytes() == r["src"].read_bytes()
    data = json.loads(r["receipt"].read_text(encoding="utf-8-sig"))
    assert data["replacedSha256"] == _content_sha(_INSTALLED_GATE.encode("utf-8")), data
    assert data["overwroteUnexplained"] is None, data


def test_a_first_install_with_no_gate_installs(tmp_path: Path) -> None:
    r = _run(tmp_path, receipt="nogate")
    assert r["dst"].read_bytes() == r["src"].read_bytes()
    data = json.loads(r["receipt"].read_text(encoding="utf-8-sig"))
    assert data["replacedSha256"] is None, data


def test_a_gate_that_does_not_match_its_receipt_is_not_overwritten(tmp_path: Path) -> None:
    r = _run(tmp_path, receipt="mismatch", expect_ok=False)
    expected = json.dumps({"gateSha256": _content_sha(b"# some other gate\n")}).encode("utf-8")
    both = _refused(r, receipt_before=expected)
    # Name the file and both hashes, so the operator can tell what changed.
    assert str(r["dst"].as_posix()) in both.replace("\\", "/"), both
    assert _content_sha(_INSTALLED_GATE.encode("utf-8")) in both, both
    assert _content_sha(b"# some other gate\n") in both, both


def test_an_unreadable_receipt_refuses(tmp_path: Path) -> None:
    both = _refused(_run(tmp_path, receipt="garbage", expect_ok=False), b"{ not json")
    assert "cannot be read" in both and "(unreadable)" in both, both


def test_a_receipt_with_no_hash_refuses(tmp_path: Path) -> None:
    both = _refused(_run(tmp_path, receipt="nohash", expect_ok=False))
    assert "records no gate hash" in both and "(no hash)" in both, both


def test_a_gate_with_no_receipt_refuses(tmp_path: Path) -> None:
    """The receipt is not protected by gate rule 1a, so deleting it must not silence the check."""
    both = _refused(_run(tmp_path, receipt="none", expect_ok=False))
    assert "has no receipt" in both and "(no receipt)" in both, both


def test_the_override_installs_and_records_what_it_overwrote(tmp_path: Path) -> None:
    r = _run(tmp_path, receipt="mismatch", override=True)
    assert r["dst"].read_bytes() == r["src"].read_bytes()
    assert r["bak"].read_bytes() == _INSTALLED_GATE.encode("utf-8")
    sha12 = _content_sha(_INSTALLED_GATE.encode("utf-8"))[:12].lower()
    kept = Path(f"{r['dst']}.unexplained-{sha12}")
    assert kept.read_bytes() == _INSTALLED_GATE.encode("utf-8"), (
        "the overridden gate's bytes were not kept"
    )
    assert "WARNING" in r["proc"].stdout, r["proc"].stdout
    data = json.loads(r["receipt"].read_text(encoding="utf-8-sig"))
    over = data["overwroteUnexplained"]
    assert over["installedSha256"] == _content_sha(_INSTALLED_GATE.encode("utf-8")), over
    assert over["receiptSha256"] == _content_sha(b"# some other gate\n"), over
    assert data["replacedSha256"] == over["installedSha256"], data


def test_the_receipt_guard_runs_before_anything_on_the_box_changes() -> None:
    """A refusal says nothing was changed, so the guard must precede every install-path write."""
    text = INSTALLER.read_text(encoding="utf-8")
    install = text.index("# " + "-" * 89 + " install\n")
    guard = text.index(_GUARD_START)
    assert install < guard, "the receipt guard is not on the install path"
    for write in (
        "$bak = Write-GovernedRoots -Path $ReposFile",
        "Copy-Item -LiteralPath $GateDst -Destination $gateBak",
        "Copy-Item -LiteralPath $GateSrc -Destination $GateDst",
    ):
        assert guard < text.index(write, install), f"the receipt guard runs after {write!r}"


def test_the_guard_judges_the_same_read_it_re_checks_before_the_copy(tmp_path: Path) -> None:
    """The guard reads the installed gate ONCE: the hash it judges is the hash re-checked later.

    A second read for ``$guardSha`` would let a write between the two reads pass as explained, so
    this counts the guard's reads of the installed gate, and checks the judged hash is the one
    handed in rather than a fresh read of the file.
    """
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    dst = tmp_path / "worktree_gate.ps1"
    dst.write_bytes(_INSTALLED_GATE.encode("utf-8"))
    Path(f"{dst}.receipt.json").write_text(
        json.dumps({"gateSha256": _content_sha(_INSTALLED_GATE.encode("utf-8"))}), encoding="utf-8"
    )
    other = _content_sha(b"# a write after the read\n")
    script = "\n".join(
        [
            "$ErrorActionPreference = 'Stop'",
            f"$GateDst = '{dst.as_posix()}'",
            "$OverwriteUnexplained = $false",
            "$checkedSha = 'X'",
            _function("Get-GateHash").replace(
                "function Get-GateHash", "function Get-GateHashReal", 1
            ),
            "$script:hashReads = 0",
            "function Get-GateHash([string]$Path) { $script:hashReads++; Get-GateHashReal $Path }",
            _function("Get-UnexplainedGate"),
            _guard(),
            'Write-Output "reads=$script:hashReads"',
            # The judged hash is the one given, not a re-read: a file matching its receipt still
            # reads as unexplained when the hash handed in differs.
            f"$r = Get-UnexplainedGate $GateDst -InstalledSha '{other}'",
            'Write-Output "judged=$($r.InstalledSha)"',
            'Write-Output "none=$($null -eq (Get-UnexplainedGate $GateDst -InstalledSha $null))"',
        ]
    )
    runner = tmp_path / "run.ps1"
    runner.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(runner)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "reads=1" in out, f"the guard must read the installed gate exactly once:\n{out}"
    assert f"judged={other}" in out, out
    assert "none=True" in out, out

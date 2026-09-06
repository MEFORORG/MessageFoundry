# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Scripts invoked by absolute ``-File`` path must act on the checkout they LIVE in, not the cwd.

The regression home for the "cwd is not the caller" family (BACKLOG #1057, #1059, #1060, #1062, #1063).
Three mechanisms in this repo silently assumed that where a command runs is where the caller is, and all
three failed in the benign-looking direction -- a wrong owner recorded, a gate armed in the wrong tree, an
occupancy of zero for a tree in active use. None of them raised.

**Every test here asserts the DIVERGENCE, never the happy path.** A script run from inside its own
checkout passes with the bug still in: cwd and script root are the same directory, so the two candidate
answers are indistinguishable. The case that can tell them apart is an absolute ``-File`` invocation whose
cwd is a DIFFERENT checkout that also carries the file the script writes -- which is the ordinary shape on
a clone carrying dozens of worktrees, and is measured at 29% of the writes made by sessions sitting in
the primary. Per BACKLOG #1000 a
control needs the case that can distinguish; a test run from inside the target proves nothing.

The static spelling guards below are deliberately paired with a behavioural test each. On their own they
would be exactly the green-because-it-cannot-see control this project keeps filing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SETUP_LEAK_GATE = _ROOT / "scripts" / "dev" / "setup-leak-gate.ps1"
_SECURITY = _ROOT / "scripts" / "security"
_ALLOC = _ROOT / "scripts" / "coord" / "alloc.ps1"
_CLAIM = _ROOT / "scripts" / "coord" / "claim.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True)


def _leak_gate_checkout(path: Path) -> Path:
    """A minimal checkout carrying setup-leak-gate.ps1 and the files it reaches for.

    Only the three files the script needs are copied, NOT the whole of scripts/security. A maintainer
    running this suite has the real ``scan-tokens.local.txt`` sitting in that directory, and a copytree
    would sweep the private token list into a temp dir -- the one mistake the script itself refuses to
    make (it deletes what it wrote rather than risk committing the list).
    """
    (path / "scripts" / "dev").mkdir(parents=True)
    (path / "scripts" / "security").mkdir(parents=True)
    shutil.copy2(_SETUP_LEAK_GATE, path / "scripts" / "dev" / "setup-leak-gate.ps1")
    for name in ("scan_forbidden.py", "scan-allowlist.txt", "scan-tokens.local.txt.example"):
        shutil.copy2(_SECURITY / name, path / "scripts" / "security" / name)
    # check-ignore reads the working-tree .gitignore, so no commit is needed -- but the repo must exist,
    # or the script's own not-git-ignored guard deletes the file it just wrote and throws.
    (path / ".gitignore").write_text("scripts/security/scan-tokens.local.txt\n", encoding="utf-8")
    _git("init", "-b", "main", ".", cwd=path)
    return path


def test_setup_leak_gate_arms_the_checkout_it_lives_in_not_the_cwd(tmp_path: Path) -> None:
    """BACKLOG #1063. Reproduced by the divergence, which is the only shape that can fail.

    Pre-fix, ``$repo`` came from ``git rev-parse --show-toplevel`` -- the CURRENT directory -- so an
    absolute ``-File`` invocation from another worktree installed the token list into the caller's tree
    and printed CONFIGURED about it, while the tree the operator named kept no token source. Both
    checkouts here carry ``scripts/security/``, so "which tree got the file" is the whole question and
    neither answer is available by accident.

    The verify step's exit code is deliberately NOT asserted: it shells out to ``python``, which is not
    guaranteed on PATH on every CI leg, and the copy has already happened by then. Placement is the fact
    under test.
    """
    named = _leak_gate_checkout(tmp_path / "Named")
    caller = _leak_gate_checkout(tmp_path / "Caller")

    subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(named / "scripts" / "dev" / "setup-leak-gate.ps1"),
            "-Synthetic",
        ],
        cwd=str(caller),  # THE POINT: the shell is standing somewhere else entirely
        capture_output=True,
        text=True,
        timeout=180,
    )

    installed = named / "scripts" / "security" / "scan-tokens.local.txt"
    stray = caller / "scripts" / "security" / "scan-tokens.local.txt"
    assert installed.is_file(), "the named checkout was not armed -- it read the cwd instead"
    assert not stray.exists(), f"armed the CALLER's checkout instead: {stray}"


def _coord_checkout(path: Path, *, drafted: int, boundary: int) -> Path:
    """A minimal checkout carrying scripts/coord/ and the two files the allocator reads from ``$repo``.

    ``drafted`` is a BACKLOG heading written to the working tree and committed NOWHERE -- the floor term
    that exists to catch exactly that, and the one where reading the wrong tree is worse than
    misattribution: a number invisible to the sweep is a number free to re-issue.

    ``boundary`` is the ``PUBLIC_BACKLOG_FLOOR`` the allocator parses out of ledger_check.py rather than
    restating. A stub is faithful here because the allocator reads it with a regex over the raw text, and
    it gives a second, independent signal for which checkout was consulted.
    """
    (path / "scripts" / "coord").mkdir(parents=True)
    (path / "scripts" / "hooks").mkdir(parents=True)
    (path / "docs").mkdir(parents=True)
    shutil.copy2(_ALLOC, path / "scripts" / "coord" / "alloc.ps1")
    shutil.copy2(_CLAIM, path / "scripts" / "coord" / "claim.ps1")
    (path / "scripts" / "hooks" / "ledger_check.py").write_text(
        f"PUBLIC_BACKLOG_FLOOR = {boundary}\n", encoding="utf-8"
    )
    (path / "docs" / "BACKLOG.md").write_text(
        f"# Backlog\n\n## {drafted}. A number drafted here and committed nowhere\n",
        encoding="utf-8",
    )
    _git("init", "-b", "main", ".", cwd=path)
    _git("config", "user.email", "t@e.com", cwd=path)
    _git("config", "user.name", "t", cwd=path)
    _git("add", "-A", cwd=path)
    _git("commit", "-m", "fixture", "--no-verify", cwd=path)
    return path


def test_alloc_reads_the_floor_from_its_own_checkout_not_the_cwd(tmp_path: Path) -> None:
    """BACKLOG #1060, asserted by ``-ShowFloor`` so no numbers are burned.

    Allocation is a one-way door -- claims are never released, "holes are free, collisions are not" --
    so a test that allocated would leave permanent holes in the shared registry for every worktree of
    this clone. ``-ShowFloor`` exists for exactly this and computes the same floor without advancing the
    ratchet.

    The caller's drafted number is deliberately HIGHER than the target's. The floor is a maximum, so a
    wrong read shows up as a floor that is too high; equal numbers, or a lower one in the caller, would
    both pass with the bug still in.
    """
    named = _coord_checkout(tmp_path / "Named", drafted=4242, boundary=1200)
    caller = _coord_checkout(tmp_path / "Caller", drafted=7777, boundary=1900)

    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(named / "scripts" / "coord" / "alloc.ps1"),
            "-ShowFloor",
            "-Kind",
            "backlog",
        ],
        cwd=str(caller),  # THE POINT: the shell is standing in the other checkout
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    out = proc.stdout

    assert "floor    : 4242" in out, f"read the CALLER's working tree, not its own:\n{out}"
    assert "7777" not in out, f"the caller's drafted number reached the floor:\n{out}"
    # Independent second signal: the boundary comes from <repo>/scripts/hooks/ledger_check.py, so it
    # answers "which checkout" without depending on the floor arithmetic at all.
    assert "boundary : 1200" in out, f"parsed the CALLER's ledger_check.py:\n{out}"
    # And the registry it would write to must live beside the named checkout's object store.
    watermark = next(line for line in out.splitlines() if line.startswith("watermark:"))
    assert str(named).replace("\\", "/").casefold() in watermark.replace("\\", "/").casefold(), (
        watermark
    )


def test_claim_records_the_checkout_it_lives_in_not_the_cwd(tmp_path: Path) -> None:
    """The same construct in claim.ps1, which was NOT filed -- found by inspection while fixing #1060.

    A numbered claim is enforced by scripts/hooks/claim_check.py at commit time. That hook reads the repo
    from cwd and is right to: cwd IS the committing worktree for a commit hook. Only the tool can be
    invoked from somewhere else, so only the tool needed anchoring.
    """
    named = _coord_checkout(tmp_path / "Named", drafted=4242, boundary=1200)
    caller = _coord_checkout(tmp_path / "Caller", drafted=7777, boundary=1900)

    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(named / "scripts" / "coord" / "claim.ps1"),
            "-Take",
            "anchoring-probe",
            "-Note",
            "divergence fixture",
        ],
        cwd=str(caller),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout

    written = list((named / ".git" / "mefor-coord" / "claims").glob("*.json"))
    assert written, f"no claim landed in the named checkout's registry:\n{proc.stdout}"
    recorded = json.loads(written[0].read_text(encoding="utf-8"))["worktree"]
    assert recorded.replace("\\", "/").casefold() == str(named).replace("\\", "/").casefold(), (
        f"claim recorded against the CALLER: {recorded}"
    )
    assert not (caller / ".git" / "mefor-coord" / "claims").exists(), (
        "the caller's registry was written to"
    )


def _run_claim(script_tree: Path, cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_tree / "scripts" / "coord" / "claim.ps1"),
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=180,
    )


#: The divergence note's own load-bearing sentence, asserted as a SUBSTRING of the rendered line.
#:
#: Not the whole line: it interpolates two absolute paths and PowerShell hard-wraps host output at the
#: console width, so an equality assertion would fail on formatting rather than on behaviour. This
#: fragment carries the instruction a reader has to act on and nothing that varies.
#:
#: REWORDED BY BACKLOG #1346, and the reword was forced rather than cosmetic. The note used to say "this
#: script lives in <path>", which was true only while one value answered both *where the script is* and
#: *who holds the claim*. ``-AsWorktree`` splits those, so the note now compares against the HOLDER and
#: the old sentence would be false in exactly the case the flag exists for. The behaviour under test --
#: that the note fires on a divergence and stays silent without one -- is unchanged; only the sentence
#: naming which tree the claim landed against moved.
_DIVERGENCE = "but this claim is recorded against"


def test_the_divergence_note_FIRES_on_take_from_a_foreign_cwd(tmp_path: Path) -> None:
    """POSITIVE CONTROL for the test below, and it must be read as one.

    Asserting only that ``-Release`` prints nothing cannot distinguish "this path is silent" from "the
    note never fires anywhere" -- an absent feature and a broken assertion print the same empty string.
    So this pins that the mechanism WORKS on the path that has it, in the same fixture, with the same
    divergence, before its sibling asserts the path that does not.
    """
    named = _coord_checkout(tmp_path / "Named", drafted=4242, boundary=1200)
    caller = _coord_checkout(tmp_path / "Caller", drafted=7777, boundary=1900)

    proc = _run_claim(named, caller, "-Take", "note-probe", "-Note", "divergence fixture")

    assert proc.returncode == 0, proc.stderr or proc.stdout
    assert _DIVERGENCE in proc.stdout, (
        "the -Take divergence note did not fire, so this control cannot support its sibling:\n"
        f"{proc.stdout}"
    )


def test_the_divergence_note_ALSO_fires_on_release_from_a_foreign_cwd(tmp_path: Path) -> None:
    """BACKLOG #1358 -- the note names the release rule and was printed only at CLAIM time.

    ``-Release`` resolves ownership and records ``released_by`` from ``$repo``, which is anchored on
    ``$PSScriptRoot`` and NOT on the caller's cwd. That is correct and deliberate; the defect is that the
    warning about it was unreachable from this path. The note lives at the end of the script, after the
    ``-Take`` success block, and ``-Release`` exits some 170 lines earlier -- so the one message that
    states *"-Release must be run against that same worktree"* was shown to the operator at claim time
    and withheld at the moment they actually did it.

    Its absence is silent in the worst way: the release SUCCEEDS, and the history records a tree the
    operator was never standing in.
    """
    named = _coord_checkout(tmp_path / "Named", drafted=4242, boundary=1200)
    caller = _coord_checkout(tmp_path / "Caller", drafted=7777, boundary=1900)

    # Claim from INSIDE the named tree, so the take is the ordinary same-tree case and this test turns
    # only on the release. A divergent take would print the note here and confuse which call emitted it.
    taken = _run_claim(named, named, "-Take", "release-note-probe", "-Note", "fixture")
    assert taken.returncode == 0, taken.stderr or taken.stdout
    assert _DIVERGENCE not in taken.stdout, "the same-tree take must stay silent"

    released = _run_claim(named, caller, "-Release", "release-note-probe")

    assert released.returncode == 0, released.stderr or released.stdout
    assert "Released claim" in released.stdout, released.stdout
    assert _DIVERGENCE in released.stdout, (
        "-Release recorded the claim against the SCRIPT's tree and said nothing about it:\n"
        f"{released.stdout}"
    )


def test_setup_leak_gate_does_not_reintroduce_an_unanchored_toplevel(tmp_path: Path) -> None:
    """A spelling guard for the regression, paired with the behavioural test above.

    Alone this would be worthless -- it cannot see the defect, only its most likely spelling. It earns
    its place by naming the exact construct so a reader who reaches for ``--show-toplevel`` again gets
    told why not, at the moment they do it.
    """
    text = _SETUP_LEAK_GATE.read_text(encoding="utf-8")
    assert "$PSScriptRoot" in text, "the repo root must be anchored to the script's own location"
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or "--show-toplevel" not in stripped:
            continue
        assert "-C " in stripped, (
            "an unanchored `git rev-parse --show-toplevel` resolves against the CURRENT directory, "
            f"which is BACKLOG #1063: {stripped}"
        )

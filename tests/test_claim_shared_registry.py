# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1346 -- the claim gate must be SATISFIABLE from a second repository that shares the registry.

``scripts/hooks/claim_check.py`` runs as a commit-msg hook in more than one repository: this engine
carries it, and the separate MessageFoundry-vault clone runs the same gate. Before this module the two
halves answered *where does the claim registry live* from DIFFERENT trees -- the tool from the checkout
the script lives in, the gate from the tree being committed. So a second repository's commit whose
SUBJECT cited a ledger number could never pass, however honestly the item was held: its gate looked in a
registry nothing had ever written.

**The only route through was to move the citation into the commit BODY**, which the gate permits by
design. That is not the same act as the evasion recorded elsewhere in the ledger, where claiming properly
was possible and the body was a way around a PASSABLE gate -- here it was the only route through an
unpassable one, and the distinction is whether a correct alternative existed. It did not. A gate whose
sole remedy is a sanctioned way around it is the state that manufactures evasion, which is the cost this
module exists to remove.

**EVERY TEST HERE NEEDS TWO INDEPENDENT CHECKOUTS, because one cannot tell the two answers apart.** Run
inside a single repository, "the registry of the tree I live in" and "the registry of the tree being
committed" name the same directory, so the defect is invisible and a passing test proves nothing. The row
recorded both control arms as unachievable; the harness that git-inits two independent checkouts already
existed one module over (``test_script_root_anchoring.py::_coord_checkout``), and the fixture below is
that same construct narrowed to this question.

The row named the two arms it owed, and they are the first tests here: **a claim held by the committing
worktree that MUST pass, and one held elsewhere that MUST fail.** *A gate that cannot demonstrate its own
pass arm has never been shown to have one.*

THE PASS ARM IS TESTED IN BOTH SHAPES THE SECOND REPOSITORY CAN BE IN, deliberately. Whether the vault
carries its own copy of ``claim.ps1`` is a fact this engine checkout cannot establish -- CLAUDE.md limits
reading that tree to ``roles/`` -- so the fix must not depend on which case it is. One test runs the
second repository's OWN copy of the tool; the other runs THIS repository's copy with ``-AsWorktree``.
Both must land one record, in one registry, that the second repository's gate accepts.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_CLAIM = _ROOT / "scripts" / "coord" / "claim.ps1"
_CHECK = _ROOT / "scripts" / "hooks" / "claim_check.py"

#: The config key that makes one registry serve two repositories. Spelled out here as well as in the two
#: scripts because a test that read it from the script under test could not fail when the script renamed
#: it -- the key is a CONTRACT between a tool and a gate that never call each other.
_POINTER = "mefor.claimsRoot"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def _git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True)


def _toplevel(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _checkout(path: Path) -> Path:
    """An independent git repository carrying BOTH halves of the claim machinery.

    Both halves on purpose. The second repository in the real topology runs the gate, and may or may not
    also carry the tool; a fixture that shipped only the gate could not exercise the case where it does,
    which is one of the two shapes the fix has to survive.
    """
    (path / "scripts" / "coord").mkdir(parents=True)
    (path / "scripts" / "hooks").mkdir(parents=True)
    shutil.copy2(_CLAIM, path / "scripts" / "coord" / "claim.ps1")
    shutil.copy2(_CHECK, path / "scripts" / "hooks" / "claim_check.py")
    (path / "code.py").write_text("x = 1\n", encoding="utf-8")
    _git("init", "-b", "main", ".", cwd=path)
    _git("config", "user.email", "t@example.invalid", cwd=path)
    _git("config", "user.name", "T", cwd=path)
    _git("add", "-A", cwd=path)
    _git("commit", "-m", "fixture", "--no-verify", cwd=path)
    return path


@pytest.fixture
def pair(tmp_path: Path) -> tuple[Path, Path]:
    """``(registry_repo, other_repo)`` -- two checkouts that share nothing but the pointer under test."""
    return _checkout(tmp_path / "Engine"), _checkout(tmp_path / "Vault")


def _point_at(repo: Path, registry_repo: Path) -> None:
    _git("config", _POINTER, str(registry_repo), cwd=repo)


def _claim(script_tree: Path, cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
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


def _records(repo: Path) -> list[Path]:
    """Every claim file in ``repo``'s OWN registry -- the directory git would put it in unpointed."""
    return sorted((repo / ".git" / "mefor-coord" / "claims").glob("*.json"))


def _commit_msg_gate(repo: Path, message: str) -> subprocess.CompletedProcess[str]:
    """Drive the REAL hook the way git drives it: argv[1] is the message file, cwd is the committing tree."""
    msg = repo / "COMMIT_EDITMSG.tmp"
    msg.write_text(message, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(repo / "scripts" / "hooks" / "claim_check.py"), str(msg)],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )


def _stage_code(repo: Path) -> None:
    """A staged CODE diff, because the gate exempts documentation-only commits by design."""
    (repo / "code.py").write_text("x = 2\n", encoding="utf-8")
    _git("add", "code.py", cwd=repo)


_SUBJECT = "feat(coord): wire the thing (BACKLOG #1346)"


def test_the_second_repositorys_own_tool_claims_into_the_shared_registry(
    pair: tuple[Path, Path],
) -> None:
    """THE PASS ARM, shape one: the other repository carries its own ``claim.ps1``.

    Unpointed, that copy writes its own tree's registry and its own gate reads the same one, so this shape
    already worked in isolation. What it could NOT do is coordinate -- two repositories claiming into two
    registries is precisely the split the row names, and a key held in one is invisible to the other. So
    the assertion is not merely that the gate passes: it is that the record landed in the ENGINE's
    registry and NOT in the second repository's, because a claim only prevents duplicate work if every
    session that might duplicate it can see it.
    """
    engine, other = pair
    _point_at(other, engine)

    taken = _claim(other, other, "-Take", "1346", "-Note", "shared-registry fixture")
    assert taken.returncode == 0, taken.stderr or taken.stdout

    landed = _records(engine)
    assert [p.name for p in landed] == ["1346.json"], (
        f"the claim did not reach the shared registry:\n{taken.stdout}\n{taken.stderr}"
    )
    assert not _records(other), (
        "a second, private registry was written -- that is the split state this fixes"
    )
    held = json.loads(landed[0].read_text(encoding="utf-8"))["worktree"]
    assert held.replace("\\", "/").casefold() == _toplevel(other).replace("\\", "/").casefold(), (
        f"the record names the wrong holder: {held}"
    )

    _stage_code(other)
    gate = _commit_msg_gate(other, _SUBJECT + "\n")
    assert gate.returncode == 0, (
        f"THE GATE IS STILL UNPASSABLE from the second repository:\n{gate.stderr}\n{gate.stdout}"
    )


def test_this_repositorys_tool_can_hold_a_claim_for_the_second_repository(
    pair: tuple[Path, Path],
) -> None:
    """THE PASS ARM, shape two: the other repository has NO ``claim.ps1`` and runs this one's by path.

    This is the measured shape -- the row records that running the claim tool from a vault worktree
    refreshes the ENGINE record rather than creating a vault one, which is what an engine-anchored script
    does. Anchoring is correct and stays (BACKLOG #1060): what was missing is that one value answered TWO
    questions, *where the registry is* and *who holds the claim*, and across two repositories those
    diverge. ``-AsWorktree`` splits them, explicitly, at the one call site that needs it.
    """
    engine, other = pair
    _point_at(other, engine)

    taken = _claim(
        engine,
        other,
        "-Take",
        "1346",
        "-AsWorktree",
        str(other),
        "-Note",
        "held for the other tree",
    )
    assert taken.returncode == 0, taken.stderr or taken.stdout

    landed = _records(engine)
    assert [p.name for p in landed] == ["1346.json"], taken.stdout
    held = json.loads(landed[0].read_text(encoding="utf-8"))["worktree"]
    assert held.replace("\\", "/").casefold() == _toplevel(other).replace("\\", "/").casefold(), (
        f"-AsWorktree did not move the holder: {held}"
    )

    _stage_code(other)
    gate = _commit_msg_gate(other, _SUBJECT + "\n")
    assert gate.returncode == 0, (
        f"THE GATE IS STILL UNPASSABLE from the second repository:\n{gate.stderr}\n{gate.stdout}"
    )


def test_a_claim_held_by_another_tree_still_fails_from_the_second_repository(
    pair: tuple[Path, Path],
) -> None:
    """THE MUST-FAIL ARM, and it asserts WHICH refusal so it cannot pass for the wrong reason.

    Before the fix this arm was green and blind: the second repository's gate read an EMPTY registry, so
    it refused every commit with 'is NOT CLAIMED' and would have refused this one too. That is a gate
    that cannot see, scoring as a gate that works. Pinning the *text* is what tells the two apart -- the
    refusal must be the one that names the rival holder, which is only reachable once the shared record
    is actually being read.
    """
    engine, other = pair
    _point_at(other, engine)

    taken = _claim(engine, engine, "-Take", "1346", "-Note", "a rival session is on this")
    assert taken.returncode == 0, taken.stderr or taken.stdout

    _stage_code(other)
    gate = _commit_msg_gate(other, _SUBJECT + "\n")
    assert gate.returncode == 1, f"a claim held elsewhere did not block:\n{gate.stdout}"
    assert "claimed by ANOTHER worktree" in gate.stderr, (
        "the gate refused for the WRONG REASON -- it did not read the shared registry at all:\n"
        f"{gate.stderr}"
    )
    assert _toplevel(engine).replace("\\", "/") in gate.stderr.replace("\\", "/"), (
        f"the refusal does not name the rival holder:\n{gate.stderr}"
    )


def test_the_deny_text_hands_over_a_command_that_can_actually_be_run(
    pair: tuple[Path, Path],
) -> None:
    """The remedy a gate prints IS its teaching surface, so it must work where it is printed.

    The unpointed remedy is a repository-RELATIVE path to ``claim.ps1``. Printed in a repository that
    carries no such file, it names nothing, and an operator who follows it lands back at the same refusal
    with no idea why -- which is how a gate teaches evasion rather than the fix. Where the registry is
    shared the gate knows both halves it needs, so it prints the absolute tool and the holder to record.
    """
    engine, other = pair
    _point_at(other, engine)
    _stage_code(other)

    gate = _commit_msg_gate(other, _SUBJECT + "\n")
    assert gate.returncode == 1, gate.stdout
    assert "is NOT CLAIMED" in gate.stderr, gate.stderr

    remedy = gate.stderr.replace("\\", "/")
    engine_fwd = str(engine).replace("\\", "/")
    other_fwd = str(other).replace("\\", "/")

    # QUOTED, and asserted quoted. A Windows checkout path can contain spaces, and an unquoted -File
    # argument binds only its first word -- a remedy that fails on `C:/Program Files/...` is the same
    # defect as one naming a file that does not exist.
    assert f'-File "{engine_fwd}/scripts/coord/claim.ps1"' in remedy, (
        f"the remedy does not name a tool that exists from here:\n{gate.stderr}"
    )
    assert f'-AsWorktree "{other_fwd}"' in remedy, (
        f"the remedy does not say whose name to claim in:\n{gate.stderr}"
    )
    # And the gate must SAY where it looked. The absence of that line is why #1346 stayed invisible: a
    # refusal against a registry in another repository is indistinguishable, from the outside, from an
    # item nobody has claimed.
    assert _POINTER in gate.stderr, gate.stderr
    assert engine_fwd in remedy, gate.stderr


def test_an_unresolvable_pointer_refuses_rather_than_falling_back(
    pair: tuple[Path, Path],
) -> None:
    """FAIL CLOSED. A pointer that cannot be resolved must not degrade into the local registry.

    The quiet fallback is the worse bug, not the safer one. It would send the gate to a directory nothing
    writes, where every claim reads as absent -- so a MISCONFIGURED pointer would present exactly as an
    unclaimed item, and the remedy printed would be the one that cannot work. The same reasoning the file
    already applies to an unreadable git: refusing costs a re-run, passing costs the duplicate build.
    """
    _engine, other = pair
    _git("config", _POINTER, str(other / "no-such-repository"), cwd=other)
    _stage_code(other)

    gate = _commit_msg_gate(other, _SUBJECT + "\n")
    assert gate.returncode == 1, f"an unresolvable pointer was silently ignored:\n{gate.stdout}"
    assert _POINTER in gate.stderr, (
        f"the refusal does not name the setting that caused it:\n{gate.stderr}"
    )


def test_a_repository_with_no_pointer_behaves_exactly_as_before(
    pair: tuple[Path, Path],
) -> None:
    """THE REGRESSION CONTROL, and the reason the shared registry is the option that was taken.

    Every claim in existence is engine-side, so a fix that moved the registry would invalidate all of
    them. This one adds a pointer that is ABSENT by default: with nothing configured, the tool writes its
    own tree and the gate reads its own tree, which is byte-for-byte the behaviour that has always
    shipped. Asserting it here is what makes 'invalidates no existing record' a measurement rather than a
    claim.
    """
    engine, _other = pair

    taken = _claim(engine, engine, "-Take", "1346", "-Note", "ordinary single-repository flow")
    assert taken.returncode == 0, taken.stderr or taken.stdout
    assert [p.name for p in _records(engine)] == ["1346.json"], taken.stdout

    _stage_code(engine)
    gate = _commit_msg_gate(engine, _SUBJECT + "\n")
    assert gate.returncode == 0, f"the unpointed single-repository flow regressed:\n{gate.stderr}"

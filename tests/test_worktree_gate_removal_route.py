# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Rule 3d names the CHECKED removal route, and only where it can reach (vault BACKLOG #1017).

The refusal itself is not in question here and no test in this file moves it: a raw
``git worktree remove`` or ``move`` aimed at a governed worktree is denied exactly as before. What
changed is the text after it. Until 2026-10-04 both deny texts handed the removal to the user. They
now name ``remove.ps1 -Path``, which makes the checks the gate cannot, and say a session may run it.

So the questions are about the TEXT, and each one is asked of every family the rule can meet:

* is the route printed where it reaches, and withheld where it does not;
* does every command the text prints pass this same gate, because a remedy the gate refuses is the
  defect of BACKLOG #1032 over again;
* does the printed line actually remove a finished tree, and leave its branch;
* is ``-Force`` kept out of every command;
* does a ``move`` get words about a move.

**The fixture copies the REAL ``remove.ps1``.** The other gate fixtures build a primary with no
scripts, or with stubs that declare no ``-Path``, and the gate prints the route only when the
governed primary's script declares it. Those fixtures therefore drive the fallback text, which is
why they stayed green; this one drives the new text.

Harness note, the same one ``tests/test_worktree_gate_remedy_families.py`` carries: ``run_gate``
passes no ``cwd=``, so every path here is absolute.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_worktree_gate import assert_denied, bash, run_gate
from tests.test_worktree_gate_emitter import _outside_single_quotes
from tests.test_worktree_remove_path import REAL_SCRIPTS, settle_worktrees, write_registry

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh (PowerShell 7) and git on PATH",
)

_REPO = Path(__file__).resolve().parents[1]

# A command-form line, by the gate's own definition: Protect-CommandLines sweeps exactly these.
_COMMAND_LINE = re.compile(r"^\s{4,}(?:pwsh|git)\s")

_FAMILIES = ("sibling", "other", "managed")

_ENV = {k: v for k, v in os.environ.items() if not k.upper().startswith("GIT_")}


def _git(*args: str, cwd: Path | None = None) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
        env=_ENV,
    )
    return proc.stdout


def _build(tmp: Path, remove_ps1: str | None) -> SimpleNamespace:
    """A governed primary whose path CONTAINS A SPACE, with one worktree of each family.

    ``remove_ps1`` is the text of the primary's ``scripts/worktree/remove.ps1``, or None to copy the
    real one with the two scripts it dot-sources. The space is there for the reason
    ``tests/test_worktree_gate_emitter.py`` gives: without it every quoting assertion passes by accident.
    """
    primary = tmp / "Pri mary"
    _git("init", "-q", "-b", "main", str(primary))
    _git("config", "user.email", "t@example.invalid", cwd=primary)
    _git("config", "user.name", "t", cwd=primary)
    _git("config", "commit.gpgsign", "false", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    # The scripts are COMMITTED, so every worktree is clean and the checked route has nothing to refuse.
    if remove_ps1 is None:
        for rel in REAL_SCRIPTS:
            dest = primary / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(_REPO / rel, dest)
    else:
        dest = primary / "scripts" / "worktree" / "remove.ps1"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(remove_ps1, encoding="utf-8")
    _git("add", "-A", cwd=primary)
    _git("commit", "-q", "-m", "seed", cwd=primary)

    sibling = tmp / "Pri mary-wt"
    _git("worktree", "add", "-q", "-b", "sib-branch", str(sibling), cwd=primary)
    other = tmp / "scratch pad" / "pad"
    _git("worktree", "add", "-q", "-b", "pad-branch", str(other), cwd=primary)
    managed = primary / ".claude" / "worktrees" / "cm"
    _git("worktree", "add", "-q", "-b", "cm-branch", str(managed), cwd=primary)

    repos = tmp / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(
        tmp=tmp,
        primary=primary,
        sibling=sibling,
        other=other,
        managed=managed,
        repos=repos,
        denies={},
    )


@pytest.fixture(scope="module")
def repo(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    """MODULE-SCOPED AND READ-ONLY: every test using it feeds a payload to the hook, which denies
    before git runs. The one test that really removes a worktree builds its own."""
    # The directory name is deliberately free of "remov": one test below searches a move's text for
    # removal wording, and the text echoes this path.
    return _build(tmp_path_factory.mktemp("route_text"), None)


def _deny(repo: SimpleNamespace, family: str, standing_in: str, verb: str = "remove") -> str:
    """The deny text for one (family, standing, verb), from a REAL hook run, remembered per rig.

    The hook is deterministic for a fixed payload and nothing here changes a rig after it is built,
    so there are twelve distinct texts for the shared rig and the tests ask for them about seventy
    times. Each launch costs seconds on the Windows leg. The cache lives ON the rig, so a rig a test
    builds for itself never reads another's.
    """
    key = (family, standing_in, verb)
    if key not in repo.denies:
        victim = getattr(repo, family)
        cwd = victim if standing_in == "victim" else repo.primary
        tail = ' "../elsewhere"' if verb == "move" else ""
        repo.denies[key] = assert_denied(
            run_gate(bash(f'git worktree {verb} "{victim}"{tail}', cwd=cwd), repo.repos)
        )
    text: str = repo.denies[key]
    return text


def _command_lines(reason: str) -> list[str]:
    return [ln.strip() for ln in reason.splitlines() if _COMMAND_LINE.match(ln)]


def _fold(text: str) -> str:
    """git prints forward slashes on Windows and pathlib prints backslashes. Same path, two spellings."""
    return text.replace("\\", "/").casefold()


def _path_lines(reason: str) -> list[str]:
    return [ln for ln in _command_lines(reason) if re.search(r"remove\.ps1'\s+-Path\s+'", ln)]


# ------------------------------------------------------------------ where the route is printed


@pytest.mark.parametrize("standing_in", ["victim", "primary"])
@pytest.mark.parametrize("family", ["sibling", "other"])
def test_the_checked_route_is_printed_for_a_tree_it_reaches(
    repo: SimpleNamespace, family: str, standing_in: str
) -> None:
    victim = getattr(repo, family)
    reason = _deny(repo, family, standing_in)

    lines = _path_lines(reason)
    assert len(lines) == 1, f"expected exactly one -Path line:\n{reason}"
    line = lines[0]
    # The script named is the GOVERNED PRIMARY's, never the reader's own copy.
    assert _fold(str(repo.primary / "scripts" / "worktree" / "remove.ps1")) in _fold(line), line
    # The target is the victim itself, already resolved: nothing is left for the reader to substitute.
    assert _fold(f"-Path '{victim}'") in _fold(line), line
    # The sibling's old `-Name` line is gone: the checked route replaced it, and it has the fence.
    # Asked of the command lines only: the prose names `remove.ps1 -Name <dir> -DeleteBranch` as the
    # separate act that deletes a branch.
    assert not [ln for ln in _command_lines(reason) if re.search(r"remove\.ps1'\s+-Name", ln)]
    assert "never the branch" in reason


@pytest.mark.parametrize("standing_in", ["victim", "primary"])
def test_a_tree_under_claude_worktrees_gets_no_command_and_is_told_why(
    repo: SimpleNamespace, standing_in: str
) -> None:
    """The batch 184 decision, kept in the text: the occupancy check cannot see a subagent there, so
    the route is not offered. The engine's script would refuse the line anyway; printing it would be
    a remedy that throws."""
    reason = _deny(repo, "managed", standing_in)

    assert not _path_lines(reason), reason
    assert not [ln for ln in _command_lines(reason) if "remove.ps1" in ln], reason
    assert not [ln for ln in _command_lines(reason) if "prune-merged.ps1" in ln], reason
    assert "THIS GATE NAMES NO SCRIPT FOR THIS TREE" in reason
    assert ".claude/worktrees" in reason
    # Control for the three absences above: the same rule DOES print the route one family over.
    assert _path_lines(_deny(repo, "other", standing_in))


def test_the_primary_itself_gets_no_command_because_nothing_removes_it(
    repo: SimpleNamespace,
) -> None:
    """The script refuses the primary by name, so the -Path line for it would be a dead end: a remedy
    that cannot work. Asked from a linked worktree, where the primary is "not the tree you are in"."""
    reason = assert_denied(
        run_gate(bash(f'git worktree remove "{repo.primary}"', cwd=repo.other), repo.repos)
    )

    assert "NOT the tree" in reason
    assert not _path_lines(reason), reason
    assert not [ln for ln in _command_lines(reason) if "remove.ps1" in ln], reason
    assert "THIS IS THE PRIMARY CHECKOUT, AND NOTHING REMOVES IT" in reason
    # Control: the same question about a linked worktree, from the same place, prints the route.
    assert _path_lines(_deny(repo, "sibling", "primary"))


def test_the_sibling_family_still_gets_the_dry_run_tool_and_the_others_do_not(
    repo: SimpleNamespace,
) -> None:
    sibling = _deny(repo, "sibling", "primary")
    assert [ln for ln in _command_lines(sibling) if "prune-merged.ps1" in ln], sibling
    for family in ("other", "managed"):
        reason = _deny(repo, family, "primary")
        assert not [ln for ln in _command_lines(reason) if "prune-merged.ps1" in ln], reason


# ------------------------------------------------------------------ what the text now says


@pytest.mark.parametrize("family", _FAMILIES)
def test_the_removal_is_no_longer_handed_to_the_user_where_a_route_exists(
    repo: SimpleNamespace, family: str
) -> None:
    """The posture BACKLOG #1294 shipped with, reversed for removal by the owner on 2026-10-04."""
    reason = _deny(repo, family, "primary")

    for retired in ("it is not yours to run", "that is the user's call, not yours"):
        assert retired not in reason, f"the retired sentence is back: {retired!r}\n{reason}"
    if family == "managed":
        assert "is the user's decision" in reason
    else:
        assert "a session may run it" in reason
        assert "IF THE SCRIPT REFUSES, STOP" in reason
        assert "final for a session" in reason


@pytest.mark.parametrize("verb", ["remove", "move"])
@pytest.mark.parametrize("standing_in", ["victim", "primary"])
@pytest.mark.parametrize("family", _FAMILIES)
def test_no_command_the_text_prints_carries_force_or_a_raw_worktree_verb(
    repo: SimpleNamespace, family: str, standing_in: str, verb: str
) -> None:
    """-Force stays the user's, so it is never printed as a command. The property is "no runnable
    line", not "the word never appears": the text SAYS -Force is the user's switch, and an assertion
    that cannot tell that sentence from an offer would push the fix toward deleting the warning."""
    reason = _deny(repo, family, standing_in, verb)

    for line in _command_lines(reason):
        assert "-Force" not in line and "--force" not in line, line
        assert "-AllowOrphanedAllocations" not in line, line
        assert "-DeleteBranch" not in line, line
        assert not re.search(r"worktree\s+(remove|move)", line), (
            f"a raw git worktree verb was printed as a command; this rule refuses it:\n{line}"
        )
    # No BARE carriage return. The old removal text carried one: a single backtick before
    # `remove.ps1` in an expandable here-string is the escape for CR. A CR that is half of a CRLF is
    # only the gate file's own line ending on a Windows checkout, so it is not counted.
    assert not re.search(r"\r(?!\n)", reason), reason


def test_the_backticked_names_print_as_written(repo: SimpleNamespace) -> None:
    reason = _deny(repo, "sibling", "primary")
    assert "`remove.ps1 -Name <dir> -DeleteBranch`" in reason, reason
    assert "`git worktree remove` does not touch the" in reason, reason


# ------------------------------------------------------------------ every printed command passes the gate


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_every_command_rule_3d_prints_passes_this_same_gate(
    repo: SimpleNamespace, tool: str
) -> None:
    """A remedy this gate would refuse is a refusal the reader cannot act on. Every command-form line
    in every deny, both verbs, both standings, every family, is fed back through the hook."""
    scanned: list[str] = []
    where: dict[str, str] = {}
    for family in _FAMILIES:
        for standing_in in ("victim", "primary"):
            for verb in ("remove", "move"):
                for line in _command_lines(_deny(repo, family, standing_in, verb)):
                    scanned.append(f"[{family}/{standing_in}/{verb}] {line}")
                    where.setdefault(line, scanned[-1])
    # The walk below must have something to walk, or "nothing was refused" is true of nothing. Three
    # is the floor: a -Path line, the prune-merged.ps1 line and the `worktree list` line.
    assert len(where) >= 3, "the deny texts printed too few command lines:\n" + "\n".join(scanned)
    # Each DISTINCT line once: the same `worktree list` line is printed by six of the texts.
    # From the PRIMARY: the route must run from outside the tree it removes.
    refused = [
        label
        for line, label in where.items()
        if run_gate(bash(line, cwd=repo.primary, tool=tool), repo.repos) is not None
    ]

    kinds = {
        "path": any("remove.ps1' -Path" in s for s in scanned),
        "prune": any("prune-merged.ps1" in s for s in scanned),
        "list": any("worktree list" in s for s in scanned),
    }
    assert all(kinds.values()), f"the scan missed a kind of line: {kinds}\n" + "\n".join(scanned)
    assert not refused, "the gate refused a command its own deny text printed:\n" + "\n".join(
        refused
    )

    # CONTROL, so the empty list above is a measurement. The raw git form of the same removal, quoted
    # the same way and sent from the same place, is still denied.
    raw = f"git -C '{repo.primary}' worktree remove '{repo.other}'"
    assert_denied(run_gate(bash(raw, cwd=repo.primary, tool=tool), repo.repos))


def test_no_metacharacter_reaches_a_command_line_outside_a_quoted_span(
    repo: SimpleNamespace,
) -> None:
    """The emitter suite's structural check, with ITS scanner, run over the text its stub fixtures
    cannot reach. That scanner has its own positive control in the emitter suite."""
    scanned = 0
    for family in _FAMILIES:
        for standing_in in ("victim", "primary"):
            for line in _command_lines(_deny(repo, family, standing_in)):
                scanned += 1
                exposed = {line[i] for i in _outside_single_quotes(line)}
                assert not exposed & set('$`;|&"'), f"outside a quoted span in: {line}"
                assert line.count("'") % 2 == 0, f"unbalanced quote in: {line}"
    assert scanned >= 6, f"only {scanned} command lines were scanned"


# ------------------------------------------------------------------ the printed line WORKS


@pytest.mark.skipif(os.name != "nt", reason="the occupancy fence reads USERPROFILE")
def test_the_printed_line_removes_a_finished_tree_and_leaves_its_branch(tmp_path: Path) -> None:
    """THE HEADLINE. The line is taken from the deny text and run exactly as printed, against the real
    script, from the primary. Its own fixture, because this one really removes a worktree."""
    rig = _build(tmp_path, None)
    home = write_registry(tmp_path, tmp_path / "home")
    tip = _git("rev-parse", "refs/heads/pad-branch", cwd=rig.primary).strip()

    reason = _deny(rig, "other", "primary")
    (line,) = _path_lines(reason)
    script = tmp_path / "run-printed-line.ps1"
    # `exit $LASTEXITCODE` is load-bearing: without it `pwsh -File` returns 0 even when the script it
    # launched refused.
    script.write_text(line.strip() + "\nexit $LASTEXITCODE\n", encoding="utf-8")
    # The route refuses a tree git wrote to inside its quiet period, and this one is seconds old.
    # "Finished" includes "has been quiet", so the fixture dates its git state two days back.
    settle_worktrees(rig.primary)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        cwd=str(rig.primary),
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
        env={**_ENV, "USERPROFILE": str(home)},
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not rig.other.exists()
    assert _git("rev-parse", "refs/heads/pad-branch", cwd=rig.primary).strip() == tip
    # Control: the route is not a blanket delete. The other two trees are exactly where they were.
    assert rig.sibling.exists() and rig.managed.exists()


# ------------------------------------------------------------------ a primary that predates the route

_NO_PATH_PARAMETER = "param([string]$Name, [switch]$Force)\nexit 0\n"
# The parameter is named only inside a COMMENT. A text search would find it; the parser does not.
_PATH_ONLY_IN_A_COMMENT = "param(\n    # [string]$Path,\n    [string]$Name\n)\nexit 0\n"
# It declares -Path and does not parse, so nothing it declares can be trusted.
_DECLARES_PATH_BUT_DOES_NOT_PARSE = "param([string]$Path, [string]$Name\nexit 0\n"


@pytest.mark.parametrize(
    "remove_ps1",
    [_NO_PATH_PARAMETER, _PATH_ONLY_IN_A_COMMENT, _DECLARES_PATH_BUT_DOES_NOT_PARSE],
    ids=["no-path-parameter", "path-only-in-a-comment", "does-not-parse"],
)
def test_a_primary_whose_script_predates_the_route_is_not_handed_the_command(
    tmp_path: Path, remove_ps1: str
) -> None:
    """The installed hook is decoupled from the checkout it names. Printing ``-Path`` against a
    script that does not declare it hands the reader a line that dies at parameter binding."""
    rig = _build(tmp_path, remove_ps1)

    other = _deny(rig, "other", "primary")
    assert not _path_lines(other), other
    assert not [ln for ln in _command_lines(other) if "remove.ps1" in ln], other
    assert "predates" in other and "THERE IS NO CHECKED ROUTE FOR THIS TREE YET" in other
    # The three variants differ only in what the probe parses, and every text below hangs off that one
    # answer. So the other two texts are read once, for the first variant.
    if remove_ps1 is not _NO_PATH_PARAMETER:
        return

    sibling = _deny(rig, "sibling", "primary")
    assert not _path_lines(sibling), sibling
    assert "predates" in sibling
    # The sibling's own-tree text keeps the one line the older script does accept.
    own = _deny(rig, "sibling", "victim")
    assert re.search(r"remove\.ps1'\s+-Name\s+'wt'", own), own


def test_the_fallback_fixtures_above_differ_from_the_real_script_only_in_the_route(
    repo: SimpleNamespace,
) -> None:
    """Non-vacuity for the test above: with the REAL script in place the same call prints the route,
    so "no -Path line" there was the probe answering, not a text that never prints one."""
    reason = _deny(repo, "other", "primary")
    assert _path_lines(reason)
    assert "predates" not in reason


# ------------------------------------------------------------------ move is not removal


@pytest.mark.parametrize("standing_in", ["victim", "primary"])
@pytest.mark.parametrize("family", _FAMILIES)
def test_a_move_is_described_as_a_move(
    repo: SimpleNamespace, family: str, standing_in: str
) -> None:
    reason = _deny(repo, family, standing_in, "move")
    removal = _deny(repo, family, standing_in, "remove")

    assert reason != removal
    assert "git worktree move" in reason
    assert "moved" in reason
    # Everything after the echoed command. The echo quotes the caller's own words back, and a
    # fixture path is free to contain any of the needles below.
    body = reason.split("\n", 1)[1].casefold()
    for needle in ("remov", "branch survives", "deletebranch", "prune-merged", "remove.ps1"):
        assert needle not in body, (
            f"a move was described with removal wording ({needle!r}):\n{reason}"
        )
    if standing_in == "victim":
        assert "THE WORKTREE THIS SESSION IS RUNNING IN" in reason
    else:
        assert "NOT the tree" in reason and "cannot tell" in reason

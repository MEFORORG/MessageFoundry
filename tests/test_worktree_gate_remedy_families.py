# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Rule 3d's deny must name a remedy that can actually reach the worktree it refused (BACKLOG #1057).

The refusal itself is not in question here and none of these tests touch it. What is in question is the
sentence after it: a caller who is told "no" is handed a command to run instead, and for the population
that most often reaches this rule that command *throws*.

* ``remove.ps1 -Name <dir>`` resolves to ``<repo-parent>/<repo-leaf>-<Name>`` and refuses anything else.
  ``new.ps1`` ASSERTS that shape after deriving it, so the ``<primary>-<name>`` sibling family is the only
  one it can produce and the only one ``remove.ps1`` can resolve.
* ``prune-merged.ps1`` excludes anything with a ``.claude/worktrees/`` path segment OUTRIGHT -- its own
  header says so, and ``-Name`` cannot reach them either. That exclusion is deliberate: those are the
  trees a live session gets relocated into.

Census on this clone 2026-08-06: 45 sibling worktrees, 8 Claude-managed, 4 other -- and all six live
sessions sat in the 8. So the remedy failed for the population that actually hits the rule.

**Same defect as BACKLOG #1032, one rule over.** There, rule 3b printed a ``new.ps1`` command that
``new.ps1`` refuses to run. A refusal the reader cannot act on is the standing invitation to route around
the guard, which costs more than the refusal it was trying to buy.

**The headline test asserts the remedy is RUNNABLE, not that a particular string is absent.** Checking
for the absence of ``prune-merged.ps1`` would pass the moment someone swapped in a different unusable
command. Extracting the ``-Name`` argument the deny actually printed and asserting the path it resolves
to exists is the assertion that would have caught this without knowing the fix.

**Harness note, so nobody re-derives it.** ``run_gate`` calls ``subprocess.run`` with no ``cwd=``, so the
hook process cwd is pytest's while the payload cwd is a tmp_path. Any rule resolving a RELATIVE path
against the process cwd behaves differently here than in production -- a red test written that way pins
the harness, which happened in this repo and was retracted after four verifiers refuted it. These tests
are immune: every path in them is absolute, and the classification under test reads the victim's absolute
``--show-toplevel``.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh (PowerShell 7) and git on PATH",
)


def shell(command: str, cwd: Path | str) -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    """A governed primary with one worktree of EACH family.

    ``sibling`` is what new.ps1 produces and what remove.ps1 can resolve. ``managed`` is where the
    Claude Code harness puts a session, and is the family both remedy tools refuse.
    """

    def git(*args: str, cwd: Path | None = None) -> None:
        subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
        )

    primary = tmp_path / "Primary"
    git("init", "-b", "main", str(primary))
    git("config", "user.email", "t@example.com", cwd=primary)
    git("config", "user.name", "t", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "-A", cwd=primary)
    git("commit", "-m", "seed", cwd=primary)

    sibling = tmp_path / "Primary-wt"
    git("worktree", "add", "-b", "sib-branch", str(sibling), cwd=primary)

    managed = primary / ".claude" / "worktrees" / "cm"
    git("worktree", "add", "-b", "cm-branch", str(managed), cwd=primary)

    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(primary=primary, sibling=sibling, managed=managed, repos=repos)


def _remedy(reason: str) -> str:
    """Only the lines AFTER "What to do instead:". The echoed command at the top is not a remedy.

    THIS SCOPING IS LOAD-BEARING AND ITS ABSENCE ALREADY PRODUCED A FALSE GREEN. Every rule 3d deny
    opens by quoting the command back: ``BLOCKED: 'git worktree remove <path>' acts on ...``. Searching
    the WHOLE reason for a runnable ``git ... worktree remove`` therefore matches the refusal's own echo,
    and the own-tree case for the Claude-managed family went green over a deny that offered nothing
    runnable at all. Measured on the unfixed gate while writing these tests.
    """
    _, sep, tail = reason.partition("What to do instead:")
    return tail if sep else ""


def _remove_ps1_targets(remedy: str, primary: Path) -> list[Path]:
    """Every path a `remove.ps1 -Name X` line would actually act on.

    ``\\S+`` rather than a name charset ON PURPOSE, so the placeholder the gate prints today
    (``-Name <directory-name>``) is CAUGHT and resolves to a path that does not exist. A remedy the
    caller cannot paste and run is not a remedy; making the regex skip placeholders would define the
    defect out of the test.
    """
    parent, leaf = primary.parent, primary.name
    return [parent / f"{leaf}-{m}" for m in re.findall(r"remove\.ps1\s+-Name\s+(\S+)", remedy)]


@pytest.mark.parametrize("standing_in", ["victim", "primary"])
@pytest.mark.parametrize("family", ["sibling", "managed"])
def test_the_remedy_rule_3d_prints_can_actually_reach_the_worktree(
    repo: SimpleNamespace, family: str, standing_in: str
) -> None:
    """THE HEADLINE. Both deny branches, both families: whatever command the deny names must work.

    Parametrised over where the session is standing because rule 3d has two branches -- "this IS your own
    tree" and "this is not" -- and the defect was in BOTH. A test covering one branch would have gone
    green over a remedy that still threw on the other.
    """
    victim = getattr(repo, family)
    cwd = victim if standing_in == "victim" else repo.primary
    reason = assert_denied(run_gate(shell(f'git worktree remove "{victim}"', cwd=cwd), repo.repos))
    remedy = _remedy(reason)
    assert remedy, "every deny must offer something; there is no 'What to do instead:' section"

    for target in _remove_ps1_targets(remedy, repo.primary):
        assert target.exists(), (
            f"the deny offered `remove.ps1 -Name` resolving to {target}, which does not exist -- "
            f"running it throws 'No such worktree'. Victim was {victim}"
        )

    if family == "managed":
        # Neither script can serve this family: prune-merged.ps1 excludes the path segment outright
        # (its own header says so) and remove.ps1 -Name cannot resolve a path outside <primary>-*.
        #
        # THE PROPERTY IS "NO RUNNABLE INVOCATION", NOT "THE NAME NEVER APPEARS" -- the same distinction
        # test_coord_claim_liveness.py already draws for -Force, and for the same reason. The remedy
        # deliberately says prune-merged.ps1 CANNOT help here, so a bare token search fails on the
        # prohibition itself. An assertion that a warning about a tool is indistinguishable from an offer
        # of it is measuring the wrong thing, and it would push the fix toward deleting the warning.
        assert not re.search(r"pwsh[^\n]*prune-merged\.ps1", remedy), (
            "prune-merged.ps1 was offered as a command; it skips anything under .claude/worktrees"
        )
        assert not re.search(r"pwsh[^\n]*remove\.ps1", remedy), (
            "remove.ps1 was offered as a command; -Name cannot resolve outside <primary>-<name>"
        )
        # ...so the remedy must contain a literal git command, and it must NAME THE VICTIM, which is
        # what distinguishes an offered route from the refusal quoting itself back.
        #
        # Separators folded on both sides: `git rev-parse --show-toplevel` returns FORWARD slashes on
        # Windows while pathlib renders backslashes, so a literal compare fails on a path that is
        # correct. Folding is the honest compare here -- it is the same path, differently spelled.
        assert re.search(r"worktree\s+remove", remedy), (
            "a family neither script can reach still needs a runnable route"
        )
        assert str(victim).replace("\\", "/").casefold() in remedy.replace("\\", "/").casefold(), (
            f"the route must NAME the victim, not leave it to be substituted: {victim}\n{remedy}"
        )


def test_the_sibling_family_keeps_the_tooling_it_has(repo: SimpleNamespace) -> None:
    """Non-vacuity for the test above. The fix must NOT become 'stop naming the scripts'.

    prune-merged.ps1 is dry-run-by-default and consults occupancy; for the family it does cover it is a
    strictly better answer than a bare `git worktree remove`, and losing it would trade one unusable
    remedy for another.
    """
    reason = assert_denied(
        run_gate(shell(f'git worktree remove "{repo.sibling}"', cwd=repo.primary), repo.repos)
    )
    own = assert_denied(
        run_gate(shell(f'git worktree remove "{repo.sibling}"', cwd=repo.sibling), repo.repos)
    )
    assert own != reason, "the two branches must stay distinguishable"
    assert "prune-merged.ps1" in _remedy(reason), (
        "the family prune-merged.ps1 DOES cover must keep being sent there -- it is dry-run by default "
        "and consults occupancy, which a bare `git worktree remove` does not"
    )
    targets = _remove_ps1_targets(_remedy(own), repo.primary)
    assert targets, "the own-tree branch must still offer remove.ps1 for the family it can resolve"
    assert targets == [repo.sibling], (
        f"remove.ps1 -Name must name the ACTUAL directory, not a placeholder: got {targets}"
    )


def test_a_junction_spelling_of_a_sibling_fails_toward_the_universal_remedy(
    repo: SimpleNamespace, tmp_path: Path
) -> None:
    """The classifier's failure DIRECTION, pinned rather than asserted in a comment.

    A junction or UNC spelling can break the `<primary>-<name>` prefix match. That misclassifies a
    sibling as 'other', and the 'other' remedy is a literal `git worktree remove <abs path>` -- valid for
    every family, siblings included. So the failure costs a less idiomatic suggestion and nothing else.

    The dangerous direction is the opposite: a non-sibling classified AS sibling emits a `remove.ps1
    -Name` that throws. That needs a path to SPURIOUSLY match the prefix, which an unresolved junction
    makes less likely rather than more. Unlike rule 3c, no security decision rides on this -- the refusal
    is unchanged and only the remedy string branches.
    """
    # `cmd` exists only on Windows, and a returncode guard cannot express that: on Linux
    # subprocess.run RAISES FileNotFoundError before there is a returncode to inspect, so the test
    # ERRORS instead of skipping. Gate on the platform first -- the same shape rule 3d's own comment
    # records, where a construct "passed on Windows and failed on the Linux CI leg". OSError is still
    # caught because `cmd` existing does not mean junction creation is permitted.
    if os.name != "nt":
        pytest.skip(
            "junctions are a Windows filesystem feature; `cmd /c mklink` does not exist here"
        )
    link = tmp_path / "viajunction"
    try:
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(repo.sibling)],
            capture_output=True,
            text=True,
        )
    except OSError as exc:  # cmd present but unusable
        pytest.skip(f"could not invoke mklink: {exc}")
    if made.returncode != 0:
        pytest.skip(f"could not create a junction: {made.stderr or made.stdout}")

    reason = assert_denied(
        run_gate(shell(f'git worktree remove "{link}"', cwd=repo.primary), repo.repos)
    )
    remedy = _remedy(reason)
    for target in _remove_ps1_targets(remedy, repo.primary):
        assert target.exists(), f"junction spelling produced an unrunnable remedy: {target}"
    # Non-vacuity: the assertion above is satisfied by an empty list, so pin that SOMETHING runnable was
    # offered. Either classification is acceptable here -- what must not happen is a remedy that throws.
    assert re.search(r"worktree\s+remove|remove\.ps1|prune-merged\.ps1", remedy), (
        f"junction spelling produced a deny with no route at all:\n{remedy}"
    )

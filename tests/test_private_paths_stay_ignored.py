# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #327 — the private-path `.gitignore` rules are a control, so they get a test.

Since the publish deny-list was retired, **the `.gitignore` rules are the sole mechanism** keeping
maintainer-internal material out of a public commit. Nothing asserted they still match anything: a
repo-wide search for `check-ignore` found one hand-run script covering a different file, and the two
nearest-looking guards (`test_scaffold.py`, `test_leak_gate_docs.py`) are about a scaffolded config
repo and about prose, not about this repo's ignore rules.

So the boundary was defended by review attention plus a hook living inside the now-ignored `/.claude/`
tree — which no fresh clone gets. A rule deleted, narrowed, or negated by a later `!` line would have
been caught by nobody.

**The list is PINNED here, not parsed out of `.gitignore`.** Guarding a file by reading that same file
is how this repo already burned itself: the guard and the guarded move together, so the test rewrites
its own expectation and stays green through the deletion it exists to catch. If you add a private path,
add it here too — that edit is the point, not an inconvenience.

Each rule is asserted in BOTH directions, because either half alone can pass for the wrong reason:
  (a) a synthetic probe path under the rule IS ignored — proves the rule still matches something;
  (b) nothing under the rule is TRACKED — proves nothing slipped in before the rule existed, which
      `check-ignore` cannot tell you (git ignores nothing that is already tracked).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]

# The private-path rules, verbatim from .gitignore's publishing-boundary block, each with a probe
# path that must fall under it. Pinned deliberately — see the module docstring.
_PRIVATE_PATHS: list[tuple[str, str]] = [
    ("/.claude/*", ".claude/probe-327.md"),
    ("/TRANSCRIPTS.md", "TRANSCRIPTS.md"),
    ("/docs/security/", "docs/security/probe-327.md"),
    ("/docs/reviews/", "docs/reviews/probe-327.md"),
    ("/docs/marketing/", "docs/marketing/probe-327.md"),
    ("/docs/CI-TOPOLOGY.md", "docs/CI-TOPOLOGY.md"),
    # ADR 0160 D1, owner-authorised 2026-08-31. Business material and internal engineering records.
    # Unlike the rules above these were never confidential and are not being withheld as secrets --
    # `git log` still holds every one of them, and the owner ruled explicitly against a history
    # rewrite. They are pinned here for the same reason as the rest: the .gitignore rule is the only
    # thing keeping them out of the next commit, and a rule nothing asserts is a rule that can be
    # narrowed by accident.
    ("/docs/BRAND.md", "docs/BRAND.md"),
    ("/docs/CONTRIBUTOR-FIRST-ISSUES.md", "docs/CONTRIBUTOR-FIRST-ISSUES.md"),
    ("/docs/CONTRIBUTOR-PROGRAM-PLAN.md", "docs/CONTRIBUTOR-PROGRAM-PLAN.md"),
    ("/docs/COUNSEL-ENGAGEMENT-BRIEF.md", "docs/COUNSEL-ENGAGEMENT-BRIEF.md"),
    ("/docs/DUAL_LICENSING_PLAN.md", "docs/DUAL_LICENSING_PLAN.md"),
    ("/docs/POSITIONING.md", "docs/POSITIONING.md"),
    ("/docs/research/", "docs/research/probe-0160.md"),
    ("/docs/archive/throughput/", "docs/archive/throughput/probe-0160.md"),
    # Contents-glob, not a directory rule, so the VERIFY.md negation below can bind. See .gitignore.
    ("/docs/testing/*", "docs/testing/probe-0160.md"),
]

# The ONE negated path in the block, and the only tracked file any private rule may cover.
#
# `/.claude/` became `/.claude/*` plus `!/.claude/settings.json` so the enforced controls -- the
# deny-list, and whatever matchers the file wires -- reach a fresh clone and every
# `git worktree add`, which deliver tracked files only. Before that, this repo's own #327 note
# recorded `block-blanket-git-stage.ps1` as one that "does not actually travel".
#
# #327's CAUSE WAS REMOVED AND ITS SYMPTOM WAS NOT, so do not read this rule as covering that
# guard. Tracking the file fixed "does not reach a fresh clone"; the script is still referenced by
# NO matcher in it, so tracking carries it as a FILE and not as a wired control. Measured and
# asserted in tests/test_claude_settings_contract.py, BACKLOG #1339.
#
# This is an exact SET, not a floor. Adding a second negation to the block -- `.claude/rules/`,
# `.claude/skills/`, an agent definition, anything -- fails here until someone writes it down, and
# `.claude/worktrees/` reaching this set would publish full nested checkouts.
_TRACKED_EXCEPTIONS: dict[str, frozenset[str]] = {
    "/.claude/*": frozenset({".claude/settings.json"}),
    # docs/testing/VERIFY.md is OPERATOR material and stays tracked while the rest of the tree does
    # not. It documents `messagefoundry verify`, the wheel-only on-box acceptance check a deployment
    # runs, and docs/README.md lists it as step 6 of "Start here -- a new operator, in order" while
    # line 8 warns that it "is an operator tool, not a test plan". Its siblings are maintainer QA:
    # two drafts awaiting owner approval, and a matrix and plan scoped to one specific build box.
    "/docs/testing/*": frozenset({"docs/testing/VERIFY.md"}),
}


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", *args], cwd=_ROOT, capture_output=True, text=True, encoding="utf-8"
    )


@pytest.mark.parametrize(("rule", "probe"), _PRIVATE_PATHS, ids=[r for r, _ in _PRIVATE_PATHS])
def test_private_path_is_still_ignored(rule: str, probe: str) -> None:
    """(a) The rule still MATCHES. A deleted or narrowed rule fails here.

    `check-ignore` is asked about a path that need not exist, which is what makes this a test of the
    RULE rather than of the working tree — it stays honest in a clone that has never held these files.
    """
    res = _git("check-ignore", "-q", "--no-index", probe)
    assert res.returncode == 0, (
        f"{probe!r} is NOT ignored — the .gitignore rule {rule!r} no longer covers it.\n"
        "These rules are the only thing keeping maintainer-internal material out of a public commit. "
        "If this rule moved, update _PRIVATE_PATHS here in the SAME commit; if it was removed, that "
        "is the publishing boundary coming down and it needs an explicit decision, not a green test."
    )


@pytest.mark.parametrize(("rule", "probe"), _PRIVATE_PATHS, ids=[r for r, _ in _PRIVATE_PATHS])
def test_nothing_under_a_private_path_is_tracked(rule: str, probe: str) -> None:
    """(b) Nothing under the rule is TRACKED — the half `check-ignore` cannot answer.

    Git does not ignore a file it is already tracking, so a path committed before its rule landed
    stays tracked forever and `check-ignore` will still cheerfully report it as ignored. Ignoring and
    not-publishing are different properties; this asserts the second one.

    Asserted as an exact SET against `_TRACKED_EXCEPTIONS`, which is empty for every rule but the
    `.claude/` one. A floor ("at least these are absent") would pass while a new negation quietly
    published a second file; the set makes each addition a deliberate, reviewed edit.
    """
    pathspec = rule.rstrip("*").lstrip("/")
    res = _git("ls-files", "--", pathspec)
    tracked = {ln for ln in res.stdout.splitlines() if ln.strip()}
    expected = _TRACKED_EXCEPTIONS.get(rule, frozenset())
    assert tracked == expected, (
        f"the tracked set under the private rule {rule!r} is not what _TRACKED_EXCEPTIONS pins.\n"
        f"  expected: {sorted(expected) or '(nothing)'}\n"
        f"  actual:   {sorted(tracked) or '(nothing)'}\n"
        "A file that appears here publishes. A file that disappears means a control stopped "
        "travelling to fresh clones and worktrees. Either way, update this pin in the SAME commit "
        "or revert the change -- git does not ignore what it already tracks."
    )


def test_the_pinned_list_has_not_silently_shrunk() -> None:
    """A liveness receipt: the parametrised tests above pass just as well over an empty list.

    Deleting an entry from `_PRIVATE_PATHS` would delete its coverage and turn this file green, which
    is the same shape as the defect it guards. The count is asserted so that removal has to be
    deliberate and reviewed rather than incidental.
    """
    assert len(_PRIVATE_PATHS) == 15, (
        f"_PRIVATE_PATHS holds {len(_PRIVATE_PATHS)} rules, expected 15. Adding a private path is "
        "fine — raise this number in the same commit. Removing one means the publishing boundary "
        "narrowed, which is a decision, not a cleanup."
    )


def test_the_negation_re_includes_exactly_one_file() -> None:
    """The `!` line is load-bearing on a public repo, and it is one character from being a no-op.

    Written as `/.claude/` the directory itself would be excluded, and git cannot re-include a file
    whose parent directory is excluded — the negation would parse fine, apply to nothing, and leave
    `settings.json` untracked with no error anywhere. The contents form `/.claude/*` is what makes it
    work, so the asymmetry is asserted rather than assumed: one path un-ignored, its siblings not.

    The siblings matter beyond hygiene. `rules/`, `skills/` and `agents/` are the directories a
    future session is most likely to reach for, and each would reach exactly one checkout while
    looking repo-wide — the same delivery failure this whole block exists to close.
    """
    negated = _git("check-ignore", "-q", "--no-index", ".claude/settings.json")
    assert negated.returncode != 0, (
        "`.claude/settings.json` is IGNORED — the `!/.claude/settings.json` negation is not taking "
        "effect. Check that the rule above it is `/.claude/*` and not `/.claude/`: a negation cannot "
        "re-include a file whose parent directory is excluded, and it fails silently when it can't."
    )

    for sibling in (
        ".claude/settings.local.json",
        ".claude/worktrees/probe-327/CLAUDE.md",
        ".claude/rules/probe-327.md",
        ".claude/skills/probe-327/SKILL.md",
        ".claude/agents/probe-327.md",
    ):
        res = _git("check-ignore", "-q", "--no-index", sibling)
        assert res.returncode == 0, (
            f"{sibling!r} is NOT ignored. The negation is meant to cover `settings.json` alone; a "
            "second `!` line publishes session state or machine-local config. If this path is now "
            "meant to travel, pin it in _TRACKED_EXCEPTIONS and say why in .gitignore."
        )


def test_the_testing_negation_re_includes_exactly_verify_md() -> None:
    """The second negation, asserted in both directions for the same reason as the first.

    `/docs/testing/*` carries the identical one-character hazard: written `/docs/testing/` the
    directory is excluded, git never descends into it, and `!/docs/testing/VERIFY.md` parses fine
    while applying to nothing. The failure is silent -- the operator's step 6 link would simply stop
    resolving for anyone who cloned, with no error at commit, push or CI.

    The siblings are asserted too, because the risk here is the opposite of the `.claude/` one. There
    the danger was publishing session state; here it is publishing maintainer QA that names a specific
    build box (`WIN2025-TEST-PLAN.md` carries the host and its service identity), plus two drafts that
    say on their face they are awaiting owner approval.
    """
    negated = _git("check-ignore", "-q", "--no-index", "docs/testing/VERIFY.md")
    assert negated.returncode != 0, (
        "`docs/testing/VERIFY.md` is IGNORED — the `!/docs/testing/VERIFY.md` negation is not taking "
        "effect. Check that the rule above it is `/docs/testing/*` and not `/docs/testing/`: a "
        "negation cannot re-include a file whose parent directory is excluded, and it fails silently. "
        "This file is an OPERATOR tool and docs/README.md links it as step 6 of the new-operator path."
    )

    for sibling in (
        "docs/testing/MASTER-TEST-PLAN.md",
        "docs/testing/WIN2025-TEST-PLAN.md",
        "docs/testing/master-test-plan/00-strategy-and-governance.md",
        "docs/testing/probe-0160.md",
    ):
        res = _git("check-ignore", "-q", "--no-index", sibling)
        assert res.returncode == 0, (
            f"{sibling!r} is NOT ignored. The negation is meant to cover `VERIFY.md` alone. If this "
            "path is now meant to travel, pin it in _TRACKED_EXCEPTIONS and say why in .gitignore."
        )

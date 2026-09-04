# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The eight pre-commit gates whose CI mirror nothing else compares (BACKLOG #1395).

``tests/test_lint_scope_parity.py`` already pins hook-versus-CI equivalence for ``ruff-format``,
``ruff-check`` and ``bandit``. **THAT LEAVES EIGHT OF THE ELEVEN HOOKS WITH A HAND-WRITTEN CI MIRROR
AND NOTHING COMPARING THE TWO.** This file covers those eight and only those eight -- duplicating the
three already pinned would create a second, silently different definition of one rule, which is the
defect this whole family of tests exists to prevent.

***WHY A MIRROR NEEDS A TEST AT ALL: CI DOES NOT RUN ``pre-commit``.*** Measured 2026-08-29 across all
24 workflows: zero ``pre-commit run`` invocations. Every CI check that "mirrors" a hook is a separate
hand-maintained re-implementation, and ``security.yml`` says so in its own comment four lines above the
bandit call -- that ``tests/test_lint_scope_parity.py`` fails if the two drift apart *again*.
***THE WORD "AGAIN" IS THE EVIDENCE: THAT DRIFT HAS ALREADY HAPPENED ONCE.***

**THIS MATTERS BECAUSE THE LOCAL HOOK IS SKIPPABLE.** ``git`` never invokes ``pre-commit`` for a commit
created by the sequencer, so a rebase or cherry-pick lands a commit with none of the eleven gates
having run (BACKLOG #1395, reproduced independently by two seats). **The CI mirror is therefore the
only enforcement left on a replayed commit, and until this file eight of those mirrors could drift away
from the rule they mirror with nothing failing.**

***WHAT THIS FILE DOES NOT DO, STATED HERE RATHER THAN DISCOVERED LATER.***

* **It does not prove a mirror is CORRECT** -- only that it still matches the hook. Both can be wrong
  together and this file stays green. It pins agreement, not truth.
* **It does not check that each mirror's workflow actually RUNS on a pull request.** Trigger and
  required-check status are a separate question and were not measured.
* ***It does not close the ledger-gate OWNERSHIP divergence, because that one is DELIBERATE and
  cannot be closed.*** ``ledger_check.py`` guards ownership as ``elif not self.ci and not
  self.owns(...)`` and CI passes ``--ci``: the allocation registry lives under ``.git/`` and never
  reaches a runner. The arm below pins the DUPLICATE-NUMBER half, which CI does enforce, and records
  the ownership gap rather than asserting it away.
* ***THE HOOK-TO-PATTERN MAP IS ITSELF HAND-WRITTEN, WHICH IS THE DEFECT THIS FILE EXISTS TO CATCH,
  ONE LEVEL UP.*** ``_MIRRORS`` says what a mirror LOOKS like, and nothing checks that a pattern
  matches the step that actually enforces the rule. A pattern matching the wrong line -- another
  job's, or an advisory copy -- satisfies its arm. Each arm asserts only that SOME non-comment line
  matches, never that it is the BLOCKING step: measured, ``ledger-gate`` matches exactly one line
  today, but one is a property of this corpus and not of the assertion.
* **It does not verify that the sibling ASSERTS anything.** ``test_the_sibling_this_file_defers_to
  _still_exists`` checks that ``tests/test_lint_scope_parity.py`` exists and still NAMES each of the
  three ids. **It cannot tell an assertion from a mention**, so gutting that file's bandit arms while
  leaving the word in place stays green here. Closing it needs the sibling to publish what its arms
  exercise -- a change there, not here.
* **The six script-path patterns are safe BY THE CURRENT CORPUS, not by construction.** They were
  measured at 1-3 hits each, all run lines. Nothing stops a future workflow from mentioning one of
  those paths on a non-comment line that is not an invocation, which is exactly how ``gitleaks`` and
  ``actionlint`` failed before they were anchored on their invocations.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

from tests._workflow_contexts import required_contexts  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_PRECOMMIT = _ROOT / ".pre-commit-config.yaml"
_WORKFLOWS = _ROOT / ".github" / "workflows"

#: The CI-side re-run of this same config -- BACKLOG #1395's PREFERRED fix, over the `post-rewrite` /
#: `pre-merge-commit` hook pair the row lists second. A local hook is advisory by construction, which
#: is the whole finding, so the remedy cannot be another local hook.
_REPLAY = _WORKFLOWS / "precommit-replay.yml"

#: The hook ids the replay leg may skip, and NOTHING ELSE. Pinned as a SET because the failure mode
#: is growth: one convenient entry at a time until the leg runs nothing and still reports green -- a
#: gate that cannot fail wearing the name of one that can.
#:
#: Both entries earn it by producing a WRONG answer on a runner rather than by being inconvenient.
#: `ledger-gate`'s hook entry omits `--ci`, so its ownership arm would read an allocation registry
#: that lives in `.git/mefor-coord/` and never reaches CI. `forbidden-content` fails closed on a
#: git-ignored token file no runner has. Neither is left unguarded by the skip: ci.yml runs
#: `ledger_check.py --ci` and security.yml's REQUIRED `forbidden-content` job scans the whole tree.
#: precommit-replay.yml's header carries the reasoning; this is the enforcement.
_REPLAY_SKIPS = frozenset({"ledger-gate", "forbidden-content"})

#: The eight hooks this file owns, mapped to a regex that must match a NON-COMMENT workflow line.
#: ruff-format, ruff-check and bandit are deliberately absent -- see the module docstring.
#:
#: ***ANCHORED ON THE INVOCATION, NOT THE TOOL NAME, AND FOR gitleaks AND actionlint THAT IS
#: LOAD-BEARING.*** The first version of this file matched the bare names. Review measured the corpus:
#: `gitleaks` appears on TEN non-invocation lines and `actionlint` on EIGHT -- job keys, `name:`
#: labels, a release URL, checksum lines, a tar call, `sudo install`, `--version`. ***DELETING THE REAL
#: RUN LINE LEFT THOSE HITS BEHIND AND THE ASSERTION STILL PASSED, so the CI mirror could be removed
#: entirely and this test would stay green -- on exactly the rebase-created commit #1395 describes.***
#: The docstring's "an executable line, not a comment" was necessary and not sufficient:
#: `sudo install ... gitleaks` IS an executable line and is not an invocation.
#:
#: The six script-path patterns were measured safe (1-3 hits each, all run lines) -- but safe BY THE
#: CURRENT CORPUS, not by construction, which is why they are regexes too rather than substrings.
_MIRRORS: dict[str, str] = {
    "ledger-gate": r"python\s+scripts/hooks/ledger_check\.py",
    "backlog-parses": r"python\s+scripts/docs/backlog_status_check\.py",
    "forbidden-content": r"python\s+scripts/security/scan_forbidden\.py",
    "licence-header": r"python\s+scripts/quality/licence_header_check\.py",
    "control-char": r"python\s+scripts/quality/control_char_check\.py",
    "username-access-key": r"python\s+scripts/quality/username_access_key_screen\.py",
    # `detect` is gitleaks' scan subcommand; `version`, `install` and the download URL are not.
    "gitleaks": r"\bgitleaks\s+detect\b",
    # the hook passes `-shellcheck=`; `--version` and `sudo install ... actionlint` must not satisfy it.
    "actionlint": r"\bactionlint\s+-shellcheck=",
}

#: The file the three hooks below are pinned by. Kept as a PATH, not just named in prose, so the
#: deferral can be CHECKED -- see test_the_sibling_this_file_defers_to_still_exists.
_SIBLING = _ROOT / "tests" / "test_lint_scope_parity.py"

#: Already pinned by _SIBLING. Named so the split is visibly deliberate and so the exhaustiveness arm
#: below can account for all eleven.
_COVERED_ELSEWHERE = frozenset({"ruff-format", "ruff-check", "bandit"})


def _hook_ids() -> set[str]:
    cfg = yaml.safe_load(_PRECOMMIT.read_text(encoding="utf-8"))
    return {h["id"] for repo in cfg["repos"] for h in repo["hooks"]}


def _workflow_lines() -> list[tuple[str, int, str]]:
    """Every workflow line that is NOT a YAML comment, as (file, lineno, stripped).

    Comment lines are dropped because a mirror mentioned only in a comment is not a mirror. That
    distinction is not hypothetical, and the live instance is in this repo, not in a ledger row:
    ``.github/workflows/ci.yml`` carries a COMMENT reading "--baseline is what makes this step able
    to FAIL", and ``tests/test_username_access_key_screen.py`` asserts ``"--baseline" in ci`` over
    the raw file text -- so THAT assertion is satisfied by the comment and would stay green with the
    run line deleted.

    ***THE RULE IS PROPHYLACTIC FOR THE EIGHT ARMS, NOT LOAD-BEARING, AND SAYING SO IS THE POINT.***
    Measured 2026-08-29 over the workflows: ZERO comment lines match ANY pattern in ``_MIRRORS``
    (control: a fabricated pattern also returns zero, so the search can return no).
    """
    out: list[tuple[str, int, str]] = []
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for n, raw in enumerate(text.splitlines(), 1):
            stripped = raw.strip()
            if stripped and not stripped.startswith("#"):
                out.append((path.name, n, stripped))
    return out


def _workflow_body() -> str:
    return "\n".join(s for _f, _n, s in _workflow_lines())


def _run_blocks() -> list[tuple[str, str]]:
    """Every ``run:`` step's RESOLVED command, as (file, the string the shell actually receives).

    A SECOND corpus beside ``_workflow_lines()``, and the reason is narrow: the ``--baseline`` arm
    below is a CONJUNCTION over ONE command -- this script, with this flag, with this value -- and a
    LINE corpus cannot express "the same command" once the command is a folded block scalar. The
    real invocation is ``run: >-`` with the script on one line and ``--baseline <path>`` alone on the
    next, so the only line carrying the flag carries no tool name. A per-line regex there would pin a
    bare fragment, and would red on a re-wrap that changes nothing about what runs. ``yaml.safe_load``
    hands back the joined string, so a re-wrap is invisible and a decoy in a DIFFERENT step cannot
    satisfy the conjunction.
    """
    out: list[tuple[str, str]] = []

    def walk(node: object, name: str) -> None:
        if isinstance(node, dict):
            run = node.get("run")
            if isinstance(run, str):
                out.append((name, run))
            for value in node.values():
                walk(value, name)
        elif isinstance(node, list):
            for value in node:
                walk(value, name)

    for path in sorted(_WORKFLOWS.glob("*.yml")):
        walk(yaml.safe_load(path.read_text(encoding="utf-8")), path.name)
    return out


def test_the_fixtures_are_not_empty() -> None:
    """CONTROL. Every assertion below has the shape "X appears in the workflows", and an empty corpus
    satisfies none of them honestly -- it fails them for the wrong reason or, worse, a mistyped path
    makes them all vacuous.

    ``pytest.importorskip("yaml")`` ALSO fails silently green if PyYAML is ever dropped, so this file
    could vanish from the run with nothing going red. This arm is what makes that loud.
    """
    assert _PRECOMMIT.is_file(), f"{_PRECOMMIT} is missing -- path resolution is wrong"
    assert len(list(_WORKFLOWS.glob("*.yml"))) >= 10, (
        "workflow directory looks empty or misresolved"
    )
    assert len(_workflow_lines()) > 500, "workflow corpus did not load"
    # The run-block corpus needs the same control as the line corpus: a walk that quietly returns
    # nothing makes every `all(...)` over it vacuously true, which is the failure this arm exists for.
    assert len(_run_blocks()) > 50, "workflow run-step corpus did not load (measured 180)"
    assert len(_hook_ids()) >= 10, "pre-commit config parsed to too few hooks"


def test_this_file_and_its_sibling_together_cover_every_hook() -> None:
    """The split between this file and test_lint_scope_parity.py must stay exhaustive.

    ***A NEW HOOK WITH NO CI MIRROR AND NO TEST IS EXACTLY THE STATE #1395 DESCRIBES.*** If one is
    added, this reds and names it instead of letting it land unmirrored and unnoticed.
    """
    declared = _hook_ids()
    accounted = set(_MIRRORS) | set(_COVERED_ELSEWHERE)
    missing = declared - accounted
    assert not missing, (
        f"hook(s) {sorted(missing)} are declared in .pre-commit-config.yaml and covered neither here "
        f"nor by tests/test_lint_scope_parity.py. Add the CI mirror and list it in _MIRRORS, or record "
        f"deliberately why it has none."
    )
    stale = accounted - declared
    assert not stale, f"{sorted(stale)} are named by these tests but no longer exist as hooks"


def test_the_sibling_this_file_defers_to_still_exists() -> None:
    """``_COVERED_ELSEWHERE`` is a claim about ANOTHER FILE, and nothing here used to open it.

    Measured: move ``tests/test_lint_scope_parity.py`` away entirely and this file stayed at 13
    passed, with three of the eleven hooks still reported covered by a file the repo no longer had.
    An assertion that cannot fail is the defect this whole family of tests exists to catch, and it
    was sitting one level up, inside the catcher.

    ***WHAT THIS ARM DOES NOT DO, STATED HERE RATHER THAN DISCOVERED LATER: it checks that the file
    EXISTS and still NAMES each id. It cannot tell an assertion from a mention.*** Measured on the
    same file: delete every arm that binds ``bandit`` to its CI mirror and several lines still say
    "bandit", so that mutation stays green here. Closing it needs the sibling to publish what its
    arms actually exercise -- a change to the sibling, not to this file.
    """
    assert _SIBLING.is_file(), (
        f"{_SIBLING} does not exist, so _COVERED_ELSEWHERE defers {sorted(_COVERED_ELSEWHERE)} to a "
        f"file this repo no longer has and the exhaustiveness arm above is vacuous for all three."
    )
    text = _SIBLING.read_text(encoding="utf-8")
    unnamed = sorted(h for h in _COVERED_ELSEWHERE if h not in text)
    assert not unnamed, (
        f"{_SIBLING.name} no longer names {unnamed}, so their CI mirror is pinned by NEITHER file -- "
        f"not here (deliberately) and not there. Add them to _MIRRORS here, or restore the arms there."
    )


@pytest.mark.parametrize("hook_id", sorted(_MIRRORS))
def test_each_hook_has_a_real_ci_invocation(hook_id: str) -> None:
    """Not a mention in a comment, and not an install line either -- an INVOCATION.

    ***"NOT A COMMENT" IS NECESSARY AND NOT SUFFICIENT.*** `sudo install -m 0755 gitleaks
    /usr/local/bin/gitleaks` is an executable line and is not a scan. See `_MIRRORS`.
    """
    pattern = _MIRRORS[hook_id]
    hits = [(f, n) for f, n, s in _workflow_lines() if re.search(pattern, s)]
    assert hits, (
        f"hook {hook_id!r} has no non-comment workflow line matching {pattern!r}. Its CI mirror is "
        f"gone, so on a rebase-created commit (BACKLOG #1395) this rule is enforced NOWHERE."
    )


def test_the_search_can_return_no() -> None:
    """NEGATIVE CONTROL, and the arm that makes every assertion above mean anything.

    A search that always finds something is indistinguishable from one that matches anything.
    """
    fabricated = "scripts/quality/there_is_no_such_gate_here.py"
    hits = [s for _f, _n, s in _workflow_lines() if fabricated in s]
    assert not hits, "the fabricated token matched -- the corpus or the matcher is wrong"


def test_the_discriminating_flags_still_match() -> None:
    """Presence is not equivalence. These carry a flag that CHANGES WHAT THE GATE CATCHES.

    A mirror running the right script with the wrong flag is worse than a missing one: it reports
    green while checking something narrower than the hook does.
    """
    cfg = yaml.safe_load(_PRECOMMIT.read_text(encoding="utf-8"))
    hooks = {h["id"]: h for repo in cfg["repos"] for h in repo["hooks"]}
    body = _workflow_body()

    # username-access-key -- the baseline path decides which sites are exempt.
    #
    # ***ANCHORED ON THE STEP'S RESOLVED COMMAND, NOT ON A BARE PATH AND NOT ON ONE LINE.*** This was
    # `assert baseline in body` -- a substring over every non-comment line of all the workflows, the
    # exact shape _MIRRORS was fixed to abandon further up. Two mutations left it GREEN: renaming the
    # flag on the real run line, and deleting the flag while the path appears in some `paths:` filter.
    # The screen makes that silent by design: `username_access_key_screen.py` hand-parses argv and
    # returns 0 when no --baseline was given, so a mirror that loses the flag CANNOT FAIL.
    #
    # A per-line regex was REJECTED, not overlooked. The real invocation is a folded scalar, so the
    # one line carrying the flag carries no tool name -- and the per-line form reds on ordinary
    # spellings this corpus already uses: `--flag=value`, a quoted value, a re-wrap, a hoisted var.
    # Requiring the three tokens in ONE resolved command tolerates all four and still refuses a decoy
    # sitting in a different step.
    #
    # `all`, not `any`: baseline-less means cannot-fail, so a SECOND invocation without the flag is a
    # step that reads as coverage and produces none.
    entry = str(hooks["username-access-key"].get("entry", ""))
    match = re.search(r"--baseline\s+(\S+)", entry)
    assert match, "the username-access-key hook no longer passes --baseline; update this test"
    baseline = match.group(1)
    invocations = [
        (f, run) for f, run in _run_blocks() if re.search(_MIRRORS["username-access-key"], run)
    ]
    assert invocations, (
        "no workflow `run:` step invokes username_access_key_screen.py at all, so its CI mirror is "
        "gone and on a rebase-created commit this screen runs NOWHERE."
    )
    unbaselined = sorted(
        f"{f}: {run[:70].strip()!r}"
        for f, run in invocations
        if not (re.search(r"--baseline\b", run) and baseline in run)
    )
    assert not unbaselined, (
        f"a workflow step runs username_access_key_screen.py without --baseline {baseline!r}: "
        f"{unbaselined}. EITHER the CI mirror lost the flag or its value -- the screen then returns 0 "
        f"for every input, so the two screens exempt different sites while both report green -- OR a "
        f"second, deliberately advisory invocation was added, which is a step that cannot fail. The "
        f"blocking one is the 'Username-as-access-key screen' step in .github/workflows/ci.yml."
    )

    # actionlint -- "-shellcheck=" disables the shellcheck integration. If only one side sets it the
    # two disagree about what counts as a finding.
    #
    # ***THE GUARD IS GONE AND THE CI HALF IS NOT RESTATED HERE.*** `if hook sets it: assert CI sets
    # it` could see CI drop the flag and NOT the hook dropping it while CI kept it -- the same
    # divergence, in the direction nothing watched. And the CI half was a substring COPY of
    # _MIRRORS["actionlint"], which already REQUIRES `-shellcheck=` on the invocation, so
    # test_each_hook_has_a_real_ci_invocation[actionlint] IS the CI half. One rule, one definition.
    args = [str(a) for a in (hooks["actionlint"].get("args") or [])]
    assert any("-shellcheck=" in a for a in args), (
        "the actionlint hook no longer disables shellcheck while the CI step still does (pinned by "
        "_MIRRORS['actionlint']), so the two now disagree about what counts as a finding. Restore the "
        "arg -- or, if enabling shellcheck on BOTH sides is the intent, change _MIRRORS['actionlint'] "
        "in the same commit so the mirror arm still describes what CI runs."
    )

    # forbidden-content -- the hook fails closed via --require-tokens. pre-commit can pass args to a
    # hook but cannot set env for one, so CI uses the env form instead; the script's own docstring
    # states that pairing. EITHER mechanism satisfies the floor; NEITHER means a vacuous green.
    hook_args = [str(a) for a in (hooks["forbidden-content"].get("args") or [])]
    assert any("--require-tokens" in a for a in hook_args), (
        "the forbidden-content hook no longer fails closed on a missing or truncated token source"
    )
    # ANCHORED ON THE ASSIGNMENT, NOT THE BARE NAME, AND THAT IS LOAD-BEARING. The first version of
    # this arm asserted `"MEFOR_MIN_DETECTORS" in body` and a mutation renaming the variable to
    # MEFOR_MIN_DETECTORS_TYPO STILL PASSED -- the old name survives as a substring of the new one, so
    # the check could not see a rename, which is the likeliest way this floor actually gets lost.
    assert re.search(r"\bMEFOR_MIN_DETECTORS=", body), (
        "no workflow ASSIGNS MEFOR_MIN_DETECTORS, so the CI leak scan has no detector floor and can "
        "pass against an empty or truncated token source -- a vacuous green on the customer/PHI guard."
    )


def test_ci_still_runs_the_ledger_gate_in_ci_mode() -> None:
    """The one DELIBERATE divergence, pinned so that it stays deliberate.

    ***CI passes ``--ci``, which skips the ownership check because the allocation registry is local
    and never reaches a runner. The duplicate-number half still runs, and that is the half CI can
    enforce.*** Drop the flag and CI fails every PR on a check it cannot satisfy; drop the whole call
    and duplicate-number detection loses its backstop on replayed commits too.
    """
    assert "ledger_check.py --ci" in _workflow_body(), (
        "CI no longer runs ledger_check.py with --ci. Without --ci it fails on the ownership check it "
        "cannot satisfy; without the call at all, duplicate-number detection has no backstop on a "
        "rebase-created commit (BACKLOG #1395)."
    )


# --- the third-party hooks' VERSIONS, which the arms above deliberately do not reach --------------
#
# _MIRRORS anchors on the INVOCATION, so it proves a mirror still runs the right tool with the right
# discriminating flag. It says nothing about WHICH BUILD of that tool runs, and for the two hooks
# whose CI half is a downloaded release tarball rather than a shared interpreter, that is a separate
# axis with its own failure: the hook and CI agree on every flag while running different scanners.
#
# THE ONLY THING HOLDING IT BEFORE THIS WAS TWO PROSE COMMENTS -- .pre-commit-config.yaml's "Keep the
# version in step" on actionlint and zizmor.yml's matching line. A comment cannot fail. The ruff pin
# has had a real test since 2026-08-18 (test_lint_scope_parity.py::
# test_ruff_hook_pin_matches_the_lock_and_the_cap); these two had nothing.


def _repo_of(hook_id: str) -> dict[str, object]:
    """The `repo:` entry declaring ``hook_id`` -- the hook's OWN URL, not a slug retyped here.

    Deriving the GitHub slug from the config rather than hard-coding it keeps one source: a hook
    repointed at a fork changes what the comparison looks for, instead of leaving this file
    confidently comparing against the abandoned upstream.
    """
    cfg = yaml.safe_load(_PRECOMMIT.read_text(encoding="utf-8"))
    matches = [r for r in cfg["repos"] if any(h["id"] == hook_id for h in r["hooks"])]
    assert len(matches) == 1, (
        f"expected exactly one repo entry declaring {hook_id!r}, got {matches}"
    )
    return dict(matches[0])


#: hook id -> the workflow whose `run:` step downloads and installs that tool's release.
#: Both are checksum-verified tarball installs pinned by a shell `VER=`, not marketplace actions, so
#: no `uses:` pin exists to compare against and the version lives in a shell assignment.
_RELEASE_INSTALLERS = {"gitleaks": "security.yml", "actionlint": "zizmor.yml"}


def _installed_version(hook_id: str, slug: str) -> tuple[str, str]:
    """(version, the run block) CI installs for ``slug``, found by that repo's own download URL.

    ANCHORED ON `<slug>/releases/download`, NOT ON A BARE `VER=`. security.yml carries several
    release installs, and matching the first `VER=` in the file would compare the hook's rev against
    whichever tool happens to be declared earliest -- a green that describes nothing.
    """
    workflow = _RELEASE_INSTALLERS[hook_id]
    blocks = [
        run
        for name, run in _run_blocks()
        if name == workflow and f"{slug}/releases/download" in run and re.search(r"\bVER=", run)
    ]
    assert len(blocks) == 1, (
        f"expected exactly one run block in {workflow} that downloads a {slug} release and assigns "
        f"VER=, found {len(blocks)}. If the install moved, move this mapping with it -- do NOT relax "
        f"the anchor to a bare VER=, which would compare against an unrelated tool's version."
    )
    match = re.search(r"\bVER=v?([0-9][^\s\"']*)", blocks[0])
    assert match, f"no VER= assignment parsed out of {workflow}'s {slug} install: {blocks[0]!r}"
    return match.group(1), blocks[0]


@pytest.mark.parametrize("hook_id", sorted(_RELEASE_INSTALLERS))
def test_the_hook_rev_matches_the_version_ci_installs(hook_id: str) -> None:
    """The pinned hook `rev` and the version CI downloads must be the SAME release.

    ***A DRIFT HERE IS INVISIBLE FROM BOTH SIDES.*** Each half is internally consistent -- the hook
    pins a tag pre-commit resolves, CI pins a tag whose tarball passes its own checksum -- so nothing
    either side checks can notice they name different releases. What it costs is the property this
    whole family of tests exists to protect: a developer's commit is screened by one scanner and the
    pull request by another, and a finding that only the newer one reports lands green locally.
    Worse in the direction that matters here, since on a rebase-created commit the local half did not
    run at all and the CI build is the ONLY one that ever looked.

    `pre-commit autoupdate` is the likely author. It walks a `rev` to the newest upstream tag with no
    idea a workflow elsewhere hard-codes the old one -- exactly the hazard .pre-commit-config.yaml
    already records for ruff's rev, which is why that one has been under a test since 2026-08-18.
    """
    repo = _repo_of(hook_id)
    url = str(repo["repo"]).rstrip("/")
    slug = "/".join(url.removesuffix(".git").split("/")[-2:])
    hook_rev = str(repo["rev"]).lstrip("v")
    ci_version, block = _installed_version(hook_id, slug)

    print(
        f"[gate-mirror] {hook_id}: hook rev {hook_rev}, {_RELEASE_INSTALLERS[hook_id]} {ci_version}"
    )
    assert hook_rev == ci_version, (
        f"the {hook_id} pre-commit hook pins {hook_rev} while "
        f"{_RELEASE_INSTALLERS[hook_id]} installs {ci_version}. The commit-time gate and the CI "
        f"mirror are now DIFFERENT BUILDS of the same scanner, so each can report a finding the "
        f"other does not -- and on a rebase-created commit only the CI one ever runs (BACKLOG "
        f"#1395). Move .pre-commit-config.yaml's `rev` and the workflow's `VER=` together; the "
        f"checksum line in that block pins the bytes, not the version, so it will not object. "
        f"Install block:\n{block}"
    )


def test_the_release_install_anchor_can_return_no() -> None:
    """NEGATIVE CONTROL for the version arms. A locator that always finds something proves nothing.

    The real risk it rules out is a search so loose that any run block satisfies it -- in which case
    the two assertions above would compare a hook's rev against whatever version string happened to
    be nearest, and pass or fail for reasons unrelated to the hooks.
    """
    fabricated = "there-is-no-such-org/there-is-no-such-tool"
    hits = [run for _f, run in _run_blocks() if f"{fabricated}/releases/download" in run]
    assert not hits, "the fabricated slug matched a release install -- the anchor is too loose"


# --- the CI-side re-run itself (BACKLOG #1395's preferred fix) -------------------------------------


def test_the_replay_leg_runs_pre_commit_over_the_diff() -> None:
    """The leg must actually invoke `pre-commit run` scoped to the pull request's diff.

    ***THE THREE TOKENS ARE ASSERTED OVER ONE RESOLVED COMMAND, NOT OVER THE FILE.*** A file-wide
    substring check is satisfied by this workflow's own header, which names `--from-ref/--to-ref`
    while explaining the choice -- so deleting the run step would leave the prose behind and the
    assertion green. That is the exact defect `_workflow_lines()` was introduced to avoid one level
    up, and the header here is long enough to make it a live risk rather than a theoretical one.

    Scoping is part of the contract, not an optimisation: `pre-commit run` with neither ref runs
    against STAGED files, and a runner stages nothing -- so the bare form exits 0 having checked
    nothing at all. That is the worst available outcome, a green tick on an empty run.
    """
    assert _REPLAY.exists(), (
        f"{_REPLAY.name} is gone. It is the CI-side re-run BACKLOG #1395 prefers over a second local "
        "hook; without it, a rebase-created commit is screened only by the hand-written mirrors."
    )
    invocations = [
        run
        for name, run in _run_blocks()
        if name == _REPLAY.name
        and re.search(r"\bpre-commit\s+run\b", run)
        and "--from-ref" in run
        and "--to-ref" in run
    ]
    assert invocations, (
        f"no `run:` step in {_REPLAY.name} invokes `pre-commit run` with BOTH --from-ref and "
        "--to-ref. Without the refs pre-commit falls back to the STAGED file set, which is empty on "
        "a runner -- the leg would report success having executed no hook."
    )


def test_the_replay_leg_skips_exactly_the_hooks_it_cannot_run() -> None:
    """`SKIP` must name `_REPLAY_SKIPS` exactly -- no growth, no shrinkage, no typos.

    THREE FAILURES IN ONE ARM, because they share a remedy and none is visible without it.

    * GROWTH is the one that matters. Every added id silently subtracts a gate, the leg keeps
      reporting green, and the report looks identical -- pre-commit prints "Skipped" for a skipped
      hook, which nobody reads on a passing run. Left alone the list reaches all eleven.
    * SHRINKAGE reds every pull request on a check no author can satisfy (the ledger gate's
      ownership arm), which is how a leg gets disabled outright rather than fixed.
    * A TYPO skips nothing -- pre-commit does not validate SKIP against declared ids -- so the hook
      runs, the leg reds, and the printed cause names a hook the author believes is skipped. Every id
      is therefore checked against the config, which is also what keeps this constant honest after a
      hook is renamed.
    """
    steps = [
        step
        for job in (yaml.safe_load(_REPLAY.read_text(encoding="utf-8"))["jobs"] or {}).values()
        for step in (job.get("steps") or [])
        if "SKIP" in (step.get("env") or {})
    ]
    assert len(steps) == 1, (
        f"expected exactly one step in {_REPLAY.name} to set SKIP, found {len(steps)}. Two steps "
        "setting it means one of them is running a different set of hooks than this test describes."
    )
    declared = {s.strip() for s in str(steps[0]["env"]["SKIP"]).split(",") if s.strip()}
    known = _hook_ids()

    unknown = sorted(declared - known)
    assert not unknown, (
        f"{_REPLAY.name} skips {unknown}, which .pre-commit-config.yaml does not declare. pre-commit "
        "does not validate SKIP, so a stale or misspelled id skips NOTHING while reading as coverage "
        "that was deliberately dropped."
    )
    assert declared == set(_REPLAY_SKIPS), (
        f"{_REPLAY.name} skips {sorted(declared)}; this file pins {sorted(_REPLAY_SKIPS)}.\n"
        f"  ADDED: {sorted(declared - set(_REPLAY_SKIPS))}\n"
        f"  REMOVED: {sorted(set(_REPLAY_SKIPS) - declared)}\n"
        "Adding one subtracts a gate from the replay path while the leg still reports green. If the "
        "addition is genuinely right, say WHY it produces a wrong answer on a runner -- not merely "
        "that it is inconvenient -- in precommit-replay.yml's header, name the mirror that still "
        "covers it, and move _REPLAY_SKIPS in the same commit."
    )


def test_the_replay_leg_adds_no_required_context() -> None:
    """The leg must stay OFF branch protection's required set unless the owner decides otherwise.

    Not a style rule. `.github/required-contexts.txt` mirrors a server-side setting, and the count
    pinned in tests/test_required_contexts.py must move in the same pull request as any change to it
    -- so a job that quietly acquires a required context reds that test leg for everyone. The
    workflow also has no `merge_group:` trigger, which for a REQUIRED context is the total failure
    codeql.yml's header records under BACKLOG #340: it would never report on a queue entry and
    NOTHING would merge.

    This is a one-directional check, and deliberately so: it reads the checked-in file, which is a
    CLAIM about the server rather than the server itself. It catches the in-repo half of the mistake.
    """
    names = {
        str(job.get("name", key))
        for key, job in (yaml.safe_load(_REPLAY.read_text(encoding="utf-8"))["jobs"] or {}).items()
    }
    required = set(required_contexts())
    overlap = sorted(names & required)
    assert not overlap, (
        f"{_REPLAY.name} declares job name(s) {overlap}, which .github/required-contexts.txt lists as "
        "REQUIRED. This leg builds every pinned hook environment from scratch and is deliberately off "
        "the critical path. Promoting it is the owner's decision, and it needs branch protection "
        "moved FIRST, then that file, then the count in tests/test_required_contexts.py -- and this "
        "workflow needs a `merge_group:` trigger before any of that, or the queue stops merging."
    )

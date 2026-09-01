# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Doc-vs-server drift guard for the REQUIRED status-check set.

THE DEFECT THIS EXISTS FOR. Branch protection lives on the server, so "is this check blocking?" could
not be answered from a clone -- and five places in this repo answered it differently at once:

    docs/CI.md                            8 contexts (and named the CLA one "CLA Assistant")
    .github/workflows/manifest-lint.yml   4 ("the `test` matrix + bandit + pip-audit + cla")
    docs/design/freethread.md             7 ("the 7 required contexts are ...")
    .github/workflows/cla.yml             "add the \"CLA Assistant\" status check" -- already required,
                                          and under a different string than its own line 18 gives
    tests/test_push_guard.py              12

The live API said 12 when those five were counted. It says 16 as of 2026-08-31. That question is not
trivia here: ``required_approving_review_count`` is 0 and auto-merge is armed, so required-set
membership is the ONLY thing separating "reviewed" from "merged unread". A session reasoning from
docs/CI.md would conclude that gitleaks, semgrep, npm-audit and crypto-inventory are advisory -- i.e.
that four blocking security gates were safe to weaken.

THE SET NOW HOLDS A CONTEXT THAT DOES NOT TEST THE CODE, and it is the one with the least behind it.
``a reviewer has read this`` (review-gate.yml, armed 2026-08-31, BACKLOG #1404) is this repository's
ENTIRE review requirement. It is load-bearing BECAUSE approvals are pinned at 0 rather than in spite of
it: every session pushes as one GitHub identity, so a human-approval rule would wedge every pull
request instead of reviewing any. Drop that context from protection and review is not weakened, it is
gone -- nothing else anywhere reports that a green pull request was never read. The count below is what
makes removing it a deliberate edit rather than a quiet one.

WHAT THIS PINS. ``.github/required-contexts.txt`` is the checked-in claim; these tests assert every
in-repo statement agrees with it. The file is NOT the enforcement -- the server is -- so when branch
protection changes, change the file in the same PR and this suite names each prose claim that must
move with it.

WHY THE REALITY CHECK MATTERS. A doc-drift test comparing prose to a file passes just as happily when
BOTH are wrong -- a context string that matches no job in any workflow is the required-but-absent trap
(docs/CI.md), which blocks every PR forever. So ``test_every_required_context_matches_a_real_job``
resolves each string against the actual job names, expanding ``${{ }}`` templates. That is the
assertion that makes the rest of this file mean something.
"""

from __future__ import annotations

import re
from pathlib import Path

from tests._workflow_contexts import (
    CANONICAL_CONTEXTS as _CANONICAL,
)
from tests._workflow_contexts import (
    ROOT as _ROOT,
)
from tests._workflow_contexts import (
    WORKFLOWS as _WORKFLOWS,
)
from tests._workflow_contexts import (
    load_workflow,
    reportable_contexts,
    required_contexts,
    resolve,
)

_CI_DOC = _ROOT / "docs" / "CI.md"

# Files that make a statement about the required set. Every one is READ, and a missing path is an
# ERROR rather than a skip: a claim file that got renamed must be re-pointed here, not silently
# dropped from the scan (that is how a doc-drift guard comes to guard nothing).
_CLAIM_FILES = (
    Path("docs/CI.md"),
    Path("docs/design/freethread.md"),
    Path(".github/workflows/manifest-lint.yml"),
    Path(".github/workflows/cla.yml"),
    Path(".github/workflows/zizmor.yml"),
    Path(".github/workflows/freethread-smoke.yml"),
    Path("tests/test_push_guard.py"),
    Path("scripts/hooks/push_guard.py"),
)

# Contexts that must NEVER appear in the canonical file. Each is a job that cannot report on an
# ordinary PR (fork-token SARIF, a paths filter, a non-PR `if:`) or is advisory by design, so
# requiring it walks straight into the required-but-absent trap.
_MUST_NOT_BE_REQUIRED = (
    "zizmor (GitHub Actions static analysis)",
    "Scorecard analysis",
    "kubeconform + HA policy lint",
    "freethread smoke (3.14t)",
    "complexity triage (advisory)",
    "clone detection (advisory)",
    "diff-coverage (advisory)",
    "mutation (advisory)",
    "gate liveness (advisory)",
    "SBOMs (CycloneDX, multi-ecosystem)",
    "trivy (container image vulnerabilities)",
)


def _canonical() -> list[str]:
    return required_contexts()


def test_the_canonical_file_parses_and_names_the_live_set() -> None:
    """A liveness receipt: report what was actually parsed, so an empty read cannot look like a pass."""
    contexts = _canonical()
    print(f"[required-contexts] parsed {len(contexts)} contexts from {_CANONICAL.name}")
    assert contexts, f"{_CANONICAL} parsed to ZERO contexts — the format changed under the parser"
    assert len(set(contexts)) == len(contexts), (
        f"duplicate context in {_CANONICAL.name}: {contexts}"
    )
    # Pinned so that ADDING or REMOVING a required check is a deliberate, reviewed edit here rather
    # than a silent one. Verified against `gh api repos/MEFORORG/MessageFoundry/branches/main/protection`
    # on 2026-08-31: 16 contexts, set-equal to the file with nothing extra on either side.
    #
    # THE PIN WENT STALE IN THE DIRECTION THAT LOOKS FINE. It read 13 while the server held 16, and
    # a context this file omits reads as NOT BLOCKING -- the reassuring answer rather than the true
    # one. A count that only ever fails when someone edits the FILE cannot notice the server moving
    # underneath it, so reconcile against the API, never against this number.
    assert len(contexts) == 14, (
        f"the canonical required set changed to {len(contexts)} contexts. If branch protection really "
        "changed, update this count AND every claim this suite checks; if it did not, revert the file."
    )


def test_every_required_context_matches_a_real_job() -> None:
    """The required-but-absent trap, made mechanical.

    A required context that no job can ever report blocks every PR forever. Resolving each string
    against the real job names also catches the quieter version: a job renamed while branch
    protection (and this file) kept the old string.
    """
    reportable = reportable_contexts()
    print(f"[required-contexts] resolving against {len(reportable)} job names in {_WORKFLOWS}")
    unresolved = [ctx for ctx in _canonical() if resolve(ctx) is None]
    assert not unresolved, (
        f"required context(s) match no job in .github/workflows/: {unresolved}. A required check that "
        "never reports blocks every PR forever (docs/CI.md, 'the required-but-absent trap'). Either a "
        "job was renamed without updating branch protection, or the string here is a typo."
    )


def test_advisory_and_path_gated_jobs_are_not_required() -> None:
    """Promoting one of these is the required-but-absent trap, or breaks a pinned invariant."""
    contexts = set(_canonical())
    wrongly_required = sorted(contexts & set(_MUST_NOT_BE_REQUIRED))
    assert not wrongly_required, (
        f"{wrongly_required} must not be a required context. These jobs either cannot report on an "
        "ordinary PR (fork-PR token, paths filter, non-PR `if:`) or are advisory by design — "
        "quality-advisory.yml's advisory status is separately pinned by "
        "tests/test_quality_advisory_invariants.py."
    )


def test_ci_doc_required_list_matches_the_canonical_file() -> None:
    """docs/CI.md's 'Checks required to merge' bullet list is the claim readers actually act on."""
    text = _CI_DOC.read_text(encoding="utf-8")
    m = re.search(r"^## Checks required to merge$(.*?)^#", text, re.MULTILINE | re.DOTALL)
    assert m, "docs/CI.md lost its '## Checks required to merge' section — re-point this test"
    documented = set(re.findall(r"^- `([^`]+)`$", m.group(1), re.MULTILINE))
    assert documented, (
        "parsed ZERO contexts out of docs/CI.md's required-checks section. The bullet format changed; "
        "an empty parse must not read as agreement."
    )
    canonical = set(_canonical())
    assert documented == canonical, (
        "docs/CI.md disagrees with .github/required-contexts.txt.\n"
        f"  documented but not required: {sorted(documented - canonical)}\n"
        f"  required but not documented: {sorted(canonical - documented)}\n"
        "This drift previously understated the required set by four blocking security gates."
    )


def test_numeric_required_set_claims_agree() -> None:
    """'the 7 required contexts', '12 status checks' — a count is a claim, and three were stale."""
    expected = len(_canonical())
    pattern = re.compile(
        r"(\d+)\s+(?:required\s+(?:status\s+)?(?:checks?|contexts?)|status\s+checks?)",
        re.IGNORECASE,
    )
    wrong: list[str] = []
    examined = 0
    for rel in _CLAIM_FILES:
        path = _ROOT / rel
        assert path.exists(), f"claim file {rel} no longer exists — re-point _CLAIM_FILES"
        examined += 1
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for found in pattern.finditer(line):
                if int(found.group(1)) != expected:
                    wrong.append(f"{rel}:{lineno} claims {found.group(1)}, live set is {expected}")
    print(f"[required-contexts] scanned {examined} claim files for numeric required-set counts")
    assert examined == len(_CLAIM_FILES)
    assert not wrong, "stale required-set counts:\n  " + "\n  ".join(wrong)


def test_the_two_workflows_that_restated_the_set_now_point_at_the_file() -> None:
    """An inline enumeration is what went stale; a pointer cannot.

    manifest-lint.yml and freethread.md each carried their own copy of the required set ("the `test`
    matrix + bandit + pip-audit + cla") to warn a reader not to add themselves to it. Both copies
    aged out. They must reference the canonical file instead.
    """
    for rel in (Path(".github/workflows/manifest-lint.yml"), Path("docs/design/freethread.md")):
        text = (_ROOT / rel).read_text(encoding="utf-8")
        assert "required-contexts.txt" in text, (
            f"{rel} warns against joining the required set but no longer points at "
            ".github/required-contexts.txt. Reference the canonical file — do not re-inline the list, "
            "which is what went stale here twice."
        )


def test_no_claim_file_names_the_cla_context_by_its_workflow_name() -> None:
    """The context is `cla` (the job key). "CLA Assistant" is the WORKFLOW name and matches nothing.

    docs/CI.md listed the wrong string in its required set, and cla.yml told a reader to add that
    string to branch protection — a change that would have wedged every PR.
    """
    offenders: list[str] = []
    banned = re.compile(r"[\"`']CLA Assistant[\"`']\s+status check|- `CLA Assistant`")
    for rel in _CLAIM_FILES:
        for lineno, line in enumerate((_ROOT / rel).read_text(encoding="utf-8").splitlines(), 1):
            if banned.search(line):
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, (
        "the required CLA context string is `cla`, not `CLA Assistant` (that is cla.yml's workflow "
        "name; branch protection matches the JOB name, and cla.yml's job declares none):\n  "
        + "\n  ".join(offenders)
    )


def test_ci_doc_does_not_contradict_the_zizmor_and_scorecard_workflows() -> None:
    """Two doc claims that the workflows themselves refute."""
    doc = _CI_DOC.read_text(encoding="utf-8")

    zizmor_row = next((ln for ln in doc.splitlines() if ln.startswith("| `zizmor.yml`")), None)
    assert zizmor_row, "docs/CI.md lost its zizmor.yml workflow row — re-point this test"
    assert "**Blocking.**" not in zizmor_row, (
        "docs/CI.md calls zizmor.yml '**Blocking.**' — .github/workflows/zizmor.yml states it is NOT "
        "a required check, and the live protection rules agree. It is also paths-filtered to "
        "`.github/**`, so requiring it would wedge every PR that does not touch a workflow."
    )

    scorecard = load_workflow("scorecard.yml")
    # `on:` parses to the boolean True under the YAML 1.1 spec PyYAML implements.
    triggers = scorecard.get("on") or scorecard.get(True) or {}
    if "pull_request" not in triggers:
        assert not re.search(r"Scorecard[^.\n]*run(s)? on PRs", doc), (
            "docs/CI.md says Scorecard runs on PRs, but scorecard.yml has no `pull_request` trigger "
            f"(it has {sorted(triggers)}). The advisory-vs-required reasoning in that sentence is "
            "sound for CodeQL and does not apply to a workflow that never reports on a PR at all."
        )


def test_the_ci_gate_rollup_comment_names_every_job_the_job_actually_needs() -> None:
    """BACKLOG #1300. ``required-contexts.txt`` described the ``CI gate`` roll-up as SIX legs when
    ``ci-gate`` needs EIGHT -- omitting ``webconsole`` and ``tooling``.

    THE TWO OMITTED ONES ARE THE TWO THAT MOST OFTEN REPORT. The other six are path-gated or nightly
    and skip on an ordinary pull request; these two run on every one. So the file that exists to
    answer *"does this check block a merge"* answered it wrong for precisely the legs a reader is most
    likely to be asking about -- and answered it in the reassuring direction, because a context this
    file does not name reads as not-blocking.

    **A PROSE-ONLY FIX WOULD ROT AGAIN THE NEXT TIME A JOB JOINS THE ROLL-UP**, which is how it got
    here: `webconsole` and `tooling` were added to `needs:` and the comment was not. This reconciles
    the comment against the LIVE `needs:` list, so the two cannot drift silently.

    Deliberately NOT asserting a count. The row's own numbers -- six versus eight -- are the thing
    that went stale; a test pinning "eight" would need editing on the next legitimate addition and
    would tempt whoever edits it to change the number rather than the comment."""
    import yaml

    workflow = yaml.safe_load(
        (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    )
    needs = workflow["jobs"]["ci-gate"]["needs"]
    assert needs, "ci-gate declares no needs -- the roll-up would gate nothing"

    doc = (_ROOT / ".github" / "required-contexts.txt").read_text(encoding="utf-8")
    unnamed = [job for job in needs if job not in doc]
    assert not unnamed, (
        f"ci-gate needs {sorted(needs)} but required-contexts.txt never names {sorted(unnamed)}. "
        f"A reader asking whether a red {unnamed[0]!r} blocks their merge finds no such context here "
        f"and concludes it does not (BACKLOG #1300)."
    )

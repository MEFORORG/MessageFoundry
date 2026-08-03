# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guards against "slug rot" — the damage the retired publish pipeline left behind.

Before the MEFORORG cutover, `scripts/publish/publish.ps1` rewrote the private source slug to the
public one across `*.yml` when it materialised the mirror. That rewrite was applied to the WORKFLOWS
THEMSELVES, so anywhere a file encoded the private/public *distinction*, both sides collapsed to the
same string and the logic became nonsense. Three instances reached main:

  * `release.yml`'s job guard became `if: github.repository != 'MEFORORG/MessageFoundry'` — "never
    release from here", on the only repo that can release. Releases were silently dead; the v0.3.0 tag
    failed and the repo had zero published releases until it was traced back.
  * A README step became `sed s#<public>#<public>#` (a no-op) followed by a guard that failed if that
    string was present — which it always is. Every tag push died there.
  * A TEST asserted the inverted guard was present, so the broken state looked deliberate AND was
    enforced. That is what makes this class expensive: it defends itself.

WHY TWO TIERS. The structural detectors below are precise: a substitution whose operands are equal can
transform nothing, and a job gated `!=` this repo's own slug can never run here. Both are always
defects, never legitimate expressions. They are absolute, with no allowlist, and currently zero hits.

Prose is different. "The mirror" in a fixed-incident record, in an idiom ("the mirror image of"), or
in advice about the ADOPTER's own private repo is correct and must not be swept — sweeping a dated
incident narrative falsifies an audit record. A regex cannot tell those from genuine rot, so prose is
a RATCHET: the count may fall, never rise. New rot fails; the existing backlog is triaged by hand.

TRIAGE TAXONOMY, for whoever lowers the ratchet next. Of the current hits:
  * KEEP — historical: "failed on the mirror" incident narratives (test_off_loopback_runbook,
    test_threat_model_doc_drift, test_ui_csp_canary), and the "pre-cutover this said X" annotations
    added when the guards above were fixed. These describe the past accurately.
  * KEEP — not about this repo: `docs/INSTALL-GUIDE.md` / `docs/VERSION-CONTROL.md` mean the ADOPTER's
    own private repo; `docs/SECURITY.md`'s GHAS note is a true statement about GitHub's pricing.
  * KEEP — idiom: "the mirror image of" in PLAN-PHASE4-GROUP-COMMIT and test_ledger_check.
  * FIX — present-tense claims that this repo is a mirror, or that a private source repo runs CI.

Rot describes the present falsely; history describes the past accurately. Same words, opposite
treatment — which is why this file ratchets rather than forbids.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_PUBLIC = "MEFORORG/MessageFoundry"

#: Records by construction — a changelog/ADR/backlog entry SHOULD describe the topology of its day.
_HISTORICAL = (
    "CHANGELOG.md",
    "docs/adr/",
    "docs/releases/",
    "docs/BACKLOG.md",
    "docs/reviews/",
    "docs/benchmarks/results",
)

#: Present-tense mirror/private-repo prose. Lines carrying a retrospective marker are excluded: those
#: are narrating history, which is the distinction this whole module turns on.
#:
#: ``private repo`` carries a word boundary: without it the alternative matched INSIDE longer words,
#: so "a private **repo**rting channel" and a quoted GitHub error about "user-owned private
#: **repo**sitories" both counted as mirror prose. Two false positives, one of which pushed the
#: ratchet over its ceiling and failed CI on a documentation-only branch. Verified before changing:
#: the boundary suppresses exactly those two lines and keeps every genuine "private repo" hit
#: (~20 of them, across workflows, INSTALL-GUIDE, VERSION-CONTROL, SECURITY and the ADRs).
_PROSE = re.compile(
    r"(?i)(the mirror|public mirror|OSS mirror|private repo\b|the published mirror)"
)
_RETROSPECTIVE = re.compile(
    r"(?i)\b(was|were|used to|retired|former|previously|until the cutover|no longer|had been|old"
    r"|legacy|pre-cutover)\b"
)

#: The ratchet. Lower it when you fix some; NEVER raise it. Measured on 4c65968 (post-#21 and #22),
#: 55 hits across 1367 tracked files. Two of those files are being edited on an unpushed branch
#: (quality-advisory.yml, docs/quality-gates/HANDOFF-mutation-coverage.md), so expect this to fall
#: again shortly — which is the ratchet working, not drift.
#:
#: 2026-07-30: 55 -> 54. Not slack being taken: the ``private repo`` word-boundary fix above removed
#: two SUBSTRING false positives, so the honest count fell and the ceiling follows it DOWN. Measured
#: at 54 across 1412 tracked files. The rule is unchanged — this number may fall again, never rise.
_PROSE_CEILING = 54


#: This module, excluded from its own scan. Its taxonomy above necessarily SPELLS every phrase it
#: searches for, so it counted itself: CI reported 61 against a ceiling of 55, which is exactly main's
#: 53 plus 8 self-hits (the file count also rose 1367 -> 1368). A detector cannot scan its own
#: specification without measuring the specification. Scoped to this one path, not a blanket ignore.
_SELF = "tests/test_cutover_slug_rot.py"


def _tracked() -> list[str]:
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "ls-files"], capture_output=True, text=True, cwd=_ROOT
    ).stdout
    return [f for f in out.split() if not f.startswith(_HISTORICAL) and f != _SELF]


def _read(rel: str) -> str:
    try:
        return (_ROOT / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:  # pragma: no cover - a tracked file that cannot be read
        return ""


def test_no_self_substituting_rewrite() -> None:
    """`sed s#X#X#` — a substitution whose operands are equal. Always a defect, never intentional.

    This is the exact shape publish.ps1's rewrite left in release.yml: it replaced the public slug with
    itself, and the guard beneath it then failed on every tag push because the README names that slug
    19 times. Zero tolerance — there is no legitimate reason to write one.
    """
    rx = re.compile(r"s([#/|])" + re.escape(_PUBLIC) + r"\1" + re.escape(_PUBLIC) + r"\1")
    hits = [
        f"{f}:{t[: m.start()].count(chr(10)) + 1}"
        for f in _tracked()
        if (t := _read(f))
        for m in [rx.search(t)]
        if m
    ]
    assert not hits, f"a self-substituting rewrite is back (it can transform nothing): {hits}"


def test_no_workflow_gates_a_job_off_this_repo() -> None:
    """No `if:` may gate a job on `github.repository != 'MEFORORG/MessageFoundry'`.

    THIS repo IS that slug, so the condition is constant-false here and the job never runs. `release.yml`
    carried exactly that on both release jobs — correct while MEFORORG was a published mirror that must
    never release, catastrophic once it became the source. Releases were silently disabled: the v0.3.0
    tag produced nothing, and it stayed that way until a later tag was traced back to this line.

    A FIRST DRAFT OF THIS TEST LOOKED FOR THE SLUG COMPARED AGAINST ITSELF (`X != X`) and was vacuous —
    that shape never existed. The defect is a VARIABLE compared to the slug, wrong only because of where
    it runs, which no amount of staring at the expression reveals. Mutation-testing is what surfaced it:
    the invented shape could not be made to fail.

    `==` is the correct form and is what every workflow now uses; it keeps jobs off forks and off the
    retired private archive.
    """
    rx = re.compile(r"github\.repository\s*!=\s*['\"]" + re.escape(_PUBLIC) + r"['\"]")
    hits = [
        f"{f}:{t[: m.start()].count(chr(10)) + 1}"
        for f in _tracked()
        if f.startswith(".github/workflows/") and (t := _read(f))
        for m in [rx.search(t)]
        if m
    ]
    assert not hits, (
        f"a job is gated OFF this repo — the branch is unreachable and the job silently never runs "
        f"(this is how releases were disabled): {hits}"
    )


def test_present_tense_mirror_prose_does_not_grow() -> None:
    """A RATCHET, not a ban: prose claiming this repo is a mirror may shrink, never grow.

    Reports the scanned volume, deliberately. A count alone cannot distinguish "nothing found" from
    "nothing scanned" — this repo has produced that failure repeatedly (a grep counting zero from empty
    input; a SAST run reporting no findings because the tool was not installed), so the assertion prints
    what it looked at.
    """
    files = _tracked()
    hits = [
        f"{f}:{i}"
        for f in files
        for i, line in enumerate(_read(f).splitlines(), 1)
        if _PROSE.search(line) and not _RETROSPECTIVE.search(line)
    ]
    scanned = len(files)
    assert scanned > 100, (
        f"only {scanned} files scanned — the file list collapsed, so a pass is meaningless"
    )
    assert len(hits) <= _PROSE_CEILING, (
        f"present-tense mirror/private-repo prose rose to {len(hits)} (ceiling {_PROSE_CEILING}) across "
        f"{scanned} files. New rot, or a retrospective marker was dropped from an existing line. See this "
        f"module's triage taxonomy before allowlisting.\nNew or changed:\n  "
        + "\n  ".join(hits[-12:])
    )


def test_the_ratchet_is_not_slack() -> None:
    """The ceiling must track reality, or it stops being a ratchet and becomes a rubber stamp.

    If the real count drops well below the ceiling and nobody lowers it, the gap silently re-admits that
    much new rot. Fails when the slack exceeds a small margin, so the fix (lower the number) is forced
    at the moment the credit is earned rather than whenever someone notices.
    """
    files = _tracked()
    actual = sum(
        1
        for f in files
        for line in _read(f).splitlines()
        if _PROSE.search(line) and not _RETROSPECTIVE.search(line)
    )
    slack = _PROSE_CEILING - actual
    assert slack <= 8, (
        f"the ratchet has {slack} unused slots ({actual} actual vs {_PROSE_CEILING} ceiling) — lower "
        f"_PROSE_CEILING to {actual}; leaving the gap re-admits {slack} lines of new rot unnoticed"
    )

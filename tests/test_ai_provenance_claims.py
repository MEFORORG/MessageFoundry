# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The AI-provenance claims in the published standard must match what the repo actually does.

THE DEFECT THIS EXISTS FOR. ``docs/Secure_AI_Development_Standards.md`` prescribed a
``Co-Authored-By`` + ``Tier:`` commit trailer, listed it under **Built (by convention)**, put it in
§11's *retained, auditable evidence* set, and cited it as evidence for two claims in the A.4 register —
a register whose stated audience is "adopters and auditors".

Measured 2026-07-29: **zero**. ``git log -n 300`` contains 0 ``Co-Authored-By`` trailers and 0
``Tier:`` lines, while **81 tracked files** under ``docs/`` instruct omitting the trailer because the
CLA bot fails on it. And the blocker is structural rather than cultural: ``cla.yml`` allowlists exactly
three identities, the CLA bot reads a trailer co-author as a contributor who must sign, and ``cla`` is
a **required** status check — so adding the trailer reds the merge gate.

Citing a control with a measured adoption of zero as audit evidence is the same integrity failure the
doc-drift test family already guards elsewhere (``test_security_doc_drift.py``,
``test_asvs_file_surface_doc_drift.py``, ``test_threat_model_doc_drift.py``). This module closes the
loop for the provenance claim specifically, so the correction cannot silently revert.

WHY IT ASSERTS CONSISTENCY, NOT A COMMIT COUNT. Counting trailers in ``git log`` would make the test
depend on clone depth — CI checks out shallow for most jobs, so the count would be measured over a
different history than the one a developer sees, and a shallow fetch returning "0 of 0 commits" is a
gate measuring nothing. Instead this asserts the invariant that actually matters and is fully
determined by the tracked tree: **the standard must not claim the trailer as built/evidence while the
repo's own documents instruct omitting it.** Whichever way that contradiction is resolved — adopt the
trailer and delete the omission instructions, or keep omitting it and don't claim it — this passes.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_STANDARD = _ROOT / "docs" / "Secure_AI_Development_Standards.md"
_CLA = _ROOT / ".github" / "workflows" / "cla.yml"

_TRAILER = "Co-Authored-By"

#: The EXACT heading of the "operating today" list — the claim an adopter acts on. Anchored on the full
#: string, not a `**Built` prefix: the doc says "Built / designed-but-deferred / aspirational" hundreds
#: of lines earlier, so a prefix match slices the wrong section and the guard silently checks nothing.
_H_BUILT = "**Built (in code today):**"


def _standard() -> str:
    return _STANDARD.read_text(encoding="utf-8")


def _files_instructing_omission() -> list[Path]:
    """Tracked docs that tell a contributor to OMIT the trailer.

    These are the counter-instruction: as long as any exist, the standard cannot honestly present the
    trailer as an operating convention.
    """
    found: list[Path] = []
    for path in sorted(_ROOT.joinpath("docs").rglob("*.md")):
        if path == _STANDARD:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if _TRAILER.lower() not in text.lower():
            continue
        for line in text.splitlines():
            low = line.lower()
            if _TRAILER.lower() not in low:
                continue
            if any(
                cue in low for cue in ("omit", "do not add", "don't add", "no co-auth", "cla bot")
            ):
                found.append(path)
                break
    return found


def test_the_omission_instruction_is_still_the_repo_norm() -> None:
    """Liveness for every assertion below: they are conditional on this contradiction existing.

    If the project ever adopts the trailer and clears those instructions, this test fails FIRST and
    tells the reader to revisit the module rather than letting the rest pass vacuously.
    """
    omitting = _files_instructing_omission()
    print(
        f"[ai-provenance] {len(omitting)} tracked doc(s) instruct omitting the {_TRAILER} trailer"
    )
    assert omitting, (
        f"no tracked doc instructs omitting the {_TRAILER} trailer any more. If the trailer has been "
        "genuinely adopted (a CLA-compatible form, enforced by a commit-msg hook plus an ungated CI "
        "backstop), then this whole module is obsolete — delete it and restore the claims in "
        "docs/Secure_AI_Development_Standards.md §6.7/§11/A.4/A.5/A.6 deliberately. Until then it must "
        "not pass by finding nothing."
    )


def _section(heading: str, *, until: str = "\n**") -> str:
    """The standard's text from ``heading`` up to ``until``.

    ``heading`` must be the FULL heading string. A prefix is not safe here: the tooling-honesty
    paragraph in §1 uses the words "Built / designed-but-deferred / aspirational", so a `**Built`
    prefix search lands ~400 lines above the real list and the guard checks the wrong text.
    """
    text = _standard()
    start = text.find(heading)
    assert start != -1, f"the standard lost its {heading!r} section — re-point this test"
    rest = text[start + len(heading) :]
    end = rest.find(until)
    return rest if end == -1 else rest[:end]


def test_the_trailer_is_not_listed_as_a_built_guardrail() -> None:
    """ "Built" is what an adopter reads as "this is operating today"."""
    built = _section(_H_BUILT)
    offending = [
        line.strip()
        for line in built.splitlines()
        if _TRAILER in line and not re.search(r"\bNOT\b|not in this list|blocked", line)
    ]
    assert not offending, (
        f"the {_TRAILER} trailer is listed as a BUILT guardrail:\n  "
        + "\n  ".join(offending)
        + "\n"
        "Measured adoption is zero and the required `cla` check blocks it (§6.7). Move it to the "
        "designed-but-deferred list, or actually adopt and enforce it."
    )


def test_the_trailer_is_not_cited_as_retained_audit_evidence() -> None:
    """§11's evidence set is a promise that the artefact can be produced on request."""
    text = _standard()
    match = re.search(r"\*\*Evidence set\.\*\*(.*?)(?:\n\n|\n#)", text, re.DOTALL)
    assert match, "the standard lost its '**Evidence set.**' paragraph — re-point this test"
    evidence = match.group(1)
    # A "removed from this set" note legitimately names the trailer; a live citation does not.
    live = re.split(r"\*\*Removed from this set[^*]*\*\*", evidence)[0]
    assert _TRAILER not in live, (
        f"§11 still cites the {_TRAILER} trailers as retained, auditable evidence. Evidence with a "
        "measured count of zero cannot be produced on request, and citing it is worse for an audit "
        "than declaring the gap."
    )


def test_the_claims_register_does_not_rest_a_live_claim_on_the_trailer() -> None:
    """A.4 is the approved external wording. A claim resting on a zero-adoption control is not usable."""
    text = _standard()
    start = text.find("### A.4 Claims register")
    assert start != -1, "the standard lost its A.4 claims register — re-point this test"
    register = text[start : text.find("### A.5", start)]

    offending: list[str] = []
    for line in register.splitlines():
        if not line.strip().startswith("|") or _TRAILER not in line:
            continue
        # A withdrawn/struck row may name it; a live row citing it as evidence may not.
        if re.search(r"WITHDRAWN|~~|struck|Previously cited", line):
            continue
        offending.append(line.strip())

    assert not offending, (
        "an A.4 claim still cites the trailer as evidence:\n  " + "\n  ".join(offending) + "\n"
        "Mark the claim WITHDRAWN or re-evidence it. This register is what gets quoted externally."
    )


def test_section_6_7_says_the_trailer_is_not_in_use_and_why() -> None:
    """A gap named without its cause gets 'fixed' by reinstating the thing that cannot work.

    §6.7 is where a reader goes to learn the commit convention. If it still presents the trailer as
    the convention, the next session re-adds it, watches the required `cla` context go red, and reaches
    for the branch-protection settings. Both halves are asserted — the STATUS (not in use) and the
    CAUSE (the required CLA check) — because the status alone reads as an oversight to correct.
    """
    section = _section("### 6.7 Commit / PR with provenance", until="### 6.8")
    low = section.lower()

    assert any(marker in low for marker in ("not in use", "not currently used", "⛔")), (
        "§6.7 does not state that the Co-Authored-By trailer is NOT in use. Measured adoption is zero, "
        "so presenting the trailer block as the commit convention makes this section fiction — and it "
        "is the section a contributor actually follows."
    )
    assert "cla" in low and re.search(r"block|reds\b|red the", low), (
        "§6.7 does not record WHY the trailer is unusable — that `cla` is a required status check and "
        "the CLA bot treats a trailer co-author as a contributor who must sign. Without the cause, the "
        "recorded gap invites exactly the change that wedges the merge gate for every PR."
    )


def test_the_cla_allowlist_is_still_what_makes_the_trailer_unusable() -> None:
    """Pins the CAUSE in the workflow, so the doc claim and the mechanism cannot drift apart.

    If the allowlist mechanism changes, the standard's explanation needs revisiting — and this is the
    test that says so, rather than the explanation quietly becoming fiction.
    """
    yaml = pytest.importorskip("yaml")
    wf = yaml.safe_load(_CLA.read_text(encoding="utf-8"))
    jobs = wf.get("jobs") or {}
    allowlists = [
        str((step.get("with") or {}).get("allowlist", ""))
        for job in jobs.values()
        for step in (job or {}).get("steps") or []
        if (step.get("with") or {}).get("allowlist")
    ]
    assert allowlists, (
        "cla.yml no longer declares an `allowlist`. That was the mechanism making a trailer co-author "
        "read as an unsigned contributor — re-check whether the trailer is now usable and update "
        "docs/Secure_AI_Development_Standards.md §6.7 either way."
    )
    assert "wshallwshall" in allowlists[0], (
        f"the CLA allowlist no longer names the maintainer: {allowlists[0]!r}. The trailer-blocking "
        "explanation in §6.7 is derived from this list; re-verify it."
    )

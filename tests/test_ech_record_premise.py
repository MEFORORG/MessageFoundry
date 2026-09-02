# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guards for the ECH record (BACKLOG #1011, ADR 0139, SDS-3.7 / CLAUDE.md section 11).

Three invariants, each of which was VIOLATED at base commit ``b52fd844`` and each of which was
repaired by hand there. A hand repair does not survive the next edit, so each one is pinned here.

1. **A compensating control must not rest on a false premise.** ``docs/SECURITY.md``'s 12.1.5
   paragraph -- the reasoning inside a documented risk acceptance -- said hiding the outbound SNI was
   "infeasible" and that a working ECH client "would require a third-party TLS stack". The repository
   it shipped in refuted both: ADR 0139's own Context recorded that ECH is buildable off-stdlib, and a
   stdlib-only Go implementation of exactly that control was tracked in the tree.

2. **A second language may not enter the tree unowned.** The Go footprint was one ``.go`` file and one
   ``go.mod`` that no workflow built, tested, linted or version-pinned -- a whole language present by
   accident rather than by decision.

3. **First-party source may not name a path that no longer exists.** ``transports/rest.py``'s
   docstring named ``tools/ech-sidecar/`` by path and asserted the implementation there was "proven to
   hide the SNI". ``scripts/docs/link_check.py`` cannot see this class: it is a bare path in prose, not
   a markdown link, so nothing in the repo would have gone red when the path stopped resolving.

**Why the first guard is not a substring search for "infeasible".** The corrected paragraph QUOTES
that word in order to deny it ("So 'infeasible' is **not** the reason"). Presence is not meaning --
the same trap CLAUDE.md section 11 records for the backlog banner alphabet -- so the check forbids the
refuted claims in their asserting form and requires the denial to be adjacent to the quotation. Its
positive control is the ORIGINAL paragraph, embedded verbatim below: the checker must red on the text
that actually shipped. That control is a literal rather than a ``git show`` of the base commit, so it
keeps working on a shallow CI clone.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

#: The retrieval reference for the retired Go implementation. A line naming the deleted tree is only
#: legitimate when it carries this, because then it points at history rather than at nothing.
_RETRIEVAL_SHA = "62fd628d"
_RETIRED_TREE = "tools/ech-sidecar"

#: First-party roots whose text must not name the retired tree as a live path. Record documents
#: (docs/BACKLOG.md, ADR 0139, the master test plan) are deliberately OUT of scope: their job is to
#: record what was retired and why, so naming it is correct there.
_SOURCE_ROOTS = ("messagefoundry/", "tests/", "samples/", "harness/", "scripts/", "tee/", "ide/")

#: Extensions and basenames that mean "a Go toolchain is required to build this".
_GO_MARKERS = (".go", "go.mod", "go.sum", "go.work")

#: What a Go build/test/lint leg looks like in a workflow, whichever tool is chosen.
_GO_TOOLCHAIN_TOKENS = (
    "setup-go",
    "go build",
    "go test",
    "go vet",
    "gofmt",
    "golangci",
    "GOTOOLCHAIN",
    "GOPROXY",
)


def _tracked() -> list[str]:
    out = subprocess.run(
        ["git", "-C", str(_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    ).stdout
    return [line for line in out.splitlines() if line]


# --- invariant 2: an unowned second language ------------------------------------------------------


def unowned_go_footprint(paths: list[str], workflow_text: str) -> list[str]:
    """Tracked Go artefacts that no CI toolchain owns.

    Empty means either "no Go in the tree" or "Go in the tree AND a leg that builds it" -- both
    acceptable end states. A non-empty result is the #1011 shape: a language present by accident.
    """
    go = [p for p in paths if p.endswith(_GO_MARKERS)]
    if not go:
        return []
    if any(token in workflow_text for token in _GO_TOOLCHAIN_TOKENS):
        return []
    return sorted(go)


def test_no_go_artefact_is_tracked_without_a_toolchain_that_owns_it() -> None:
    paths = _tracked()
    workflows = _ROOT / ".github" / "workflows"
    files = sorted(workflows.glob("*.yml")) + sorted(workflows.glob("*.yaml"))
    text = "\n".join(f.read_text(encoding="utf-8", errors="replace") for f in files)

    # Anti-narrowing floor: assert the scan READ something on both sides. Without this the guard
    # passes just as happily when `git ls-files` returns nothing or the workflow directory moves.
    assert len(paths) > 1000, f"expected the whole tracked tree, scanned {len(paths)} paths"
    assert len(files) > 5, f"expected the workflow directory, scanned {len(files)} files"

    unowned = unowned_go_footprint(paths, text)
    assert not unowned, (
        f"scanned {len(paths)} tracked paths against {len(files)} workflow files; "
        f"these Go artefacts have no build/test/lint leg: {unowned}. Either give the language a "
        f"pinned toolchain and a CI leg, or keep it out of the tree (BACKLOG #1011, ADR 0139)."
    )


def test_the_unowned_go_check_fires_on_a_planted_footprint() -> None:
    """The positive control. Without it, a green above is indistinguishable from a dead predicate."""
    planted = [
        "messagefoundry/__init__.py",
        "tools/ech-sidecar/main.go",
        "tools/ech-sidecar/go.mod",
    ]
    assert unowned_go_footprint(
        planted, "on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
    ) == [
        "tools/ech-sidecar/go.mod",
        "tools/ech-sidecar/main.go",
    ]
    # ...and stays silent once a leg exists, so it gates OWNERSHIP rather than banning a language.
    assert unowned_go_footprint(planted, "  - uses: actions/setup-go@v5\n") == []
    # ...and on a tree with no Go at all.
    assert unowned_go_footprint(["messagefoundry/__init__.py"], "") == []


# --- invariant 3: a bare path in prose that no link checker can see -------------------------------


def stale_tree_references(path: str, body: str) -> list[str]:
    """Lines under a first-party root that name the retired tree WITHOUT the retrieval SHA."""
    if not path.startswith(_SOURCE_ROOTS):
        return []
    return [
        f"{path}:{n}"
        for n, line in enumerate(body.splitlines(), start=1)
        if _RETIRED_TREE in line and _RETRIEVAL_SHA not in line
    ]


def test_no_first_party_source_names_the_retired_tree_as_a_live_path() -> None:
    scanned = 0
    stale: list[str] = []
    for rel in _tracked():
        if not rel.startswith(_SOURCE_ROOTS):
            continue
        f = _ROOT / rel
        if not f.is_file():
            continue
        if f.name == Path(__file__).name:
            # This module is the ONE file whose job is to name the retired tree: it holds the
            # constant, the planted fixtures and the prose explaining the retirement. Matched by
            # basename rather than by path so moving the module cannot silently widen the exemption.
            #
            # This exemption exists because the guard CAUGHT ITSELF. It passed while the module was
            # untracked -- `git ls-files` could not see it -- and went red the moment it was
            # committed. A green that depended on the file not yet existing is exactly the shape
            # "a check that cannot fail looks identical to one that passed" warns about.
            continue
        try:
            body = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # a binary or unreadable fixture carries no prose path reference
        scanned += 1
        stale.extend(stale_tree_references(rel, body))

    assert scanned > 500, f"expected the first-party roots, scanned only {scanned} files"
    assert not stale, (
        f"scanned {scanned} files under {list(_SOURCE_ROOTS)}; these name the retired "
        f"{_RETIRED_TREE!r} without the retrieval SHA {_RETRIEVAL_SHA}, so the path resolves to "
        f"nothing: {stale}. link_check.py cannot see this class -- it is prose, not a link."
    )


def test_the_stale_reference_check_fires_on_a_planted_line() -> None:
    """Positive control, both directions: a bare path is caught, a retrieval reference is not."""
    bare = "the re-originator at tools/ech-sidecar/ is proven to hide the SNI\n"
    assert stale_tree_references("messagefoundry/transports/rest.py", bare) == [
        "messagefoundry/transports/rest.py:1"
    ]
    kept = f"``git show {_RETRIEVAL_SHA}:{_RETIRED_TREE}/main.go`` recovers it\n"
    assert stale_tree_references("messagefoundry/transports/rest.py", kept) == []
    # Record documents are deliberately out of scope -- they exist to name what was retired.
    assert stale_tree_references("docs/BACKLOG.md", bare) == []


# --- invariant 1: the risk acceptance may not rest on a refuted premise ---------------------------

#: The paragraph as it shipped at base commit ``b52fd844``, verbatim. It is the positive control for
#: :func:`refuted_premise_claims` -- the checker MUST red on it -- and it keeps the refuted wording on
#: the record so a future reader can see exactly what was corrected.
_ORIGINAL_12_1_5_PARAGRAPH = """- **ECH (Encrypted Client Hello) for outbound SNI — infeasible, documented risk acceptance
  (12.1.5).** Hiding the destination hostname in the outbound TLS ClientHello is not buildable here:
  Python 3.14's stdlib `ssl` exposes **no ECH API**, there is **no SVCB/HTTPS DNS resolver** (ECHConfig
  is DNS-published) and adding one is out of scope, and a working ECH client would require a
  **third-party TLS stack** — violating the no-new-dependency rule for a security-core path."""

#: Claims the tree refutes. Each is forbidden in its ASSERTING form; the paragraph may still quote a
#: word in order to deny it, which is why "infeasible" alone is not on this list.
_REFUTED = (
    "not buildable here",
    "third-party TLS stack",
    "infeasible, documented risk acceptance",
)


def _flat(text: str) -> str:
    """Collapse whitespace so a claim split across a line wrap still matches.

    Not cosmetic. The first draft of this module missed ADR 0093's "would require a third-party\\n
    TLS stack" entirely, because markdown had wrapped the phrase -- and the SECURITY.md check matched
    only by the luck of where ITS wrap fell. A phrase check over hard-wrapped prose is a decaying
    budget without this.
    """
    return re.sub(r"\s+", " ", text)


def refuted_premise_claims(paragraph: str) -> list[str]:
    """Refuted claims the ECH risk acceptance still asserts, plus a missing denial.

    A bare quotation of "infeasible" is allowed only when the paragraph also denies it, so the record
    can name the corrected premise without re-adopting it.
    """
    paragraph = _flat(paragraph)
    found = [claim for claim in _REFUTED if claim in paragraph]
    if "infeasible" in paragraph and "is **not** the reason" not in paragraph:
        found.append("infeasible (quoted without the denial that makes it a correction)")
    return found


def _ech_paragraph() -> str:
    body = (_ROOT / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    marker = "- **ECH (Encrypted Client Hello) for outbound SNI"
    start = body.find(marker)
    assert start != -1, (
        f"docs/SECURITY.md no longer carries {marker!r}. The 12.1.5 risk acceptance is what this "
        f"guard exists to hold; if it moved or was renamed, re-point the slice rather than deleting "
        f"the guard (BACKLOG #1011)."
    )
    end = body.find("\n- **", start + 1)
    nxt = body.find("\n#", start + 1)
    if nxt != -1 and (end == -1 or nxt < end):
        end = nxt
    return body[start:] if end == -1 else body[start:end]


def test_the_ech_risk_acceptance_rests_on_a_premise_the_tree_does_not_refute() -> None:
    para = _ech_paragraph()
    assert len(para) > 400, (
        f"the sliced 12.1.5 paragraph is {len(para)} chars -- the slice is wrong"
    )

    assert not refuted_premise_claims(para), (
        f"docs/SECURITY.md's 12.1.5 risk acceptance asserts {refuted_premise_claims(para)}, which "
        f"ADR 0139 and this repository's own history refute: ECH IS buildable off-stdlib and was "
        f"built here. SDS-3.7 -- a compensating control must not rest on a false premise."
    )
    # The true premise has to be present, not merely the false one absent: the operative reason
    # nothing more was built is that no partner endpoint publishes an ECHConfig.
    for required in ("buildable off-stdlib", "ECHConfig", "adr/0139-"):
        assert required in para, f"the 12.1.5 paragraph no longer carries {required!r}"


@pytest.mark.parametrize(
    "expected",
    [
        "not buildable here",
        "third-party TLS stack",
        "infeasible, documented risk acceptance",
    ],
)
def test_the_premise_check_fires_on_the_paragraph_that_actually_shipped(expected: str) -> None:
    """Positive control against the real historical text, not a synthetic one."""
    assert expected in refuted_premise_claims(_ORIGINAL_12_1_5_PARAGRAPH)


# --- invariant 1, widened: the SAME premise had THREE carriers, not one ---------------------------
#
# Guarding only docs/SECURITY.md would have been the narrow fix. A repo-wide grep during #1011 found
# the identical refuted claim live in two further security records: ADR 0093 section 3 ("empirically
# not buildable ... would require a third-party TLS stack"), which is where the SECURITY.md paragraph
# came from, and chapter 19's standing-risk-acceptance table ("documented infeasibility, not a
# deferral"), which a reader re-confirms at EVERY release sign-off. So the guard is scoped to the
# document set where a premise is load-bearing, not to the one file that was named in the item.
#
# docs/BACKLOG.md and the closed-item archive are deliberately OUT of scope: a ledger's job is to
# QUOTE a defect as evidence, so an asserting phrase there is correct usage, not a live claim.

# `docs/testing/master-test-plan/` WAS a fourth root, for chapter 19's standing-risk-acceptance
# table. ADR 0160 D1 untracked that whole tree on 2026-08-31, so `_tracked()` no longer returns a
# single path under it and the root matched nothing. Dropping it is a stale anchor coming out, not a
# guard being weakened -- but say the narrowing out loud rather than let a green run imply coverage:
# the chapter-19 carrier of this premise now lives only in the vault and NOTHING in this repository
# checks it. If that tree ever returns, this root returns with it.
#
#: Records where a risk acceptance's premise is load-bearing.
_RECORD_ROOTS = ("docs/SECURITY.md", "docs/PHI.md", "docs/adr/")

#: The refuted claim in ASSERTING form. "infeasible" alone is absent for the reason given above.
_ASSERTING = ("not buildable", "third-party TLS stack", "documented infeasibility")

#: A correction marker. Its presence in the SAME section is what turns a quotation into a denial --
#: the section, not a character window, because a correction block sits above the text it corrects.
_DENIALS = ("is **not** the reason", "it did not", "refuted", "REFUTED", "as authored")

_ECH_TOKEN = re.compile(r"\bECH\b")


def unretracted_ech_claims(body: str) -> list[str]:
    """Markdown sections that assert the refuted premise about ECH without correcting it.

    A section qualifies only when it actually discusses ECH -- ``\\bECH\\b`` deliberately does NOT
    match ``ECHConfig`` or DICOM's ``C-ECHO``, so an unrelated "not buildable" elsewhere in the corpus
    (ADR 0015's WSDL note, ADR 0142's on-prem AD note) cannot red this guard.
    """
    out: list[str] = []
    for section in re.split(r"\n(?=#{1,6} )", body):
        flat = _flat(section)
        if not _ECH_TOKEN.search(flat):
            continue
        asserted = [phrase for phrase in _ASSERTING if phrase in flat]
        if asserted and not any(d in flat for d in _DENIALS):
            head = section.splitlines()[0][:80]
            out.append(f"{head!r}: {asserted}")
    return out


def test_no_security_record_still_asserts_that_ech_is_unbuildable() -> None:
    scanned = 0
    offenders: list[str] = []
    for rel in _tracked():
        if not rel.startswith(_RECORD_ROOTS) or not rel.endswith(".md"):
            continue
        f = _ROOT / rel
        if not f.is_file():
            continue
        scanned += 1
        offenders.extend(f"{rel} -> {hit}" for hit in unretracted_ech_claims(f.read_text("utf-8")))

    assert scanned > 100, f"expected the record corpus, scanned only {scanned} markdown files"
    assert not offenders, (
        f"scanned {scanned} markdown records under {list(_RECORD_ROOTS)}; these still assert the "
        f"premise ADR 0139 and this repository's own history refute: {offenders}. SDS-3.7 -- a "
        f"compensating control must not rest on a false premise (BACKLOG #1011)."
    )


#: ADR 0093 section 3 as it stood before the 2026-08-10 correction. The second positive control, and
#: the reason this guard is section-scoped: the correction that retracts it sits ABOVE it, far outside
#: any plausible character window.
_ORIGINAL_ADR_0093_SECTION_3 = """### 3. ECH for outbound SNI (scope out — infeasible)

ECH (Encrypted Client Hello) would hide the destination hostname (partner/EHR identity) in the outbound
TLS ClientHello SNI. It is **not buildable** under the project's constraints, empirically:

- **It would violate the no-new-dependency rule** — a working ECH client would require a third-party
  TLS stack (a `cryptography`-external library), which the project's dependency discipline rejects for
  a security-core path."""


def test_the_record_wide_check_fires_on_adr_0093_as_it_stood() -> None:
    """Positive control 2, and the negative controls that keep the guard from being a blanket ban."""
    hits = unretracted_ech_claims(_ORIGINAL_ADR_0093_SECTION_3)
    assert len(hits) == 1 and "not buildable" in hits[0] and "third-party TLS stack" in hits[0], (
        hits
    )

    # A section that quotes the claim IN ORDER TO RETRACT it is not an offender.
    assert (
        unretracted_ech_claims(_ORIGINAL_ADR_0093_SECTION_3 + "\n\nThat claim is refuted.\n") == []
    )

    # An unrelated "not buildable" is not an ECH claim. ADR 0015 and ADR 0142 both carry one, and a
    # guard that reddened on those would be a blanket ban on a common English phrase.
    assert unretracted_ech_claims("## WSDL\n\nNot buildable against an unread WSDL.\n") == []
    # ...including in text that mentions C-ECHO or an ECHConfig, neither of which is the token ECH.
    assert unretracted_ech_claims("## DICOM\n\nC-ECHO is not buildable here.\n") == []
    assert unretracted_ech_claims("## DNS\n\nECHConfig lookups are not buildable here.\n") == []

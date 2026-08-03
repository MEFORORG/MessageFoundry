# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The honesty gate for the DAST tier (ADR 0155), inside the required test legs.

WHY THIS EXISTS AS CI RATHER THAN CONVENTION. ``docs/Secure_Build_Standards.md`` grades independent
external verification as signal 10, and it names the gameable proxy for that signal explicitly in its
theater table: *an internal "L3 verified" / self-assessment pass*. A self-run automated DAST tier IS
that substitute. Shipping one therefore creates a live incentive to let the boundary blur — one edit
turning "no independent DAST" into "DAST coverage", one scorecard row quietly re-graded — and a
boundary held only by convention is a boundary that survives exactly as long as nobody is in a hurry.

So the guards below are structural. They pin the two permitted copies of the boundary text
byte-identical, pin the rubric rows this work must NOT be read as satisfying, and sweep the files this
change introduces for language that would let a reader conclude the independent gap is closed.

The boundary text itself is deliberately NOT restated in this file. It is read from the two permitted
sources — a third copy here would be a third thing to keep in sync, which is the defect, not the fix.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from scripts.security.dast_auth_sweep import INDEPENDENCE_NOTICE

_REPO = Path(__file__).resolve().parents[1]
_ADR = _REPO / "docs" / "adr" / "0155-dast-dynamic-security-testing-of-the-running-engine.md"
_BUILD_STANDARDS = _REPO / "docs" / "Secure_Build_Standards.md"
_SCORECARD = _REPO / "docs" / "Secure_Build_Scorecard_MEFOR.md"
_SDS = _REPO / "docs" / "Secure_Development_Standards.md"

#: The FEATURE-MAP clause this change pins. It was UNGUARDED before: only "self-assessment", "not a
#: certification" and "no third-party assessment" were pinned, so an edit implying DAST coverage passed
#: CI. Green CI was not evidence of honesty on this row until this phrase was added.
_PINNED_DAST_PHRASE = "no independent dynamic (DAST) testing"

#: A distinctive fragment of the boundary text, used to find stray copies. It is a SLICE of the shipped
#: constant, never a retyped one, so it cannot drift into a third source of truth.
_NOTICE_FINGERPRINT = "is the substitute that rubric explicitly exists to grade"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _normalised(text: str) -> str:
    """Line endings and TRAILING whitespace only. Nothing else is normalised: the point of a
    byte-identical pin is that a reworded copy fails, and a normaliser that smooths over punctuation
    would let exactly the drift this guard exists for through."""
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").split("\n"))


# =====================================================================================================
# The two permitted copies of the boundary
# =====================================================================================================


def test_independence_notice_is_byte_identical() -> None:
    """AC-7. The receipt travels outside the repository as a CI artifact, so the boundary is duplicated
    into ``INDEPENDENCE_NOTICE`` — a number circulating stripped of its boundary is worse than no
    number. That duplication is only safe while the two copies cannot drift, so they are pinned equal
    here rather than by convention.
    """
    assert INDEPENDENCE_NOTICE.strip(), "the shipped notice is empty"
    assert _normalised(INDEPENDENCE_NOTICE) in _normalised(_read(_ADR)), (
        "the INDEPENDENCE_NOTICE constant in scripts/security/dast_auth_sweep.py no longer appears "
        "VERBATIM in ADR 0155's Scope boundary section. These are the only two permitted copies and "
        "they must be byte-identical; edit both in the same change (compare them character by "
        "character — a typographic quote against a straight quote is a real drift, not a cosmetic one)."
    )


#: Independence-boundary language. The exclusivity claim in ADR 0155's *Scope boundary* section is only
#: worth making if a PARAPHRASE reds too: the fingerprint sweep below catches a verbatim third copy, but
#: a reworded one — "self-run DAST does not satisfy signal 10, which requires independence" — is exactly
#: the copy that would be left behind and go stale when the boundary is next sharpened.
_PARAPHRASE = re.compile(
    r"signal 10|independent external verification|requires independence", re.IGNORECASE
)


def _section(path: Path, start: str, stop: str | None) -> str:
    """The slice of ``path`` from the line beginning ``start`` up to the next line beginning ``stop``.

    Used to scope the sweep to the passages this change OWNS inside shared documents, so the guard
    cannot be satisfied (or defeated) by unrelated prose elsewhere in the same file.
    """
    text = _read(path)
    begin = text.find(start)
    assert begin != -1, f"{path.name} no longer contains {start!r} — this guard is scanning nothing"
    rest = text[begin:]
    if stop is not None:
        end = rest.find(stop, len(start))
        if end != -1:
            return rest[:end]
    return rest


def _pointer_only_passages() -> dict[str, str]:
    """The DAST passages that must carry a POINTER to ADR 0155 and no independence wording of their own.

    Deliberately excludes the two permitted carriers, and deliberately excludes
    ``docs/FEATURE-MAP.md``: that row's independence language is a claim about the PROJECT's assessment
    posture which predates this change, and it is pinned separately by
    ``tests/test_feature_map_claims.py``. Including it here would make this guard red on honest,
    already-guarded prose.
    """
    return {
        ".github/workflows/dast.yml": _read(_REPO / ".github" / "workflows" / "dast.yml"),
        "scripts/security/dast_target.py": _read(_REPO / "scripts" / "security" / "dast_target.py"),
        "scripts/security/route_gates.py": _read(_REPO / "scripts" / "security" / "route_gates.py"),
        "docs/BACKLOG.md #318": _section(_REPO / "docs" / "BACKLOG.md", "## 318. DAST", "\n## "),
        "docs/adr/README.md (the 0155 row)": _section(
            _REPO / "docs" / "adr" / "README.md",
            "| [0155](0155-dast-dynamic-security-testing-of-the-running-engine.md) |",
            "\n|",
        ),
        "docs/CI.md (the dast.yml row)": _section(
            _REPO / "docs" / "CI.md", "| `dast.yml` |", "\n|"
        ),
    }


def test_no_stray_paraphrase_of_the_boundary() -> None:
    """ADR 0155's *Scope boundary* claims every other file carries a bare pointer. This is what makes
    that claim CI-enforced rather than asserted — and it is the half the fingerprint sweep cannot do.

    The failure it prevents is concrete: sharpen the boundary wording, the two verbatim carriers move
    together because they are pinned equal, and four paraphrases keep the old wording. Nothing reds, and
    the tree now holds several contradictory answers to *has anything independent run?*
    """
    passages = _pointer_only_passages()
    hits = [
        f"{label}: {match.group(0)!r}"
        for label, text in passages.items()
        if (match := _PARAPHRASE.search(text)) is not None
    ]
    assert not hits, (
        "a DAST passage restates the independence boundary instead of pointing at ADR 0155's Scope "
        f"boundary section: {hits}. State it once and link; a paraphrase here goes stale silently."
    )
    # Every READER-FACING passage must also actually POINT somewhere, or "carries no restatement" would
    # be satisfied by a passage that says nothing at all — which is not a boundary held once, it is a
    # boundary dropped. The two implementation modules are exempt: they make no claim to point away
    # from, and they are swept above only so a paraphrase cannot hide in a docstring.
    reader_facing = {
        label: text for label, text in passages.items() if not label.startswith("scripts/security/")
    }
    assert len(reader_facing) >= 4, reader_facing.keys()
    silent = [label for label, text in reader_facing.items() if "0155" not in text]
    assert not silent, (
        f"DAST passage(s) with neither the boundary nor a pointer to ADR 0155: {silent}"
    )


def test_the_paraphrase_guard_can_see_a_paraphrase() -> None:
    """Prove the pattern bites before crediting the clean result above."""
    assert _PARAPHRASE.search("it does not satisfy signal 10")
    assert _PARAPHRASE.search("Independent External Verification is not claimed")
    assert _PARAPHRASE.search("which requires independence rather than automation")
    assert not _PARAPHRASE.search("see ADR 0155 for the scope boundary")


def test_the_notice_has_exactly_two_copies() -> None:
    """ "State a load-bearing fact ONCE and link to it" (CLAUDE.md §11). BACKLOG #318, docs/CI.md,
    the workflow and FEATURE-MAP must LINK to ADR 0155, never restate the boundary — a restated copy
    survives the next revision of the original and becomes a second, contradictory answer."""
    assert _NOTICE_FINGERPRINT in INDEPENDENCE_NOTICE, (
        "the fingerprint this guard searches for is no longer part of the shipped notice, so the "
        "stray-copy sweep below is scanning for a string that cannot occur — update it"
    )
    searched = [
        *sorted((_REPO / "docs").rglob("*.md")),
        *sorted((_REPO / "scripts").rglob("*.py")),
        *sorted((_REPO / ".github" / "workflows").glob("*.yml")),
    ]
    carriers = [p for p in searched if _NOTICE_FINGERPRINT in _read(p)]
    relative = sorted(p.relative_to(_REPO).as_posix() for p in carriers)
    assert relative == [
        "docs/adr/0155-dast-dynamic-security-testing-of-the-running-engine.md",
        "scripts/security/dast_auth_sweep.py",
    ], f"the boundary text is carried by {relative}; exactly two copies are permitted"
    assert len(searched) > 100, (
        f"the sweep examined only {len(searched)} files — that is too few to be the docs, scripts and "
        "workflow trees, so this guard is looking in the wrong place"
    )


# =====================================================================================================
# The rubric rows this work must NOT be read as satisfying
# =====================================================================================================


@pytest.mark.parametrize(
    "row",
    [
        "Third-party source review + penetration test + DAST before production or off-loopback",
        'An internal "L3 verified" / self-assessment pass',
    ],
)
def test_signal_10_rows_are_unchanged(row: str) -> None:
    """Signal 10 and its theater-table twin are the rows this change is most likely to be mistaken for
    satisfying. Row 6 of the theater table names an internal self-assessment pass as the gameable proxy
    — which is precisely the shape of a self-run DAST tier — so neither may be softened."""
    assert row in _read(_BUILD_STANDARDS), (
        f"docs/Secure_Build_Standards.md no longer contains {row!r} verbatim. A self-run DAST tier does "
        "not satisfy signal 10, and this row must not be edited to suggest otherwise."
    )


@pytest.mark.parametrize(
    "sentence",
    [
        "capped below a full A only by independent external verification (signal 10)",
        "capped below a full A only by signal 10 (independent external verification)",
        "No independent third-party ASVS review, penetration test, or DAST has run.",
        "**No independent external verification** (third-party ASVS L2/L3 review + penetration test "
        "+ DAST).",
        "**No independent external verification.** No third-party ASVS review, penetration test, or "
        "DAST has run (signal 10). This is not treated as passed.",
    ],
)
def test_scorecard_negative_claims_survive(sentence: str) -> None:
    """Five places in the scorecard assert the ABSENCE of independent verification. A self-run tier does
    not falsify any of them, so none may be softened or re-scored off the back of this change — that is
    an owner decision on a dated pass, not a side effect of shipping a scanner.

    Asserted on the SENTENCES, never on line numbers: a line number is a fact about the file's shape,
    not about its claims, and it goes stale on the next unrelated paragraph.
    """
    assert "independent" in sentence.lower(), "this guard's own fixture must contain the claim word"
    assert sentence in _read(_SCORECARD), (
        f"docs/Secure_Build_Scorecard_MEFOR.md no longer contains {sentence!r}. The A- grade and its "
        "capping gap stand; ADR 0155 must not be used to argue a re-score."
    )


@pytest.mark.parametrize(
    "row",
    [
        # §6.1 — the Dynamic tier row this work SATISFIES rather than contradicts, so it is unchanged.
        "| Dynamic | DAST / authenticated testing of the running app | Per release and periodically |",
        # §6.1 — the Independent review row, a DIFFERENT tier, untouched by a self-run pass.
        "| Independent review | Third-party source-code review + penetration test per 800-115",
        # §A.6 — the source of record for the independent-engagement status.
        "**Independent ASVS-L3 review & DAST (§6.3 / §6.4).** Not yet performed",
    ],
)
def test_sds_independent_review_row_is_unchanged(row: str) -> None:
    """§A.6 is the SINGLE source of record for whether anything independent has run. ADR 0155 links to
    it rather than restating it, so this file must keep saying what the link promises."""
    assert row in _read(_SDS), (
        f"docs/Secure_Development_Standards.md no longer contains {row!r} verbatim. ADR 0155 links here "
        "as the source of record for the independent-engagement status; if this moved, the link now "
        "points at nothing and the boundary has quietly lost its anchor."
    )


# =====================================================================================================
# No file this change introduces may claim the gap is closed
# =====================================================================================================

_CLOSURE_CLAIM = re.compile(
    r"(pen ?test|penetration test|independen\w*).{0,60}(complete|satisfied|closed|covered|discharg)",
    re.IGNORECASE,
)


def test_no_file_claims_dast_closes_the_independent_gap() -> None:
    """The failure mode is not a lie; it is a sentence that reads like one to a hurried reader. Sweep
    every file this change introduces for language putting a closure verb within a clause of the
    independence claim."""
    targets = [
        *sorted((_REPO / "docs" / "adr").glob("0155*")),
        _REPO / "docs" / "BACKLOG.md",
        _REPO / "docs" / "CI.md",
        _REPO / ".github" / "workflows" / "dast.yml",
        *sorted((_REPO / "scripts" / "security").glob("dast_*.py")),
    ]
    assert len(targets) >= 6, f"the sweep found only {targets} to examine"

    hits: list[str] = []
    for path in targets:
        assert path.is_file(), f"{path} is missing — this guard cannot be credited without it"
        for number, line in enumerate(_read(path).splitlines(), start=1):
            match = _CLOSURE_CLAIM.search(line)
            if match is not None:
                hits.append(f"{path.relative_to(_REPO).as_posix()}:{number}: {match.group(0)!r}")
    assert not hits, (
        "a file introduced by this change reads as if the independent-verification gap were closed: "
        + "; ".join(hits)
        + ". Self-run automation does not close it; state the boundary and link to ADR 0155."
    )


def test_the_closure_sweep_can_actually_see_a_claim() -> None:
    """A green sweep is evidence only if it can SEE the class it hunts. Prove the pattern bites before
    crediting the clean result above."""
    assert _CLOSURE_CLAIM.search("the independent verification requirement is now satisfied")
    assert _CLOSURE_CLAIM.search("pentest coverage is complete")
    assert not _CLOSURE_CLAIM.search("the independent engagement has not been performed")


# =====================================================================================================
# Prove the FEATURE-MAP guard catches the rewrite it exists for
# =====================================================================================================


def test_the_guard_catches_the_rewrite_it_exists_to_prevent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A new guard is not credited until it has caught the exact regression it exists for.

    Drives the SHIPPED assertion — ``tests/test_feature_map_claims.test_asvs_row_keeps_its_framing`` —
    over an in-memory copy of the catalog whose DAST clause has been rewritten to imply coverage, and
    requires it to red. Before this phrase was pinned, that rewrite passed CI.
    """
    import tests.test_feature_map_claims as feature_map

    # Read the phrase list off the parametrize mark rather than retyping it: a second copy here could
    # agree with the FEATURE-MAP row while the REAL list had already dropped the phrase, and this guard
    # would then certify an unarmed guard.
    marks = getattr(feature_map.test_asvs_row_keeps_its_framing, "pytestmark", [])
    pinned = [mark for mark in marks if mark.name == "parametrize"][0].args[1]
    assert _PINNED_DAST_PHRASE in pinned, (
        f"{_PINNED_DAST_PHRASE!r} is not in the pinned phrase list ({pinned}), so the FEATURE-MAP "
        "guard is not armed against a rewrite of the DAST clause at all."
    )

    # It passes on the real document, so the failure below is caused by the rewrite and nothing else.
    feature_map.test_asvs_row_keeps_its_framing(_PINNED_DAST_PHRASE)

    real = feature_map._text()
    rewritten = real.replace(_PINNED_DAST_PHRASE, "DAST testing now runs")
    assert rewritten != real, (
        f"docs/FEATURE-MAP.md does not contain {_PINNED_DAST_PHRASE!r}, so there was nothing to rewrite"
    )
    monkeypatch.setattr(feature_map, "_text", lambda: rewritten)
    with pytest.raises(AssertionError):
        feature_map.test_asvs_row_keeps_its_framing(_PINNED_DAST_PHRASE)

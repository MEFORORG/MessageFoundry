# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guards on `docs/FEATURE-MAP.md`, the **public** capability catalog.

FEATURE-MAP.md is not git-ignored as a private-only path, so it reaches the public
mirror. In July 2026 it carried a hardcoded ASVS score (`214 / 0 / 0 / 131`) copied from
`docs/security/ASVS-L3-ASSESSMENT.md` — a document that had since been banner-marked
"⛔ SUPERSEDED … the scoring in this document is not reliable". Three defects at once: a
false public security claim, a link into a private (deny-listed) path that 404s on the
mirror, and a count that nothing in CI was checking. See BACKLOG #310.

These guards are deliberately *narrow*. They do not try to know the correct score — by the
project's own rule no ASVS figure is quotable until the final re-score lands — they only
stop the public catalog from asserting one, or from pointing at private/superseded sources.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_FEATURE_MAP = _REPO / "docs" / "FEATURE-MAP.md"
_DENYLIST = _REPO / "scripts" / "publish" / "publish-denylist.txt"

# "214 / 0 / 0 / 131", "195/89/0/61" — an ASVS Pass/Partial/Fail/N-A tuple.
_SCORE_TUPLE = re.compile(r"\d{1,3}\s*/\s*\d{1,3}\s*/\s*\d{1,3}\s*/\s*\d{1,3}")
# Relative markdown links only (skip http/https/mailto and pure anchors).
_REL_LINK = re.compile(r"\]\((?!https?:|mailto:|#)([^)]+)\)")
_SUPERSEDED = "⛔ SUPERSEDED"


def _text() -> str:
    return _FEATURE_MAP.read_text(encoding="utf-8")


def _denylist_prefixes() -> list[str] | None:
    """Deny-listed path prefixes, or ``None`` in a checkout that has no deny-list.

    A "link into a private path" MANIFESTS DIFFERENTLY depending on which checkout you are in, and that
    is why there are two modes rather than one list from two sources:

    * **Private repo** — the target file is present locally but is stripped from the published snapshot,
      so only the deny-list can tell you the link will 404 for a reader. Existence proves nothing.
    * **Public repo / mirror** — the private path is simply ABSENT, so a link into one is just a broken
      relative link. No list is needed, and the existence check is strictly STRONGER: it also catches
      links to files that were deleted or renamed, which a deny-list never could.

    An earlier version of this tried to keep one list by parsing a marker block out of ``.gitignore``
    after the cutover. That marker did not exist in any ``.gitignore`` — the string appeared only in
    this test — and its unit test built a synthetic file in ``tmp_path``, so it exercised the parser
    and could never notice the real marker was missing. It was a check that could not fail.
    """
    if not _DENYLIST.exists():
        return None
    return [
        entry
        for line in _DENYLIST.read_text(encoding="utf-8").splitlines()
        if (entry := line.strip()) and not entry.startswith("#")
    ]


def test_link_check_catches_a_missing_target_without_a_denylist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The public-repo mode must actually FAIL on a bad link, not just run.

    This is the branch that is live on the mirror and will be the ONLY branch after the cutover, so it
    is asserted directly rather than via a synthetic parser fixture. Both halves matter: a link whose
    target exists passes, and one whose target does not FAILS.
    """
    monkeypatch.setattr(sys.modules[__name__], "_DENYLIST", tmp_path / "absent.txt")
    assert _denylist_prefixes() is None, "precondition: this must exercise the no-denylist mode"

    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "present.md").write_text("hi\n", encoding="utf-8")
    fm = docs / "FEATURE-MAP.md"
    monkeypatch.setattr(sys.modules[__name__], "_FEATURE_MAP", fm)

    fm.write_text("see [ok](present.md)\n", encoding="utf-8")
    test_no_links_into_private_paths()  # must not raise

    fm.write_text("see [gone](security/THREAT-MODEL.md)\n", encoding="utf-8")
    with pytest.raises(AssertionError, match="do not exist"):
        test_no_links_into_private_paths()


def test_feature_map_is_actually_published() -> None:
    """The premise of every other guard here: FEATURE-MAP reaches the reader.

    With a deny-list, prove it is not on it. Without one, the file's own presence in this checkout IS
    the proof — a deny-listed/vaulted file would not be here to read.
    """
    prefixes = _denylist_prefixes()
    if prefixes is None:
        assert _FEATURE_MAP.is_file(), (
            "FEATURE-MAP.md is missing — the guards below have no subject"
        )
        return
    assert not any(
        p == "docs/FEATURE-MAP.md" or "docs/FEATURE-MAP.md".startswith(p.rstrip("/") + "/")
        for p in prefixes
    ), "FEATURE-MAP.md is now deny-listed — revisit the guards in this module"


def test_no_hardcoded_asvs_score_tuple() -> None:
    """The public catalog must not assert a Pass/Partial/Fail/N-A count.

    Counts go stale silently and this one was wrong in public for weeks. Point at the
    assessment set instead; the score of record is designated under BACKLOG #310.
    """
    hits = [
        (i, m.group(0))
        for i, line in enumerate(_text().splitlines(), start=1)
        for m in _SCORE_TUPLE.finditer(line)
    ]
    assert not hits, (
        "docs/FEATURE-MAP.md asserts ASVS-style score tuple(s) "
        + ", ".join(f"{tup!r} at line {ln}" for ln, tup in hits)
        + ". The public catalog must not publish a count — no figure is quotable until the "
        "final re-score lands (BACKLOG #310)."
    )


def test_no_links_into_private_paths() -> None:
    """A link into a private path is a dead link for the reader.

    Two modes, because the defect looks different depending on the checkout — see
    :func:`_denylist_prefixes`. With a deny-list, match the link against it (the target is present
    locally, so only the list knows it will 404). Without one, the private path is simply absent, so
    a missing target IS the defect — and that also catches deleted or renamed files.
    """
    prefixes = _denylist_prefixes()
    bad: list[tuple[int, str]] = []
    for i, line in enumerate(_text().splitlines(), start=1):
        for m in _REL_LINK.finditer(line):
            target = m.group(1).split("#", 1)[0].strip()
            if not target:
                continue
            if prefixes is None:
                if not (_FEATURE_MAP.parent / target).exists():
                    bad.append((i, target))
                continue
            repo_rel = f"docs/{target}".replace("\\", "/")
            if any(repo_rel == p or repo_rel.startswith(p.rstrip("/") + "/") for p in prefixes):
                bad.append((i, target))
    detail = ", ".join(f"{t!r} at line {ln}" for ln, t in bad)
    if prefixes is None:
        assert not bad, (
            f"docs/FEATURE-MAP.md links to targets that do not exist in this checkout: {detail}. "
            "In a public checkout that means either a link into a private/vaulted path, or a stale "
            "link to something deleted or renamed. Either way it is a 404 for the reader."
        )
    else:
        assert not bad, (
            f"docs/FEATURE-MAP.md links into private, deny-listed paths (these 404 on the public "
            f"mirror): {detail}"
        )


def test_no_links_to_superseded_documents() -> None:
    """Never point the public catalog at a document banner-marked superseded."""
    bad: list[tuple[int, str]] = []
    for i, line in enumerate(_text().splitlines(), start=1):
        for m in _REL_LINK.finditer(line):
            target = m.group(1).split("#", 1)[0].strip()
            if not target.endswith(".md"):
                continue
            path = (_FEATURE_MAP.parent / target).resolve()
            if not path.is_file():
                continue
            head = "\n".join(path.read_text(encoding="utf-8").splitlines()[:20])
            if _SUPERSEDED in head:
                bad.append((i, target))
    assert not bad, "docs/FEATURE-MAP.md links to superseded document(s): " + ", ".join(
        f"{t!r} at line {ln}" for ln, t in bad
    )


@pytest.mark.parametrize(
    "phrase",
    [
        "self-assessment",
        "not a certification",
        "no third-party assessment",
    ],
)
def test_asvs_row_keeps_its_framing(phrase: str) -> None:
    """The honesty framing is load-bearing and has been dropped before.

    A reader who takes "ASVS L3 ✅" as an audited result has been misled; these phrases are
    what stop that, so their removal should fail CI rather than pass review.
    """
    rows = [ln for ln in _text().splitlines() if ln.startswith("| OWASP ASVS L3 posture |")]
    assert len(rows) == 1, f"expected exactly one ASVS posture row, found {len(rows)}"
    assert phrase.lower() in rows[0].lower(), (
        f"the ASVS posture row in docs/FEATURE-MAP.md no longer says {phrase!r}. "
        "This framing is required: the posture is a point-in-time, AI-assisted "
        "self-assessment, not a certification or an independent review."
    )

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guards on `docs/FEATURE-MAP.md`, the **public** capability catalog.

FEATURE-MAP.md is not in `scripts/publish/publish-denylist.txt`, so it reaches the public
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
_GITIGNORE = _REPO / ".gitignore"
# Marker opening the .gitignore vault block that replaces the deny-list after the cutover.
_VAULT_MARKER = "Private-content vault"

# "214 / 0 / 0 / 131", "195/89/0/61" — an ASVS Pass/Partial/Fail/N-A tuple.
_SCORE_TUPLE = re.compile(r"\d{1,3}\s*/\s*\d{1,3}\s*/\s*\d{1,3}\s*/\s*\d{1,3}")
# Relative markdown links only (skip http/https/mailto and pure anchors).
_REL_LINK = re.compile(r"\]\((?!https?:|mailto:|#)([^)]+)\)")
_SUPERSEDED = "⛔ SUPERSEDED"


def _text() -> str:
    return _FEATURE_MAP.read_text(encoding="utf-8")


def _private_prefixes() -> list[str]:
    """Paths the public catalog must never link into.

    The SOURCE of that list changes across the repo's lifetime, but the question does not. While the
    private+mirror model is live it is the publish deny-list. Once development moves into the public
    repo the deny-list is deleted and the same role is played by the ``.gitignore`` private-content
    vault block — which is *broader*, so the guard gets stronger, not weaker. Read whichever exists.

    If NEITHER exists this RAISES rather than returning an empty list. Empty would make every guard in
    this module vacuously pass: no prefixes, so nothing can link into one, so green. A leak guard that
    silently stops guarding when its input disappears is worse than no guard, because it still reports
    a green tick — the precise failure mode this cutover's pre-flight found in the CI leak gate itself.
    """
    if _DENYLIST.exists():
        return [
            entry
            for line in _DENYLIST.read_text(encoding="utf-8").splitlines()
            if (entry := line.strip()) and not entry.startswith("#")
        ]
    if _GITIGNORE.exists():
        out: list[str] = []
        in_vault = False
        for line in _GITIGNORE.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if _VAULT_MARKER in stripped:
                in_vault = True
                continue
            if in_vault:
                if not stripped:
                    break
                if not stripped.startswith("#"):
                    # "docs/security/**" and "/docs/security/" both mean the prefix docs/security.
                    out.append(stripped.lstrip("/").replace("**", "").rstrip("/"))
        if out:
            return out
    raise AssertionError(
        "neither the publish deny-list nor the .gitignore private-content vault block was found, so "
        "these guards cannot tell which paths are private. Failing closed rather than passing green "
        "on no data — if the vault block moved, point _VAULT_MARKER at it."
    )


def test_private_prefixes_falls_back_to_the_gitignore_vault_block(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """After the cutover the publish deny-list is deleted; the vault block must take over seamlessly.

    Without this fallback two guards in this module raise FileNotFoundError on the public repo — which
    is at least loud. The subtler risk is "fixing" that by deleting them, which quietly removes the only
    automated check that the public catalog never links into a vaulted path.
    """
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text(
        "*.pyc\n\n"
        f"# --- {_VAULT_MARKER} (never commit) ---\n"
        "docs/security/**\n"
        "/docs/reviews/\n"
        "docs/BACKLOG.md\n"
        "\n"
        "# Tooling — must NOT be picked up: the block ends at the blank line\n"
        ".ruff_cache/\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "_DENYLIST", tmp_path / "absent.txt")
    monkeypatch.setattr(sys.modules[__name__], "_GITIGNORE", gitignore)
    assert _private_prefixes() == ["docs/security", "docs/reviews", "docs/BACKLOG.md"]


def test_private_prefixes_fails_closed_when_no_source_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Returning [] would make every guard here pass VACUOUSLY and still report green."""
    monkeypatch.setattr(sys.modules[__name__], "_DENYLIST", tmp_path / "absent.txt")
    monkeypatch.setattr(sys.modules[__name__], "_GITIGNORE", tmp_path / "also-absent")
    with pytest.raises(AssertionError, match="Failing closed"):
        _private_prefixes()


def test_feature_map_is_actually_published() -> None:
    """The premise of every other guard here: FEATURE-MAP reaches the public mirror.

    If it is ever added to the denylist these guards become pointless rather than wrong —
    this test makes that transition loud instead of silent.
    """
    assert not any(
        p == "docs/FEATURE-MAP.md" or "docs/FEATURE-MAP.md".startswith(p.rstrip("/") + "/")
        for p in _private_prefixes()
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
    """A link into a deny-listed path is a dead link on the public mirror."""
    prefixes = _private_prefixes()
    bad: list[tuple[int, str]] = []
    for i, line in enumerate(_text().splitlines(), start=1):
        for m in _REL_LINK.finditer(line):
            target = m.group(1).split("#", 1)[0].strip()
            if not target:
                continue
            repo_rel = f"docs/{target}".replace("\\", "/")
            if any(repo_rel == p or repo_rel.startswith(p.rstrip("/") + "/") for p in prefixes):
                bad.append((i, target))
    assert not bad, (
        "docs/FEATURE-MAP.md links into private, deny-listed paths (these 404 on the public "
        "mirror): " + ", ".join(f"{t!r} at line {ln}" for ln, t in bad)
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

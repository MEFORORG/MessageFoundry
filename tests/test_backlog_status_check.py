# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the backlog status-hygiene gate (``scripts/docs/backlog_status_check.py``).

The last test is the one that matters operationally: it runs the checker against the **real**
``docs/BACKLOG.md``, so the invariant is enforced by the normal pytest job on every PR — no separate
CI leg needed for the structural half of the rule.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "docs" / "backlog_status_check.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("backlog_status_check", _SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


bsc = _load()


def _scan(text: str, changelog: str | None = None) -> tuple[list[str], list[str]]:
    """Single-source shorthand for the unit cases below.

    ``scan()`` takes ``(label, text)`` pairs on purpose — the number namespace spans the published
    backlog *and* every archive file, and a caller that cannot name its sources is how a per-file
    duplicate check gets reintroduced. The cross-file behaviour is covered explicitly by
    ``test_duplicate_across_two_sources_is_an_error``; these unit cases only need one source.
    """
    return bsc.scan([("BACKLOG.md", text)], changelog)  # type: ignore[no-any-return]


def test_open_item_with_priority_banner_passes() -> None:
    text = "## 7. Something\n\n> 🔢 **Re-prioritized 2026-07-09 → P2.** Value **3/5**.\n\n**Scope:** x\n"
    errors, warnings = _scan(text)
    assert errors == []
    assert warnings == []


def test_shipped_item_passes() -> None:
    text = (
        "## 8. Something\n\n> ✅ **SHIPPED — verified on `origin/main`.** Evidence.\n\n**Why:** x\n"
    )
    assert _scan(text)[0] == []


@pytest.mark.parametrize("emoji", ["⛔", "🪦", "🚧"])
def test_each_recognized_banner_satisfies_the_invariant(emoji: str) -> None:
    assert _scan(f"## 9. T\n\n> {emoji} **STATUS.** x\n\n**Why:** y\n")[0] == []


def test_missing_status_banner_is_an_error() -> None:
    # The boilerplate demand-gate blockquote is NOT a status banner.
    text = (
        "## 10. T\n\n> **On-trigger / demand-gate.** Numbered for tracking only.\n\n**Scope:** x\n"
    )
    errors, _ = _scan(text)
    assert len(errors) == 1
    assert "declares no status" in errors[0]


def test_shipped_and_open_banners_contradict() -> None:
    text = "## 11. T\n\n> ✅ **SHIPPED.** yes\n\n> 🔢 **Re-prioritized → P1.** no\n\n**Scope:** x\n"
    errors, _ = _scan(text)
    assert len(errors) == 1
    assert "contradicts itself" in errors[0]


def test_duplicate_item_numbers_are_an_error() -> None:
    text = "## 12. A\n\n> 🔢 **P.** x\n\n## 12. B\n\n> 🔢 **P.** y\n"
    errors, _ = _scan(text)
    assert any("duplicate" in e for e in errors)


def test_prose_containing_the_word_decline_is_not_a_status_banner() -> None:
    """Regression: the '🛠 Decline overturned' note must not read as a DECLINED status.

    This exact false positive fooled a naive word-match during the 2026-07-09 audit.
    """
    text = (
        "## 13. T\n\n"
        "> 🛠 **Decline overturned.** A pass recommended DECLINE; the stated reason was invalid.\n"
        ">\n"
        "> **Build constraints:** build at the connector.\n\n"
        "> 🔢 **Re-prioritized → DEMAND-GATE.** Value **2/5**.\n\n"
        "**Scope:** x\n"
    )
    errors, _ = _scan(text)
    assert errors == []


def test_banner_after_prose_does_not_count() -> None:
    """A status banner must lead the item, before its Scope/Why prose."""
    text = "## 14. T\n\n**Scope:** x\n\n> ✅ **SHIPPED.** too late\n"
    errors, _ = _scan(text)
    assert any("declares no status" in e for e in errors)


def test_changelog_crossref_flags_an_open_item_cited_as_shipped() -> None:
    """The #60 failure mode: CHANGELOG says it shipped, BACKLOG still says open."""
    backlog = "## 60. Turnkey DR\n\n> 🔢 **Re-prioritized → P3.** still open\n"
    changelog = (
        "- **Turnkey DR backup + restore-verify** (#60, [ADR 0049](docs/adr/0049.md)) — ships.\n"
    )
    errors, warnings = _scan(backlog, changelog)
    assert errors == []  # advisory only — never fatal
    assert len(warnings) == 1
    assert "#60" in warnings[0]


def test_changelog_crossref_ignores_pr_numbers() -> None:
    """`(#641)` is a PR number, not a backlog item — must not warn."""
    backlog = "## 641. Not a real item\n\n> 🔢 **Re-prioritized → P3.** open\n"
    changelog = "- Something landed (#641).\n"
    assert _scan(backlog, changelog)[1] == []


def test_changelog_crossref_ignores_narrative_prose() -> None:
    """A mention outside a change bullet is a reference, not a shipped claim.

    Real case: "the correctness edge is closed (… BACKLOG #82) or field-confirmed benign" is a
    continuation line, not an entry. A noisy advisory is an ignored advisory.
    """
    backlog = "## 82. Sender transport polish\n\n> 🔢 **Re-prioritized → P1.** open\n"
    changelog = "    correctness edge is closed (the MSA-2 correlation, BACKLOG #82) or benign.\n"
    assert _scan(backlog, changelog)[1] == []


def test_changelog_crossref_is_quiet_for_closed_items() -> None:
    backlog = "## 60. Turnkey DR\n\n> ✅ **SHIPPED.** ADR 0049\n"
    changelog = "- **Turnkey DR** (#60, [ADR 0049](x)) — ships.\n"
    assert _scan(backlog, changelog)[1] == []


def test_duplicate_across_two_sources_is_an_error() -> None:
    """The cross-file collision — invisible to a per-file check, and the reason scan() takes pairs.

    This is the erratum's own shape: the same number filed in two places that each look internally
    consistent. Scanning the published backlog and the archive as separate namespaces is exactly how
    it stays invisible, so the guard has to be exercised across sources, not merely within one.
    """
    live = "## 118. Live item\n\n> 🔢 **Re-scored.** x\n"
    archived = "## 118. Archived item\n\n> ✅ **SHIPPED.** y\n"
    errors, _ = bsc.scan(
        [("docs/BACKLOG.md", live), ("docs/archive/backlog/BACKLOG-CLOSED.md", archived)]
    )
    assert len(errors) == 1
    assert "#118 is a duplicate" in errors[0]
    # The message must name the OTHER file, or a maintainer cannot find the collision.
    assert "docs/BACKLOG.md:1" in errors[0]


_BACKLOG = _ROOT / "docs" / "BACKLOG.md"
_SOURCES = [_ROOT / p for p in bsc.DEFAULT_SOURCES]

# The namespace has only ever grown: items are CLOSED (and, once archived, moved between the files
# below) but never deleted. So a total below the count at the time this floor was set means either an
# item was dropped or — the failure this exists for — a file holding items stopped being scanned.
# Both are bugs; neither is visible from `errors == []`, which passes happily over a smaller corpus.
#
# ⚠️ THIS FLOOR EXISTS IN TWO PLACES AND THEY ARE NOT CROSS-CHECKED. The other is the
# `--min-items` argument in `.github/workflows/ci.yml`'s "Backlog status invariant" step. Raise BOTH or
# the lower one silently becomes the only floor that binds — on 2026-08-05 this copy was found at 277
# while the corpus had reached 300, so 23 items of slack had accumulated unnoticed. That is the same
# duplicated-constant shape as BACKLOG #1018 (three copies of one scan, nothing comparing them); it is
# noted rather than mechanised here because a test parsing a workflow YAML to compare an integer is a
# new coupling, and the honest fix belongs with #1018's helper rather than beside it.
_MIN_TOTAL_ITEMS = 300


@pytest.mark.skipif(
    not _BACKLOG.exists(),
    reason="docs/BACKLOG.md absent — only expected in an installed wheel with no docs/ tree",
)
def test_the_real_backlog_satisfies_the_invariant() -> None:
    """The operative guard: the real item namespace must pass on every PR.

    THE SKIP ABOVE SHOULD NEVER FIRE IN A SOURCE CHECKOUT. It used to read "private-only (OSS-mirror
    deny-list); absent on the mirror snapshot" — true while the backlog was git-ignored and this repo
    was a published mirror, and quietly false afterwards: the file was un-ignored and committed, but
    the reason still described a topology that had ended, so a reader who saw a skip would have
    concluded it was expected rather than a missing file. Same shape as the guard it protects.

    It scans **every** source in ``DEFAULT_SOURCES`` that exists, not just the published backlog, so
    retiring items into the archive does not quietly take them out of the invariant's reach.
    """
    present = [
        (p.relative_to(_ROOT).as_posix(), p.read_text(encoding="utf-8"))
        for p in _SOURCES
        if p.exists()
    ]
    assert present, "no backlog source exists — DEFAULT_SOURCES is stale"
    errors, _ = bsc.scan(present)
    scanned = ", ".join(label for label, _ in present)
    assert errors == [], (
        f"the backlog namespace ({scanned}) violates the status invariant:\n" + "\n".join(errors)
    )


@pytest.mark.skipif(
    not _BACKLOG.exists(),
    reason="docs/BACKLOG.md absent — only expected in an installed wheel with no docs/ tree",
)
def test_the_scanned_namespace_has_not_silently_narrowed() -> None:
    """Liveness receipt: prove the guard above ran over the WHOLE corpus, not a remnant of it.

    ``errors == []`` is satisfied just as well by scanning three items as by scanning three hundred,
    so on its own it cannot distinguish "the invariant holds" from "the invariant was barely
    consulted". Moving items to a file nobody reads is the specific way that happens here.
    """
    total = sum(len(bsc.parse_items(p.read_text(encoding="utf-8"))) for p in _SOURCES if p.exists())
    assert total >= _MIN_TOTAL_ITEMS, (
        f"found {total} items across {[p.name for p in _SOURCES if p.exists()]}, below the floor of "
        f"{_MIN_TOTAL_ITEMS}. Items were deleted, or a file holding them left DEFAULT_SOURCES."
    )


# --- the banner block's END is the load-bearing part, and it is what a paraphrase gets wrong -------
#
# `parse_items` ends an item's banner block at the first line that is neither blank nor a blockquote.
# So a closed glyph quoted in an item's PROSE is narrative, not that item's status.
#
# That rule is invisible to anyone who learns the format from examples. On 2026-08-04 two independent
# scans of docs/BACKLOG.md disagreed on exactly it -- one asking "does a closed glyph appear anywhere
# in this item", the other "does this item DECLARE closed status" -- and they agreed on the real file
# ANYWAY, because no item currently has the discriminating shape. A hand-rolled census got 93, the
# right answer, by luck. Another session's hand-rolled checker got three different WRONG answers the
# same day, including calling three open items closed.
#
# `test_banner_after_prose_does_not_count` above ALSO separates the two definitions -- measured, a
# whole-range scan calls that fixture "closed" where `parse_items` says "no status". So the boundary
# was not unguarded, and claiming it was would have been the overclaim this file exists to prevent.
#
# What the fixture below adds is the shape that actually OCCURS: a legitimately OPEN item whose prose
# quotes a sibling's closed banner. The old test's item has no status at all, which is a malformed
# item nobody writes on purpose; this one is well-formed, realistic, and asserts the item keeps the
# CORRECT status rather than merely lacking one.


def test_an_open_item_may_quote_a_closed_banner_in_its_prose() -> None:
    """The discriminating fixture. A whole-range scan fails this; `parse_items` passes it.

    Batch-filing narrative routinely quotes a sibling's status ("the sweep that filed this also closed
    #499"). That must not make THIS item closed, and must not read as a self-contradiction either.
    """
    text = (
        "## 500. An open item whose prose quotes a closed banner\n\n"
        "> 🔢 **Filed.** Value **5/10** · Difficulty **3/10** · _fill-in_.\n\n"
        "**Why:** the batch that filed this also closed its siblings, recorded for context:\n\n"
        "> ✅ **SHIPPED.** #499 landed in the same sweep.\n\n"
        "**Source:** a filing note.\n"
    )
    errors, _ = _scan(text)
    assert errors == [], f"a quoted closed banner was treated as this item's status: {errors}"

    item = bsc.parse_items(text)[0]
    assert item.is_open is True, "the item must remain OPEN — the ✅ is narrative, not its status"
    assert item.closed == [], f"the prose ✅ leaked into the status block: {item.closed}"


def test_nothing_else_in_the_repo_re_derives_item_status() -> None:
    """`parse_items` DEFINES item status. A second implementation is a second definition.

    Same single-source discipline `ledger_check.py` states for `PUBLIC_BACKLOG_FLOOR`, and the same
    reason: two copies of one rule do not fail when they drift, they just quietly disagree. The
    2026-08-04 divergence was a scratch script, so it never reached the repo — this keeps it that way.
    """
    banner_alphabet = "🔢🚧"
    offenders = []
    for path in sorted(_ROOT.glob("scripts/**/*.py")) + sorted(_ROOT.glob("tests/**/*.py")):
        if path.name in {"backlog_status_check.py", Path(__file__).name}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if any(g in text for g in banner_alphabet):
            offenders.append(path.relative_to(_ROOT).as_posix())
    assert not offenders, (
        "these files reference the OPEN-banner alphabet and may be re-deriving item status: "
        f"{offenders}. Import parse_items from scripts/docs/backlog_status_check.py instead — it "
        "defines where an item's banner block ENDS, and a hand-rolled scan is a second, silently "
        "different definition of 'closed'."
    )

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


def test_open_item_with_priority_banner_passes() -> None:
    text = "## 7. Something\n\n> 🔢 **Re-prioritized 2026-07-09 → P2.** Value **3/5**.\n\n**Scope:** x\n"
    errors, warnings = bsc.scan(text)
    assert errors == []
    assert warnings == []


def test_shipped_item_passes() -> None:
    text = (
        "## 8. Something\n\n> ✅ **SHIPPED — verified on `origin/main`.** Evidence.\n\n**Why:** x\n"
    )
    assert bsc.scan(text)[0] == []


@pytest.mark.parametrize("emoji", ["⛔", "🪦", "🚧"])
def test_each_recognized_banner_satisfies_the_invariant(emoji: str) -> None:
    assert bsc.scan(f"## 9. T\n\n> {emoji} **STATUS.** x\n\n**Why:** y\n")[0] == []


def test_missing_status_banner_is_an_error() -> None:
    # The boilerplate demand-gate blockquote is NOT a status banner.
    text = (
        "## 10. T\n\n> **On-trigger / demand-gate.** Numbered for tracking only.\n\n**Scope:** x\n"
    )
    errors, _ = bsc.scan(text)
    assert len(errors) == 1
    assert "declares no status" in errors[0]


def test_shipped_and_open_banners_contradict() -> None:
    text = "## 11. T\n\n> ✅ **SHIPPED.** yes\n\n> 🔢 **Re-prioritized → P1.** no\n\n**Scope:** x\n"
    errors, _ = bsc.scan(text)
    assert len(errors) == 1
    assert "contradicts itself" in errors[0]


def test_duplicate_item_numbers_are_an_error() -> None:
    text = "## 12. A\n\n> 🔢 **P.** x\n\n## 12. B\n\n> 🔢 **P.** y\n"
    errors, _ = bsc.scan(text)
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
    errors, _ = bsc.scan(text)
    assert errors == []


def test_banner_after_prose_does_not_count() -> None:
    """A status banner must lead the item, before its Scope/Why prose."""
    text = "## 14. T\n\n**Scope:** x\n\n> ✅ **SHIPPED.** too late\n"
    errors, _ = bsc.scan(text)
    assert any("declares no status" in e for e in errors)


def test_changelog_crossref_flags_an_open_item_cited_as_shipped() -> None:
    """The #60 failure mode: CHANGELOG says it shipped, BACKLOG still says open."""
    backlog = "## 60. Turnkey DR\n\n> 🔢 **Re-prioritized → P3.** still open\n"
    changelog = (
        "- **Turnkey DR backup + restore-verify** (#60, [ADR 0049](docs/adr/0049.md)) — ships.\n"
    )
    errors, warnings = bsc.scan(backlog, changelog)
    assert errors == []  # advisory only — never fatal
    assert len(warnings) == 1
    assert "#60" in warnings[0]


def test_changelog_crossref_ignores_pr_numbers() -> None:
    """`(#641)` is a PR number, not a backlog item — must not warn."""
    backlog = "## 641. Not a real item\n\n> 🔢 **Re-prioritized → P3.** open\n"
    changelog = "- Something landed (#641).\n"
    assert bsc.scan(backlog, changelog)[1] == []


def test_changelog_crossref_ignores_narrative_prose() -> None:
    """A mention outside a change bullet is a reference, not a shipped claim.

    Real case: "the correctness edge is closed (… BACKLOG #82) or field-confirmed benign" is a
    continuation line, not an entry. A noisy advisory is an ignored advisory.
    """
    backlog = "## 82. Sender transport polish\n\n> 🔢 **Re-prioritized → P1.** open\n"
    changelog = "    correctness edge is closed (the MSA-2 correlation, BACKLOG #82) or benign.\n"
    assert bsc.scan(backlog, changelog)[1] == []


def test_changelog_crossref_is_quiet_for_closed_items() -> None:
    backlog = "## 60. Turnkey DR\n\n> ✅ **SHIPPED.** ADR 0049\n"
    changelog = "- **Turnkey DR** (#60, [ADR 0049](x)) — ships.\n"
    assert bsc.scan(backlog, changelog)[1] == []


def test_the_real_backlog_satisfies_the_invariant() -> None:
    """The operative guard: `docs/BACKLOG.md` itself must pass on every PR."""
    errors, _ = bsc.scan((_ROOT / "docs" / "BACKLOG.md").read_text(encoding="utf-8"))
    assert errors == [], "docs/BACKLOG.md violates the status invariant:\n" + "\n".join(errors)

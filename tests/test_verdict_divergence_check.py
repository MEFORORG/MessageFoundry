# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The verdict-divergence check must fire on a contradicted banner and on nothing else (#1342).

Every test is one half of a PAIR. A bare-word search for ``demand-gate`` reports FIVE against a true
three, and the two extras are ordinary correct prose -- so a suite of must-fire arms alone would be
satisfied by the naive version this narrowing exists to replace.

**The two false-positive arms below are not hypothetical.** Both were measured on the live ledger
before this checker was written, and one of them was CREATED BY THE MIGRATION that populated the
banner fields in the first place.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_CHECK = _ROOT / "scripts" / "docs" / "verdict_divergence_check.py"

CLOSED = "\U0001f522"  # the OPEN status banner glyph, quoted as a token per CLAUDE.md section 11


def _load():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("_verdict_divergence_check", _CHECK)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _ledger(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "LEDGER.md"
    p.write_text(body, encoding="utf-8", newline="")
    return p


def test_a_banner_contradicted_by_its_own_rescore_is_reported(tmp_path: Path) -> None:
    """MUST FIRE. The filed defect: every tool reads the banner, so this item dispatches as workable
    while its own re-score says it must not be."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {CLOSED} **Re-scored 2026-08-20 -> DEMAND-GATE.** Value 5/10.\r\n"
        "> Verdict: build\r\n\r\nprose\r\n",
    )
    r = _load().scan(led)
    assert len(r.divergences) == 1, r
    assert r.divergences[0].item == 500
    assert r.divergences[0].banner == "build"
    assert r.divergences[0].prose == "demand-gate"


def test_a_banner_that_AGREES_with_its_rescore_is_silent(tmp_path: Path) -> None:
    """MUST NOT FIRE -- the twin, differing only in the banner value."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {CLOSED} **Re-scored 2026-08-20 -> DEMAND-GATE.** Value 5/10.\r\n"
        "> Verdict: demand-gate\r\n\r\nprose\r\n",
    )
    r = _load().scan(led)
    assert r.divergences == []
    assert r.agreed == 1


def test_a_CROSS_REFERENCE_to_another_items_verdict_does_not_fire(tmp_path: Path) -> None:
    """MUST NOT FIRE. Measured on the live ledger: one body reads *"#1008 is DEMAND-GATE on whether
    the engine should perform a startup privilege probe"* -- a TRUE statement about a DIFFERENT item.
    A bare-word matcher calls that a contradiction; it is correct prose."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {CLOSED} **Filed.**\r\n> Verdict: build\r\n\r\n"
        "**Independent of #1008 and deliberately filed separately.** #1008 is DEMAND-GATE on "
        "whether the engine should perform a startup privilege probe.\r\n",
    )
    r = _load().scan(led)
    assert r.divergences == [], "a cross-reference to another item's verdict is not a contradiction"


def test_an_item_DOCUMENTING_the_vocabulary_does_not_fire(tmp_path: Path) -> None:
    """MUST NOT FIRE, AND THIS ARM EXISTS BECAUSE THE FIELD MIGRATION CREATED IT.

    The item that documents the verdict field necessarily WRITES the vocabulary and the distribution
    into its own body -- ``Verdict: build | research | demand-gate | owner-ruling`` and *"roughly 158
    build, 94 research, 41 demand-gate"*. To a bare-word check, the item that DOCUMENTS the field
    looks governed by it. A landmine laid in good faith by the work that made the field
    machine-readable."""
    led = _ledger(
        tmp_path,
        f"## 500. promote the fields\r\n\r\n> {CLOSED} **Filed.**\r\n> Verdict: build\r\n\r\n"
        "Promote three lines into each banner:\r\n\r\n"
        "```\r\nVerdict: build | research | demand-gate | owner-ruling\r\n```\r\n\r\n"
        "The distribution is real: roughly 158 build, 94 research, 41 demand-gate.\r\n",
    )
    r = _load().scan(led)
    assert r.divergences == [], "an item documenting the vocabulary is not declaring it"


def test_a_rescore_to_a_PRIORITY_is_not_read_as_a_verdict(tmp_path: Path) -> None:
    """MUST NOT FIRE. Most re-score lines resolve to a PRIORITY (``-> P3``), not a verdict. Treating
    those as verdict claims would compare a priority against a verdict and flag every one of them."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {CLOSED} **Re-scored 2026-08-20 -> P3.** Value 3/10.\r\n"
        "> Verdict: build\r\n\r\nprose\r\n",
    )
    r = _load().scan(led)
    assert r.divergences == []
    assert r.with_rescore == 0, "a priority re-score must not enter the compared population"


def test_an_item_with_no_banner_verdict_is_not_compared(tmp_path: Path) -> None:
    """MUST NOT FIRE. Nothing to contradict. The dispatch gate already REFUSES an item declaring no
    state, which is the correct handling and is not this check's job to duplicate."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {CLOSED} **Re-scored 2026-08-20 -> DEMAND-GATE.**\r\n\r\nprose\r\n",
    )
    r = _load().scan(led)
    assert r.divergences == [] and r.with_banner == 0


def test_the_summary_reports_the_compared_denominator(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """A clean run must say how many items it actually COMPARED. Without that, a run that compared
    three of two hundred and forty-six reads exactly like one that compared them all."""
    led = _ledger(
        tmp_path,
        f"## 500. an item\r\n\r\n> {CLOSED} **Re-scored 2026-08-20 -> BUILD.**\r\n"
        "> Verdict: build\r\n\r\nprose\r\n",
    )
    rc = _load().main(["--backlog", str(led)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "ALSO carry a prose re-score naming a verdict and were compared" in out
    assert "1 agree" in out

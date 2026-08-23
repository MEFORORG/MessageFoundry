# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""An item's banner ``Verdict`` and its prose re-score must not disagree (BACKLOG #1342).

Three open items declare ``Verdict: build`` in the banner block and ``Re-scored -> DEMAND-GATE`` in
their prose. **Every tool reads the banner**: ``parse_items`` exposes it, the dispatch gate consults
it, and dispatch screens filter on it. All three therefore read as freely dispatchable and the gate
returns a pass for each.

***THE STRUCTURED FIELD WAS ADDED TO MAKE THE GATE RELIABLE, AND WHERE THE TWO SOURCES DIVERGE IT
MAKES IT CONFIDENTLY WRONG.*** Before the banner existed a dispatcher had to read the prose, and would
have seen the re-score. Adding a machine-readable field REMOVED the step that would have caught this.
That is not a gap in the field; it is a cost of having one.

HOW IT WAS FOUND, which matters more than that it was
-------------------------------------------------------
The dispatcher screened one of the three clean on five filters and was about to dispatch it. What
stopped them was reading the row by eye -- prompted by an UNRELATED suspicion that it duplicated
another item. **The duplicate check caught a gate violation it was not looking for.** Recorded because
a future reader would otherwise conclude a demand-gate screen exists and works.

WHY THIS MATCHES THE RE-SCORE DECLARATION AND NOT THE BARE WORD
-----------------------------------------------------------------
A naive search for ``demand-gate`` anywhere in the item body reports **five**, and two of those are
wrong in ways worth naming because both are ordinary, correct prose:

* **A CROSS-REFERENCE TO ANOTHER ITEM.** One body reads *"#1008 is DEMAND-GATE on whether the engine
  should perform a startup privilege probe"* -- a true statement about a DIFFERENT item.
* **THE VOCABULARY ITSELF.** Another carries ``Verdict: build | research | demand-gate | owner-ruling``
  and the distribution *"roughly 158 build, 94 research, 41 demand-gate"* -- an item that DOCUMENTS
  the field appears, to a bare-word matcher, to be governed by it.

**The second was introduced by the migration that populated these very fields.** Writing the closed
vocabulary into an item body makes that item look demand-gated to any bare-word check -- a landmine
laid, in good faith, by the work that made the field machine-readable in the first place.

So the needle is the DECLARATION form: a re-score line resolving to ``DEMAND-GATE``. Same narrowing as
the ledger's other citation checks, for the same reason -- a detector that flags correct prose is not
noisy, it is wrong.

WHAT THIS DELIBERATELY DOES NOT DO
------------------------------------
**It does not reconcile.** Which source wins -- banner or prose -- is an assessor decision, and the
item was filed without scoping it on purpose. This makes the divergence VISIBLE and resolves none of
it. Choosing a winner here would encode an answer nobody has given, and a wrong machine-readable
verdict is worse than a visible disagreement: one is refusable, the other is trusted.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path
from typing import NamedTuple

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent

#: A re-score line DECLARING a verdict: `**Re-scored 2026-08-20 -> DEMAND-GATE.**`. The arrow and the
#: re-score word are what make it a declaration about THIS item rather than a mention of the word.
_RESCORE = re.compile(r"Re-scored[^\n>]{0,40}->\s*\*{0,2}([A-Za-z-]+)", re.I)

#: The closed verdict vocabulary, lower-cased for comparison.
_VERDICTS = frozenset({"build", "research", "demand-gate", "owner-ruling"})


class Divergence(NamedTuple):
    item: int
    banner: str
    prose: str


class Report(NamedTuple):
    open_items: int
    with_banner: int
    with_rescore: int
    agreed: int
    divergences: list[Divergence]


def _parse_items(text: str):  # type: ignore[no-untyped-def]
    """Item status via the SHARED parser. A second scan would be a different definition of status."""
    path = _HERE / "backlog_status_check.py"
    spec = importlib.util.spec_from_file_location("_backlog_status_check", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.parse_items(text)


def scan(ledger: Path) -> Report:
    text = ledger.read_text(encoding="utf-8", newline="")
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    items = _parse_items(text)

    open_items = with_banner = with_rescore = agreed = 0
    divergences: list[Divergence] = []
    heading = re.compile(r"^## \d+\.\s")

    for item in items:
        if not item.is_open:
            continue
        open_items += 1
        banner = item.fields.get("verdict")
        if not banner:
            continue
        with_banner += 1

        end = len(lines)
        for k in range(item.line, len(lines)):
            if heading.match(lines[k]):
                end = k
                break
        body = "\n".join(lines[item.line - 1 : end])

        m = _RESCORE.search(body)
        if m is None:
            continue
        prose = m.group(1).strip().lower()
        if prose not in _VERDICTS:
            continue  # a re-score to a PRIORITY (P2, P3) is not a verdict claim
        with_rescore += 1
        if prose == banner.strip().lower():
            agreed += 1
        else:
            divergences.append(Divergence(item.num, banner.strip(), prose))

    return Report(open_items, with_banner, with_rescore, agreed, divergences)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--backlog", type=Path, default=_ROOT / "docs" / "BACKLOG.md")
    args = ap.parse_args(argv)

    if not args.backlog.is_file():
        print(
            f"verdict-divergence: {args.backlog} not found -- refusing to report clean",
            file=sys.stderr,
        )
        return 2

    r = scan(args.backlog)

    # THE DENOMINATOR IS PART OF THE RESULT. Without `with_rescore` a reader cannot tell whether the
    # comparison examined three items or three hundred, and a clean run would look like coverage.
    print(
        f"verdict-divergence: {r.open_items} open item(s); {r.with_banner} carry a banner Verdict; "
        f"{r.with_rescore} ALSO carry a prose re-score naming a verdict and were compared -- "
        f"{r.agreed} agree, {len(r.divergences)} DIVERGE"
    )
    if not r.divergences:
        print("verdict-divergence: OK -- no item's banner contradicts its own re-score")
        return 0

    print("")
    for d in r.divergences:
        print(
            f"  #{d.item}: banner says Verdict: {d.banner} -- its re-score says {d.prose.upper()}"
        )
    print("")
    print(
        "  Every tool reads the BANNER, so each of these dispatches as freely workable. Which source "
        "wins is an ASSESSOR decision and this check does not make it."
    )
    return 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Dispatch gate — refuse a wave containing items a builder cannot close.

**The failure this exists to prevent, measured.** On 2026-08-21 thirty items were dispatched to two
builder lanes overnight. Nine product-code commits landed and reached ``main``. **Zero items
closed.** Not because the builders failed -- one lane was measured shipping a tested limb every
twelve minutes -- but because **every item in the assigned range closes by an act no builder can
perform.**

All 93 items in the range declared ``Verdict: research``. Across all 330 closed items in this
ledger, 145 carry ``Verdict: build`` and **zero** carry ``Verdict: research``. No research-verdict
item has ever closed. They close by a re-score in the vault ASVS scorecard, which is gitignored in
the engine repo and invisible from any engine checkout. All 93 mention "scorecard"; ``BUILDER.md``
contains the word **zero times**, so the seat receiving the item is never told what its closing act
is. A 76-item open *build* pool sat untouched beside it.

``DISPATCHER.md`` predicted this before the wave, in these words: *"a builder can finish the
research, the code and the tests and still be unable to close the item."* The prediction was
written down and nothing enforced it. This is the enforcement.

**How it decides.** Each item's banner blockquote may declare three fields, read by the SAME parser
that defines item status (``backlog_status_check.parse_items``), never a second scan::

    > Verdict: build | research | demand-gate | owner-ruling
    > Research: none | done <date>
    > Closing-act: code | scorecard-rescore | owner-ruling | banner-only

An item passes only when its ``Closing-act`` is one a builder can perform. **A MISSING field is a
refusal, not a pass** -- fail closed. Almost no item carries these fields yet, so this gate is
expected to refuse most of the ledger today; that is the correct behaviour and the migration is the
work, not a reason to soften the gate. Use ``--explain`` to see what each item needs.

**It is a DISPATCH gate, not a CI gate, on purpose.** Making missing fields a CI error would red the
build for all 328 items at once and be disabled within a day. Dispatch is where the decision is
actually made, the set is small, and a refusal there costs one edit.

Usage::

    python scripts/coord/dispatch_gate.py 1107 1112 1122
    python scripts/coord/dispatch_gate.py --range 1107-1199 --explain
    python scripts/coord/dispatch_gate.py --self-test

Exit 0 only when EVERY named item is dispatchable. Exit 1 otherwise, listing each refusal and why.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docs"))

from backlog_status_check import (  # type: ignore[import-not-found]  # noqa: E402
    BUILDABLE_CLOSING_ACTS,
    DEFAULT_SOURCES,
    Item,
    parse_items,
)

# Below this, the ledger did not parse and no verdict from this gate is evidence.
MIN_ITEMS = 50


def load_items(root: Path) -> dict[int, Item]:
    """Every item across the ledger namespace, keyed by number."""
    out: dict[int, Item] = {}
    for src in DEFAULT_SOURCES:
        path = root / src
        if not path.is_file():
            continue
        for item in parse_items(path.read_text(encoding="utf-8", errors="replace")):
            out[item.num] = item
    return out


def judge(item: Item) -> tuple[bool, str]:
    """Return (dispatchable, reason). Fail closed: an undeclared item is refused."""
    act = item.fields.get("closing-act", "").strip().lower()
    verdict = item.fields.get("verdict", "").strip().lower()
    research = item.fields.get("research", "").strip().lower()

    if not act:
        missing = [k for k in ("verdict", "research", "closing-act") if k not in item.fields]
        return False, (
            f"declares no Closing-act (missing: {', '.join(missing)}). A builder cannot be told "
            f"what would close this. Add the three lines to the banner blockquote."
        )
    if act not in BUILDABLE_CLOSING_ACTS:
        return False, (
            f"Closing-act is {act!r}, which no builder can perform. Dispatching it produces code "
            f"and no closure -- the exact shape of the 2026-08-21 wave."
        )
    if verdict == "research" and research in ("", "none"):
        return False, (
            "Verdict is 'research' with no completed research pass. Route it to research first; a "
            "builder cannot close an open research question by building."
        )
    return True, "dispatchable"


def _self_test() -> int:
    """Prove the gate refuses what it must before anyone trusts a pass from it."""
    failures: list[str] = []

    def mk(fields: dict[str, str]) -> Item:
        it = Item(1, 1)
        it.fields.update(fields)
        return it

    cases: list[tuple[dict[str, str], bool, str]] = [
        ({}, False, "an item declaring nothing must be refused (fail closed)"),
        (
            {"closing-act": "code", "verdict": "build", "research": "none"},
            True,
            "a build item passes",
        ),
        (
            {
                "closing-act": "scorecard-rescore",
                "verdict": "research",
                "research": "done 2026-08-20",
            },
            False,
            "the exact shape of the wave that closed zero must be refused",
        ),
        (
            {"closing-act": "code", "verdict": "research", "research": "none"},
            False,
            "an open research question must not be dispatched as a build",
        ),
        (
            {"closing-act": "code", "verdict": "research", "research": "done 2026-08-20"},
            True,
            "research already done, closing act is code -- buildable",
        ),
    ]
    for fields, want, why in cases:
        got, reason = judge(mk(fields))
        if got != want:
            failures.append(f"{why}: wanted {want}, got {got} ({reason})")

    for line in failures:
        print(f"SELF-TEST FAIL: {line}", file=sys.stderr)
    if failures:
        return 1
    print(f"self-test PASS: {len(cases)} cases, including the wave shape that closed zero")
    return 0


def _parse_range(spec: str) -> list[int]:
    lo, _, hi = spec.partition("-")
    if not hi:
        return [int(lo)]
    return list(range(int(lo), int(hi) + 1))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("items", nargs="*", type=int, help="item numbers to dispatch")
    ap.add_argument("--range", action="append", default=[], help="inclusive range, e.g. 1107-1199")
    ap.add_argument("--root", type=Path, default=Path.cwd())
    ap.add_argument("--explain", action="store_true", help="show every item, not only refusals")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()

    wanted: list[int] = list(args.items)
    for spec in args.range:
        wanted.extend(_parse_range(spec))
    if not wanted:
        ap.error("name at least one item, or a --range, or pass --self-test")

    items = load_items(args.root)
    if len(items) < MIN_ITEMS:
        print(
            f"INSTRUMENT ERROR: parsed {len(items)} items from {args.root}, below the floor of "
            f"{MIN_ITEMS}. The ledger did not resolve, so no verdict below is evidence.",
            file=sys.stderr,
        )
        return 1

    ok: list[int] = []
    refused: list[tuple[int, str]] = []
    unknown: list[int] = []
    for num in sorted(set(wanted)):
        item = items.get(num)
        if item is None:
            unknown.append(num)
            continue
        good, reason = judge(item)
        (ok.append(num) if good else refused.append((num, reason)))

    print(f"dispatchable: {len(ok)} of {len(set(wanted))}   refused: {len(refused)}")
    print(f"  ledger parsed: {len(items)} items from {args.root}")
    print()

    for num in unknown:
        print(f"  #{num}: NOT IN THE LEDGER")
    for num, reason in refused:
        print(f"  #{num}: REFUSED -- {reason}")
    if args.explain:
        for num in ok:
            print(f"  #{num}: dispatchable")

    if refused or unknown:
        print()
        print(
            "Refusing the wave. An item a builder cannot close produces code and no closure, which\n"
            "is what a 30-item overnight wave did on 2026-08-21 while every gauge read healthy."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

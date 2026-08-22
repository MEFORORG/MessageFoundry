#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Throughput counter — how many backlog items CLOSED between two refs.

**Why this exists.** On 2026-08-21 a wave of 30 items ran overnight across two builder lanes and
closed **zero**, while nine product-code commits landed. Every gauge the fleet owns reported health,
because every one of them measures free capacity or work in motion: `BUILDER.md` requires stating N
FREE, `DISPATCHER.md` requires asking what is in flight, `fleet.ps1` emits ten columns and every one
is a liveness fact. A grep for a closure count across all of `scripts/coord/` and `scripts/docs/`
returned one hit, and it was a comment. The dispatcher's own postmortem names the gap: *"I had no
signal that said items closed: 0 until the owner asked."*

The rule already existed in prose, in three places (`DISPATCHER.md`, `COMMON.md`). Prose is advisory.
This is the instrument.

**It compares ledger CONTENT at two refs, never commit ancestry, and that is deliberate.** The
obvious implementation asks whether a lane's commits are ancestors of `main`. That returns a false
negative on every commit in this repo, because the repo squash-merges: the original SHAs can never
be ancestors even after landing. `CLAUDE.md` section 11 names this exact trap (*"`--is-ancestor`
under squash-merge"*), and it was reproduced during the investigation that produced this script --
all nine feature commits read as "not on main" while their work sat on main. A counter built that
way prints a permanent zero and escalates forever.

**The status alphabet is imported, never re-derived.** `parse_items` *defines* item status, including
where an item's banner block ends. A hand-rolled scan is a second, silently different definition --
the single-source rule `CLAUDE.md` section 11 states for exactly this reader.

**Positive controls are printed, not optional.** Every assertion here is satisfied just as well by a
remnant of the corpus as by all of it: if a source stops resolving at one ref, the diff goes quiet
and reads as "nothing closed". So the item count at each ref is printed beside the result, and a ref
that yields fewer than ``--min-items`` is a hard error. `--self-test` proves the counter can see a
closure at all before you trust a zero it prints.

Usage::

    python scripts/coord/throughput.py origin/main HEAD
    python scripts/coord/throughput.py HEAD~20            # ref-b defaults to HEAD
    python scripts/coord/throughput.py --self-test        # prove it can detect a closure

Exit 0 when the comparison completes, 1 on a broken instrument (missing source, floor breach, an
unresolvable ref, or a failed self-test). **A zero closure count is exit 0** -- zero is a finding,
not an error, and conflating them is how a throughput gauge becomes a nag.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docs"))

# mypy cannot follow a runtime sys.path insert, and scripts/ is outside the CI mypy scope
# (ci.yml types `messagefoundry messagefoundry_webconsole` only). The import is load-bearing:
# CLAUDE.md section 11 requires importing parse_items rather than re-deriving the alphabet.
from backlog_status_check import (  # type: ignore[import-not-found]  # noqa: E402
    DEFAULT_SOURCES,
    Item,
    parse_items,
)

# A ref whose ledger parses to fewer items than this is a broken read, not a small backlog. The live
# ledger carried 328 items on 2026-08-22 and the archive 236; a floor of 50 catches a source that
# stopped resolving without tripping on a legitimately young repo.
DEFAULT_MIN_ITEMS = 50


class RefRead:
    """The parsed ledger at one ref, with the provenance needed to trust its counts."""

    __slots__ = ("ref", "sources", "items", "missing")

    def __init__(self, ref: str) -> None:
        self.ref = ref
        self.sources: list[str] = []
        self.items: dict[int, Item] = {}
        self.missing: list[str] = []

    @property
    def open_nums(self) -> set[int]:
        return {n for n, i in self.items.items() if i.is_open}

    @property
    def closed_nums(self) -> set[int]:
        return {n for n, i in self.items.items() if i.closed and not i.open}


def _git_show(ref: str, path: str, root: Path) -> str | None:
    """Return the file's content at ``ref``, or None when it does not exist there.

    ``ref`` reaches here from argparse. A leading dash would be read by git as an OPTION rather than
    a revision, so it is refused outright -- that is what makes the fixed-argv claim below true
    rather than merely conventional. There is no shell, so this is an argument-parsing guard, not an
    injection one.
    """
    if ref.startswith("-"):
        raise ValueError(f"refusing a ref that git would parse as an option: {ref!r}")
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell; ref is dash-guarded above
        ["git", "show", f"{ref}:{path}"],
        cwd=root,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        return None
    return proc.stdout


def read_ref(ref: str, root: Path, sources: tuple[Path, ...] = DEFAULT_SOURCES) -> RefRead:
    """Parse every ledger source at ``ref`` into ONE namespace.

    One namespace because an item moves between the live file and the archive when it closes. Read
    per-file, that move looks like a deletion in one and an appearance in the other; read together,
    it is what it is -- a closure.
    """
    out = RefRead(ref)
    for src in sources:
        label = src.as_posix()
        text = _git_show(ref, label, root)
        if text is None:
            out.missing.append(label)
            continue
        out.sources.append(label)
        for item in parse_items(text):
            # Last write wins across sources; a number in both is a duplicate the status gate
            # already reports, and re-reporting it here would be a second definition of the defect.
            out.items[item.num] = item
    return out


def compare(a: RefRead, b: RefRead) -> dict[str, list[int]]:
    """Classify every item number by how its status moved from ``a`` to ``b``."""
    a_open, b_open = a.open_nums, b.open_nums
    a_closed, b_closed = a.closed_nums, b.closed_nums
    return {
        "closed": sorted(a_open & b_closed),
        "reopened": sorted(a_closed & b_open),
        "filed_open": sorted(b_open - set(a.items)),
        "filed_closed": sorted(b_closed - set(a.items)),
        "vanished": sorted(set(a.items) - set(b.items)),
    }


def _self_test() -> int:
    """Prove the counter detects a closure before anyone trusts a zero from it.

    Builds a synthetic before/after pair in memory and asserts the movement is seen. A gauge that has
    never been shown to fire is indistinguishable from one that cannot.
    """
    before = "## 1. alpha\n> \U0001f522 prioritized\n\nbody\n\n## 2. beta\n> \U0001f522 prioritized\n\nbody\n"
    after = "## 1. alpha\n> ✅ shipped\n\nbody\n\n## 2. beta\n> \U0001f522 prioritized\n\nbody\n"

    a, b = RefRead("synthetic-before"), RefRead("synthetic-after")
    for item in parse_items(before):
        a.items[item.num] = item
    for item in parse_items(after):
        b.items[item.num] = item

    moved = compare(a, b)
    failures: list[str] = []
    if moved["closed"] != [1]:
        failures.append(f"expected item 1 to read as closed, got {moved['closed']}")
    if moved["reopened"]:
        failures.append(f"expected no reopenings, got {moved['reopened']}")
    if len(a.items) != 2 or len(b.items) != 2:
        failures.append(f"expected 2 items each side, got {len(a.items)} and {len(b.items)}")

    # The negative half: an unchanged pair must report nothing. A counter that always reports a
    # closure is as useless as one that never does.
    same = compare(a, a)
    if same["closed"]:
        failures.append(f"an unchanged pair reported closures: {same['closed']}")

    for line in failures:
        print(f"SELF-TEST FAIL: {line}", file=sys.stderr)
    if failures:
        return 1
    print("self-test PASS: a closure is detected, an unchanged pair reports none")
    return 0


def _repo_root() -> Path:
    proc = subprocess.run(  # nosec B603 B607 - fixed argv, no shell, no caller input
        ["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        return Path.cwd()
    return Path(proc.stdout.strip())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("ref_a", nargs="?", help="the earlier ref (e.g. origin/main, HEAD~20)")
    ap.add_argument("ref_b", nargs="?", default="HEAD", help="the later ref (default: HEAD)")
    ap.add_argument("--min-items", type=int, default=DEFAULT_MIN_ITEMS)
    ap.add_argument("--self-test", action="store_true", help="prove the counter can see a closure")
    ap.add_argument("--quiet", action="store_true", help="print only the headline line")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not args.ref_a:
        ap.error("ref_a is required unless --self-test is given")

    root = _repo_root()
    a = read_ref(args.ref_a, root)
    b = read_ref(args.ref_b, root)

    broken: list[str] = []
    for read in (a, b):
        if read.missing:
            broken.append(f"{read.ref}: source(s) did not resolve: {', '.join(read.missing)}")
        if len(read.items) < args.min_items:
            broken.append(
                f"{read.ref}: parsed {len(read.items)} items, below the --min-items floor of "
                f"{args.min_items}. This is a broken read, not a small backlog."
            )
    if broken:
        for line in broken:
            print(f"INSTRUMENT ERROR: {line}", file=sys.stderr)
        print(
            "Refusing to report a count from a source that may not have been scanned.",
            file=sys.stderr,
        )
        return 1

    moved = compare(a, b)
    closed = moved["closed"]

    # The headline goes first and says the number, because the whole point is that it was never on
    # the page. Everything below it is provenance.
    print(f"items closed: {len(closed)}   ({args.ref_a} -> {args.ref_b})")
    if args.quiet:
        return 0

    print(f"  scanned      : {', '.join(a.sources)}")
    print(f"  items at {args.ref_a}: {len(a.items)}  ({len(a.open_nums)} open)")
    print(f"  items at {args.ref_b}: {len(b.items)}  ({len(b.open_nums)} open)")
    print(f"  closed       : {len(closed)}  {closed if closed else ''}")
    print(
        f"  filed open   : {len(moved['filed_open'])}  {moved['filed_open'] if moved['filed_open'] else ''}"
    )
    print(f"  filed closed : {len(moved['filed_closed'])}")
    print(
        f"  reopened     : {len(moved['reopened'])}  {moved['reopened'] if moved['reopened'] else ''}"
    )
    if moved["vanished"]:
        print(f"  VANISHED     : {len(moved['vanished'])}  {moved['vanished']}")
        print("               an item present at the earlier ref and absent at the later one is a")
        print(
            "               loss, not a closure. Check it before reading the headline as good news."
        )
    net = len(b.open_nums) - len(a.open_nums)
    print(f"  net open     : {net:+d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Refuse a NEW ``file:line`` citation in ASVS scorecard prose (ADR 0156).

Half the assessment record is prose nothing checks. Roughly two thousand ``file:line`` citations
live inside ``residual`` text across ~250 cells; a sample measured 44.9% of them stale. The
demonstration case is cell 6.3.3, where the GATED evidence anchor for ``instance_exposed`` points at
``messagefoundry/__main__.py:1125`` -- which is correct -- while the prose in the SAME CELL cites
``__main__.py:1917``, which is a different statement altogether. **A reviewer reads the prose.**

WHAT THIS IS NOT. It does not promote those citations into gated anchors. That was costed and
refused: roughly a thousand hand-authored tokens, it doubles the gated surface, and it makes
*delete the citation* the cheapest compliant act on the ~1,000 bare basenames.

THE KEY IS THE POINT, so it is stated before the code. A citation is identified by
``cell id + field + FILE``, and deliberately **not** by its line number. Three consequences, and the
third is the whole design:

  * the population of (cell, field, file) citations cannot grow, and because the baseline carries an
    occurrence COUNT, the number of citations inside an existing one cannot grow either. The total
    can only shrink;
  * a baseline keyed on line numbers would be invalidated by every edit above a citation, which
    turns a frozen list into a list that must be re-typed -- the decaying-budget failure this
    programme is unpicking elsewhere;
  * **REPAIRING A STALE LINE IS FREE. ADDING A CITATION IS NOT. DELETING ONE COSTS A BASELINE EDIT.**
    That ordering is chosen. The rejected approach made deletion the cheapest compliant act; this
    makes correction the cheapest, which is the behaviour actually wanted from someone who has just
    noticed a citation is wrong.

IT REFUSES TO SUCCEED ON AN EMPTY SCAN. This tool runs where the data is, which is not this repo, so
the failure that matters most is the silent one: pointed at a moved file, a renamed field or an
empty document, "no new citations" and "nothing was examined" are the same exit code. Both are
therefore errors, and the scan inventory is printed before the verdict rather than after it.

Stdlib only, so it can be mirrored and run without an install -- the property
``tests/test_asvs_verifier_vault_contract.py`` holds over every mirrored tool.

    python scripts/docs/asvs_residual_lint.py <scorecard.toml> --baseline <baseline.txt>
    python scripts/docs/asvs_residual_lint.py <scorecard.toml> --print-keys > <baseline.txt>

THE SECOND COMMAND REDIRECTS STDOUT, so under ``--print-keys`` stdout carries baseline lines and
nothing else; the inventory and the verdict go to stderr instead. They are still printed and still
read by a person -- they are just not swallowed into the artifact. Routed rather than suppressed,
because an empty-scan refusal that only a redirected file could see would defeat the property this
tool exists to hold. The generating run still exits 1: against an absent baseline every citation is
correctly NEW, and the file it just wrote is what makes the next run exit 0.

AN EMPTY BASELINE IS THEREFORE REFUSED LIKE A MISSING ONE. The shell truncates the target before
this program starts, so a generating run that refuses still leaves a 0-byte file behind -- and a
baseline carrying zero claims grandfathers nothing while reading, in the inventory, as a baseline
that loaded. Same "examined nothing" failure as an empty scan, arriving by a different door.

DO NOT RUN THE GENERATING COMMAND UNDER ``set -e``, since it exits 1 by design, and verify the
result by re-running with ``--baseline <baseline.txt>`` and requiring exit 0. That one check
catches a truncated, mis-encoded or mis-filtered baseline without anyone having to enumerate the
ways it can go wrong.
"""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from functools import partial
from pathlib import Path

# A source reference carrying a line number. The extension list is closed on purpose: an open
# `\w+\.\w+:\d+` matches version strings, host:port pairs and ordinary sentences, and a citation
# lint whose first delivery is false positives does not get a second one.
CITATION = re.compile(
    r"(?<![\w/\\.-])"
    r"([\w][\w./\\-]*\.(?:py|toml|md|yml|yaml|json|ts|tsx|ps1|sh|cfg|ini|txt|lock))"
    r"\s*:\s*(\d+)\b"
)

# The prose field scanned unless told otherwise. `absence[].mutation` also carries citations (32 of
# them across 24 cells, measured) and can be added with --field; it is not on by default because the
# brief scopes this to residuals and a wider default would change what an existing baseline means.
DEFAULT_FIELDS = ("residual",)


@dataclass(frozen=True)
class Citation:
    """One ``file:line`` citation found in a cell's prose."""

    cell: str
    field: str
    file: str
    line: int

    @property
    def bare(self) -> bool:
        """A basename with no directory component -- it names no location by itself."""
        return "/" not in self.file and "\\" not in self.file

    def key(self) -> str:
        """Baseline identity. Note the ABSENCE of the line number: see the module docstring."""
        return f"{self.cell}\t{self.field}\t{self.file}"


class EmptyScan(RuntimeError):
    """Raised when nothing was examined. Never let that report as success."""


def _field_values(cell: dict[str, object], field: str) -> Iterator[str]:
    """Resolve a field spec against one cell.

    ``residual`` is a plain string field; ``absence[].mutation`` addresses a member of every entry
    in a list of tables. Both forms occur in the record, so both are supported rather than the
    caller being asked to flatten first.
    """
    head, _, rest = field.partition("[].")
    value = cell.get(head)
    if not rest:
        if isinstance(value, str):
            yield value
        return
    if isinstance(value, list):
        for entry in value:
            if isinstance(entry, dict):
                inner = entry.get(rest)
                if isinstance(inner, str):
                    yield inner


def scan_cells(
    cells: Iterable[dict[str, object]], fields: Iterable[str]
) -> tuple[list[Citation], int, int]:
    """Return (citations, cells examined, prose characters examined)."""
    fields = tuple(fields)
    out: list[Citation] = []
    n_cells = 0
    n_chars = 0
    for cell in cells:
        n_cells += 1
        cid = str(cell.get("id", "?"))
        for field in fields:
            for text in _field_values(cell, field):
                n_chars += len(text)
                for m in CITATION.finditer(text):
                    out.append(Citation(cid, field, m.group(1), int(m.group(2))))
    return out, n_cells, n_chars


def load_scorecard(path: Path) -> list[dict[str, object]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    cells = data.get("cell")
    if not isinstance(cells, list) or not cells:
        raise EmptyScan(
            f"{path} contains no [[cell]] entries. Refusing to report a clean scan of nothing: "
            f"'no new citations' and 'nothing was examined' must not share an exit code."
        )
    return [c for c in cells if isinstance(c, dict)]


def load_baseline(path: Path | None) -> dict[str, int]:
    """Grandfathered citations as ``key -> occurrence count``."""
    out: dict[str, int] = {}
    if path is None:
        return out
    if not path.is_file():
        raise EmptyScan(
            f"baseline {path} does not exist. A missing baseline silently reclassifies every "
            f"grandfathered citation as NEW, or -- read the other way -- makes the gate vacuous. "
            f"Pass --no-baseline to scan without one deliberately."
        )
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, _, count = line.rpartition("\t")
        if not key or not count.isdigit() or key.count("\t") != 2:
            raise ValueError(
                f"malformed baseline line (expected 'cell<TAB>field<TAB>file<TAB>count'): {line!r}"
            )
        out[key] = int(count)
    if not out:
        raise EmptyScan(
            f"baseline {path} carries zero claims. The documented generation command redirects "
            f"stdout, and the shell truncates the target BEFORE this program runs -- so a "
            f"generating run that refused leaves exactly this file behind. An empty baseline "
            f"grandfathers nothing while the inventory reports a baseline that loaded. "
            f"Pass --no-baseline to scan without one deliberately."
        )
    return out


def counted(cites: Iterable[Citation]) -> dict[str, int]:
    out: dict[str, int] = {}
    for c in cites:
        out[c.key()] = out.get(c.key(), 0) + 1
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("scorecard", type=Path)
    ap.add_argument("--baseline", type=Path, default=None)
    ap.add_argument(
        "--no-baseline",
        action="store_true",
        help="scan with no baseline at all (every citation reads as NEW); for generating one.",
    )
    ap.add_argument(
        "--field", action="append", default=None, help="prose field to scan; repeatable."
    )
    ap.add_argument("--print-keys", action="store_true")
    args = ap.parse_args(argv)

    fields = tuple(args.field) if args.field else DEFAULT_FIELDS

    # Everything this run has to SAY goes through `say`; the only bare `print` calls left are the
    # baseline lines themselves, which is what makes them legible as the deliberate exception. See
    # the module docstring for why the two streams part under --print-keys.
    say = partial(print, file=sys.stderr if args.print_keys else sys.stdout)

    try:
        cells = load_scorecard(args.scorecard)
        baseline = {} if args.no_baseline else load_baseline(args.baseline)
    except EmptyScan as exc:
        say(f"FAIL: {exc}")
        return 2

    cites, n_cells, n_chars = scan_cells(cells, fields)

    # THE INVENTORY COMES FIRST. A run that examined nothing must be visibly different from a run
    # that found nothing, and only the inventory distinguishes them.
    bare = [c for c in cites if c.bare]
    say(f"SCANNED: {args.scorecard}")
    say(f"SCANNED: {n_cells} cells, fields {list(fields)}, {n_chars} characters of prose")
    say(
        f"SCANNED: baseline {args.baseline} -> {len(baseline)} claims ({sum(baseline.values())} occurrences)"
    )
    say(
        f"FOUND:   {len(cites)} citations across {len({c.cell for c in cites})} cells; "
        f"{len(bare)} are bare basenames that name no directory"
    )

    if n_chars == 0:
        say(
            f"FAIL: examined {n_cells} cells and found ZERO characters of prose in {list(fields)}. "
            f"That is a field name that no longer resolves, not a clean record."
        )
        return 2

    observed = counted(cites)
    if args.print_keys:
        # A `#` line is skipped by load_baseline, so the artifact can describe itself the way
        # scripts/docs/asvs_tally_baseline.txt does -- without that header having to be typed back
        # in by hand every time the file is regenerated. The provenance line spells out the FIELDS
        # actually scanned rather than assuming the default: a baseline means "these citations, in
        # these fields", so one generated with --field would otherwise claim a command that does
        # not reproduce it.
        scanned_fields = "".join(f" --field {f}" for f in fields)
        print("# Grandfathered residual citations -- FROZEN, and this list may only SHRINK.")
        print("# Format:  <cell id> TAB <field> TAB <file> TAB <occurrence count>")
        print(
            f"# Produced by:  asvs_residual_lint.py {args.scorecard}{scanned_fields} --print-keys"
        )
        for key in sorted(observed):
            print(f"{key}\t{observed[key]}")

    new = [c for c in cites if observed[c.key()] > baseline.get(c.key(), 0)]
    stale = sorted(k for k, n in baseline.items() if observed.get(k, 0) < n)

    rc = 0
    if new:
        rc = 1
        seen: set[str] = set()
        say(f"\nFAIL: {len(new)} citation(s) beyond what the frozen baseline grandfathers:")
        for c in sorted(new, key=lambda c: (c.cell, c.field, c.file, c.line)):
            if c.key() in seen:
                continue
            seen.add(c.key())
            say(
                f"  cell {c.cell} [{c.field}] {c.file}:{c.line}"
                f"{'   (bare basename -- names no location)' if c.bare else ''}"
            )
        say(
            "\nA file:line in prose is checked by nothing and goes stale silently -- measured at "
            "44.9% in a sample, with cell 6.3.3 citing a line in the same file its own gated anchor "
            "gets right. Cite the behaviour, or add a real [[cell.evidence]] anchor, which IS gated. "
            "REPAIRING an existing citation's line number is free and needs no baseline edit."
        )
    if stale:
        rc = 1
        say(f"\nFAIL: {len(stale)} baseline entr(ies) over-count the record. The list may only")
        say("SHRINK -- lower or delete these in the change that removed the citation:")
        for k in stale:
            say(f"  have {observed.get(k, 0)}, baseline says {baseline[k]}:  {k}")
    if rc == 0:
        say("\nOK: no new file:line citation in scorecard prose.")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

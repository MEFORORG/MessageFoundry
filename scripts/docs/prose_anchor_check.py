#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A NEW ``path:line`` citation in the ledger must carry something that can find the line again.

BACKLOG #1315. A bare ``path:line`` asserts nothing an independent reference could check. It does not
break when the code moves -- it resolves to a line that still exists and says something else, and
nothing anywhere reports a problem. CLAUDE.md section 5 states the consequence as a rule: *"line
numbers are navigation aids and never evidence"*.

THE CRITERION IS NOT "IS THERE A LINE NUMBER", IT IS "CAN SOMETHING ELSE IN THE SENTENCE FIND THE
LINE AGAIN" -- the row's own words, and it is what makes this gradeable rather than a ban::

    settings.py:1520 requires `require_time_sync`     -> LOCATED. The symbol survives the line moving.
    durability_push.sh:80 also carries the bare form  -> NAKED. Nothing here outlives one refactor.

Two locators satisfy it, and the row establishes both:

* **A SYMBOL, for WHERE.** It survives a line moving and does NOT survive the code changing under it,
  which is the right failure: a citation whose subject was rewritten SHOULD stop resolving.
* **A COMMIT SHA, for WHEN.** Pin the base you read against, never the commit you are creating -- the
  latter is circular, and writing the base is what exposes a stale address at write time.

WHY DIFF-SCOPED, AND WHY THAT IS THE DESIGN RATHER THAN A CONVENIENCE
----------------------------------------------------------------------
``docs/BACKLOG.md`` carries thousands of these already. A corpus-wide gate would be red on day one
and get suppressed -- ``backlog_citation_check.py`` records the same reasoning in the same words
(*"a gate that fails on a legitimate archive is one people delete"*) and this reuses its diff scope
rather than restating it. With ``--base``/``--head`` this can only be red about a line the change
WROTE.

**IT DOES NOT RETROFIT THE EXISTING CORPUS, and that bound is deliberate.** The row's own measurement
is that the existing citations are not rotting -- 16 of 1,196 distinct pairs had decayed. The defect
is that **nothing can tell whether one has**, and the fix for that is the convention holding from
here on, not a bulk rewrite of 93 item spans in the most-edited file in the repository.

WHAT IT DELIBERATELY DOES NOT DECIDE
--------------------------------------
Whether the named symbol is really in the cited file, and whether the cited line is the right one.
``citation_line_check.py`` asks exactly that and is wired to its own advisory job; asking it twice,
in two places, is how two silently different definitions of "a citation" get born. **This gate asks
only whether a locator is PRESENT**, and it imports that module's notion of a citation and of a
symbol rather than re-deriving either -- the same single-source rule CLAUDE.md section 11 states for
``parse_items``.

MEASURING THIS HAS ITS OWN TRAP, RECORDED BY THE ROW AND WORTH REPEATING
--------------------------------------------------------------------------
Count with a pattern carrying no path-prefix anchor: three conventions are in use here (full-prefix,
package-relative, bare filename) and a prefix-requiring pattern under-reports by about sixfold. And
state the UNIT -- ``grep -c`` counts LINES and a regex ``findall`` counts OCCURRENCES, which differ
about twofold on this file because rows are enormous single lines. This module counts OCCURRENCES and
says so on every run.

Usage::

    python scripts/docs/prose_anchor_check.py                     # corpus census, never gates
    python scripts/docs/prose_anchor_check.py --base A --head B   # only lines B added; exit 1 on one

Exit 1 if an in-scope ADDED citation carries no locator; 0 for the census; 2 on a malfunction.
"""

from __future__ import annotations

import argparse
import importlib.util
import sys
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path
from types import ModuleType
from typing import NamedTuple

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent

#: The one file this gates. The ledger is where the convention was adopted and where the population
#: is; widening the scope is a separate decision with a separate population to measure first.
LEDGER = "docs/BACKLOG.md"


def _sibling(name: str) -> ModuleType:
    """Import a sibling checker so its definitions are used rather than re-derived.

    REGISTERED IN ``sys.modules`` BEFORE EXECUTION, and that is not boilerplate: a module defining a
    ``@dataclass`` looks its own name up there while the decorator runs, and an unregistered one dies
    with ``'NoneType' object has no attribute '__dict__'`` -- which reads as a corrupt file rather
    than a loader mistake. Cached for the same reason: three of these run per scan.
    """
    key = f"_prose_anchor_{name}"
    if (cached := sys.modules.get(key)) is not None:
        return cached
    path = _HERE / f"{name}.py"
    spec = importlib.util.spec_from_file_location(key, path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    spec.loader.exec_module(module)
    return module


class Naked(NamedTuple):
    """One citation with no way back to its line."""

    line: int
    citation: str
    sentence: str


def scan_text(text: str, scope: set[int] | None = None) -> tuple[int, list[Naked]]:
    """Return ``(citations examined, naked ones)`` for one ledger's content.

    ``scope`` limits findings to those line numbers -- the lines a change ADDED. None means every
    line, which is the census.
    """
    citation_check = _sibling("citation_line_check")
    banner_check = _sibling("banner_sha_check")
    examined = 0
    naked: list[Naked] = []

    # Offset of each line's start, so a match position becomes a line number by bisection rather
    # than by counting newlines per citation. The ledger's rows are single lines of tens of
    # kilobytes and there are thousands of citations, so the table is built once and read many times.
    starts = list(accumulate(map(len, text.splitlines(keepends=True)), initial=0))

    for match in citation_check._CITE.finditer(text):
        lineno = bisect_right(starts, match.start())
        if scope is not None and lineno not in scope:
            continue
        examined += 1
        window = _window(text, match, citation_check._PROSE_WINDOW)
        if banner_check._SHA.search(window):
            continue  # a pinned base commit: the WHEN half
        if any(citation_check._is_symbol(t) for t in citation_check._SYM.findall(window)):
            continue  # a named symbol: the WHERE half
        naked.append(Naked(lineno, match.group(0), window.strip()))
    return examined, naked


def _window(text: str, match, width: int) -> str:  # type: ignore[no-untyped-def]
    """The prose either side of the citation -- deliberately the SAME width citation_line_check uses.

    A wider window here than there would let a citation satisfy this gate with a symbol the drift
    detector will not associate with it, which is two tools disagreeing about one sentence.
    """
    return text[max(0, match.start() - width) : match.end() + width]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--base", default=None, metavar="SHA", help="merge-base side of the diff scope")
    ap.add_argument("--head", default=None, metavar="SHA", help="head side of the diff scope")
    ap.add_argument("--root", type=Path, default=_ROOT, help="repository to read")
    args = ap.parse_args(argv)

    if (args.base is None) != (args.head is None):
        print("prose-anchor: --base and --head must be given together", file=sys.stderr)
        return 2

    root: Path = args.root.resolve()
    ledger = root / LEDGER

    if args.base is None:
        text = _read(ledger)
        if text is None:
            print(
                f"prose-anchor: cannot read {ledger} -- refusing to report clean", file=sys.stderr
            )
            return 2
        examined, naked = scan_text(text)
        # THE CENSUS NEVER GATES, and the line says so rather than leaving a zero exit to be read as
        # approval of a corpus that has thousands of these.
        print(
            f"prose-anchor: census over {LEDGER} -- {examined} path:line citation OCCURRENCE(s), "
            f"{len(naked)} carry no symbol and no pinned commit"
        )
        print("prose-anchor: a census is a measurement, not a gate. Only --base/--head can fail.")
        return 0

    # DIFF SCOPE READS THE FILE AT --head, NOT THE WORKING TREE, for the reason
    # backlog_citation_check._read_at states: on a pull_request event the checkout is the MERGE ref
    # while the line numbers are computed against HEAD, so content and line numbers must come from
    # the same revision or the instrument answers an adjacent question.
    #
    # Loaded HERE rather than beside the other siblings: the census branch above never calls it, and
    # executing a whole module to reach a branch that does not use it is work nobody asked for.
    citation_module = _sibling("backlog_citation_check")
    added = citation_module.added_lines(root, args.base, args.head).get(LEDGER, set())
    if not added:
        print(f"prose-anchor: this change added no line to {LEDGER} -- nothing in scope.")
        return 0
    text = citation_module._read_at(root, args.head, LEDGER)
    if text is None:
        print(f"prose-anchor: cannot read {LEDGER} at {args.head}", file=sys.stderr)
        return 2

    examined, naked = scan_text(text, scope=added)
    # THE DENOMINATOR IS PART OF THE RESULT. A run that examined nothing and a run that examined
    # every added citation must not print the same reassuring line.
    print(
        f"prose-anchor: {len(added)} added line(s) in {LEDGER}; {examined} path:line citation "
        f"OCCURRENCE(s) among them, {len(naked)} with no locator"
    )
    if not naked:
        print("prose-anchor: OK -- every citation this change added can find its line again.")
        return 0

    print("")
    for hit in naked:
        print(f"{LEDGER}:{hit.line}: {hit.citation} carries no locator")
        print(f"    ...{hit.sentence}...")
    print("")
    print(
        "A bare path:line asserts nothing anything can check, and it does not fail when the code\n"
        "moves -- it resolves to a line that still says something else. Add ONE of:\n"
        "  * the SYMBOL the line is about, in backticks -- `settings.py:1520 requires "
        "`require_time_sync``;\n"
        "  * the base commit you READ AGAINST, in backticks -- never the commit you are creating,\n"
        "    which is circular.\n"
        "Only lines THIS change added are in scope. See BACKLOG item 1315 and CLAUDE.md section 11."
    )
    return 1


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

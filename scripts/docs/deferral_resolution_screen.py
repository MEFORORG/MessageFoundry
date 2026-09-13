# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An open row whose Verdict defers to a condition, aged and joined to the register (BACKLOG #1527).

A row may defer part of itself: *"build slice 1; leave the VIP mechanism gated on the owner's
privileged-helper decision."* The row records the CONDITION. Until `docs/DEFERRAL-RESOLUTIONS.md`
existed, nothing recorded the RESOLUTION -- so **a row saying "gated on X" was indistinguishable,
forever, from a row whose X was decided**.

Measured on 2026-09-10: one ruling lifted the ADR 0056 privileged-helper pause and staled three
artefacts -- #1494, #1495 and ADR 0056. Two of the three were repaired by ACCIDENT, by a builder
editing nearby. Nothing directed either fix, and no instrument could have: `subject_exists_screen.py`
resolves only subjects a row NAMES, and the commit-citation join reads landed commits, while deciding
produces no commit at all. Both were structurally blind rather than merely missing it.

WHAT THIS REPORTS, IN TWO CLASSES THAT MUST NOT BE CONFLATED
--------------------------------------------------------------
* **RESOLVED AND STILL DECLARED** -- the deferral names a `ruling-key` the register records. The
  condition is settled and the row still says it is waiting. This is the measured defect, and it is
  the only thing that sets a non-zero exit.
* **OPEN DEFERRALS** -- every other declared deferral, with the age of the declaration. Not a defect.
  It is the enumeration the item asked for, because that set "is currently unenumerable". A gate that
  fires on good news gets muted, so ageing never fails anything.

WHY THE NEEDLE IS A REGION AND NOT A PHRASE
----------------------------------------------
The clause words here -- ``gated on``, ``pending``, ``awaiting`` -- are ordinary English, and the
ledger is a document ABOUT deferrals. Searched over a whole item body they fire on correct prose:

* **#1527 -- the item that filed this defect -- quotes the defect's own shape in its body**, as
  *"leave X gated on the owner's decision about Y"*. A bare-word matcher reads the row that
  DOCUMENTS the pattern as governed by it. Same landmine the sibling verdict check records, laid by
  the same kind of good-faith writing.
* A **cross-reference** to another row's deferral is a true statement about a DIFFERENT item.
* **The line AFTER the Verdict is usually `**Severity:**`**, and one of those legitimately reads
  *"the loss is pending on the next routine operation"*. Measured: a paragraph-wide capture pulled
  #1242's severity sentence into its verdict and reported the row as deferred. It is not.

So the narrowing is the REGION: only the item's own **Verdict statement** is read -- the banner
``Verdict:`` field that ``parse_items`` exposes, and the prose ``**Verdict:**`` declaration in the
body, bounded at the next ``**Key:**`` marker. A deferral clause anywhere else is prose and is
ignored. Same narrowing as the ledger's other checks, for the same reason: a detector that flags
correct prose is not noisy, it is wrong.

WHAT THE NEEDLE DELIBERATELY MISSES, SAID OUT LOUD
-----------------------------------------------------
A verdict phrased as an INSTRUCTION TO DECIDE -- #1503's *"decide batch-or-defer, then make AC-1
match"* -- is a deferral in substance and is NOT caught, because the only word that would catch it is
``decide``, which appears in ordinary workable verdicts. An unstated limit is the thing this item
exists to prevent, so it is stated. Widening the clause list is cheap; widening it into a detector
that flags correct prose is not recoverable, because the reader stops believing it.

THE JOIN, AND THE HONEST LIMIT UNDER IT
------------------------------------------
A deferral opts into the join by writing ``[ruling-key: <slug>]`` inside its own Verdict statement.
No fuzzy match is attempted. Guessing which register row resolves which deferral is precisely the
"confidently wrong" failure the sibling check was written against -- a wrong machine-readable answer
is worse than a visible unknown, because one is refusable and the other is trusted.

The cost is that a deferral with no key is only AGED, never resolved. The count of keyed deferrals is
printed beside the count of deferrals so a reader can never mistake one for the other.

AGE IS A FLOOR, NOT A MEASUREMENT. The Verdict statement carries no date of its own, so the age comes
from the EARLIEST ISO date in the item's banner block -- the filing. That is a floor: the row has
declared this deferral for at LEAST that long. Measured on the live ledger, every row in the
owner-ruling population carries such a date, and a row carrying none is reported as undated rather
than dropped.

WHERE IT RUNS, AND WHY IT CANNOT FAIL A MERGE
------------------------------------------------
``.github/workflows/quality-advisory.yml`` runs it with ``--advisory``, in the one workflow in this
repository that holds no required status-check context. **Making a check RUN is a Builder's call;
making one BLOCK is the owner's** (CLAUDE.md section 5), and it is not promoted here.

It reads two TRACKED FILES and no git history, so the workflow's default shallow checkout is
sufficient. That is a property worth naming rather than assuming: this file's own liveness job
records three separate signals that reported success for months while measuring nothing, and one of
them died on exactly that -- a shallow clone with no merge base.

``tests/test_deferral_resolution_screen.py`` pins the shape and the wiring. A wiring claim in a
docstring is only as fresh as the day it was written, so trust that file over this paragraph where
they disagree.
"""

from __future__ import annotations

import argparse
import datetime
import importlib.util
import re
import sys
from pathlib import Path
from typing import NamedTuple

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent

DEFAULT_BACKLOG = _ROOT / "docs" / "BACKLOG.md"
DEFAULT_REGISTER = _ROOT / "docs" / "DEFERRAL-RESOLUTIONS.md"

#: The prose Verdict declaration opens the region.
_PROSE_VERDICT = "**Verdict:**"

#: ...and the next bold key closes it. `**Cluster:** x. **Priority:** P2. **Verdict:** build.` puts
#: three declarations on one line, and `**Severity:**` usually follows on the next -- so the region
#: ends at whichever bold key comes first, not at the end of the paragraph.
_NEXT_BOLD_KEY = re.compile(r"\*\*[A-Z][\w /'-]{1,24}:\*\*")

#: A deferral CLAUSE, matched only inside a Verdict statement. Closed list: each entry governs an
#: object ("gated ON x", "pending x"), which is what makes it a declaration rather than a topic.
#:
#: BARE `pending` SUBSUMES EVERY `... pending` FORM, so `deferred pending` and `held pending` are
#: deliberately absent rather than listed for symmetry. An alternative that can never change the
#: verdict -- only which clause string gets printed -- reads as a rule and is not one, and the next
#: person widening this list would copy that shape.
_DEFERRAL = re.compile(
    r"(?<![\w-])("
    r"gated on"
    r"|blocked on"
    r"|waiting on"
    r"|awaiting"
    r"|pending"
    r"|defer(?:red)?\s+(?:until|to)"
    r"|(?:hold|held)\s+until"
    r"|until the owner"
    r")(?![\w-])",
    re.I,
)

#: The banner verdict value that IS a deferral on its own: the whole row waits on a ruling.
_DEFERRING_BANNER_VERDICT = "owner-ruling"

#: The opt-in join key, written inside the Verdict statement: `[ruling-key: adr-0056-helper]`.
_RULING_KEY = re.compile(r"ruling-key:\s*`?\[?\s*([a-z0-9][a-z0-9._-]{2,60})", re.I)

#: A bracketed key ANNOTATION, stripped before the banner value is compared to the vocabulary.
#: `backlog_status_check._FIELD` captures the whole rest of the banner line, so a row written
#: `> Verdict: owner-ruling [ruling-key: x]` yields the value WITH the annotation attached. Compared
#: raw it fails the equality and the row is not seen as a deferral at all -- so the 8 open rows this
#: branch exists to serve would have been structurally unjoinable, and the key search below would
#: have looked like it handled them.
_KEY_ANNOTATION = re.compile(r"\[\s*ruling-key:[^\]]*\]", re.I)

_ISO_DATE = re.compile(r"\b(20\d\d-\d\d-\d\d)\b")


class Ruling(NamedTuple):
    """One row of the resolution register."""

    date: str
    key: str
    resolution: str
    authority: str
    sources: str


class Deferral(NamedTuple):
    item: int
    source: str  # "prose verdict" or "banner verdict"
    clause: str
    statement: str
    key: str | None
    since: str | None  # ISO date floor, or None when the banner block carries no date
    age_days: int | None
    ruling: Ruling | None


class Report(NamedTuple):
    open_items: int
    with_verdict: int
    deferrals: list[Deferral]
    rulings: int
    malformed_register_rows: list[str]

    @property
    def keyed(self) -> list[Deferral]:
        return [d for d in self.deferrals if d.key]

    @property
    def stale(self) -> list[Deferral]:
        return [d for d in self.deferrals if d.ruling is not None]


def _parse_items(text: str):  # type: ignore[no-untyped-def]
    """Item status via the SHARED parser. A second scan would be a different definition of status.

    ``Item.body_line`` is used for the banner/prose boundary for the same reason -- that parser owns
    it and publishes it precisely so readers do not re-derive it.
    """
    path = _HERE / "backlog_status_check.py"
    spec = importlib.util.spec_from_file_location("_backlog_status_check", path)
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise RuntimeError(f"cannot import {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.parse_items(text)


def read_register(path: Path) -> tuple[list[Ruling], list[str]]:
    """Parse the resolution register into ``(rulings, malformed_rows)``.

    A row whose date is not an ISO date is RETURNED as malformed, never dropped. Dropping it would
    take a real resolution out of the join with nothing saying so -- which is this item's own defect
    reproduced inside its fix.
    """
    rulings: list[Ruling] = []
    malformed: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) != len(Ruling._fields):
            continue  # a different table, or the column-legend table above the register
        if set("".join(cells)) <= set("-: "):
            continue  # the separator row
        date, key, resolution, authority, sources = cells
        if date == "date" and key == "key":
            continue  # the header
        if not _ISO_DATE.fullmatch(date):
            malformed.append(line)
            continue
        rulings.append(Ruling(date, key.strip().lower(), resolution, authority, sources))
    return rulings, malformed


def _verdict_statement(lines: list[str], start: int, end: int) -> str:
    """The prose ``**Verdict:**`` declaration, bounded at the next bold key.

    ``start`` is the 0-based index of the item's first BODY line (past the banner block), ``end`` the
    index of the next item's heading. The banner block is excluded deliberately: a closing note there
    often QUOTES the row's own Verdict, and reading the quote would make every closed-out deferral
    fire on its own obituary.
    """
    for idx in range(start, end):
        if _PROSE_VERDICT not in lines[idx]:
            continue
        tail = lines[idx].split(_PROSE_VERDICT, 1)[1]
        chunk = [tail]
        for nxt in lines[idx + 1 : end]:
            if not nxt.strip() or nxt.startswith("#"):
                break
            chunk.append(nxt)
        joined = " ".join(part.strip() for part in chunk)
        cut = _NEXT_BOLD_KEY.search(joined)
        return (joined[: cut.start()] if cut else joined).strip()
    return ""


def _age_floor(banner: str, today: datetime.date) -> tuple[str | None, int | None]:
    """The EARLIEST ISO date in the banner block, and how many days ago that was."""
    dates = sorted(_ISO_DATE.findall(banner))
    if not dates:
        return None, None
    since = dates[0]
    try:
        then = datetime.date.fromisoformat(since)
    except ValueError:  # pragma: no cover - the regex already fixes the shape
        return since, None
    return since, (today - then).days


def scan(ledger: Path, register: Path, today: datetime.date) -> Report:
    rulings, malformed = read_register(register)
    by_key = {r.key: r for r in rulings}

    text = ledger.read_text(encoding="utf-8", newline="")
    # `splitlines()`, MATCHING `parse_items`, NOT `split("\r\n")`. `Item.line` and `Item.body_line`
    # index into the parser's own `text.splitlines()`, and `splitlines` additionally breaks on the
    # vertical tab, form feed and U+2028 family. A single one of those anywhere in the ledger would
    # desynchronise a `split("\n")` array from those indices and shift every region silently.
    lines = text.splitlines()
    items = _parse_items(text)

    # An item's region ends where the NEXT item's heading begins. Taken from the parser's own item
    # order rather than from a second `^## N\.` regex: the heading form is `parse_items`' to define,
    # and a private copy that drifts from it would shift every region with nothing reporting it.
    ends = {items[i].num: items[i + 1].line - 1 for i in range(len(items) - 1)}

    open_items = with_verdict = 0
    deferrals: list[Deferral] = []

    for item in items:
        if not item.is_open:
            continue
        open_items += 1

        end = ends.get(item.num, len(lines))
        banner = "\n".join(lines[item.line : min(item.body_line - 1, end)])
        prose = _verdict_statement(lines, item.body_line - 1, end)
        field = (item.fields.get("verdict") or "").strip()
        if not prose and not field:
            continue
        with_verdict += 1

        match = _DEFERRAL.search(prose)
        if match is not None:
            source, clause, statement = "prose verdict", match.group(1).lower(), prose
        elif _KEY_ANNOTATION.sub("", field).strip().lower() == _DEFERRING_BANNER_VERDICT:
            source, clause, statement = "banner verdict", _DEFERRING_BANNER_VERDICT, field
        else:
            continue

        key_match = _RULING_KEY.search(prose) or _RULING_KEY.search(field)
        key = key_match.group(1).lower() if key_match else None
        since, age = _age_floor(banner, today)
        deferrals.append(
            Deferral(item.num, source, clause, statement, key, since, age, by_key.get(key or ""))
        )

    return Report(open_items, with_verdict, deferrals, len(rulings), malformed)


def _age(d: Deferral) -> str:
    if d.age_days is None:
        return "undated"
    return f"{d.age_days}d since {d.since}"


def _refuse(message: str, backlog: Path, register: Path) -> int:
    print(f"deferral-resolution: {message}", file=sys.stderr)
    print(f"                     backlog={backlog} register={register}", file=sys.stderr)
    return 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--backlog", type=Path, default=DEFAULT_BACKLOG)
    ap.add_argument("--register", type=Path, default=DEFAULT_REGISTER)
    ap.add_argument(
        "--today",
        default=None,
        help="ISO date to age against (default: today). Deterministic ageing for tests.",
    )
    ap.add_argument(
        "--advisory",
        action="store_true",
        help="report and exit 0 even when a settled condition is still declared (default: exit 1)",
    )
    args = ap.parse_args(argv)

    # REFUSE RATHER THAN REPORT CLEAN. Each of these renders identically to a reconciled ledger --
    # "nothing to report" -- and each is a statement about the INSTRUMENT, not about the tree.
    #
    # Exit 2, not 1, and the advisory wiring reads the difference: 1 is a FINDING (suppressed by
    # --advisory), 2 is "the tool did not measure" (never suppressed). That split is what lets an
    # advisory job keep a broken scan visible while a real finding stays green.
    if not args.backlog.is_file():
        return _refuse(f"{args.backlog} not found", args.backlog, args.register)
    if not args.register.is_file():
        return _refuse(
            f"{args.register} not found -- the register IS the join, so with no register every "
            "deferral would read as unresolved and the screen would report a clean tree",
            args.backlog,
            args.register,
        )

    today = datetime.date.fromisoformat(args.today) if args.today else datetime.date.today()
    r = scan(args.backlog, args.register, today)

    # ONE TEST FOR THE LEDGER SIDE, NOT TWO: `with_verdict` counts a SUBSET of the open items, so it
    # is zero whenever `open_items` is. Two assertions would read as two independent failure modes
    # and be one, which is the shape of a guard that cannot fire. The message prints both counts, so
    # a reader still sees which way it died -- no items at all is `parse_items` or the wrong file,
    # items with no Verdict among them is the STATEMENT region.
    if r.with_verdict == 0:
        return _refuse(
            f"refusing to report on an empty population -- {r.open_items} open item(s), "
            f"{r.with_verdict} carrying a Verdict statement. A clean result over nothing is not a "
            "clean result.",
            args.backlog,
            args.register,
        )
    # AN EMPTY REGISTER REPORTS ITSELF AS EMPTY, NOT AS CLEAN. With no rulings the join can never
    # find a stale row, so the screen would print zero findings on every tree forever -- a green
    # that describes the parse rather than the ledger. The register ships seeded with the ruling
    # this item was filed from, so zero here means the table parse is dead.
    if r.rulings == 0:
        return _refuse(
            f"{args.register} yielded no ruling rows. That is an EMPTY register, not a CLEAN one: "
            "with nothing to join against, every deferral reads as unresolved.",
            args.backlog,
            args.register,
        )

    # THE DENOMINATORS ARE PART OF THE RESULT. Without them a reader cannot tell whether the join
    # examined one deferral or forty, and a clean run would look like coverage.
    print(
        f"deferral-resolution: {r.open_items} open item(s); {r.with_verdict} carry a Verdict "
        f"statement; {len(r.deferrals)} DECLARE A DEFERRAL and were aged -- {len(r.keyed)} name a "
        f"ruling key and {len(r.stale)} of those are RECORDED AS SETTLED. "
        f"{r.rulings} ruling(s) in the register."
    )

    for row in r.malformed_register_rows:
        print(f"  register row ignored, date is not ISO: {row[:120]}")

    # ZERO ADOPTION IS THE STATE WHERE THE JOIN IS INERT, AND IT MUST NOT BE SILENT. With no
    # deferral naming a key, the settled-condition class can never fire and a reader would take the
    # OK line below as "nothing is stale" when it means "nothing was joinable". Not a failure -- day
    # one is legitimately zero, and failing here would red the tree on the absence of a convention
    # rather than on a defect.
    if r.deferrals and not r.keyed:
        print(
            f"  NOTE: none of the {len(r.deferrals)} deferral(s) names a ruling key, so the "
            f"settled-condition join examined nothing. Write `[ruling-key: <key>]` into a "
            f"deferral's Verdict statement to connect it to {args.register.name}."
        )

    # THE TWO CLASSES ARE PRINTED ONCE EACH, AND THIS LIST IS THE ONE THAT IS NOT A FINDING. A
    # settled row belongs only under the heading below: listing it here too, under a status column,
    # conflates the classes the docstring says must not be conflated and makes a reader counting
    # findings count each one twice.
    waiting = [d for d in r.deferrals if d.ruling is None]
    if waiting:
        print("")
        print("  OPEN DEFERRALS, oldest first. Age is a FLOOR from the banner's earliest date.")
        for d in sorted(waiting, key=lambda x: (x.age_days is None, -(x.age_days or 0), x.item)):
            print(f"  #{d.item:<5} {_age(d):<22} {d.source} declares {d.clause!r}")
            print(f"        {d.statement.strip()[:150]}")

    if not r.stale:
        print("")
        print(
            "deferral-resolution: OK -- no open row declares a deferral the register records as "
            "settled"
        )
        return 0

    print("")
    print("  *** SETTLED CONDITIONS STILL DECLARED AS PENDING ***")
    for d in r.stale:
        assert d.ruling is not None
        print(f"  #{d.item}: declares {d.clause!r}, key {d.key}")
        print(f"      register: {d.ruling.date} -- {d.ruling.resolution}")
        print(f"      authority: {d.ruling.authority}   sources: {d.ruling.sources}")
    print("")
    print(
        "  Each row above reads as waiting on a condition that is settled. Re-read it, correct the "
        "Verdict, and check what else that ruling reached -- one ruling staled three artefacts in "
        "the case this screen was built from."
    )
    # FAIL CLOSED BY DEFAULT; `--advisory` is the opt-out the wiring passes. A row describing a
    # settled condition as pending is never benign -- but promoting this to a BLOCKING gate is the
    # owner's call, not a Builder's, and the same split governs the sibling ledger checks.
    return 0 if args.advisory else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

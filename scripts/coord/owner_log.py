#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""OWNER ITEM LOG -- the four-leg ledger for anything routed to the repository owner.

WHY THIS EXISTS. The prior send log recorded that an item was SENT and never that it was
ANSWERED, so a routed item and an answered item were the same row forever. "Sent at 16:38,
still unanswered eight hours later" could not be expressed at all, which made a stalled item
INVISIBLE rather than merely stale. Measured 2026-08-26: two board cycles routed 5-of-6 and
6-of-6 items to the owner that needed nothing from them, while three genuinely-owed items sat
unseen -- and a fourth seat reported an item as still-owed that had been answered hours before.

THE FOUR LEGS. An owner item has two round trips, and a loss at any leg looks like silence:

    request_sent      a seat routes an item toward the owner
    request_received  the LIAISON has it and will present it
    answer_sent       the owner ruled; the LIAISON writes the ruling down
    answer_received   the ORIGINATING seat has the ruling and can act

Gap between legs 1 and 2: a message lost on the way in.
Gap between 2 and 3: sitting with the owner, or one the Liaison never presented.
Gap between 3 and 4: A RULING THAT NEVER GOT BACK. That is the worst of the three, because the
owner believes they answered while the seat is still waiting, and NEITHER SIDE HAS A REASON TO
SPEAK. No board, message log or PR state can detect it.

SCOPE. Owner-targeted items ONLY. Not a message log, not a task board. If no human decision is
required, it does not belong here.

WHERE THE LEDGER LIVES. A markdown table under the shared git common dir, so every worktree
sees ONE file with no merge latency. Markdown is deliberate rather than lazy: the worktree gate
treats a machine-read state file under that directory as AUTHORITY and refuses new ones by
shape -- correctly, since a hand-written copy of such a file is indistinguishable from a real
one. A document is exempt, human-readable, and the owner can open it without a tool.

USAGE

    python scripts/coord/owner_log.py sent      --item 340 --actor dispatcher \\
        --summary "enable the merge queue" --blocks "nothing; builder continues"
    python scripts/coord/owner_log.py received  --item 340 --actor liaison
    python scripts/coord/owner_log.py answered  --item 340 --actor liaison --ruling "enable it"
    python scripts/coord/owner_log.py delivered --item 340 --actor dispatcher

    python scripts/coord/owner_log.py declined  --item cap --actor liaison \\
        --ruling "absorbed as context into 340; not worth a turn"

    python scripts/coord/owner_log.py check --stale-minutes 45   # EXIT 1 if anything stalled
    python scripts/coord/owner_log.py status                     # every item and its legs

DESIGN NOTES, each one paid for on 2026-08-26:
  - APPEND-ONLY. Rows are added, never rewritten, so history cannot be quietly edited.
  - check EXITS NONZERO on gaps. A checker whose failure looks like its success is not a
    checker -- and piping a count into ``wc -l`` discards the exit code entirely, which is how
    three seats read a fatal error as the number zero in one evening.
  - Every command PRINTS THE LEDGER PATH. A count with no named corpus cannot be audited.
  - AN EMPTY LEDGER REPORTS ITSELF AS EMPTY, NOT AS CLEAN. Absent and green printing the same
    is the single defect that cost this fleet the most time in one day.
  - declined is a FIRST-CLASS TERMINAL STATE. An item the Liaison judged not worth the owner's
    turn is neither owed nor absent, and with no written state it is invisible to every board.
"""

from __future__ import annotations

import argparse
import datetime
import os
import shutil
import subprocess
import sys

COLUMNS = ["ts", "item", "event", "actor", "counterparty", "summary", "ruling", "blocks"]

LEGS = ["request_sent", "request_received", "answer_sent", "answer_received"]
TERMINAL = {"declined", "withdrawn"}
NEXT_LEG = {
    "request_sent": "request_received",
    "request_received": "answer_sent",
    "answer_sent": "answer_received",
}
MEANING = {
    "request_sent": "the LIAISON has not acknowledged it -- lost on the way in",
    "request_received": "sitting with the OWNER, or never presented to them",
    "answer_sent": "*** THE RULING NEVER GOT BACK TO THE ORIGINATOR ***",
}

HEADER = [
    "# OWNER ITEMS -- four-leg ledger",
    "",
    "Append-only. One row per EVENT, not per item. An item is complete when it reaches",
    "`answer_received`, `declined` or `withdrawn`; anything else is open and `check` finds it.",
    "",
    "Written by `scripts/coord/owner_log.py`. Rows may be appended by hand in the same shape,",
    "but prefer the script -- it stamps UTC and escapes pipes that would split a row.",
    "",
    "| " + " | ".join(COLUMNS) + " |",
    "|" + "|".join(["---"] * len(COLUMNS)) + "|",
]


def ledger_path() -> str:
    """The shared ledger, resolved from the git COMMON dir so every worktree agrees."""
    env = os.environ.get("MEFOR_OWNER_LOG")
    if env:
        return env
    git = shutil.which("git")
    if not git:
        sys.stderr.write("  FATAL: git not on PATH, and MEFOR_OWNER_LOG is unset.\n")
        raise SystemExit(2)
    # Fixed argument vector, absolute interpreter, no shell, no caller-supplied input.
    out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, absolute git, no shell
        [git, "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode != 0:
        sys.stderr.write("  FATAL: not in a git repo, and MEFOR_OWNER_LOG is unset.\n")
        raise SystemExit(2)
    common = out.stdout.strip()
    return os.path.join(common, "mefor-coord", "owner-log", "OWNER-ITEMS.md")


def now() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def cell(v: str | None) -> str:
    """A pipe inside a cell would silently split the row, so escape it."""
    s = (v or "").replace("|", "\\|").replace("\r", " ").replace("\n", " ").strip()
    return s if s else "-"


def ensure(path: str) -> None:
    d = os.path.dirname(path)
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    if not os.path.isfile(path):
        with open(path, "wb") as fh:
            fh.write(("\n".join(HEADER) + "\n").encode())


def append(path: str, rec: dict[str, str]) -> None:
    ensure(path)
    row = "| " + " | ".join(cell(rec.get(c)) for c in COLUMNS) + " |\n"
    with open(path, "ab") as fh:
        fh.write(row.encode())


def read(path: str) -> list[dict[str, str]]:
    if not os.path.isfile(path):
        return []
    rows: list[dict[str, str]] = []
    with open(path, "rb") as fh:
        for raw in fh:
            line = raw.decode("utf-8", "replace").strip()
            if not line.startswith("|") or line.startswith("|---"):
                continue
            parts = [p.strip() for p in line.strip("|").split("|")]
            if len(parts) != len(COLUMNS):
                continue
            rec = dict(zip(COLUMNS, parts, strict=True))
            if rec.get("ts") == "ts":
                continue
            rows.append(rec)
    return rows


def by_item(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    items: dict[str, list[dict[str, str]]] = {}
    for r in rows:
        items.setdefault(r.get("item", "?"), []).append(r)
    for v in items.values():
        v.sort(key=lambda r: r.get("ts", ""))
    return items


def age_minutes(ts: str) -> float:
    try:
        t = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.UTC)
    except ValueError:
        return -1.0
    return (datetime.datetime.now(datetime.UTC) - t).total_seconds() / 60.0


def cmd_event(a: argparse.Namespace) -> int:
    path = ledger_path()
    append(
        path,
        {
            "ts": now(),
            "item": a.item,
            "event": a.event,
            "actor": a.actor,
            "counterparty": a.counterparty,
            "summary": a.summary,
            "ruling": a.ruling,
            "blocks": a.blocks,
        },
    )
    print(f"  ledger: {path}")
    print(f"  wrote : {a.item}  {a.event}  by {a.actor}")
    return 0


def cmd_check(a: argparse.Namespace) -> int:
    path = ledger_path()
    items = by_item(read(path))
    print(f"  ledger: {path}")
    if not items:
        print("  NO ITEMS LOGGED. That is an EMPTY ledger, not a CLEAN one.")
        print("  If seats are routing owner items without logging them, this check is blind")
        print("  and will stay green forever. Confirm seats are writing before trusting it.")
        return 0
    stale = []
    for item, evs in sorted(items.items()):
        seen = {r.get("event") for r in evs}
        if (seen & TERMINAL) or ("answer_received" in seen):
            continue
        last = None
        for leg in LEGS:
            if leg in seen:
                last = leg
        if last is None:
            continue
        want = NEXT_LEG.get(last)
        if not want:
            continue
        lastev = [r for r in evs if r.get("event") == last][-1]
        mins = age_minutes(lastev.get("ts", ""))
        if mins >= a.stale_minutes:
            stale.append((item, last, want, mins, lastev))
    if not stale:
        print(f"  {len(items)} item(s). NO GAPS older than {a.stale_minutes:g} min. Exit 0.")
        return 0
    print(f"  *** {len(stale)} STALLED ITEM(S), threshold {a.stale_minutes:g} min ***")
    print("")
    for item, last, want, mins, ev in sorted(stale, key=lambda r: -r[3]):
        print(f"  {item}")
        print(f"      last leg   : {last}  ({mins:.0f} min ago, by {ev.get('actor')})")
        print(f"      waiting on : {want}")
        print(f"      meaning    : {MEANING.get(last, '?')}")
        summary = ev.get("summary")
        blocks = ev.get("blocks")
        if summary and summary != "-":
            print(f"      summary    : {summary[:110]}")
        if blocks and blocks != "-":
            print(f"      BLOCKS     : {blocks[:110]}")
        print("")
    return 1


def cmd_status(a: argparse.Namespace) -> int:
    path = ledger_path()
    items = by_item(read(path))
    print(f"  ledger: {path}")
    print(f"  {len(items)} item(s)")
    print("")
    for item, evs in sorted(items.items()):
        seen = [r.get("event") for r in evs]
        done = ("answer_received" in seen) or (set(seen) & TERMINAL)
        legs = " -> ".join(str(s) for s in seen)
        print(f"  [{'closed' if done else 'OPEN  '}] {item}")
        print(f"           {legs}")
        summ = next((r["summary"] for r in evs if r.get("summary", "-") != "-"), None)
        rule = next((r["ruling"] for r in evs if r.get("ruling", "-") != "-"), None)
        if summ:
            print(f"           {summ[:110]}")
        if rule:
            print(f"           RULING: {rule[:110]}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Owner item log -- four-leg ledger for owner-targeted decisions.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    pairs = [
        ("sent", "request_sent"),
        ("received", "request_received"),
        ("answered", "answer_sent"),
        ("delivered", "answer_received"),
        ("declined", "declined"),
        ("withdrawn", "withdrawn"),
    ]
    for name, ev in pairs:
        s = sub.add_parser(name, help="log " + ev)
        s.add_argument("--item", required=True, help="stable id, e.g. 340 / pr-618 / asvs-37")
        s.add_argument("--actor", required=True, help="the seat writing this line")
        s.add_argument("--counterparty", default="")
        s.add_argument("--summary", default="", help="one line; give it on the FIRST leg")
        s.add_argument("--ruling", default="", help="the answer, on answered/declined")
        s.add_argument(
            "--blocks",
            default="",
            help="what stalls without an answer; say 'nothing' if nothing does",
        )
        s.set_defaults(func=cmd_event, event=ev)
    c = sub.add_parser("check", help="find items stalled between legs (EXIT 1 if any)")
    c.add_argument("--stale-minutes", type=float, default=45.0)
    c.set_defaults(func=cmd_check)
    st = sub.add_parser("status", help="every item and its legs")
    st.set_defaults(func=cmd_status)
    a = p.parse_args()
    result: int = a.func(a)
    return result


if __name__ == "__main__":
    sys.exit(main())

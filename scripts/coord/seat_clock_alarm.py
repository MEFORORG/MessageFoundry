# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A watchdog cannot watch its own death, so something outside the chain has to (BACKLOG #1269).

The seat clock (``MEFOR-Seat-Clock``, ``PT10M``) is what makes a session's "keep going" duty
physically possible. The chain is SERIAL -- each tick re-arms the next watcher -- so it has ONE LIFE.
One missed re-arm and every seat whose only wake source is the clock goes quiet, silently.

WHICH FILE ANSWERS WHICH QUESTION, AND WHY THE OBVIOUS ONE IS WRONG
--------------------------------------------------------------------
The obvious build reads ``seat-tick.last`` and asks whether the watched seat appears in it. That file
cannot answer the question, and its own author says so at the point where the second file is declared:

    "seat-tick.last is a human-readable one-liner describing the LAST RUN; it cannot answer 'when did
    THIS seat last actually get a tick', because a run that reported COLD for a seat OVERWRITES the
    run in which that seat was SENT."

An alarm reading only that file GOES HEALTHY ON THE OVERWRITE -- precisely the defect this item was
filed to prevent. **The throttle already hit this exact wall and was given its own file for it, so
this reuses the mechanism the same author built for the same problem rather than inventing one.**

    seat-tick.state.json   WHEN and WHO -- keyed by ABSOLUTE WORKTREE PATH, values unix seconds
    seat-tick.last         WHY NOT -- consulted only to decide whether a gap is deliberate

THE SEAT NAME IS NOT A KEY. Measured 2026-08-23: the live one-liner carried ``steward``, ``lander``
and ``dispatcher`` TWICE EACH -- once ``STALE(no-live-session)``, once ``SENT:<id>``. A first-match
scan for a seat name reads STALE for all three while the clock ticks normally. That is the same
first-match trap that cost four seats a wrong answer the same morning, sitting inside the file the
alarm was told to parse. The worktree PATH is unique; the seat name is not.

PIN THE PATH. DO NOT GLOB THE FILENAME
----------------------------------------
At least four files are named ``seat-tick.last``. The two decoys the item recorded are already gone
and three different ones exist today, all under a live lane's scratchpad, one in a directory named
``ticktest``. **Stale evidence for a correct rule is the strongest kind**: "search, then take the
newest" works until any scratchpad copy is written after the real one, and today it would land in
another lane's test fixture. The decoys also fail in OPPOSITE directions -- one is a permanent
``FATAL`` record that makes the alarm scream on a healthy clock; the other reads ``THROTTLED`` for
every seat and routes into the exclusion rule below, so the alarm goes SILENT on a ten-hour-old file.

BOTH CONSTRUCTION FAULTS REPORT A HEALTHY CLOCK AS BROKEN, AND THAT DIRECTION MATTERS
--------------------------------------------------------------------------------------
An alarm that fires on healthy cases gets discounted, and is therefore absent on the day it matters.
A false-positive watchdog is not a safe failure mode; it is a slow-acting off switch.

* **Dedupe by tick IDENTITY, not timestamp proximity.** A raw scan once produced ten 0.0-minute
  intervals, because 22 records were about 12 ticks differing in milliseconds. Here the identity is
  the stamp VALUE: an unchanged value is the SAME tick observed twice, never a zero-length interval.
* **Do not read a suppressed seat as a dead one.** An 88-minute gap that read as "chain broken" was
  deliberate suppression on a seat taking continuous turns.

VOCABULARY IS AS MEASURED TODAY, NOT AS THE ITEM LISTED IT. The item names
COLD/BACKLOG/THROTTLED. The emitter also produces ``STALE(no-live-session)`` and can suffix a
send with ``(roster-blind)``, both of which postdate the item.

THE EMITTER IS NOT IN THIS REPOSITORY. ``seat-tick.ps1`` is a machine-global install:
``git ls-tree -r origin/main`` returns zero for it, against a positive control of one for
``scripts/coord/seat.ps1``. So no line number could be resolved by a reader of this repo, and
any quoted here would drift silently. Grep that file for its ``$results.Add`` sites instead --
each token is minted in exactly one place. Treat this list as a snapshot of a file this
repository cannot pin, and re-derive it rather than trusting it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import NamedTuple

#: THE ONE AUTHORITATIVE DIRECTORY. Never search for these basenames -- see the module docstring.
_MEFOR = Path(os.environ.get("USERPROFILE", str(Path.home()))) / ".claude" / "mefor-usage"

#: A gap longer than this, with no deliberate suppression, means the chain is gone. The clock is
#: ``PT10M``, so this tolerates one missed tick rather than firing on ordinary jitter.
DEAD_AFTER_SECONDS = 25 * 60

#: Ticks closer together than this are OVER-firing, which is the EXPENSIVE fault: every tick wakes a
#: seat and spends a turn, so a runaway clock burns the budget the alarm exists to protect.
OVERFIRE_UNDER_SECONDS = 6 * 60

#: Statuses that make a gap DELIBERATE rather than evidence of death.
_SUPPRESSED = ("THROTTLED", "COLD", "BACKLOG", "STALE")

#: ``steward=THROTTLED(last-send--35997s-ago,floor-360s)``
_THROTTLE = re.compile(r"THROTTLED\(last-send-(-?\d+)s-ago,floor-(\d+)s\)")

#: A THROTTLED record whose own age exceeds its own floor by more than this is self-contradictory:
#: throttling means "suppressed because a send was too RECENT". The known decoy claims ``floor-360s``
#: at an age of ~36000s -- a hundred-fold contradiction of the state it declares.
_THROTTLE_SANITY_FACTOR = 10


class Verdict(NamedTuple):
    """``alarm`` is the only field a caller must act on; the rest explain it."""

    alarm: bool
    code: str
    detail: str


def read_state(path: Path) -> dict[str, int]:
    """Worktree path (normalised) -> unix seconds of that worktree's last real tick.

    Keys are lowercased because a Windows path-casing collision has already killed this clock once:
    ``seats.json`` carried the same directory under two casings and the tick script died on the parse.
    """
    doc = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, int] = {}
    for key, value in doc.items():
        if not isinstance(key, str) or not isinstance(value, int):
            continue
        out[key.replace("/", "\\").lower()] = value
    return out


def suppression_for(last_line: str, seat: str) -> str | None:
    """The suppression token for ``seat``, or ``None`` if it was sent or is absent.

    A SEND ANYWHERE IN THE LINE WINS. The seat name repeats -- measured, three seats twice each in one
    line -- so returning the first match is exactly how a normally-ticking seat reads as STALE.
    """
    found: list[str] = []
    for token in last_line.split():
        name, sep, status = token.partition("=")
        if sep and name == seat:
            found.append(status)
    if not found:
        return None
    if any(s.startswith("SENT:") for s in found):
        return None
    for status in found:
        if status.startswith(_SUPPRESSED):
            return status
    return None


def throttle_is_credible(status: str) -> bool:
    """False when a THROTTLED record contradicts itself, so its exclusion must not be honoured.

    One comparison. It rejects the ten-hour-old decoy, and it catches genuine corruption in the
    authoritative file -- which is the better reason to have it.
    """
    m = _THROTTLE.search(status)
    if m is None:
        return True
    age, floor = int(m.group(1)), int(m.group(2))
    if age < 0:
        return False  # a send in the FUTURE; self-contradictory either way it is read
    return age <= floor * _THROTTLE_SANITY_FACTOR


def evaluate(
    watched: str,
    seat: str,
    state: dict[str, int],
    last_line: str,
    now: float,
    previous_tick: int | None = None,
) -> Verdict:
    """Decide whether to alarm for one watched worktree."""
    key = watched.replace("/", "\\").lower()
    tick = state.get(key)

    suppression = suppression_for(last_line, seat)
    if suppression is not None and not throttle_is_credible(suppression):
        suppression = None  # the record contradicts itself; it must not silence the alarm

    if tick is None:
        # THE DISCRIMINATING CASE. A freshness-only alarm is GREEN here, because other seats keep the
        # file fresh -- and this is exactly when the watched seat has stopped being woken.
        if suppression is not None:
            return Verdict(
                False, "SUPPRESSED-ABSENT", f"{seat} absent from state but {suppression}"
            )
        return Verdict(True, "ABSENT", f"{seat} ({watched}) has no entry in the state file at all")

    age = int(now - tick)

    # DEDUPE BY IDENTITY: an unchanged stamp is the SAME tick observed twice, not a zero-length gap.
    if previous_tick is not None and tick != previous_tick:
        interval = tick - previous_tick
        if 0 < interval < OVERFIRE_UNDER_SECONDS:
            return Verdict(
                True,
                "OVERFIRING",
                f"two ticks {interval}s apart, under the {OVERFIRE_UNDER_SECONDS}s floor",
            )

    if age > DEAD_AFTER_SECONDS:
        if suppression is not None:
            return Verdict(
                False, "SUPPRESSED", f"{age}s since last tick, but {seat} is {suppression}"
            )
        return Verdict(
            True, "DEAD", f"{age}s since {seat} last ticked (dead after {DEAD_AFTER_SECONDS}s)"
        )

    return Verdict(False, "OK", f"{age}s since last tick")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--worktree", required=True, help="absolute path of the worktree to watch")
    ap.add_argument("--seat", required=True, help="that worktree's seat name in seat-tick.last")
    ap.add_argument("--state", type=Path, default=_MEFOR / "seat-tick.state.json")
    ap.add_argument("--last", type=Path, default=_MEFOR / "seat-tick.last")
    ap.add_argument("--previous-tick", type=int, default=None)
    args = ap.parse_args(argv)

    # A MISSING INSTRUMENT IS NOT A CLEAN RESULT. Reporting OK here would be the same false green the
    # alarm exists to catch, one level up.
    for path in (args.state, args.last):
        if not path.is_file():
            print(f"seat-clock-alarm: CANNOT MEASURE -- {path} is absent", file=sys.stderr)
            return 2

    state = read_state(args.state)
    last_line = args.last.read_text(encoding="utf-8", errors="replace").strip()

    verdict = evaluate(args.worktree, args.seat, state, last_line, time.time(), args.previous_tick)
    # THE DENOMINATOR IS PART OF THE RESULT: a state file holding 3 worktrees and one holding 60 must
    # not print the same reassuring line.
    print(f"seat-clock-alarm: {verdict.code} -- {verdict.detail} ({len(state)} worktrees in state)")
    return 1 if verdict.alarm else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

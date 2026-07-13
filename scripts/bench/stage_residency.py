#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Where does a message's wall-clock actually go? — the per-stage residency decomposition.

Seven throughput runs (C1–C7, P0) asked *"is X a lever?"* and got seven no's. **Nobody has ever asked
where the time goes.** This does, from data the engine already writes.

``message_events`` carries a row per stage boundary — ``received`` / ``routed`` / ``transformed`` /
``delivered`` — each stamped ``ts`` by the **engine's own clock** (so there is no cross-box skew to
correct). Event verbosity defaults to ``all``. This script reads those rows and prints the decomposition:

    A = ts(routed)      − ts(received)      ingress residency + ingress claim + route_only
    B = ts(transformed) − ts(routed)        routed residency  + routed claim  + transform_one
    C = ts(delivered)   − ts(transformed)   outbound residency + outbound claim + send + complete
    E2E = ts(delivered) − ts(received)      the whole life

**Residency, not service.** Each term is *queueing + claim + work* for that stage. A term that dwarfs its
stage's measured claim/service time is **idle waiting**, and that is the interesting case: at the C6-n4x2
ceiling the outbound lane episode was 250 ms against 23.8 ms of measured work — **226 ms (90.5%)
unexplained.** This tells you which stage that residual lives in.

⚠️ **CLEAR ``message_events`` BEFORE THE SOAK — this table is NOT reset for you.**
``shardcert._reset_store`` ``DELETE``s nine *named* tables (``queue``, ``outbox``, ``response``,
``delivered_keys``, ``state``, ``leader_lease``, ``nodes``, ``cluster_config``, ``messages``) — and
``message_events`` is **not one of them**. It has no foreign key to ``messages``, so nothing cascades into it
either. **The rows therefore ACCUMULATE across every run, rung and arm.** The query below has no run filter
and no time filter, so a stale table does not make this script fail loudly — it makes it **silently blend your
soak with every soak that came before it.** A wrong number that looks entirely right.

So: ``DELETE FROM message_events;`` **immediately before the soak you intend to decompose**, then run this
**immediately after** it. (Corollary, if you inherited a rig: rows from earlier runs may still be sitting
there — ``SELECT COUNT(*), MIN(ts), MAX(ts) FROM message_events`` before you clear it, and consider whether
that history is worth banking first.)

Usage (reads the same MEFOR_STORE_* env the engine uses):

    python scripts/bench/stage_residency.py                 # summary table
    python scripts/bench/stage_residency.py --json out.json # machine-readable
    python scripts/bench/stage_residency.py --limit 50000   # cap the scan

PHI: reads only ``message_id`` + ``event`` + ``ts``. Never a payload, never a lane/destination name.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import json
import statistics
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from messagefoundry.config.settings import load_settings  # noqa: E402
from messagefoundry.store.base import open_store  # noqa: E402

_STAGES = ("received", "routed", "transformed", "delivered")

#: One row per (message, event) — the FIRST ts for each, so a fan-out message (D `delivered` rows, one per
#: destination) contributes its *first* delivery. `min(ts)` also makes the query insensitive to a handler
#: that emits several `transformed` rows. Ordered by nothing: we aggregate in Python.
_SQL = """
SELECT message_id, event, MIN(ts) AS ts
FROM message_events
WHERE event IN ('received','routed','transformed','delivered')
GROUP BY message_id, event
"""


def _pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
    return s[k]


def _summarise(name: str, values: list[float]) -> dict[str, Any]:
    return {
        "stage": name,
        "n": len(values),
        "mean_ms": round(statistics.fmean(values) * 1000, 3) if values else 0.0,
        "p50_ms": round(_pct(values, 50) * 1000, 3),
        "p95_ms": round(_pct(values, 95) * 1000, 3),
        "p99_ms": round(_pct(values, 99) * 1000, 3),
    }


async def _fetch(store: Any) -> list[tuple[str, str, float]]:
    """Run the aggregate through the BACKEND's own connection primitives.

    The ``Store`` protocol deliberately exposes no raw-query escape hatch (``base.py`` says: route a
    one-off through the backend's own ``_acquire``/``_cursor``). This is a bench script, so it does
    exactly that rather than widening the protocol for a diagnostic.
    """
    # SQLite (MessageStore) — a single aiosqlite handle.
    db = getattr(store, "_db", None)
    if db is not None:
        cur = await db.execute(_SQL)
        try:
            return [(str(r[0]), str(r[1]), float(r[2])) for r in await cur.fetchall()]
        finally:
            await cur.close()

    # Postgres — asyncpg pool.
    pool = getattr(store, "_pool", None)
    if pool is not None and hasattr(pool, "acquire") and not hasattr(store, "_cursor"):
        async with pool.acquire() as conn:
            rows = await conn.fetch(_SQL)
        return [(str(r["message_id"]), str(r["event"]), float(r["ts"])) for r in rows]

    # SQL Server — aioodbc pool via _acquire/_cursor (EF-6: one cursor, no MARS).
    if hasattr(store, "_acquire") and hasattr(store, "_cursor"):
        async with store._acquire() as conn, store._cursor(conn) as cur:
            await cur.execute(_SQL)
            return [(str(r[0]), str(r[1]), float(r[2])) for r in await cur.fetchall()]

    raise RuntimeError(f"no known connection primitive on {type(store).__name__}")


async def _collect(limit: int | None) -> dict[str, Any]:
    settings = load_settings()
    store = await open_store(settings.store)
    try:
        rows = await _fetch(store)
    finally:
        await store.close()

    by_msg: dict[str, dict[str, float]] = {}
    for mid, event, ts in rows:
        by_msg.setdefault(mid, {})[event] = ts

    a: list[float] = []
    b: list[float] = []
    c: list[float] = []
    e2e: list[float] = []
    complete = 0
    for i, (_mid, ev) in enumerate(by_msg.items()):
        if limit is not None and i >= limit:
            break
        if not {"received", "routed", "transformed", "delivered"} <= ev.keys():
            continue  # a message that did not run the full path (filtered/errored) — excluded, not zeroed
        complete += 1
        a.append(ev["routed"] - ev["received"])
        b.append(ev["transformed"] - ev["routed"])
        c.append(ev["delivered"] - ev["transformed"])
        e2e.append(ev["delivered"] - ev["received"])

    return {
        "messages_seen": len(by_msg),
        "messages_complete": complete,
        "stages": [
            _summarise("A ingress->routed   (ingress residency + claim + route_only)", a),
            _summarise("B routed->transformed (routed residency + claim + transform)", b),
            _summarise("C transformed->delivered (outbound residency + claim + send)", c),
            _summarise("E2E received->delivered (the whole life)", e2e),
        ],
    }


def _render(d: dict[str, Any]) -> str:
    out = [
        "",
        "PER-STAGE RESIDENCY — where a message's wall-clock actually goes",
        f"  messages seen={d['messages_seen']}  complete-path={d['messages_complete']}",
        "",
        f"  {'stage':<58} {'n':>7} {'mean':>9} {'p50':>9} {'p95':>9} {'p99':>9}",
    ]
    for s in d["stages"]:
        out.append(
            f"  {s['stage']:<58} {s['n']:>7} {s['mean_ms']:>8.1f}ms "
            f"{s['p50_ms']:>7.1f}ms {s['p95_ms']:>7.1f}ms {s['p99_ms']:>7.1f}ms"
        )
    out += [
        "",
        "  Read it against the stage's MEASURED claim/service time (report `claim_timing.by_stage`).",
        "  A residency that dwarfs its stage's service time is IDLE WAITING — that is the residual.",
        "",
    ]
    return "\n".join(out)


def main() -> int:
    # This report (and --help, which prints the module docstring) carries U+2014/U+2212. On Windows a
    # REDIRECTED stdout defaults to the ANSI codepage, not UTF-8, so `... > out.txt` would die with
    # UnicodeEncodeError — at exactly the moment the operator is banking the artifact.
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--json", type=Path, default=None, help="also write the decomposition as JSON")
    ap.add_argument("--limit", type=int, default=None, help="cap the number of messages aggregated")
    args = ap.parse_args()

    d = asyncio.run(_collect(args.limit))
    if d["messages_complete"] == 0:
        print(
            "\n  NO COMPLETE-PATH MESSAGES FOUND.\n"
            "  `message_events` is empty of full-path messages. Either no soak has run against this store,\n"
            "  or it is not the store the soak wrote to — check MEFOR_STORE_* in THIS shell (with none set,\n"
            "  the settings default to a local SQLite file and this script quietly measures an empty one).\n"
            "  Note _reset_store does NOT clear message_events, so a soak's rows are not deleted by the next\n"
            "  run — if you expected data here, you are probably pointed at the wrong store.\n",
            file=sys.stderr,
        )
        return 1
    # The JSON artifact is written BEFORE the table is printed: rendering to a redirected stdout can still
    # fail on a legacy-codepage console, and the artifact is the thing you cannot re-derive once the next
    # soak starts.
    if args.json:
        args.json.write_text(json.dumps(d, indent=2), encoding="utf-8")
    print(_render(d))
    if args.json:
        print(f"  wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

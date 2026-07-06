# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""
ADR 0071 (B5) thread-hop-fusion micro-bench — SQLite leg.

Reproduces the Windows ProactorEventLoop async-marshaling wall named by the
2026-07-04 py-spy profile, and measures whether THREAD-HOP FUSION (running a
CPU stage + its adjacent store transaction on ONE worker-thread hop) cuts
executor->loop crossings and Proactor self-pipe (_write_to_self) wakeups per
message WITHOUT changing the durable DB work (byte-identical commit count).

Self-contained: does NOT import the messagefoundry package. It faithfully
reproduces the mechanism with REAL committed SQLite writes driven off the
Proactor loop via asyncio.to_thread / loop.run_in_executor.

Arms (SQLite leg):
  A0 UNFUSED  : per stage  await exec(cpu)      ; await exec(sync_db)   -> 4 hops/msg (2 stages)
  A1 FUSED    : per stage  await exec(cpu_then_sync_db)                 -> 2 hops/msg
                (A0/A1 hold the DRIVER CONSTANT = sync sqlite3; only to_thread submission count varies)
  B0 ASYNC    : per stage  await exec(cpu)      ; await async_handoff(aiosqlite)  (many per-statement crossings)
  B1 FUSED    : per stage  await exec(cpu_then_sync_handoff)  (dedicated sync sqlite3)
                (B0/B1 additionally isolate the async->sync driver change)

Instrumentation (all in-process, monkeypatched on the running loop):
  * loop._write_to_self wrapped -> counts Proactor self-pipe SOCKET wakeups
  * loop.call_soon_threadsafe wrapped -> counts EVERY executor->loop crossing
  * COMMIT counter incremented in BOTH sync and async DB paths (identity guard)

Fused/arm hops run on a DEDICATED bounded executor sized to the sync conn pool.
A background 'validate' CPU stream runs on the DEFAULT executor throughout; its
p99 latency is the starvation tripwire.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# ---------------------------------------------------------------------------
# Config (scaled so the SQLite mechanism proof is stable but runs in minutes;
# SQLite is the LOCAL MECHANISM PROOF only, not a throughput target per spec)
# ---------------------------------------------------------------------------
WARMUP = int(os.environ.get("B5_WARMUP", "1500"))
MEASURED = int(os.environ.get("B5_MEASURED", "6000"))
C_SWEEP = [int(x) for x in os.environ.get("B5_C", "1,64,256,1024").split(",")]
TRIALS = int(os.environ.get("B5_TRIALS", "3"))
POOL = int(os.environ.get("B5_POOL", "8"))  # sync connection pool == dedicated executor size

# ---------------------------------------------------------------------------
# Synthetic HL7 (no PHI) + a realistic CPU slice for route_only / transform_one
# ---------------------------------------------------------------------------
_ADT = (
    "MSH|^~\\&|SENDAPP|SENDFAC|RECVAPP|RECVFAC|20260704120000||ADT^A01|MSG00001|P|2.3\r"
    "EVN|A01|20260704120000\r"
    "PID|1||PATID1234^5^M11^ADT1^MRN^HOSP~123456789^^^USSSA^SS||SYNTH^TEST^Q||19800101|M\r"
    "PV1|1|I|2000^2012^01||||004777^SYNTH^ATTEND|||SUR||||ADM|A0\r"
)


def _read_sep(msg: str) -> tuple[str, str]:
    # Read encoding chars from MSH (do not hardcode) — like the real peek path.
    fs = msg[3]
    cs = msg[4]
    return fs, cs


def route_only_cpu(msg: str) -> str:
    """Tolerant field peek (python-hl7 hot-path analog). Holds the GIL a slice."""
    fs, cs = _read_sep(msg)
    acc = 0
    handler = "H_DEFAULT"
    for seg in msg.split("\r"):
        if not seg:
            continue
        fields = seg.split(fs)
        code = fields[0]
        for f in fields:
            for comp in f.split(cs):
                acc += len(comp)
        if code == "MSH" and len(fields) > 8:
            msgtype = fields[8]
            if "ADT" in msgtype:
                handler = "H_ADT"
        if code == "PID" and len(fields) > 5:
            acc += sum(ord(ch) for ch in fields[5])
    # a little more deterministic churn to model realistic per-message CPU
    for _ in range(6):
        acc = (acc * 1103515245 + 12345) & 0x7FFFFFFF
    return handler if acc >= 0 else "H_NONE"


def transform_one_cpu(msg: str) -> str:
    """Filter->transform analog: rebuild segments via parsed model + re-encode."""
    fs, cs = _read_sep(msg)
    out_segs = []
    for seg in msg.split("\r"):
        if not seg:
            continue
        fields = seg.split(fs)
        if fields[0] == "PID":
            # touch a component without raw slicing: split/join through the model
            comps = fields[5].split(cs)
            comps = [c.upper() for c in comps]
            fields[5] = cs.join(comps)
        out_segs.append(fs.join(fields))
    rebuilt = "\r".join(out_segs)
    acc = 0
    for _ in range(6):
        acc = (acc * 1103515245 + 12345) & 0x7FFFFFFF
    return rebuilt


def validate_cpu() -> int:
    """Co-tenant strict-validation/decrypt analog on the DEFAULT executor."""
    fs, cs = _read_sep(_ADT)
    acc = 0
    for seg in _ADT.split("\r"):
        for f in seg.split(fs):
            for comp in f.split(cs):
                acc += len(comp)
    for _ in range(20):
        acc = (acc * 1103515245 + 12345) & 0x7FFFFFFF
    return acc


# ---------------------------------------------------------------------------
# Loop instrumentation counters
# ---------------------------------------------------------------------------
class Counters:
    __slots__ = ("cst", "wts", "commits")

    def __init__(self) -> None:
        self.cst = 0  # call_soon_threadsafe crossings
        self.wts = 0  # _write_to_self self-pipe sends
        self.commits = 0  # durable COMMITs (identity guard)


def instrument_loop(loop: asyncio.AbstractEventLoop, ctr: Counters) -> None:
    orig_cst = loop.call_soon_threadsafe
    orig_wts = loop._write_to_self  # type: ignore[attr-defined]

    def counting_cst(callback, *args, **kwargs):  # type: ignore[no-untyped-def]
        ctr.cst += 1
        return orig_cst(callback, *args, **kwargs)

    def counting_wts():  # type: ignore[no-untyped-def]
        ctr.wts += 1
        return orig_wts()

    loop.call_soon_threadsafe = counting_cst  # type: ignore[method-assign]
    loop._write_to_self = counting_wts  # type: ignore[method-assign,attr-defined]


# ---------------------------------------------------------------------------
# Store schema + DB work (byte-identical SQL across all arms)
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS stage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stage TEXT NOT NULL,
    msg_id INTEGER NOT NULL,
    payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS message_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id INTEGER NOT NULL,
    event TEXT NOT NULL
);
"""

# The handoff statements — identical text/row-shape in every arm.
SQL_DELETE = "DELETE FROM stage WHERE id = ?"
SQL_INSERT = "INSERT INTO stage (stage, msg_id, payload) VALUES (?, ?, ?)"
SQL_UPDATE = "UPDATE messages SET status = ? WHERE id = ?"
SQL_EVENT = "INSERT INTO message_events (msg_id, event) VALUES (?, ?)"


def _init_db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


# --- sync driver (thread-local connection == a real per-worker pooled conn) ---
_tls = threading.local()


def _sync_conn(path: str) -> sqlite3.Connection:
    c = getattr(_tls, "conn", None)
    if c is None:
        c = sqlite3.connect(path)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        _tls.conn = c
    return c


def sync_handoff(
    path: str,
    ctr: Counters,
    stage_row_id: int,
    msg_id: int,
    next_stage: str,
    payload: str,
    status: str,
    event: str,
) -> None:
    """One committed transaction: guard DELETE + INSERT next + UPDATE + event + COMMIT.
    Runs entirely on the calling worker thread (fresh conn acquired, released at commit)."""
    conn = _sync_conn(path)
    conn.execute(SQL_DELETE, (stage_row_id,))
    conn.execute(SQL_INSERT, (next_stage, msg_id, payload))
    conn.execute(SQL_UPDATE, (status, msg_id))
    conn.execute(SQL_EVENT, (msg_id, event))
    conn.commit()
    ctr.commits += 1  # sync-path COMMIT counter


async def async_handoff(
    conn,
    ctr: Counters,
    stage_row_id: int,
    msg_id: int,
    next_stage: str,
    payload: str,
    status: str,
    event: str,
) -> None:
    """Async (aiosqlite) handoff: each statement + commit marshals to the aiosqlite
    connection thread and back -> the many per-statement executor->loop crossings B0 exposes."""
    await conn.execute(SQL_DELETE, (stage_row_id,))
    await conn.execute(SQL_INSERT, (next_stage, msg_id, payload))
    await conn.execute(SQL_UPDATE, (status, msg_id))
    await conn.execute(SQL_EVENT, (msg_id, event))
    await conn.commit()
    ctr.commits += 1  # async-path COMMIT counter (same increment => identity guard)


# ---------------------------------------------------------------------------
# Fused callables (run inside ONE worker hop)
# ---------------------------------------------------------------------------
def _route_and_handoff_sync(path: str, ctr: Counters, msg: str, msg_id: int, row_id: int) -> str:
    handler = route_only_cpu(msg)  # CPU, off-loop (SEC-013) — no DB conn held here
    sync_handoff(path, ctr, row_id, msg_id, "routed", msg, "ROUTED", "routed:" + handler)
    return handler


def _transform_and_handoff_sync(
    path: str, ctr: Counters, msg: str, msg_id: int, row_id: int
) -> str:
    out = transform_one_cpu(msg)  # CPU, off-loop
    sync_handoff(path, ctr, row_id, msg_id, "outbound", out, "PROCESSED", "transformed")
    return out


def _cpu_only(fn, msg: str) -> str:  # type: ignore[no-untyped-def]
    return fn(msg)


def _db_only_sync(
    path: str,
    ctr: Counters,
    msg_id: int,
    row_id: int,
    next_stage: str,
    payload: str,
    status: str,
    event: str,
) -> None:
    sync_handoff(path, ctr, row_id, msg_id, next_stage, payload, status, event)


# ---------------------------------------------------------------------------
# Per-message pipelines (one per arm). All drive the SAME two stages
# (route, transform) => 2 COMMITs/msg in every arm.
# ---------------------------------------------------------------------------
async def msg_A0(loop, ex, path, ctr, msg, msg_id):  # UNFUSED sync driver: 4 hops
    h = await loop.run_in_executor(ex, _cpu_only, route_only_cpu, msg)
    await loop.run_in_executor(
        ex, _db_only_sync, path, ctr, msg_id, msg_id, "routed", msg, "ROUTED", "routed:" + h
    )
    out = await loop.run_in_executor(ex, _cpu_only, transform_one_cpu, msg)
    await loop.run_in_executor(
        ex, _db_only_sync, path, ctr, msg_id, msg_id, "outbound", out, "PROCESSED", "transformed"
    )


async def msg_A1(loop, ex, path, ctr, msg, msg_id):  # FUSED sync driver: 2 hops
    await loop.run_in_executor(ex, _route_and_handoff_sync, path, ctr, msg, msg_id, msg_id)
    await loop.run_in_executor(ex, _transform_and_handoff_sync, path, ctr, msg, msg_id, msg_id)


async def msg_B0(loop, ex, path, ctr, aconn, msg, msg_id):  # ASYNC driver, unfused
    h = await loop.run_in_executor(ex, _cpu_only, route_only_cpu, msg)
    await async_handoff(aconn, ctr, msg_id, msg_id, "routed", msg, "ROUTED", "routed:" + h)
    out = await loop.run_in_executor(ex, _cpu_only, transform_one_cpu, msg)
    await async_handoff(aconn, ctr, msg_id, msg_id, "outbound", out, "PROCESSED", "transformed")


async def msg_B1(loop, ex, path, ctr, msg, msg_id):  # FUSED dedicated sync conn: 2 hops
    await loop.run_in_executor(ex, _route_and_handoff_sync, path, ctr, msg, msg_id, msg_id)
    await loop.run_in_executor(ex, _transform_and_handoff_sync, path, ctr, msg, msg_id, msg_id)


# ---------------------------------------------------------------------------
# Co-tenant validate stream (default executor) — starvation tripwire
# ---------------------------------------------------------------------------
class ValidateStream:
    def __init__(self, loop):
        self.loop = loop
        self._stop = False
        self.samples: list[float] = []
        self._task = None

    async def _run(self):
        while not self._stop:
            t0 = time.perf_counter()
            await self.loop.run_in_executor(None, validate_cpu)  # DEFAULT executor
            self.samples.append((time.perf_counter() - t0) * 1000.0)
            await asyncio.sleep(0)

    def start(self):
        self.samples = []
        self._stop = False
        self._task = asyncio.ensure_future(self._run())

    async def stop(self):
        self._stop = True
        if self._task:
            await self._task

    def p99(self) -> float:
        if not self.samples:
            return float("nan")
        s = sorted(self.samples)
        idx = min(len(s) - 1, int(round(0.99 * (len(s) - 1))))
        return s[idx]


# ---------------------------------------------------------------------------
# Driver: sustain C concurrent tasks through the ONE loop for a fixed count
# ---------------------------------------------------------------------------
async def run_arm(arm: str, C: int, path: str, ex, aconn, vs) -> dict:
    loop = asyncio.get_running_loop()
    total = WARMUP + MEASURED
    ctr = Counters()  # per-run COMMIT counter (identity guard)
    loop_ctr: Counters = loop._b5_ctr  # type: ignore[attr-defined]

    next_id = 0
    lat_samples: list[float] = []
    snap: dict = {}

    async def worker():
        nonlocal next_id
        while True:
            # single-threaded loop: read+increment has no await between => atomic
            i = next_id
            next_id += 1
            if i >= total:
                return
            if i == WARMUP:
                # warmup boundary: snapshot the loop crossing counters + validate
                # iterations so the measured window excludes warmup AND the co-tenant
                # validate stream's own executor completions.
                snap["cst0"] = loop_ctr.cst
                snap["wts0"] = loop_ctr.wts
                snap["val0"] = len(vs.samples)
                snap["commit0"] = ctr.commits
                snap["t0"] = time.perf_counter()
            mid = (i % 20000) + 1
            lat0 = time.perf_counter()
            if arm == "A0":
                await msg_A0(loop, ex, path, ctr, _ADT, mid)
            elif arm == "A1":
                await msg_A1(loop, ex, path, ctr, _ADT, mid)
            elif arm == "B0":
                await msg_B0(loop, ex, path, ctr, aconn, _ADT, mid)
            elif arm == "B1":
                await msg_B1(loop, ex, path, ctr, _ADT, mid)
            if i >= WARMUP:
                lat_samples.append((time.perf_counter() - lat0) * 1000.0)

    workers = [asyncio.ensure_future(worker()) for _ in range(C)]
    await asyncio.gather(*workers)
    t1 = time.perf_counter()

    # IDENTITY GUARD (exact, race-free): every message does exactly 2 handoffs =>
    # 2 COMMITs. Total commits must equal 2 * total messages regardless of arm.
    commits_total = ctr.commits
    identity_exact = commits_total == 2 * total

    # crossings attributable to the MESSAGE pipeline over the measured window =
    # total loop crossings MINUS the validate stream's completions in the window.
    val_iters = len(vs.samples) - snap["val0"]
    cst = (loop_ctr.cst - snap["cst0"]) - val_iters
    wts = (loop_ctr.wts - snap["wts0"]) - val_iters
    wall = t1 - snap["t0"]
    lat_sorted = sorted(lat_samples)

    def pct(p):
        if not lat_sorted:
            return float("nan")
        return lat_sorted[min(len(lat_sorted) - 1, int(round(p * (len(lat_sorted) - 1))))]

    return {
        "arm": arm,
        "C": C,
        "msgs": MEASURED,
        "cross_per_msg": cst / MEASURED,
        "wts_per_msg": wts / MEASURED,
        "wts_per_s": wts / wall if wall else 0.0,
        "commits_total": commits_total,
        "commits_expected": 2 * total,
        "identity_exact": identity_exact,
        "commits_per_msg": commits_total / total,
        "throughput": MEASURED / wall if wall else 0.0,
        "p50_ms": pct(0.50),
        "p99_ms": pct(0.99),
        "wall_s": wall,
    }


async def main() -> int:
    loop = asyncio.get_running_loop()
    if not isinstance(loop, asyncio.ProactorEventLoop):
        print(
            f"SKIP: not a ProactorEventLoop (got {type(loop).__name__}). "
            "The wall is Proactor-specific; a selector/Linux run is NOT evidence."
        )
        return 2
    print(f"ProactorEventLoop confirmed: {type(loop).__name__}")
    print(f"Python {sys.version.split()[0]} on {sys.platform}")
    print(
        f"Config: WARMUP={WARMUP} MEASURED={MEASURED} TRIALS={TRIALS} "
        f"C_SWEEP={C_SWEEP} POOL={POOL}\n"
    )

    loop_ctr = Counters()
    loop._b5_ctr = loop_ctr  # type: ignore[attr-defined]
    instrument_loop(loop, loop_ctr)

    dbdir = os.path.dirname(os.path.abspath(__file__))
    results: list[dict] = []

    import aiosqlite

    for C in C_SWEEP:
        for arm in ("A0", "A1", "B0", "B1"):
            for trial in range(TRIALS):
                path = os.path.join(dbdir, f"b5_{arm}_{C}_{trial}.db")
                for suffix in ("", "-wal", "-shm"):
                    try:
                        os.remove(path + suffix)
                    except OSError:
                        pass
                _init_db(path)
                # seed messages rows for UPDATEs
                sc = sqlite3.connect(path)
                sc.executemany(
                    "INSERT INTO messages (id, status) VALUES (?, 'RECEIVED')",
                    [(i,) for i in range(1, 20001)],
                )
                sc.commit()
                sc.close()

                # dedicated bounded executor sized to the sync pool
                ex = ThreadPoolExecutor(max_workers=POOL, thread_name_prefix="fused")
                aconn = None
                if arm == "B0":
                    aconn = await aiosqlite.connect(path)
                    await aconn.execute("PRAGMA journal_mode=WAL")
                    await aconn.execute("PRAGMA synchronous=NORMAL")

                vs = ValidateStream(loop)
                vs.start()
                res = await run_arm(arm, C, path, ex, aconn, vs)
                await vs.stop()
                res["validate_p99_ms"] = vs.p99()
                res["trial"] = trial
                results.append(res)

                if aconn is not None:
                    await aconn.close()
                ex.shutdown(wait=True)
                # reset per-worker thread-local conns are gone with the executor threads
                for suffix in ("", "-wal", "-shm"):
                    try:
                        os.remove(path + suffix)
                    except OSError:
                        pass

    # ---- aggregate: median + spread across trials ----
    def agg(arm, C, key):
        vals = [r[key] for r in results if r["arm"] == arm and r["C"] == C]
        return statistics.median(vals), (max(vals) - min(vals))

    print("=" * 118)
    print("RAW PER-TRIAL RESULTS")
    print("=" * 118)
    hdr = (
        "arm",
        "C",
        "tr",
        "cross/msg",
        "wts/msg",
        "wts/s",
        "commit/msg",
        "msg/s",
        "p50ms",
        "p99ms",
        "val_p99ms",
    )
    print(
        f"{hdr[0]:<4}{hdr[1]:>6}{hdr[2]:>4}{hdr[3]:>11}{hdr[4]:>10}{hdr[5]:>10}"
        f"{hdr[6]:>12}{hdr[7]:>10}{hdr[8]:>9}{hdr[9]:>9}{hdr[10]:>11}"
    )
    for r in results:
        print(
            f"{r['arm']:<4}{r['C']:>6}{r['trial']:>4}{r['cross_per_msg']:>11.3f}"
            f"{r['wts_per_msg']:>10.3f}{r['wts_per_s']:>10.0f}{r['commits_per_msg']:>12.3f}"
            f"{r['throughput']:>10.1f}{r['p50_ms']:>9.2f}{r['p99_ms']:>9.2f}"
            f"{r['validate_p99_ms']:>11.3f}"
        )

    print("\n" + "=" * 118)
    print("MEDIAN (spread = max-min across trials)")
    print("=" * 118)
    print(
        f"{'arm':<4}{'C':>6}{'cross/msg':>11}{'wts/msg':>10}{'commit/msg':>12}"
        f"{'msg/s':>10}{'msg/s spr':>11}{'p99ms':>9}{'val_p99ms':>11}"
    )
    med = {}
    for C in C_SWEEP:
        for arm in ("A0", "A1", "B0", "B1"):
            cm, _ = agg(arm, C, "cross_per_msg")
            wm, _ = agg(arm, C, "wts_per_msg")
            com, _ = agg(arm, C, "commits_per_msg")
            th, ths = agg(arm, C, "throughput")
            p99, _ = agg(arm, C, "p99_ms")
            vp, _ = agg(arm, C, "validate_p99_ms")
            med[(arm, C)] = dict(
                cross=cm, wts=wm, commit=com, thr=th, thr_spr=ths, p99=p99, valp99=vp
            )
            print(
                f"{arm:<4}{C:>6}{cm:>11.3f}{wm:>10.3f}{com:>12.3f}{th:>10.1f}"
                f"{ths:>11.1f}{p99:>9.2f}{vp:>11.3f}"
            )

    # ---- verdicts ----
    print("\n" + "=" * 118)
    print("VERDICTS")
    print("=" * 118)
    # identity guard: EXACT per-run commits == 2 * total messages, every run
    identity_ok = all(r["identity_exact"] for r in results)
    bad = [
        (r["arm"], r["C"], r["trial"], r["commits_total"], r["commits_expected"])
        for r in results
        if not r["identity_exact"]
    ]
    print(
        f"IDENTITY GUARD (per-run commits == 2*msgs, EXACT, race-free): "
        f"{'PASS' if identity_ok else 'FAIL'}"
    )
    print(
        f"  every run commits/msg == 2.000 (durable work byte-identical across arms); "
        f"violations={bad if bad else 'none'}"
    )

    for C in C_SWEEP:
        a0 = med[("A0", C)]
        a1 = med[("A1", C)]
        b0 = med[("B0", C)]
        b1 = med[("B1", C)]
        a_drop = (a0["cross"] - a1["cross"]) / a0["cross"] * 100 if a0["cross"] else 0
        wts_drop = (a0["wts"] - a1["wts"]) / a0["wts"] * 100 if a0["wts"] else 0
        b_drop = (b0["cross"] - b1["cross"]) / b0["cross"] * 100 if b0["cross"] else 0
        thr_delta_A = (a1["thr"] - a0["thr"]) / a0["thr"] * 100 if a0["thr"] else 0
        thr_delta_B = (b1["thr"] - b0["thr"]) / b0["thr"] * 100 if b0["thr"] else 0
        print(f"\n--- C={C} ---")
        print(
            f"  MECHANISM A0->A1 crossings/msg: {a0['cross']:.3f} -> {a1['cross']:.3f} "
            f"({a_drop:+.1f}%)   [pass if >=40% fewer]"
        )
        print(
            f"  MECHANISM A0->A1 wts/msg:       {a0['wts']:.3f} -> {a1['wts']:.3f} ({wts_drop:+.1f}%)"
        )
        print(
            f"  REALISTIC B0->B1 crossings/msg: {b0['cross']:.3f} -> {b1['cross']:.3f} "
            f"({b_drop:+.1f}%)   [expect > A-delta: aioodbc/aiosqlite per-stmt collapse]"
        )
        print(
            f"  THROUGHPUT A1 vs A0: {a0['thr']:.1f} -> {a1['thr']:.1f} msg/s ({thr_delta_A:+.1f}%)"
        )
        print(
            f"  THROUGHPUT B1 vs B0: {b0['thr']:.1f} -> {b1['thr']:.1f} msg/s ({thr_delta_B:+.1f}%)"
        )
        print(f"  STARVATION validate p99 (A0/A1): {a0['valp99']:.3f} / {a1['valp99']:.3f} ms")

    print("\nDONE.")
    return 0


if __name__ == "__main__":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    sys.exit(asyncio.run(main()))

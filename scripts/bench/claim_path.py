#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Claim-path latency of the pooled claim, ``claim_fifo_heads``, on one server store, for one commit.

Vault BACKLOG #4915 step 1 asks for claim-path latency before and after engine PR 1782, which moved
the Postgres claim UPDATE into a data-modifying ``claimed`` CTE and added a head-skip marker arm on
both server backends, and asks whether that move costs Postgres an extra buffering of the claimed
rows. This tool measures one commit at a time, so the same file times both sides of the change.

``measure`` imports ``messagefoundry`` from ``--code-root`` (an extracted tree of the commit under
test, put first on ``sys.path``) and refuses to run if the import resolved anywhere else, or if the
root's ``CLAIM_PATH_COMMIT`` file (written at extraction) does not name ``--commit``. It refuses any
database whose name is not one of the bench's own (``mf_claim_*`` or ``MfClaim*``), because it
empties the queue tables of the database the ``MEFOR_STORE_*`` environment names. It opens the store
through ``open_store``, the engine's one store-open seam, at its refusing keyless default, so a fresh
bench database opens only with a store key in hand: claim_path.sh mints a throwaway
``MEFOR_STORE_ENCRYPTION_KEY`` for the run, and each report records ``store_keyed``. A commit whose
``open_store`` takes no ``create`` cannot be measured. It seeds synthetic
ingress rows (one fixed, PHI-free HL7 message padded to ``--payload-bytes`` with seeded random
base64, never printed), resets the queue table before each scenario, then times each
``claim_fifo_heads`` call alone. After every claim it calls ``release_claimed``, which puts the
claimed rows back to pending with their attempts restored, so every iteration claims the same rows.

On a keyed store the rows are sealed at rest, so each timed claim includes decrypting the rows it
returns, on both sides, and the stored payload is larger than ``payload_bytes``, which is the
plaintext size. A keyed figure is therefore not comparable with an unkeyed one.

A claim that returns a different row count than the scenario expects, or reports a lock timeout, is
not a sample: a timing over the wrong work is not a figure. It is released, counted by reason, and
the slot is tried again, up to ``--max-discards`` per scenario; past that the scenario stops short
and the next one runs.

``compare`` reads the JSON reports ``measure`` wrote and prints one Markdown table per backend. A
report keeps summary statistics, not samples, so rounds are not pooled: each cell is the median over
rounds of that round's statistic, with each round's p50 listed in round order, and each side's
discarded claims by reason, and names whether each report's store was keyed. It refuses a scenario
whose two sides did not measure the same work (rows claimed, payload size, rows per lane,
iterations, store keyed) or whose sample count fell short, and exits
non-zero if it refused any scenario or if no scenario has both sides.

Only timings, counts, the backend's version line, the Python version, the commit label and whether
the store was keyed reach the output.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import math
import os
import platform
import random
import statistics
import sys
import time
from collections import defaultdict
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

_MSH = "MSH|^~\\&|BENCH|BENCH|BENCH|BENCH|20260101||ADT^A01|BENCH1|P|2.5.1\r"
_STAGE = "ingress"
_SEED_NOW = 100.0
_CLAIM_NOW = 200.0
# The queue tables a claim reads or a seed writes, emptied before a run (the same set the live
# claim tests empty, so it exists at every commit this tool is pointed at).
_TABLES = ("message_events", "queue", "response", "delivered_keys", "messages")
_BENCH_DB_PREFIXES = ("mf_claim_", "MfClaim")
# The server stores clamp one claim to this many lanes (_FIFO_HEADS_LANE_CHUNK).
_MAX_LANES = 500
_PAD_SEED = 4915
# The work both sides of a compared scenario must share. A keyed store encrypts and decrypts the
# rows a claim reads, so a keyed side and an unkeyed side did not do the same work.
_SAME_WORK = ("rows_claimed", "payload_bytes", "rows_per_lane", "iterations", "store_keyed")

# One claim: (milliseconds, the claimed row ids, the lock-timeout phase if the store reported one).
ClaimFn = Callable[[], Awaitable[tuple[float, list[Any], str | None]]]
ReleaseFn = Callable[[list[Any]], Awaitable[None]]


def _raw(payload_bytes: int) -> str:
    """One synthetic message: the MSH line plus an NTE segment padding it to ``payload_bytes``.

    The padding is seeded random bytes in base64. A run of one character compresses to almost
    nothing in Postgres's TOAST, so the rows would not carry the size asked for; random bytes do
    not compress. Base64 holds no HL7 separator, so the NTE stays one field. The fixed seed gives
    the same message on every run and at both commits."""
    pad = max(0, payload_bytes - len(_MSH) - len("NTE|1||\r"))
    # Seeded filler, not a secret; its base64 is longer than pad characters, so it is cut to fit.
    noise = random.Random(_PAD_SEED).randbytes(pad)  # nosec B311 (synthetic filler, seeded)
    return f"{_MSH}NTE|1||{base64.b64encode(noise).decode('ascii')[:pad]}\r"


def _expected_rows(lanes: int, limit: int, rows_per_lane: int) -> int:
    """Rows one claim of ``lanes`` x ``limit`` must return when each seeded lane holds
    ``rows_per_lane`` pending rows: the limit per lane, capped at what a lane holds, and 0 for the
    empty scenario."""
    return lanes * min(limit, rows_per_lane)


async def _sample(
    claim: ClaimFn,
    release: ReleaseFn,
    *,
    expected: int,
    warmup: int,
    iterations: int,
    max_discards: int,
) -> tuple[list[float], dict[str, int]]:
    """Run ``warmup`` then ``iterations`` full claims; return the timed samples, the warm-up
    dropped, and the discarded claims by reason.

    Every claim's rows are released before the next claim. A claim that returned other than
    ``expected`` rows, or reported a lock timeout, fills no slot, warm-up or timed: it is counted
    and the slot is tried again. At ``max_discards`` discards the scenario stops, so fewer than
    ``iterations`` samples come back, and the report shows it."""
    samples: list[float] = []
    discards: dict[str, int] = defaultdict(int)
    done = 0
    while done < warmup + iterations:
        elapsed_ms, ids, lock_timeout = await claim()
        if ids:
            await release(ids)
        if lock_timeout is not None or len(ids) != expected:
            if lock_timeout is not None:
                reason = f"lock_timeout:{lock_timeout}"
            elif not ids:
                reason = "empty"
            else:
                reason = "short" if len(ids) < expected else "over"
            discards[reason] += 1
            if sum(discards.values()) >= max_discards:
                break
            continue
        if done >= warmup:
            samples.append(elapsed_ms)
        done += 1
    return samples, dict(discards)


def _parse_scenarios(text: str) -> list[tuple[int, int]]:
    """``"1x1,64x16"`` -> ``[(1, 1), (64, 16)]``: lanes x per-lane limit. A limit of 0 names the
    empty scenario: the lanes are requested but hold no rows, which times the claim's fixed cost."""
    out: list[tuple[int, int]] = []
    for part in text.split(","):
        lanes_s, _, limit_s = part.strip().partition("x")
        lanes, limit = int(lanes_s), int(limit_s)
        if not 1 <= lanes <= _MAX_LANES or limit < 0:
            raise ValueError(
                f"bad scenario {part!r}: lanes must be 1-{_MAX_LANES} and the limit >= 0"
            )
        out.append((lanes, limit))
    return out


def _import_engine(code_root: Path, commit: str) -> Any:
    """Import ``messagefoundry`` from ``code_root``, and only from a root that holds ``commit``."""
    stamp = code_root / "CLAIM_PATH_COMMIT"
    held = stamp.read_text(encoding="utf-8").strip() if stamp.is_file() else ""
    if held != commit:
        raise SystemExit(
            f"--code-root {code_root} holds commit {held or 'unknown'!r}, not --commit {commit!r};"
            " refusing to credit this run's figures to the wrong commit"
        )
    sys.path.insert(0, str(code_root))
    import messagefoundry

    where = Path(messagefoundry.__file__).resolve()
    if code_root.resolve() not in where.parents:
        raise SystemExit(
            f"messagefoundry imported from {where}, not from --code-root {code_root}; refusing to"
            " credit this run's figures to the wrong commit"
        )
    return messagefoundry


def _check_bench_database(environ: dict[str, str] | os._Environ[str]) -> str:
    name = environ.get("MEFOR_STORE_DATABASE", "")
    if not name.startswith(_BENCH_DB_PREFIXES):
        raise SystemExit(
            f"MEFOR_STORE_DATABASE={name!r} is not a bench database ({' or '.join(_BENCH_DB_PREFIXES)}"
            "...); measure empties its queue tables, so it refuses any other"
        )
    return name


async def _open_store(backend: str) -> Any:
    """Open the bench database through ``open_store``, the engine's one store-open seam, at its
    refusing keyless default: a fresh bench database has an empty audit chain, so the open is
    refused unless a key is in hand (claim_path.sh mints a throwaway one). ``create=True`` is the
    default the backend ``open`` this replaced ran with, so a new database gets its schema as
    before. The backend is selected through the environment the settings are loaded from, so the
    settings are validated for the backend that opens them."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.base import open_store

    settings = load_settings(environ={**os.environ, "MEFOR_STORE_BACKEND": backend}).store
    return await open_store(settings, create=True)


def _store_keyed(store: Any) -> bool:
    """Whether the opened store holds a keying secret: ``open_store``'s own test, either audit MAC
    present, read from the store rather than from which key setting was named."""
    return store._audit_mac_key is not None or store._audit_mac_fn is not None


async def _fetchval(store: Any, backend: str, query: str) -> Any:
    """First column of the first row of one test-owned constant query."""
    async with store._pool.acquire() as conn:
        if backend == "postgres":
            return await conn.fetchval(query)
        cur = await conn.cursor()
        try:
            await cur.execute(query)
            rows = await cur.fetchall()  # drain, so no open result rides back into the pool
        finally:
            await cur.close()
        return rows[0][0] if rows else None


async def _execute(store: Any, backend: str, statements: list[str]) -> None:
    """Run test-owned constant statements, in one connection, committed."""
    async with store._pool.acquire() as conn:
        if backend == "postgres":
            for statement in statements:
                await conn.execute(statement)
            return
        cur = await conn.cursor()
        try:
            for statement in statements:
                await cur.execute(statement)
        finally:
            await cur.close()
        await conn.commit()


def _stats(samples_ms: list[float]) -> dict[str, float]:
    ordered = sorted(samples_ms)

    def pct(p: float) -> float:  # nearest rank: the ceil(p * n)-th smallest
        return ordered[max(0, math.ceil(p * len(ordered)) - 1)]

    return {
        "n": float(len(ordered)),
        "min": ordered[0],
        "p50": pct(0.50),
        "p90": pct(0.90),
        "p99": pct(0.99),
        "max": ordered[-1],
        "mean": statistics.fmean(ordered),
    }


async def _measure(args: argparse.Namespace) -> dict[str, Any]:
    _check_bench_database(os.environ)
    _import_engine(Path(args.code_root), args.commit)
    backend = args.backend
    scenarios = _parse_scenarios(args.scenarios)
    seeded_lanes = max((lanes for lanes, limit in scenarios if limit), default=0)
    empty_lanes = max((lanes for lanes, limit in scenarios if not limit), default=0)
    seeded = [f"IB_BENCH_{i:04d}" for i in range(seeded_lanes)]
    unseeded = [f"IB_EMPTY_{i:04d}" for i in range(empty_lanes)]
    raw = _raw(args.payload_bytes)
    report: dict[str, Any] = {
        "label": args.label,
        "commit": args.commit,
        "round": args.round,
        "backend": backend,
        "rows_per_lane": args.rows_per_lane,
        "payload_bytes": len(raw),
        "warmup": args.warmup,
        "iterations": args.iterations,
        "max_discards": args.max_discards,
        "python": platform.python_version(),
        "scenarios": [],
    }
    store = await _open_store(backend)
    try:
        report["store_keyed"] = _store_keyed(store)
        version = await _fetchval(
            store, backend, "SELECT version()" if backend == "postgres" else "SELECT @@VERSION"
        )
        report["server"] = str(version).splitlines()[0] if version else "unknown"
        if backend == "postgres":
            # Autovacuum off on the queue table, so it cannot fire partway through a scenario at a
            # point that differs per run; the VACUUM below resets the table between scenarios.
            await _execute(
                store,
                backend,
                [
                    f"TRUNCATE {', '.join(_TABLES)} RESTART IDENTITY CASCADE",
                    "ALTER TABLE queue SET"
                    " (autovacuum_enabled = false, toast.autovacuum_enabled = false)",
                ],
            )
        else:
            await _execute(store, backend, [f"DELETE FROM {table}" for table in _TABLES])
        for lane in seeded:
            for _ in range(args.rows_per_lane):
                await store.enqueue_ingress(channel_id=lane, raw=raw, now=_SEED_NOW)
        for lanes, limit in scenarios:
            # Before each scenario, so it starts from the same table whatever ran before it. On
            # Postgres, VACUUM clears the dead row versions the previous scenario's claims and
            # releases left, and ANALYZE refreshes the statistics so the planner sees the seeded
            # table rather than the empty one. SQL Server only refreshes statistics; its automatic
            # statistics update stays on and may still fire within a scenario.
            await _execute(
                store,
                backend,
                ["VACUUM ANALYZE queue" if backend == "postgres" else "UPDATE STATISTICS queue"],
            )
            names = seeded[:lanes] if limit else unseeded[:lanes]
            per_lane = max(limit, 1)
            expected = _expected_rows(lanes, limit, args.rows_per_lane)

            async def claim(
                names: list[str] = names, per_lane: int = per_lane
            ) -> tuple[float, list[Any], str | None]:
                start = time.perf_counter()
                res = await store.claim_fifo_heads(
                    _STAGE, names, now=_CLAIM_NOW, per_lane_limit=per_lane
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                ids = [item.id for items in res.by_lane.values() for item in items]
                timeout = getattr(res, "lock_timeout", None)
                return elapsed_ms, ids, None if timeout is None else str(timeout.phase)

            async def release(ids: list[Any]) -> None:
                await store.release_claimed(ids, now=_CLAIM_NOW)

            samples, discards = await _sample(
                claim,
                release,
                expected=expected,
                warmup=args.warmup,
                iterations=args.iterations,
                max_discards=args.max_discards,
            )
            scenario: dict[str, Any] = {
                "lanes": lanes,
                "per_lane_limit": limit,
                "rows_claimed": expected,
                "discarded": discards,
                "n": float(len(samples)),
            }
            line = f"{backend} {args.label} r{args.round} {lanes}x{limit} rows={expected}"
            if samples:
                stats = _stats(samples)
                scenario.update(stats)
                line += (
                    f" p50={stats['p50']:.2f}ms p90={stats['p90']:.2f}ms"
                    f" p99={stats['p99']:.2f}ms mean={stats['mean']:.2f}ms"
                )
            if len(samples) < args.iterations:
                line += f" STOPPED SHORT at {len(samples)} of {args.iterations} samples"
            report["scenarios"].append(scenario)
            print(f"{line} discarded={_discard_text(discards)}", flush=True)
    finally:
        await store.close()
    return report


def _median(rows: list[dict[str, Any]], stat: str) -> float:
    return float(statistics.median(float(r[stat]) for r in rows))


def _discard_text(discards: dict[str, int]) -> str:
    """``{"empty": 1, "lock_timeout:head": 2}`` -> ``"3 (empty 1, lock_timeout:head 2)"``."""
    total = sum(discards.values())
    if not total:
        return "0"
    return f"{total} ({', '.join(f'{k} {v}' for k, v in sorted(discards.items()))})"


def _summed_discards(rows: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = defaultdict(int)
    for r in rows:
        for reason, count in r.get("discarded", {}).items():
            out[reason] += int(count)
    return dict(out)


def _refusal(rows: list[dict[str, Any]]) -> str | None:
    """Why the reports of one scenario, both sides and every round, cannot be compared, or None."""
    for field in _SAME_WORK:
        values = sorted({repr(r.get(field)) for r in rows})
        if len(values) > 1:
            return f"refused: {field} differs across reports ({', '.join(values)})"
    short = [
        f"{r['label']} r{r['round']} n={int(r.get('n', 0))}"
        for r in rows
        if int(r.get("n", 0)) != r.get("iterations")
    ]
    if short:
        return f"refused: fewer samples than iterations ({'; '.join(short)})"
    return None


def _compare(paths: list[Path], before: str, after: str) -> tuple[str, int, int]:
    """The before/after table, how many scenario rows it holds, and how many it refused."""
    grouped: dict[tuple[str, int, int], dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    meta: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        rep = json.loads(path.read_text(encoding="utf-8"))
        keyed = {True: "keyed", False: "unkeyed"}.get(rep.get("store_keyed"), "keying unrecorded")
        meta[rep["backend"]].add(
            f"{rep['label']}={rep['commit']} on {rep.get('server', '?')}, store {keyed}"
        )
        run = {
            k: rep.get(k)
            for k in ("label", "payload_bytes", "rows_per_lane", "iterations", "store_keyed")
        }
        for sc in rep["scenarios"]:
            key = (rep["backend"], sc["lanes"], sc["per_lane_limit"])
            grouped[key][rep["label"]].append({**sc, **run, "round": rep.get("round", 0)})
    lines: list[str] = []
    emitted = refused = 0
    for backend in sorted(meta):
        lines.append(f"### {backend}")
        lines.extend(f"- {m}" for m in sorted(meta[backend]))
        lines.append("")
        lines.append(
            "| lanes x limit | rows | before p50 ms (r1, r2, ...) | after p50 ms (r1, r2, ...) |"
            " p50 after/before | before p90 | after p90 | p90 after/before | before p99 |"
            " after p99 | before discarded | after discarded |"
        )
        lines.append("|---|---:|---|---|---:|---:|---:|---:|---:|---:|---|---|")
        for key in sorted(k for k in grouped if k[0] == backend):
            b = sorted(grouped[key].get(before, []), key=lambda r: r["round"])
            a = sorted(grouped[key].get(after, []), key=lambda r: r["round"])
            if not b or not a:
                lines.append(f"| {key[1]}x{key[2]} | missing: {'before' if not b else 'after'} |")
                continue
            discarded = (
                f" {_discard_text(_summed_discards(b))} | {_discard_text(_summed_discards(a))} |"
            )
            why = _refusal(b + a)
            if why is not None:
                lines.append(f"| {key[1]}x{key[2]} | {why} |{discarded}")
                refused += 1
                continue
            b50, a50, b90, a90 = (
                _median(b, "p50"),
                _median(a, "p50"),
                _median(b, "p90"),
                _median(a, "p90"),
            )
            lines.append(
                f"| {key[1]}x{key[2]} | {b[0]['rows_claimed']} |"
                f" {b50:.2f} ({', '.join(f'{r["p50"]:.2f}' for r in b)}) |"
                f" {a50:.2f} ({', '.join(f'{r["p50"]:.2f}' for r in a)}) |"
                f" {a50 / b50 if b50 else float('nan'):.3f} | {b90:.2f} | {a90:.2f} |"
                f" {a90 / b90 if b90 else float('nan'):.3f} |"
                f" {_median(b, 'p99'):.2f} | {_median(a, 'p99'):.2f} |{discarded}"
            )
            emitted += 1
        lines.append("")
    return "\n".join(lines), emitted, refused


def _positive(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, not {value}")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    sub = parser.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure", help="time claim_fifo_heads for one commit on one backend")
    m.add_argument("--code-root", required=True, help="extracted tree of the commit under test")
    m.add_argument("--backend", required=True, choices=("postgres", "sqlserver"))
    m.add_argument("--label", required=True, help="before or after")
    m.add_argument("--commit", required=True, help="the commit SHA the code root holds")
    m.add_argument("--round", type=int, default=1)
    m.add_argument("--scenarios", default="1x1,64x1,64x16,256x1,256x16,256x0")
    m.add_argument("--rows-per-lane", type=_positive, default=16)
    m.add_argument("--payload-bytes", type=_positive, default=2048)
    m.add_argument("--warmup", type=int, default=10)
    m.add_argument("--iterations", type=_positive, default=100)
    m.add_argument(
        "--max-discards",
        type=_positive,
        default=50,
        help="per scenario: wrong-count or lock-timeout claims allowed before the scenario stops",
    )
    m.add_argument("--out", required=True, type=Path)
    c = sub.add_parser("compare", help="print the before/after table from measure's reports")
    c.add_argument("reports", nargs="+", type=Path)
    c.add_argument("--before", default="before")
    c.add_argument("--after", default="after")
    args = parser.parse_args(argv)
    if args.cmd == "measure":
        report = asyncio.run(_measure(args))
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return 0
    table, emitted, refused = _compare(args.reports, args.before, args.after)
    print(table)
    if refused:
        print(f"refused {refused} scenario(s) whose sides differ or fell short", file=sys.stderr)
        return 1
    if not emitted:
        print("no scenario has both a before and an after report", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

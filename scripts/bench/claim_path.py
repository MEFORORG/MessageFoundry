#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Claim-path latency of the pooled claim, ``claim_fifo_heads``, on one server store, for one commit.

Vault BACKLOG #4915 step 1 asks for claim-path latency before and after engine PR 1782, which moved
the Postgres claim UPDATE into a data-modifying ``claimed`` CTE and added a head-skip marker arm on
both server backends, and asks whether that move costs Postgres an extra buffering of the claimed
rows. This tool measures one commit at a time, so the same file times both sides of the change.

``measure`` imports ``messagefoundry`` from ``--code-root`` (an extracted tree of the commit under
test, put first on ``sys.path``) and refuses to run if the import resolved anywhere else, so a
figure is never credited to the wrong commit. It opens the server store that the ``MEFOR_STORE_*``
environment names, empties its queue tables, seeds synthetic ingress rows (one fixed, PHI-free HL7
line, never printed), and times each ``claim_fifo_heads`` call alone. After every timed claim it
calls ``release_claimed``, which restores exactly what the claim changed, so every iteration claims
the same rows from the same state. A claim that returns a different row count than the scenario
expects stops the run: a timing over the wrong work is not a figure.

``compare`` reads the JSON reports ``measure`` wrote and prints one Markdown table per backend, the
samples of every round of a label pooled, with the after/before ratio of each statistic.

Only timings, counts, the backend's version line and the commit label reach the output.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

# One synthetic HL7 line; it is stored as the raw body of every seeded row and never printed.
_RAW = "MSH|^~\\&|BENCH|BENCH|BENCH|BENCH|20260101||ADT^A01|BENCH1|P|2.5.1\r"
_STAGE = "ingress"
_SEED_NOW = 100.0
_CLAIM_NOW = 200.0
# The queue tables a claim reads or a seed writes, emptied before a run (the same set the live
# claim tests empty, so it exists at every commit this tool is pointed at).
_TABLES = ("message_events", "queue", "response", "delivered_keys", "messages")


def _parse_scenarios(text: str) -> list[tuple[int, int]]:
    """``"1x1,64x16"`` -> ``[(1, 1), (64, 16)]``: lanes x per-lane limit. A limit of 0 names the
    empty scenario: the lanes are requested but hold no rows, which times the claim's fixed cost."""
    out: list[tuple[int, int]] = []
    for part in text.split(","):
        lanes_s, _, limit_s = part.strip().partition("x")
        lanes, limit = int(lanes_s), int(limit_s)
        if lanes < 1 or limit < 0:
            raise ValueError(f"bad scenario {part!r}: lanes must be >= 1 and the limit >= 0")
        out.append((lanes, limit))
    return out


def _import_engine(code_root: Path) -> Any:
    """Import ``messagefoundry`` from ``code_root`` and nowhere else."""
    sys.path.insert(0, str(code_root))
    import messagefoundry

    where = Path(messagefoundry.__file__).resolve()
    if code_root.resolve() not in where.parents:
        raise SystemExit(
            f"messagefoundry imported from {where}, not from --code-root {code_root}; refusing to"
            " credit this run's figures to the wrong commit"
        )
    return messagefoundry


async def _open_store(backend: str) -> Any:
    from messagefoundry.config.settings import load_settings

    settings = load_settings(environ=os.environ).store
    if backend == "postgres":
        from messagefoundry.store.postgres import PostgresStore

        return await PostgresStore.open(settings)
    from messagefoundry.store.sqlserver import SqlServerStore

    return await SqlServerStore.open(settings)


async def _sql(store: Any, backend: str, statement: str) -> Any:
    """Run one test-owned constant statement; return the first column of the first row, if any."""
    async with store._pool.acquire() as conn:
        if backend == "postgres":
            if statement.lstrip().upper().startswith("SELECT"):
                return await conn.fetchval(statement)
            await conn.execute(statement)
            return None
        cur = await conn.cursor()
        await cur.execute(statement)
        row = await cur.fetchone() if statement.lstrip().upper().startswith("SELECT") else None
        await conn.commit()
        return row[0] if row else None


async def _empty(store: Any, backend: str) -> None:
    if backend == "postgres":
        await _sql(store, backend, f"TRUNCATE {', '.join(_TABLES)} RESTART IDENTITY CASCADE")
    else:
        for table in _TABLES:
            await _sql(store, backend, f"DELETE FROM {table}")


def _stats(samples_ms: list[float]) -> dict[str, float]:
    ordered = sorted(samples_ms)

    def pct(p: float) -> float:
        return ordered[min(len(ordered) - 1, round(p * (len(ordered) - 1)))]

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
    _import_engine(Path(args.code_root))
    backend = args.backend
    store = await _open_store(backend)
    scenarios = _parse_scenarios(args.scenarios)
    max_lanes = max(lanes for lanes, _ in scenarios)
    seeded = [f"IB_BENCH_{i:04d}" for i in range(max_lanes)]
    unseeded = [f"IB_EMPTY_{i:04d}" for i in range(max_lanes)]
    report: dict[str, Any] = {
        "label": args.label,
        "commit": args.commit,
        "round": args.round,
        "backend": backend,
        "rows_per_lane": args.rows_per_lane,
        "warmup": args.warmup,
        "iterations": args.iterations,
        "python": platform.python_version(),
        "scenarios": [],
    }
    try:
        version = await _sql(
            store, backend, "SELECT version()" if backend == "postgres" else "SELECT @@VERSION"
        )
        report["server"] = str(version).splitlines()[0] if version else "unknown"
        await _empty(store, backend)
        for lane in seeded:
            for _ in range(args.rows_per_lane):
                await store.enqueue_ingress(channel_id=lane, raw=_RAW, now=_SEED_NOW)
        for lanes, limit in scenarios:
            names = seeded[:lanes] if limit else unseeded[:lanes]
            per_lane = max(limit, 1)
            expected = lanes * min(limit, args.rows_per_lane)
            samples: list[float] = []
            for i in range(args.warmup + args.iterations):
                start = time.perf_counter()
                res = await store.claim_fifo_heads(
                    _STAGE, names, now=_CLAIM_NOW, per_lane_limit=per_lane
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                ids = [item.id for items in res.by_lane.values() for item in items]
                if ids:
                    await store.release_claimed(ids, now=_CLAIM_NOW)
                if len(ids) != expected:
                    raise SystemExit(
                        f"{backend} {lanes}x{limit}: claimed {len(ids)} rows, expected {expected};"
                        " refusing to time the wrong work"
                    )
                if i >= args.warmup:
                    samples.append(elapsed_ms)
            stats = _stats(samples)
            report["scenarios"].append(
                {"lanes": lanes, "per_lane_limit": limit, "rows_claimed": expected, **stats}
            )
            print(
                f"{backend} {args.label} r{args.round} {lanes}x{limit} rows={expected}"
                f" p50={stats['p50']:.2f}ms p90={stats['p90']:.2f}ms p99={stats['p99']:.2f}ms"
                f" mean={stats['mean']:.2f}ms",
                flush=True,
            )
    finally:
        await store.close()
    return report


def _compare(paths: list[Path], before: str, after: str) -> str:
    # A report keeps summaries, not samples, so rounds cannot be pooled into one distribution. The
    # table gives each round's p50 and the median of the rounds' statistics; the runs interleave
    # before and after, so a drift across the job shows up as rounds that disagree.
    grouped: dict[tuple[str, int, int], dict[str, list[dict[str, Any]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    meta: dict[str, set[str]] = defaultdict(set)
    for path in paths:
        rep = json.loads(path.read_text(encoding="utf-8"))
        meta[rep["backend"]].add(f"{rep['label']}={rep['commit']} on {rep.get('server', '?')}")
        for sc in rep["scenarios"]:
            key = (rep["backend"], sc["lanes"], sc["per_lane_limit"])
            grouped[key][rep["label"]].append(sc)
    lines: list[str] = []
    for backend in sorted(meta):
        lines.append(f"### {backend}")
        lines.extend(f"- {m}" for m in sorted(meta[backend]))
        lines.append("")
        lines.append(
            "| lanes x limit | rows | before p50 ms (rounds) | after p50 ms (rounds) |"
            " p50 after/before | before p90 | after p90 | before p99 | after p99 |"
        )
        lines.append("|---|---:|---|---|---:|---:|---:|---:|---:|")
        for key in sorted(k for k in grouped if k[0] == backend):
            by_label = grouped[key]
            b, a = by_label.get(before, []), by_label.get(after, [])
            if not b or not a:
                continue

            def med(rows: list[dict[str, Any]], stat: str) -> float:
                return float(statistics.median(float(r[stat]) for r in rows))

            ratio = med(a, "p50") / med(b, "p50") if med(b, "p50") else float("nan")
            lines.append(
                f"| {key[1]}x{key[2]} | {b[0]['rows_claimed']} |"
                f" {med(b, 'p50'):.2f} ({', '.join(f'{r["p50"]:.2f}' for r in b)}) |"
                f" {med(a, 'p50'):.2f} ({', '.join(f'{r["p50"]:.2f}' for r in a)}) |"
                f" {ratio:.3f} | {med(b, 'p90'):.2f} | {med(a, 'p90'):.2f} |"
                f" {med(b, 'p99'):.2f} | {med(a, 'p99'):.2f} |"
            )
        lines.append("")
    return "\n".join(lines)


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
    m.add_argument("--rows-per-lane", type=int, default=16)
    m.add_argument("--warmup", type=int, default=10)
    m.add_argument("--iterations", type=int, default=100)
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
    print(_compare(args.reports, args.before, args.after))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

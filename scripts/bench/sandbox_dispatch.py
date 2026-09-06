#!/usr/bin/env python
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""What does ``[sandbox].mode = "subprocess"`` actually cost per message? (ADR 0087, BACKLOG #1194)

ADR 0087 states a price -- ``~6.2 ms end-to-end per dispatch, ~0.19 ms with no reference view``,
against a ``~1.4x`` pickle-round-trip ratio on a 20k-entry table -- and calls it "the standing,
measured price of a non-executing wire". No artifact records that measurement: at 2026-09-04
``git ls-files docs/benchmarks scripts/bench | xargs grep -ril sandbox`` returned **0** files against
a positive control of **59** over ``messagefoundry docs/adr tests``. This tool is the missing
instrument. It measures the SAME quantity the ADR names, so a reader can compare the two numbers
rather than choose between an assertion and nothing.

WHAT IS MEASURED, AND WHY IT IS THE RIGHT QUANTITY
--------------------------------------------------
The isolation seam is :func:`messagefoundry.pipeline.sandbox.run_sandboxed`, called from
``route_only`` (router phase) and ``transform_one`` (transform phase). At ``mode=off`` it is
``fn(payload)``; at ``mode=subprocess`` it marshals the call to a persistent per-inbound worker
child. Everything else on those two call paths -- the HL7 parse, the registry lookup, the Send
validation -- is identical in both modes, so the DIFFERENCE of the two end-to-end call walls is the
isolation overhead and nothing else. Both are timed end-to-end rather than around the seam, because
an in-seam timer would not see the payload rebuild the child does on its side of the wire.

One received message that routes to one handler costs ONE router dispatch plus ONE transform
dispatch, so ``router + transform`` is the per-message figure. Both legs are reported separately;
do not add a router leg to a transform leg from different rows.

RULES THIS TOOL FOLLOWS, EACH BECAUSE THE OPPOSITE MANUFACTURES A NUMBER
------------------------------------------------------------------------
1. LEVELS, NOT RATES. Every reported figure is milliseconds per dispatch. A msg/s figure derived
   from one of them would cross a regime change (a single-lane microbenchmark against a staged
   pipeline with store commits), and a rate across a regime change is not trustworthy.

2. INTERLEAVED A/B, NOT TWO RUNS. Each repetition measures ``off`` and ``subprocess`` back to back
   inside the same repetition, so thermal drift, another process waking, and CPU frequency scaling
   move both arms together instead of becoming the effect.

3. MEDIAN AND SPREAD, NEVER A MEAN. A subprocess round-trip has a long right tail (scheduler
   latency, a GC pause in either process). The mean reports the tail; the median reports the
   typical message. Both p50 and p90 are printed, plus the min and max of the per-repetition
   medians, which is the honest uncertainty band for "what would another run of this tool say".

4. WARMUP IS DISCARDED, AND THE SPAWN IS REPORTED SEPARATELY. The first dispatch of a
   ``subprocess`` session pays the one-time child bootstrap (spawn + ``load_config`` + guard
   install). Folding it into a per-message figure would overstate a steady-state cost by orders of
   magnitude; dropping it silently would hide a real operational cost. It gets its own row.

5. SYNTHETIC HL7 ONLY. The message below is a fabricated ADT^A01 with invented identifiers. Never
   point this tool at a real feed: it prints nothing PHI-bearing, but the graph it loads is its own.

USAGE
-----
    python scripts/bench/sandbox_dispatch.py                    # default: 7 reps x 200 dispatches
    python scripts/bench/sandbox_dispatch.py --reference 20000  # the ADR's 20k-entry table case
    python scripts/bench/sandbox_dispatch.py --reps 3 --iters 50 --json

The reference-view case is the ADR's own worst case: ``enc_run_context`` walks the engine's live
reference tables onto the wire on EVERY dispatch, whether or not the Handler reads them, so the
table size is a per-message cost of the isolation mode and not of the Handler.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType

# Run from a source checkout without an install: put the repo root on the path ahead of anything
# else, so the child worker (which inherits this process's environment) loads the same build.
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from messagefoundry.config.run_context import RunContext  # noqa: E402
from messagefoundry.config.wiring import Registry, load_config  # noqa: E402
from messagefoundry.pipeline.dryrun import route_only, transform_one  # noqa: E402
from messagefoundry.pipeline.sandbox import (  # noqa: E402
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
)

#: A minimal conformant synthetic ADT^A01. Fabricated identifiers and names -- no PHI.
RAW = (
    "MSH|^~\\&|SEND|FAC|RECV|FAC|20240101120000||ADT^A01|MSG00001|P|2.3\r"
    "EVN|A01|20240101120000\r"
    "PID|1||900001||DOE^JANE||19700101|F|||1 TEST ST^^TESTVILLE^ZZ^00000\r"
    "PV1|1|I|WARD^101^A||||1234^SMITH^JOHN\r"
)


def _raw(obx: int) -> str:
    """``RAW`` with ``obx`` synthetic result segments appended -- the payload-size dimension.

    The payload crosses the wire in both directions under ``mode=subprocess`` (request in, the
    Handler's ``Send`` payload back), so message size is a second per-message cost of the isolation
    mode. A bare ADT is a few hundred bytes; a result message with a hundred OBX segments is tens of
    kilobytes, and a feed's real size sits somewhere between.
    """
    if obx <= 0:
        return RAW
    segs = "".join(
        f"OBX|{i + 1}|NM|TEST{i:04d}^SYNTHETIC RESULT {i}^L||{i % 100}.5|mg/dL|0-100|N|||F\r"
        for i in range(obx)
    )
    return RAW + segs


#: The bench graph. One inbound, one router, one pass-through handler -- deliberately trivial, so
#: the measured difference is the seam and not the Handler's own work.
_GRAPH = """
from messagefoundry import inbound, outbound, router, handler, MLLP, Send

inbound("IB_BENCH", MLLP(port=19801), router="r_bench")
outbound("OB_BENCH", MLLP(host="127.0.0.1", port=19802))


@router("r_bench")
def r_bench(msg):
    return "h_bench"


@handler("h_bench")
def h_bench(msg):
    msg.set("MSH-6", "BENCH")
    return Send("OB_BENCH", str(msg))
"""


@dataclass
class Leg:
    """One (phase, mode) arm: the per-dispatch walls of every repetition, in milliseconds."""

    phase: str
    mode: str
    per_rep: list[list[float]] = field(default_factory=list)

    @property
    def flat(self) -> list[float]:
        return [ms for rep in self.per_rep for ms in rep]

    @property
    def rep_medians(self) -> list[float]:
        return [statistics.median(rep) for rep in self.per_rep if rep]

    def summary(self) -> dict[str, float]:
        flat = sorted(self.flat)
        medians = self.rep_medians
        return {
            "p50_ms": statistics.median(flat),
            "p90_ms": flat[min(len(flat) - 1, int(0.90 * len(flat)))],
            "rep_median_min_ms": min(medians),
            "rep_median_max_ms": max(medians),
            "n": float(len(flat)),
            "reps": float(len(medians)),
        }


def _write_graph(root: Path) -> Registry:
    (root / "graph.py").write_text(_GRAPH, encoding="utf-8")
    return load_config(root)


def _run_context(reference_entries: int) -> RunContext:
    """A run context carrying ``reference_entries`` rows in one reference table.

    Zero (the default) is the common case: no reference sets published. A non-zero count reproduces
    the ADR 0087 worst case, where the whole table is snapshotted onto the wire per dispatch.
    """
    if reference_entries <= 0:
        return RunContext()
    table = MappingProxyType({f"K{i:06d}": f"V{i:06d}" for i in range(reference_entries)})
    return RunContext(reference_view=MappingProxyType({"crosswalk": table}))


def _time_router(
    registry: Registry, session: SandboxSession | None, rc: RunContext, raw: str
) -> float:
    ic = registry.inbound["IB_BENCH"]
    t0 = time.perf_counter_ns()
    route_only(registry, ic, raw, sandbox=session, run_context=rc)
    return (time.perf_counter_ns() - t0) / 1e6


def _time_transform(
    registry: Registry, session: SandboxSession | None, rc: RunContext, raw: str
) -> float:
    t0 = time.perf_counter_ns()
    transform_one(registry, "h_bench", raw, sandbox=session, run_context=rc)
    return (time.perf_counter_ns() - t0) / 1e6


def _worker_memory_mb(session: SandboxSession) -> tuple[float, float, int] | None:
    """``(tree RSS MiB, tree USS MiB, process count)`` for the live worker, or ``None``.

    ADR 0087 spawns ONE persistent child per inbound. The committed enterprise target is 1,500
    inbound connections, so this figure multiplies by the connection count at ``mode=subprocess``
    and nothing in the record states it. Reaches into ``_proc`` deliberately: there is no public
    accessor, and this is a measurement tool, not engine code.

    THE TREE, NOT THE DIRECT CHILD -- this is a measured correction, not caution. Under a Windows
    virtual environment ``Scripts\\python.exe`` is a launcher stub that re-execs the base
    interpreter, so ``Popen``'s own pid is a ~6 MiB shim and the real ~70 MiB interpreter is its
    CHILD. Reading only the direct pid under-reports the worker by an order of magnitude and returns
    a clean-looking wrong answer. RSS double-counts pages shared with the parent; USS is the
    marginal cost of one more worker, which is the figure that multiplies by the connection count.
    """
    proc = session._proc  # noqa: SLF001 - measurement tool, no public accessor exists
    if proc is None or proc.pid is None:
        return None
    try:
        import psutil
    except ImportError:  # pragma: no cover - psutil is a core dep, but do not fail the bench on it
        return None
    try:
        top = psutil.Process(proc.pid)
        tree = [top, *top.children(recursive=True)]
        rss = sum(p.memory_info().rss for p in tree)
        uss = sum(p.memory_full_info().uss for p in tree)
        return rss / (1024 * 1024), uss / (1024 * 1024), len(tree)
    except Exception:  # pragma: no cover - the child may have died; a missing number is not a fault
        return None


def _sessions(config_dir: str, wall_seconds: float) -> Iterator[tuple[str, SandboxSession]]:
    for mode, policy in (
        ("off", SandboxPolicy(mode=SandboxMode.OFF)),
        ("subprocess", SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=wall_seconds)),
    ):
        yield mode, SandboxSession(policy, inbound="IB_BENCH", config_dir=config_dir, env=None)


def measure(
    *,
    reps: int,
    iters: int,
    warmup: int,
    reference_entries: int,
    obx: int,
    wall_seconds: float,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="mf-sandbox-bench-") as tmp:
        root = Path(tmp)
        registry = _write_graph(root)
        rc = _run_context(reference_entries)
        raw = _raw(obx)
        legs = {
            (phase, mode): Leg(phase, mode)
            for phase in ("router", "transform")
            for mode in ("off", "subprocess")
        }
        sessions = dict(_sessions(str(root), wall_seconds))
        spawn_ms: float | None = None
        worker_mem: tuple[float, float, int] | None = None
        try:
            # The one-time child bootstrap, timed on its own: the first subprocess dispatch pays
            # spawn + load_config + guard install, and it belongs in no steady-state figure.
            sub = sessions["subprocess"]
            t0 = time.perf_counter_ns()
            _time_router(registry, sub, rc, raw)
            spawn_ms = (time.perf_counter_ns() - t0) / 1e6

            for mode, session in sessions.items():
                arg = None if mode == "off" else session
                for _ in range(warmup):
                    _time_router(registry, arg, rc, raw)
                    _time_transform(registry, arg, rc, raw)

            for _ in range(reps):
                # Interleaved inside the repetition: drift moves both arms, not one.
                for mode, session in sessions.items():
                    arg = None if mode == "off" else session
                    legs[("router", mode)].per_rep.append(
                        [_time_router(registry, arg, rc, raw) for _ in range(iters)]
                    )
                    legs[("transform", mode)].per_rep.append(
                        [_time_transform(registry, arg, rc, raw) for _ in range(iters)]
                    )
            worker_mem = _worker_memory_mb(sessions["subprocess"])
        finally:
            for session in sessions.values():
                session.close()

    rows = {f"{leg.phase}/{leg.mode}": leg.summary() for leg in legs.values()}
    overhead = {
        phase: rows[f"{phase}/subprocess"]["p50_ms"] - rows[f"{phase}/off"]["p50_ms"]
        for phase in ("router", "transform")
    }
    out: dict[str, object] = {
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "reps": reps,
        "iters_per_rep": iters,
        "warmup": warmup,
        "reference_entries": reference_entries,
        "obx_segments": obx,
        "payload_bytes": len(raw.encode("utf-8")),
        "one_time_spawn_ms": spawn_ms,
        "worker_tree_rss_mb": None if worker_mem is None else worker_mem[0],
        "worker_tree_uss_mb": None if worker_mem is None else worker_mem[1],
        "worker_tree_processes": None if worker_mem is None else worker_mem[2],
        "router_overhead_p50_ms": overhead["router"],
        "transform_overhead_p50_ms": overhead["transform"],
        # A message that routes to one handler pays BOTH dispatches, on the same serialized worker.
        "per_message_overhead_p50_ms": overhead["router"] + overhead["transform"],
        "legs": rows,
    }
    return out


def _num(result: dict[str, object], key: str) -> float:
    """One numeric field of a result, narrowed. ``measure`` returns ``dict[str, object]`` because
    it mixes strings, numbers and the nested leg table; every read here is of a field it wrote."""
    value = result[key]
    assert isinstance(value, int | float), key
    return float(value)


def _fmt(result: dict[str, object]) -> str:
    legs = result["legs"]
    assert isinstance(legs, dict)
    lines = [
        f"python {result['python']} on {result['platform']}; "
        f"{result['reps']} reps x {result['iters_per_rep']} dispatches, "
        f"warmup {result['warmup']}, reference_entries={result['reference_entries']}, "
        f"payload {result['payload_bytes']} B ({result['obx_segments']} OBX)",
        "",
        f"{'leg':<24}{'p50 ms':>10}{'p90 ms':>10}{'rep-median range ms':>24}{'n':>8}",
        "-" * 76,
    ]
    for key in ("router/off", "router/subprocess", "transform/off", "transform/subprocess"):
        s = legs[key]
        band = f"{s['rep_median_min_ms']:.4f} .. {s['rep_median_max_ms']:.4f}"
        lines.append(f"{key:<24}{s['p50_ms']:>10.4f}{s['p90_ms']:>10.4f}{band:>24}{int(s['n']):>8}")
    lines += [
        "-" * 76,
        f"router overhead (p50 delta):     {_num(result, 'router_overhead_p50_ms'):.4f} ms/dispatch",
        f"transform overhead (p50 delta):  "
        f"{_num(result, 'transform_overhead_p50_ms'):.4f} ms/dispatch",
        f"per-message overhead (1 router + 1 transform): "
        f"{_num(result, 'per_message_overhead_p50_ms'):.4f} ms",
        f"one-time worker spawn + bootstrap: {_num(result, 'one_time_spawn_ms'):.1f} ms "
        f"(once per inbound per engine start, NOT per message)",
    ]
    if result["worker_tree_rss_mb"] is not None:
        lines.append(
            f"worker process tree: {_num(result, 'worker_tree_rss_mb'):.1f} MiB RSS / "
            f"{_num(result, 'worker_tree_uss_mb'):.1f} MiB USS across "
            f"{result['worker_tree_processes']} process(es) -- ONE tree PER INBOUND, so USS "
            f"multiplies by the connection count"
        )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--reps", type=int, default=7, help="independent repetitions (default 7)")
    ap.add_argument(
        "--iters", type=int, default=200, help="dispatches per leg per rep (default 200)"
    )
    ap.add_argument(
        "--warmup", type=int, default=20, help="discarded dispatches per leg (default 20)"
    )
    ap.add_argument(
        "--reference",
        type=int,
        default=0,
        help="entries in the published reference table (0 = none, the common case)",
    )
    ap.add_argument(
        "--obx",
        type=int,
        default=0,
        help="synthetic OBX segments appended to the payload (0 = a bare ADT)",
    )
    ap.add_argument(
        "--wall-seconds", type=float, default=60.0, help="sandbox wall cap (default 60)"
    )
    ap.add_argument("--json", action="store_true", help="emit the raw result as JSON")
    args = ap.parse_args(argv)

    result = measure(
        reps=args.reps,
        iters=args.iters,
        warmup=args.warmup,
        reference_entries=args.reference,
        obx=args.obx,
        wall_seconds=args.wall_seconds,
    )
    print(json.dumps(result, indent=2) if args.json else _fmt(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Measure the MLLP ingress SERVICE RATE of the machine this runs on (#320).

THE QUESTION THIS EXISTS FOR. `test_load_runner::test_run_load_end_to_end_no_loss` red the required
windows-2025 leg twice on `main` (9b03057f, 56f7d240) with byte-identical counters -- 90 sent, 44
acked, 46 stranded, 52 read -- on runs that lost nothing. The reconcile's stranding budget was widened
(#115) so a saturated-but-lossless run stops failing, but that treats the symptom: the leg saturates at
an offered rate a healthy box absorbs ten times over, and *pass/fail on one fixed rate cannot tell you
that*. This probe reports the rate itself.

WHAT SATURATION LOOKS LIKE, AND WHY IT IS NOT LOSS. The listener ingests strictly serially per
connection (`messagefoundry/transports/mllp.py`: read chunk -> for each frame -> await the durable
commit -> next), so total ingress is ``pool_size / commit-latency``. Offer more than that and the
excess is still in the client's socket when the phase ends; those sends are counted UNCONFIRMED, never
lost -- everything the engine did ingest is delivered and reconciles clean. So the honest signal of
"this machine cannot keep up" is the stranded FRACTION at a known offered rate, not a verdict.

ALWAYS REPEAT. A SINGLE RUN PROVES NOTHING -- this was learned the expensive way. On 2026-08-01 one
600/s run on a developer box produced 456 stranded of 900 (50.7%), a near-exact match for the
windows-2025 CI signature, and it was written up as a clean reproduction. Four repeats of the SAME
command on the SAME box then produced **0 stranded, every time**:

    60/s   x1  ->  90 sent,  90 acked,   0 stranded (0.0%),  90 read
    300/s  x1  -> 450 sent, 450 acked,   0 stranded (0.0%), 450 read
    600/s  x5  -> ~899 sent, 0 stranded in 4 runs; 456 stranded (50.7%) in the 1 run taken while the
                  machine was busy with an unrelated test suite

So stranding here is a CONTENTION artifact, not a clean function of offered rate: the outlier was the
machine being loaded, which is exactly the "runner weather" this probe exists to characterise. Hence
``--repeat``: report the distribution, and never draw a conclusion from n=1. What survives that
correction is only the weaker, still-useful claim -- an unloaded machine strands ZERO at rates up to
10x the CI profile's, while windows-2025 stranded ~51% at the profile's own 60/s, twice, with
byte-identical counters.

WHAT SATURATION IS NOT. Stranded sends are UNCONFIRMED, never lost: everything the engine ingested is
delivered and reconciles clean. The signal is the stranded FRACTION at a known offered rate, not a
verdict.

NOT A BENCHMARK, AND NOT A GATE. One short phase on SQLite in a temp dir; it answers "can this machine
service N msg/s through 4 connections", nothing about production capacity. It is `workflow_dispatch`
only and asserts nothing -- a number that varies with runner weather must never gate a merge.

Usage:  python -m harness.load.ingress_probe <rate> [--repeat N] [--duration S] [--pool N]
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

import uvicorn

from harness.load.profile import load_profile_text
from harness.load.runner import run_load

_CONFIG_DIR = Path("harness/config/load")
_START_TIMEOUT_S = 15.0


def _reserve() -> socket.socket:
    """A bound-but-unlistened loopback socket, kept open so the OS cannot re-hand the port.

    Mirrors tests/test_load_runner.py's `_reserve_port`: closing a socket just to learn its number
    opens a window where a contended runner reassigns it before the real server binds.
    """
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    return s


def _profile(*, adt_port: int, rate: float, duration_s: float, pool_size: int) -> object:
    return load_profile_text(f"""
[load]
name = "ingress-probe"
pool_size = {pool_size}
poll_interval_s = 0.25
drain_timeout_s = 30.0
[[load.target]]
name = "adt_hub"
host = "127.0.0.1"
port = {adt_port}
types = ["ADT"]
[load.mix]
"ADT^A05" = 1.0
[load.slo]
zero_loss = true
max_drain_seconds = 30.0
[[load.phase]]
name = "steady"
kind = "sustained"
loop = "open"
rate_start = {rate}
duration_s = {duration_s}
""")


def probe(rate: float, duration_s: float = 1.5, pool_size: int = 4) -> int:
    """Run one phase at ``rate`` and print a single machine-parseable RESULT line."""
    tmp = tempfile.mkdtemp(prefix="mefor-ingress-probe-")
    adt_s, res_s, oth_s, sink_s, api_s = (_reserve() for _ in range(5))
    adt_port, sink_port, api_port = (
        adt_s.getsockname()[1],
        sink_s.getsockname()[1],
        api_s.getsockname()[1],
    )
    os.environ.update(
        MEFOR_LOAD_FANOUT="2",
        MEFOR_LOAD_RESULTS_FANOUT="1",
        MEFOR_LOAD_TRANSFORM="cheap",
        MEFOR_LOAD_ADT_PORT=str(adt_port),
        MEFOR_LOAD_RESULTS_PORT=str(res_s.getsockname()[1]),
        MEFOR_LOAD_OTHER_PORT=str(oth_s.getsockname()[1]),
        MEFOR_LOAD_SINK_PORT=str(sink_port),
    )
    from messagefoundry.api import create_managed_app

    app = create_managed_app(
        db_path=Path(tmp) / "probe.db", config_dir=_CONFIG_DIR, poll_interval=0.05
    )
    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="error"))
    # Release the MLLP ports at the last moment; hand the still-bound API socket to uvicorn.
    for s in (adt_s, res_s, oth_s, sink_s):
        s.close()
    threading.Thread(target=lambda: uv.run(sockets=[api_s]), daemon=True).start()
    deadline = time.time() + _START_TIMEOUT_S
    while not uv.started:
        time.sleep(0.05)
        if time.time() > deadline:
            print(f"RESULT rate={rate:g} ERROR=engine_did_not_start", flush=True)
            return 2

    t0 = time.perf_counter()
    report = asyncio.run(
        run_load(
            _profile(adt_port=adt_port, rate=rate, duration_s=duration_s, pool_size=pool_size),  # type: ignore[arg-type]
            engine_url=f"http://127.0.0.1:{api_port}",
            id_prefix="PROBE1",
            sink_port=sink_port,
            db_backend="sqlite",
        )
    )
    wall = time.perf_counter() - t0
    c, nl = report.counters, report.no_loss
    pct = (c.timeouts / c.sent * 100.0) if c.sent else 0.0
    # NO derived per-second figure is printed. `engine_read / wall` looks like a service rate and is
    # not one: `wall` includes the stop grace, the drain and the settle-poll, so it lands at ~25/s
    # whether the run offered 60/s or 600/s. Report what was measured -- offered, ingested, stranded
    # -- and let the reader compare across rows.
    print(
        f"RESULT rate={rate:g} sent={c.sent} acked={c.acked} stranded={c.timeouts} "
        f"pct={pct:.1f} read={nl.engine_read} written={nl.engine_written} "
        f"sink={nl.sink_received} backlog={nl.backlog} ok={nl.ok} wall={wall:.2f}",
        flush=True,
    )
    # Deliberately exit 0 even on a reconcile failure: this is a MEASUREMENT, not a gate. A machine
    # too slow to keep up is the finding, not an error, and a non-zero exit here would turn runner
    # weather into a red workflow.
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(__doc__)
        return 2
    rate = float(args[0])
    repeat, duration_s, pool_size = 1, 1.5, 4
    i = 1
    while i < len(args):
        flag = args[i]
        value = args[i + 1] if i + 1 < len(args) else ""
        if flag == "--repeat":
            repeat = int(value)
        elif flag == "--duration":
            duration_s = float(value)
        elif flag == "--pool":
            pool_size = int(value)
        else:
            print(f"unknown option {flag!r}", file=sys.stderr)
            return 2
        i += 2
    for _ in range(repeat):
        rc = probe(rate, duration_s, pool_size)
        if rc != 0:
            return rc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

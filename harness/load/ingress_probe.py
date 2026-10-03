# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

THE ENGINE IS A SIGNED-IN ``serve``, AS IN EVERY OTHER RIG. Each repeat starts its own
``messagefoundry serve`` subprocess on loopback with a fresh temp store (``failover.EngineNode``),
provisions the rig Administrator in that store (``harness/load/rigadmin.py``), signs in, reads the
API with that session, and stops the engine before the next repeat. Until 2026-10-03 the probe built
the engine in-process with sign-in off and left its server thread running until the process exited;
ADR 0203 named this fix. Rows taken before then are not directly comparable with rows taken after,
for at least these reasons: the engine now runs in its own process instead of sharing this one's
interpreter and CPU with the sender, sink and poller; its API hop is TLS; its queue workers fall
back to ``serve``'s default 0.25 s poll rather than 0.05 s; and the poller's signed-in reads cost
store commits (``harness/load/enginepoll.py`` says how many).

Usage:  python -m harness.load.ingress_probe <rate> [--repeat N] [--duration S] [--pool N]
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

import httpx

from harness.load import rigadmin
from harness.load.failover import EngineNode, FailoverError, _await_all_healthy
from harness.load.profile import load_profile_text
from harness.load.runner import run_load
from harness.load.tlsmat import harness_ssl_context
from messagefoundry.terminal_text import escape_for_terminal

_CONFIG_DIR = Path("harness/config/load")
#: How long the engine has to answer ``/health`` once ``serve`` is spawned. The account step runs
#: before the spawn under its own timeout (``rigadmin.provision``), so this covers only the process
#: start: imports, store open, TLS, the graph load and the listeners. A cold Windows runner has been
#: seen to take most of 15 s for that alone, which was this probe's budget when the engine ran in
#: its own thread.
_START_TIMEOUT_S = 60.0
#: Settings prefixes the probe's engine never inherits from the shell (see :func:`_node_env`).
_SHELL_SETTINGS_DROPPED = ("MEFOR_STORE_", "MEFOR_CLUSTER_", "MEFOR_API_")


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
    return asyncio.run(_probe(rate, duration_s, pool_size))


def _node_env(store: Path, *, adt: int, results: int, other: int, sink: int) -> dict[str, str]:
    """The probe engine's environment: this process's, plus the load graph's shape and its store.

    The load settings go to the ``serve`` child only, never into ``os.environ``, so a later repeat
    cannot inherit a previous one's ports. The rig credential that provisioning publishes into
    ``os.environ`` IS copied here; ``EngineNode`` drops it before ``serve`` sees the environment.

    ``serve`` reads the environment, so the shell's own store, cluster and API settings are dropped
    and the store backend and enforcement dial are SET, not defaulted. Otherwise a shell set up for
    a server store, a cluster or ``enforce`` would point every repeat at a shared store (whose
    existing Administrator refuses the rig's sign-in) or stop the engine starting. The probe
    measures SQLite in a temp dir under the synthetic-load posture, every time.
    """
    inherited = {
        name: value
        for name, value in os.environ.items()
        if not name.upper().startswith(_SHELL_SETTINGS_DROPPED)
    }
    return {
        **inherited,
        "MEFOR_STORE_BACKEND": "sqlite",
        "MEFOR_SECURITY_ENFORCEMENT": "warn",
        "MEFOR_LOAD_FANOUT": "2",
        "MEFOR_LOAD_RESULTS_FANOUT": "1",
        "MEFOR_LOAD_TRANSFORM": "cheap",
        "MEFOR_LOAD_ADT_PORT": str(adt),
        "MEFOR_LOAD_RESULTS_PORT": str(results),
        "MEFOR_LOAD_OTHER_PORT": str(other),
        "MEFOR_LOAD_SINK_PORT": str(sink),
        "MEFOR_STORE_PATH": str(store),
    }


def _setup_failed(rate: float, reason: str, exc: BaseException) -> int:
    """Report a repeat whose engine never got as far as the measurement, and end the run.

    ``exc`` can carry an engine log tail (``failover._await_all_healthy``), so it is escaped, and
    to ONE line, newlines included (ASVS 1.1.2). Unlike the other rig setup errors, which keep a
    tail's lines, this line is printed beside the ``RESULT`` verdict, and the ingress-rate-probe
    workflow merges stderr into stdout and reads every line starting ``RESULT``: a tail line of its
    own could forge one."""
    shown = escape_for_terminal(str(exc), single_line=True)
    print(f"ingress probe: {reason}: {shown}", file=sys.stderr, flush=True)
    print(f"RESULT rate={rate:g} ERROR={reason}", flush=True)
    return 2


async def _probe(rate: float, duration_s: float, pool_size: int) -> int:
    with tempfile.TemporaryDirectory(
        prefix="mefor-ingress-probe-", ignore_cleanup_errors=True
    ) as tmp:
        reserved = [_reserve() for _ in range(5)]
        adt_port, results_port, other_port, sink_port, api_port = (
            r.getsockname()[1] for r in reserved
        )
        env = _node_env(
            Path(tmp) / "probe.db",
            adt=adt_port,
            results=results_port,
            other=other_port,
            sink=sink_port,
        )
        # EngineNode is the `serve` subprocess every other harness rig runs. It binds loopback,
        # serves the run's own TLS certificate, takes the synthetic-load posture (warn dial, no
        # store key, open loopback egress; the config-source escape on win32 only), and keeps the
        # rig password out of the engine's environment. The API port in the name keeps each
        # repeat's kept log (MEFOR_BENCH_KEEP_NODE_LOGS) from overwriting the last one's.
        node: EngineNode | None = None
        try:
            try:
                node = EngineNode(
                    f"ingress-probe-{api_port}",
                    api_port,
                    env=env,
                    config_dir=str(_CONFIG_DIR),
                    cwd=Path.cwd(),
                )
                # Provision this repeat's fresh store while the ports are still held: it is a
                # process start of its own, and releasing them first would leave them free to any
                # other process for its whole length.
                await node.provision()
            except (FailoverError, OSError) as exc:
                return _setup_failed(rate, "provision_failed", exc)
            finally:
                for r in reserved:
                    r.close()
            try:
                await node.start(provision=False)
                # The run's own anchor is node.cacert here: _node_env drops any MEFOR_API_* the
                # shell carries, so EngineNode hands serve harness_tls_material()'s pair.
                async with httpx.AsyncClient(timeout=4.0, verify=harness_ssl_context()) as client:
                    await _await_all_healthy([node], client, timeout=_START_TIMEOUT_S)
            except (FailoverError, OSError) as exc:
                return _setup_failed(rate, "engine_did_not_start", exc)
            try:
                # Each repeat has its own store, so it signs in afresh: a session from an earlier
                # repeat's store would be refused here.
                token = await asyncio.to_thread(rigadmin.sign_in, node.url, cacert=node.cacert)
            except rigadmin.RigUnreachable as exc:
                return _setup_failed(rate, "engine_stopped_answering", exc)
            except rigadmin.RigAdminError as exc:
                return _setup_failed(rate, "sign_in_refused", exc)

            t0 = time.perf_counter()
            report = await run_load(
                _profile(adt_port=adt_port, rate=rate, duration_s=duration_s, pool_size=pool_size),  # type: ignore[arg-type]
                engine_url=node.url,
                id_prefix="PROBE1",
                token=token,
                sink_port=sink_port,
                db_backend="sqlite",
                cacert=node.cacert,
            )
            wall = time.perf_counter() - t0
        finally:
            # Every exit this code sees stops the engine: a finished repeat, a failed setup, an
            # exception and Ctrl-C. An exit it does not see leaves the child running -- at least a
            # SIGKILL or a SIGTERM of the probe, and a Windows TerminateProcess.
            if node is not None:
                await node.stop()
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

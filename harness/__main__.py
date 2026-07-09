# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Test harness entrypoint.

``python -m harness``                 → launch the GUI (Send/Receive/File/Compose/Monitor).
``python -m harness --list-scenarios``→ list the built-in scenarios.
``python -m harness --scenario NAME`` → run one scenario headless against a running engine
                                                and exit 0 (pass) / 1 (fail) — for CI.
``python -m harness --list-profiles`` → list the built-in load profiles.
``python -m harness --load NAME``     → run a load profile headless against a running engine and exit
                                                0 (SLOs met) / 1 (SLO violation, incl. zero_loss when
                                                the profile sets it, or a baseline regression) / 2
                                                (setup error) / 3 (interrupted).
``python -m harness --failover NAME`` → run the two-node primary-kill scenario (the profile must carry a
                                                [load.failover] table) against a shared server DB
                                                (MEFOR_STORE_BACKEND=postgres|sqlserver + MEFOR_STORE_*);
                                                the harness OWNS the two engines, SIGKILLs the primary
                                                mid-load, and exits 0 (recovery + no-loss + ordering met)
                                                / 1 (an SLO violated) / 2 (setup) / 3 (interrupted).
``python -m harness --connscale NAME``→ run the CONNECTION-SCALE measurement sweep (B11): spin up N
                                                inbound MLLP connections (the profile's counts, e.g.
                                                500/1000/1500) at a low per-connection rate against a real
                                                engine the harness OWNS, and read the connection-scale
                                                walls vs N. Exits 0 (no-loss + SLOs met) / 1 (an SLO
                                                violated) / 2 (setup) / 3 (interrupted).
``python -m harness multishard ...``  → run the multi-ENGINE store-contention sweep (WS-B): spin up N
                                                concurrently-active `serve` engines against ONE shared
                                                store (disjoint inbound/sink/API ports + disjoint
                                                connection names), drive per-engine load, and read whether
                                                one store is the aggregate ceiling. Exits 0 (zero-loss at
                                                every N) / 1 (loss) / 2 (setup) / 3 (interrupted).
``python -m harness shardcert ...``   → run the N-active engine-shard SIZING bench (ADR 0073): N
                                                `serve --shard` engines on ONE unified server store with
                                                OVERLAPPING outbound destinations, driven at a single rate
                                                or an ascending --rate-ladder (ceiling hunt), with the W1
                                                persistent-outbound + many-thin-lane knobs. Exits 0 (every
                                                step held the correctness invariants) / 1 (an invariant
                                                broke) / 2 (setup) / 3 (interrupted).
``python -m harness shardcert-engine ...`` → the ENGINE-box half of the WS-C two-box N-active cert: bring
                                                the `serve --shard` fleet up against the unified store,
                                                post SHARDS_READY, run the LOCAL kill timer, drain, report.
                                                Does NOT drive load. Exits 0 (drained, no stranded rows) /
                                                1 (store-truth fail) / 3 (interrupted).
``python -m harness shardcert-driver ...`` → the LOAD-GEN-box half: wait for SHARDS_READY, bind the sink
                                                locally, open one MLLP connection per (shard, lane), drive
                                                + post DRIVE_START, drain the REMOTE /stats, emit the
                                                sink/tracker verdict. Does NOT spawn engines. Exits 0
                                                (no-loss + FIFO) / 1 (verdict fail) / 2 (setup/timeout).
``python -m harness shardcert-sink ...`` → one SINK-tier process of the WS-C multi-process SIZING drive
                                                (PR-C): bind a correlation sink over a contiguous chunk of
                                                the destination-port band, post SINK_BOUND.<i>, absorb the
                                                fan-out until DRIVE_COMPLETE, post SINK_DONE.<i> with its
                                                delivered/order tally. Does NOT drive or spawn. Exit 0.
``python -m harness shardcert-driver-worker ...`` → one SENDER-tier process: learn the topology from
                                                SHARDS_READY, own a contiguous band slice, arm + post
                                                DRIVER_ARMED.<j>, wait for DRIVE_GO, drive its bands, post
                                                DRIVER_DONE.<j>. Binds no sink. Exit 0 (armed + drove) / 2.
``python -m harness shardcert-drive ...`` → the multi-process drive COORDINATOR: spawn K sender + M sink
                                                children, handshake the engine + children, drain the REMOTE
                                                /stats, aggregate + count-balance reconcile. Exits 0 (no-loss
                                                + FIFO + non-vacuous) / 1 (verdict fail) / 2 (setup/timeout).
``python -m harness shardcert-engine-ladder ...`` → the ENGINE-box half of the TURNKEY two-box SIZING
                                                ceiling ladder (PR-C2): loop the fixed rung plan (fresh
                                                store + run_id per rung), post each rung's store-truth +
                                                phase timing, honour LADDER_STOP, arm the soak. Pair it with
                                                shardcert-drive-ladder. Exit 0.
``python -m harness shardcert-drive-ladder ...`` → the LOAD-GEN-box half + consolidated report: loop the
                                                same rungs, drive each under the drain gate, classify
                                                (sustained / collapsed / frozen-tail), early-stop at the
                                                ceiling, soak, and emit the ONE consolidated report. Exits 0
                                                (correctness held) / 1 (correctness break) / 2 (setup/timeout).

The headless paths import no PySide6, so they run on a display-less runner; the GUI import is
deferred into :func:`_launch_gui`.
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    # Scenario text uses arrows (U+2192); a legacy Windows console (cp1252) would otherwise raise
    # UnicodeEncodeError when --list-scenarios / --scenario prints them, breaking the documented
    # CI use. Force UTF-8 on the CLI streams — best-effort, since a pytest/redirect wrapper may
    # not support reconfigure.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass

    # `multishard` / `shardcert` (+ the WS-C two-box `shardcert-engine`/`shardcert-driver`) are positional
    # subcommands with their own option sets (the flag-based `--connscale`/`--load` style doesn't fit an
    # N-engine sweep or a driver/engine split), so route them before the shared flag parser.
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "multishard":
        return _run_multishard(raw[1:])
    if raw and raw[0] == "shardcert":
        return _run_shardcert(raw[1:])
    if raw and raw[0] == "shardcert-engine":
        return _run_shardcert_engine(raw[1:])
    if raw and raw[0] == "shardcert-driver":
        return _run_shardcert_driver(raw[1:])
    if raw and raw[0] == "shardcert-sink":
        return _run_shardcert_sink(raw[1:])
    if raw and raw[0] == "shardcert-driver-worker":
        return _run_shardcert_driver_worker(raw[1:])
    if raw and raw[0] == "shardcert-drive":
        return _run_shardcert_drive(raw[1:])
    if raw and raw[0] == "shardcert-engine-ladder":
        return _run_shardcert_engine_ladder(raw[1:])
    if raw and raw[0] == "shardcert-drive-ladder":
        return _run_shardcert_drive_ladder(raw[1:])

    parser = argparse.ArgumentParser(prog="harness", description="MessageFoundry test harness")
    parser.add_argument(
        "--scenario", help="run this scenario headless and exit (see --list-scenarios)"
    )
    parser.add_argument("--list-scenarios", action="store_true", help="list built-in scenarios")
    parser.add_argument(
        "--load", help="run this load profile (built-in name or path to a .toml) and exit"
    )
    parser.add_argument(
        "--failover",
        help="run this profile's two-node primary-kill scenario (needs a [load.failover] table + a "
        "shared server DB via MEFOR_STORE_*) and exit",
    )
    parser.add_argument(
        "--inbound-base-port",
        type=int,
        default=2600,
        help="failover: base inbound MLLP port (ADT hub; results/other = base+1/+2). Both nodes bind it",
    )
    parser.add_argument(
        "--connscale",
        help="run this connection-scale profile (B11; built-in name or path to a .toml) and exit",
    )
    parser.add_argument(
        "--connscale-api-port",
        type=int,
        default=8800,
        help="connscale: base engine API port (each sweep step's owned engine uses base + step)",
    )
    parser.add_argument(
        "--list-connscale-profiles",
        action="store_true",
        help="list built-in connection-scale profiles",
    )
    parser.add_argument("--list-profiles", action="store_true", help="list built-in load profiles")
    parser.add_argument("--engine", default="http://127.0.0.1:8765", help="engine API base URL")
    parser.add_argument("--token", help="bearer token for an auth-enabled engine")
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="scenario: seconds to wait for the outcome"
    )
    # Load-run options.
    parser.add_argument(
        "--sink-port", type=int, default=2700, help="load: base correlation-sink port"
    )
    parser.add_argument("--sink-ports", type=int, default=1, help="load: contiguous sink ports")
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help="load: skip the 'engine serves all target ports' check — for driving a `supervise` "
        "multi-shard cluster from one harness (the MLLP ports are spread across the shard engines, "
        "so no single --engine serves them all). Point every shard's MEFOR_LOAD_SINK_PORT at this "
        "run's --sink-port so the one correlation sink aggregates all shards' end-to-end throughput.",
    )
    parser.add_argument(
        "--shard-engine",
        action="append",
        metavar="URL",
        help="load: an EXTRA engine API base URL to poll + aggregate alongside --engine (repeatable). "
        "Drives a `supervise` multi-shard cluster: pass --engine for the primary shard and one "
        "--shard-engine per other shard, and the harness sums every shard's /stats so the no-loss "
        "reconcile + drain see true cluster totals. Pair with --skip-preflight (no one engine serves "
        "all MLLP ports). With none given the single --engine is polled exactly as before.",
    )
    parser.add_argument("--report-json", help="load: write the JSON report to this path")
    parser.add_argument("--report-csv", help="load: write the per-phase CSV to this path")
    parser.add_argument(
        "--report-compare",
        help="connscale: write the A/B comparison table(s) to this path -- the claim-mode A/B "
        "(per_lane vs pooled, ADR 0066), the thread-hop-fusion A/B (B0 vs B1 with the GO/NO-GO verdict, "
        "ADR 0071 B5), and/or the statement-batching A/B (B0 vs B1, ADR 0075 Bench B). Each is produced "
        "when its axis has >1 arm (e.g. pooled_ab / fuse_ab / batch_ab); the same tables also print via "
        "the console report and embed under 'comparison' / 'fuse_comparison' / 'batch_comparison' in "
        "--report-json.",
    )
    parser.add_argument("--baseline", help="load: compare against this saved JSON report")
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.1,
        help="load: baseline regression tolerance (fraction)",
    )
    parser.add_argument("--db-backend", help="load: label the store backend in the report")
    args = parser.parse_args(argv)

    if args.list_scenarios:
        return _list_scenarios()
    if args.list_profiles:
        return _list_profiles()
    if args.list_connscale_profiles:
        return _list_connscale_profiles()
    if sum(bool(x) for x in (args.load, args.scenario, args.failover, args.connscale)) > 1:
        print(
            "--load, --failover, --connscale, and --scenario are mutually exclusive",
            file=sys.stderr,
        )
        return 2
    if args.failover:
        return _run_failover(args)
    if args.connscale:
        return _run_connscale(args)
    if args.load:
        return _run_load(args)
    if args.scenario:
        return _run_scenario(args.scenario, args.engine, args.token, args.timeout)
    return _launch_gui()


def _list_scenarios() -> int:
    from harness.scenarios import SCENARIOS

    for name, scenario in SCENARIOS.items():
        print(f"  {name:<12} {scenario.description}")
    return 0


def _run_scenario(name: str, engine_url: str, token: str | None, timeout: float) -> int:
    from messagefoundry.console.client import ApiError, EngineClient
    from harness.scenarios import SCENARIOS, run_scenario

    scenario = SCENARIOS.get(name)
    if scenario is None:
        print(f"unknown scenario {name!r}; choices: {', '.join(SCENARIOS)}", file=sys.stderr)
        return 2
    try:
        with EngineClient(engine_url) as client:
            if token:
                client.set_token(token)
            result = run_scenario(scenario, client, timeout=timeout)
    except ApiError as exc:
        print(f"FAIL  {name}: {exc}", file=sys.stderr)
        return 1
    print(f"{'PASS' if result.ok else 'FAIL'}  {name}: {result.detail}")
    return 0 if result.ok else 1


def _list_profiles() -> int:
    from harness.load.profile import list_profiles

    for name, description in list_profiles().items():
        print(f"  {name:<18} {description}")
    return 0


def _run_load(args: argparse.Namespace) -> int:
    import asyncio
    import json
    import os
    import time
    from pathlib import Path

    from messagefoundry.console.client import ApiError

    from harness.load.profile import LoadProfileError, get_profile
    from harness.load.report import compare_to_baseline
    from harness.load.runner import PreflightError, run_load

    try:
        profile = get_profile(args.load)
    except LoadProfileError as exc:
        print(f"bad profile: {exc}", file=sys.stderr)
        return 2

    # A run-scoped, ASCII-alnum control-id prefix so a re-run can't collide with a prior run's ids in
    # a long-lived DB. (pid + monotonic ns; no wall clock needed.)
    prefix = f"L{os.getpid():x}{time.perf_counter_ns():x}"[:16]

    try:
        report = asyncio.run(
            run_load(
                profile,
                engine_url=args.engine,
                id_prefix=prefix,
                token=args.token,
                sink_port=args.sink_port,
                sink_ports=args.sink_ports,
                db_backend=args.db_backend,
                skip_preflight=args.skip_preflight,
                shard_engines=tuple(args.shard_engine or ()),
            )
        )
    except PreflightError as exc:
        print(f"preflight failed: {exc}", file=sys.stderr)
        return 2
    except ApiError as exc:
        # A bad/expired --token or an engine that's down surfaces here (the client validates the token
        # via /auth/me before preflight). That's a setup failure, not an SLO violation → exit 2.
        print(f"engine setup failed: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render_console())

    if args.report_json:
        Path(args.report_json).write_text(report.to_json(), encoding="utf-8")
    if args.report_csv:
        Path(args.report_csv).write_text(report.to_csv(), encoding="utf-8")

    exit_code = report.exit_code
    if args.baseline:
        try:
            baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"could not read baseline {args.baseline!r}: {exc}", file=sys.stderr)
            return 2
        regressions = compare_to_baseline(report.to_json_dict(), baseline, tolerance=args.tolerance)
        if regressions:
            print("\nBASELINE REGRESSIONS:", file=sys.stderr)
            for r in regressions:
                print(f"  - {r}", file=sys.stderr)
            exit_code = exit_code or 1
    return exit_code


def _run_failover(args: argparse.Namespace) -> int:
    import asyncio
    import json
    import os
    import socket
    from pathlib import Path

    from harness.load.failover import FailoverError, FailoverPorts, run_failover_load
    from harness.load.profile import LoadProfileError, get_profile

    try:
        profile = get_profile(args.failover)
    except LoadProfileError as exc:
        print(f"bad profile: {exc}", file=sys.stderr)
        return 2
    if profile.failover is None:
        print(
            f"profile {profile.name!r} has no [load.failover] table — not a failover profile",
            file=sys.stderr,
        )
        return 2
    # A failover needs a SHARED server DB (SQLite is single-file/single-node — it can't cluster).
    backend = os.environ.get("MEFOR_STORE_BACKEND", "").strip().lower()
    if backend not in ("postgres", "sqlserver"):
        print(
            "failover needs a shared server DB: set MEFOR_STORE_BACKEND=postgres|sqlserver (+ the "
            f"MEFOR_STORE_* connection env); got {backend or '(unset → sqlite)'!r}",
            file=sys.stderr,
        )
        return 2

    def _two_free_ports() -> tuple[int, int]:
        # Hold BOTH sockets open while reading their ports so the kernel can't hand the same ephemeral
        # port back to the second bind (the close->rebind race that would launch both nodes on one --port).
        s1, s2 = socket.socket(), socket.socket()
        for s in (s1, s2):
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 0))
        try:
            return int(s1.getsockname()[1]), int(s2.getsockname()[1])
        finally:
            s1.close()
            s2.close()

    base = args.inbound_base_port
    api_a, api_b = _two_free_ports()
    ports = FailoverPorts(
        inbound_adt=base,
        inbound_results=base + 1,
        inbound_other=base + 2,
        sink=args.sink_port,
        sink_count=args.sink_ports,
        api_a=api_a,
        api_b=api_b,
    )
    try:
        report = asyncio.run(
            run_failover_load(profile, ports=ports, db_backend=args.db_backend or backend)
        )
    except FailoverError as exc:
        print(f"failover setup failed: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render_console())
    if args.report_json:
        Path(args.report_json).write_text(
            json.dumps(report.to_json_dict(), indent=2), encoding="utf-8"
        )
    return report.exit_code


def _list_connscale_profiles() -> int:
    from harness.load.connscale.profile import list_connscale_profiles

    for name, description in list_connscale_profiles().items():
        print(f"  {name:<20} {description}")
    return 0


def _run_connscale(args: argparse.Namespace) -> int:
    import asyncio
    from pathlib import Path

    from harness.load.connscale.profile import ConnScaleProfileError, get_connscale_profile
    from harness.load.connscale.runner import ConnScaleError, run_connscale

    try:
        profile = get_connscale_profile(args.connscale)
    except ConnScaleProfileError as exc:
        print(f"bad connscale profile: {exc}", file=sys.stderr)
        return 2

    try:
        report = asyncio.run(
            run_connscale(
                profile,
                engine_api_port_base=args.connscale_api_port,
                sink_host="127.0.0.1",
                sink_port=args.sink_port,
                sink_ports=args.sink_ports,
            )
        )
    except ConnScaleError as exc:
        print(f"connscale setup failed: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render_console())
    if args.report_json:
        Path(args.report_json).write_text(report.to_json(), encoding="utf-8")
    if args.report_csv:
        Path(args.report_csv).write_text(report.to_csv(), encoding="utf-8")
    if args.report_compare:
        tables: list[str] = []
        if report.comparison is not None:
            tables.append(report.comparison.render_table())
        if report.fuse_comparison is not None:
            tables.append(report.fuse_comparison.render_table())
        if report.batch_comparison is not None:
            tables.append(report.batch_comparison.render_table())
        if tables:
            Path(args.report_compare).write_text("\n\n".join(tables) + "\n", encoding="utf-8")
        else:
            print(
                "--report-compare: this profile has a single claim mode, a single fuse mode, AND a "
                'single batch mode (no A/B to write); use claim_modes = ["per_lane", "pooled"] (e.g. '
                "pooled_ab), fuse_modes = [false, true] (e.g. fuse_ab), or batch_modes = [false, true] "
                "(e.g. batch_ab)",
                file=sys.stderr,
            )
    return report.exit_code


def _run_multishard(argv: list[str]) -> int:
    import asyncio
    import os
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="harness multishard",
        description="Multi-ENGINE store-contention sweep (WS-B): N concurrently-active `serve` engines "
        "against ONE shared store, disjoint lanes, measuring whether one store is the aggregate ceiling.",
    )
    parser.add_argument(
        "--engines",
        required=True,
        help="engine count(s) to sweep — a single N or a comma-separated list (e.g. 2,4,8,16)",
    )
    parser.add_argument(
        "--count", type=int, default=30, help="inbound MLLP connections PER engine (C)"
    )
    parser.add_argument(
        "--per-conn-rate", type=float, default=13.0, help="target msg/s per connection (R)"
    )
    parser.add_argument(
        "--hold-seconds", type=float, default=60.0, help="steady-state hold per N step"
    )
    parser.add_argument("--inbound-base", type=int, default=20000, help="base inbound MLLP port")
    parser.add_argument("--sink-base", type=int, default=40000, help="base correlation-sink port")
    parser.add_argument(
        "--stride", type=int, default=200, help="per-engine port stride (must be >= --count)"
    )
    parser.add_argument("--api-base", type=int, default=9000, help="base engine API port")
    parser.add_argument(
        "--engine-index-base",
        type=int,
        default=0,
        help="offset the per-engine lane index (E{k+base}) so a SECOND concurrent orchestrator "
        "process drives DISJOINT lanes on the SAME store — the WS-B de-confound: one process has a "
        "measured ~457 msg/s ACK ceiling, so split a high-aggregate run across >=2 processes, each "
        "under the ceiling, each with disjoint --inbound-base/--sink-base/--api-base port bands "
        "(e.g. proc A: --engines 2 --engine-index-base 0; proc B: --engines 2 --engine-index-base 2)",
    )
    parser.add_argument(
        "--store",
        default="sqlite",
        choices=("sqlite", "sqlserver", "postgres"),
        help="store backend LABEL for the report; the actual connection comes from MEFOR_STORE_*",
    )
    parser.add_argument(
        "--db",
        help="sqlite only: the SHARED .db file every engine's MEFOR_STORE_PATH points at (required so "
        "the engines truly share one store; ignored for server backends)",
    )
    parser.add_argument(
        "--cluster",
        action="store_true",
        help="the [cluster]-ON comparison arm (sets MEFOR_CLUSTER_ENABLED=true on every engine); the "
        "PRIMARY sweep is cluster OFF (all N engines write simultaneously with disjoint rows)",
    )
    parser.add_argument("--report-json", help="write the JSON report to this path")
    args = parser.parse_args(argv)

    from harness.load.connscale.runner import ConnScaleError
    from harness.load.multishard import run_multishard

    try:
        engine_counts = [int(x) for x in str(args.engines).split(",") if x.strip()]
    except ValueError:
        print(
            f"--engines must be an int or comma-separated ints, got {args.engines!r}",
            file=sys.stderr,
        )
        return 2
    if not engine_counts or any(n < 1 for n in engine_counts):
        print("--engines must list one or more positive integers", file=sys.stderr)
        return 2

    db_path: str | None = None
    if args.store == "sqlite":
        if not args.db:
            print(
                "sqlite: pass --db <shared.db> so every engine shares ONE store file (else each engine "
                "gets its own default messagefoundry.db and there is no contention to measure)",
                file=sys.stderr,
            )
            return 2
        db_path = str(Path(args.db).resolve())
    else:
        backend = os.environ.get("MEFOR_STORE_BACKEND", "").strip().lower()
        if backend != args.store:
            print(
                f"--store {args.store} needs MEFOR_STORE_BACKEND={args.store} (+ the MEFOR_STORE_* "
                f"connection env); got {backend or '(unset)'!r}",
                file=sys.stderr,
            )
            return 2

    try:
        report = asyncio.run(
            run_multishard(
                engine_counts=engine_counts,
                count_per_engine=args.count,
                per_conn_rate=args.per_conn_rate,
                hold_seconds=args.hold_seconds,
                inbound_base=args.inbound_base,
                sink_base=args.sink_base,
                stride=args.stride,
                api_base=args.api_base,
                engine_index_base=args.engine_index_base,
                store_backend=args.store,
                cluster_enabled=args.cluster,
                db_path=db_path,
            )
        )
    except ConnScaleError as exc:
        print(f"multishard setup failed: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render_console())
    if args.report_json:
        import json

        Path(args.report_json).write_text(
            json.dumps(report.to_json_dict(), indent=2), encoding="utf-8"
        )
    return report.exit_code


def _run_shardcert(argv: list[str]) -> int:
    import asyncio
    import json
    import os
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="harness shardcert",
        description="N-active engine-shard SIZING bench (ADR 0073): N `serve --shard` engines on ONE "
        "unified server store with OVERLAPPING outbound destinations, driven at a single --rate or an "
        "ascending --rate-ladder ceiling hunt.",
    )
    parser.add_argument(
        "--shards", default="a,b,c,d", help="comma list of shard ids (default 4: a,b,c,d)"
    )
    parser.add_argument(
        "--dests", type=int, default=8, help="shared outbound destinations every shard sends to"
    )
    parser.add_argument(
        "--lanes-per-shard",
        type=int,
        default=1,
        help="inbound->router->handler chains per shard (many-thin-lanes; 1 = one fat lane, today)",
    )
    parser.add_argument(
        "--persistent",
        action="store_true",
        help="give the shared outbounds the ADR 0067 persistent connection (the W1 sizing fix)",
    )
    parser.add_argument(
        "--rate-ladder",
        help="ascending aggregate rates for the ceiling hunt: a comma list (e.g. 40,80,120) or a "
        "start:stop:step range (e.g. 40:200:40). Omit to drive the single --rate.",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=40.0,
        help="single aggregate msg/s when --rate-ladder is not given",
    )
    parser.add_argument(
        "--hold-seconds", type=float, default=60.0, help="steady-state hold per rate step"
    )
    parser.add_argument(
        "--drain-timeout", type=float, default=120.0, help="post-hold drain timeout per step"
    )
    parser.add_argument("--sink-host", default="127.0.0.1", help="correlation-sink bind host")
    parser.add_argument(
        "--sink-port", type=int, help="pin the correlation-sink port (default: an ephemeral port)"
    )
    parser.add_argument(
        "--store",
        default="sqlserver",
        choices=("sqlserver",),
        help="server store backend LABEL (SQL Server only — this bench's reset/queue helpers are "
        "SqlServerStore-specific); the connection itself comes from MEFOR_STORE_*",
    )
    parser.add_argument("--report-json", help="write the JSON report to this path")
    args = parser.parse_args(argv)

    if args.lanes_per_shard < 1:
        print("--lanes-per-shard must be >= 1", file=sys.stderr)
        return 2

    # Wire the graph-shape env knobs BEFORE the loader discovery + the serve subprocesses read them.
    os.environ["MEFOR_SHARDCERT_SHARDS"] = args.shards
    os.environ["MEFOR_SHARDCERT_LANES_PER_SHARD"] = str(args.lanes_per_shard)
    os.environ["MEFOR_SHARDCERT_PERSISTENT"] = "1" if args.persistent else "0"

    # N shards on ONE unified store ⇒ a server-DB backend is required (mirrors _run_multishard).
    backend = os.environ.get("MEFOR_STORE_BACKEND", "").strip().lower()
    if backend != args.store:
        print(
            f"--store {args.store} needs MEFOR_STORE_BACKEND={args.store} (+ the MEFOR_STORE_* "
            f"connection env); got {backend or '(unset)'!r}",
            file=sys.stderr,
        )
        return 2
    store_env = {k: v for k, v in os.environ.items() if k.startswith("MEFOR_STORE_")}

    from harness.load.shardcert import parse_rate_ladder, run_shardcert, run_shardcert_ladder

    try:
        if args.rate_ladder:
            try:
                rates = parse_rate_ladder(args.rate_ladder)
            except ValueError as exc:
                print(f"bad --rate-ladder: {exc}", file=sys.stderr)
                return 2
            ladder = asyncio.run(
                run_shardcert_ladder(
                    rates=rates,
                    dests=args.dests,
                    hold_seconds=args.hold_seconds,
                    drain_timeout=args.drain_timeout,
                    sink_host=args.sink_host,
                    sink_port=args.sink_port,
                    store_env=store_env,
                )
            )
            print(ladder.render())
            if args.report_json:
                Path(args.report_json).write_text(
                    json.dumps(ladder.to_json_dict(), indent=2), encoding="utf-8"
                )
            return ladder.exit_code

        single = asyncio.run(
            run_shardcert(
                dests=args.dests,
                aggregate_rate=args.rate,
                hold_seconds=args.hold_seconds,
                drain_timeout=args.drain_timeout,
                sink_host=args.sink_host,
                sink_port=args.sink_port,
                store_env=store_env,
                capture_peak=True,
            )
        )
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(single.render())
    if args.report_json:
        Path(args.report_json).write_text(
            json.dumps(single.to_json_dict(), indent=2), encoding="utf-8"
        )
    return 0 if single.ok else 1


# --- WS-C two-box shardcert drive (engine box + load-gen box) ----------------------------------------


def _store_env_from_os() -> dict[str, str]:
    """The ambient ``MEFOR_STORE_*`` connection env — the unified-store connection every ``serve --shard``
    shares (the shardcert engine launcher adds the graph shape + auth/insecure escapes itself)."""
    import os

    return {k: v for k, v in os.environ.items() if k.startswith("MEFOR_STORE_")}


def _coord_from_args(args: argparse.Namespace) -> object:
    from harness.load.coord import FileDropCoord, default_coord_dir

    return FileDropCoord(args.coord_dir or default_coord_dir(), run_id=args.run_id)


def _add_coord_args(parser: argparse.ArgumentParser, *, default_run_id: str = "shardcert") -> None:
    from harness.load.coord import default_coord_dir

    parser.add_argument(
        "--coord-dir",
        default=None,
        help=f"the shared file-drop coord directory both halves rendezvous in (default: "
        f"$MEFOR_COORD_DIR or {default_coord_dir()!r})",
    )
    parser.add_argument(
        "--run-id",
        default=default_run_id,
        help=f"coord run id — scopes the handshake files so parallel runs don't cross (default "
        f"{default_run_id!r})",
    )


def _run_shardcert_engine(argv: list[str]) -> int:
    import asyncio
    import os

    parser = argparse.ArgumentParser(
        prog="harness shardcert-engine",
        description="ENGINE-box half of the WS-C two-box N-active cert (ADR 0073): bring the serve --shard "
        "fleet up against the unified store, handshake with the driver via the file-drop coord, run the "
        "LOCAL kill timer, drain, report. Does NOT drive load — that is the load-gen box's shardcert-driver.",
    )
    parser.add_argument(
        "--shards", default="a,b,c,d", help="comma list of shard ids (default 4: a,b,c,d)"
    )
    parser.add_argument(
        "--dests",
        type=int,
        default=8,
        help="shared overlapping outbound destinations every shard sends to",
    )
    parser.add_argument(
        "--lanes-per-shard",
        type=int,
        default=1,
        help="inbound->router->handler chains per shard (many-thin-lanes; 1 = one fat lane). The engine "
        "reserves N*lanes contiguous inbound ports and advertises `lanes` in SHARDS_READY so the driver "
        "opens N*lanes connections",
    )
    parser.add_argument(
        "--persistent",
        action="store_true",
        help="give the shared outbounds the ADR 0067 persistent connection (the W1 sizing fix)",
    )
    parser.add_argument(
        "--hold-seconds", type=float, default=20.0, help="the driver's steady-state hold"
    )
    parser.add_argument("--drain-timeout", type=float, default=90.0, help="post-hold drain timeout")
    parser.add_argument(
        "--kill", action="store_true", help="the crash leg: SIGKILL the max-owner shard mid-hold"
    )
    parser.add_argument(
        "--kill-shard", help="pin which shard to kill (default: the one owning most lanes)"
    )
    parser.add_argument(
        "--kill-at-fraction",
        type=float,
        default=0.4,
        help="fire the LOCAL SIGKILL this fraction into the hold (anchored on observing DRIVE_START)",
    )
    parser.add_argument(
        "--sink-port",
        type=int,
        required=True,
        help="the agreed BASE sink port the DRIVER binds (advertised in SHARDS_READY; the shards deliver here)",
    )
    parser.add_argument(
        "--sink-ports",
        type=int,
        default=1,
        help="width of the sink port band the driver binds (single sink for the correctness cert; the "
        "fan-out width is exercised in a later PR)",
    )
    parser.add_argument(
        "--sink-host",
        default="127.0.0.1",
        help="the LOAD-GEN box IP the shards deliver their outbound fan-out to (MEFOR_SHARDCERT_SINK_HOST)",
    )
    parser.add_argument(
        "--inbound-bind-host",
        default="0.0.0.0",
        help="interface every shard's inbound MLLP listener binds (0.0.0.0 so the off-box driver reaches it)",
    )
    parser.add_argument(
        "--claim-mode",
        default="pooled",
        choices=("pooled", "per_lane"),
        help="pipeline claim mode set on every serve --shard subprocess (MEFOR_PIPELINE_CLAIM_MODE) for "
        "the ADR 0066 §8.2 pooled-vs-per_lane A/B (default pooled)",
    )
    parser.add_argument(
        "--store",
        default="sqlserver",
        choices=("sqlserver",),
        help="server store backend LABEL (SQL Server only — this bench's reset/queue helpers are "
        "SqlServerStore-specific); the connection itself comes from MEFOR_STORE_*",
    )
    _add_coord_args(parser)
    args = parser.parse_args(argv)

    if args.lanes_per_shard < 1:
        print("--lanes-per-shard must be >= 1", file=sys.stderr)
        return 2

    # Wire the graph-shape env knobs BEFORE run_shardcert_engine's config discovery + the serve
    # subprocesses read them (mirrors the single-box `_run_shardcert`).
    os.environ["MEFOR_SHARDCERT_SHARDS"] = args.shards
    os.environ["MEFOR_SHARDCERT_LANES_PER_SHARD"] = str(args.lanes_per_shard)
    os.environ["MEFOR_SHARDCERT_PERSISTENT"] = "1" if args.persistent else "0"

    # N shards on ONE unified store ⇒ a server-DB backend is required (mirrors _run_shardcert).
    backend = os.environ.get("MEFOR_STORE_BACKEND", "").strip().lower()
    if backend != args.store:
        print(
            f"--store {args.store} needs MEFOR_STORE_BACKEND={args.store} (+ the MEFOR_STORE_* "
            f"connection env); got {backend or '(unset)'!r}",
            file=sys.stderr,
        )
        return 2

    from harness.load.coord import FileDropCoord
    from harness.load.shardcert import run_shardcert_engine

    coord = _coord_from_args(args)
    assert isinstance(coord, FileDropCoord)
    coord.clear()  # the engine is the first mover — clear any stale prior-run handshake files

    try:
        report = asyncio.run(
            run_shardcert_engine(
                dests=args.dests,
                hold_seconds=args.hold_seconds,
                kill=args.kill,
                kill_shard=args.kill_shard,
                kill_at_fraction=args.kill_at_fraction,
                drain_timeout=args.drain_timeout,
                sink_port=args.sink_port,
                sink_ports=args.sink_ports,
                store_env=_store_env_from_os(),
                coord=coord,
                inbound_bind_host=args.inbound_bind_host,
                sink_host=args.sink_host,
                claim_mode=args.claim_mode,
            )
        )
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render())
    # The engine half's gate is store-truth: drained, no stranded non-terminal rows, no dead-letters.
    # The no-loss/FIFO VERDICT is the driver half's report (it holds the sink/tracker).
    return 0 if report.ok else 1


def _run_shardcert_driver(argv: list[str]) -> int:
    import asyncio

    parser = argparse.ArgumentParser(
        prog="harness shardcert-driver",
        description="LOAD-GEN-box half of the WS-C two-box N-active cert (ADR 0073): wait for SHARDS_READY, "
        "bind the sink locally, open one MLLP connection per (shard, lane), drive the fleet + post "
        "DRIVE_START, drain the REMOTE /stats, emit the sink/tracker verdict. Does NOT spawn engines.",
    )
    parser.add_argument(
        "--engine-host",
        required=True,
        help="the engine box's inbound IP the senders dial (inbound_base + i*lanes + l, learned from "
        "SHARDS_READY)",
    )
    parser.add_argument(
        "--aggregate-rate", type=float, default=40.0, help="aggregate offered msg/s"
    )
    parser.add_argument("--hold-seconds", type=float, default=20.0, help="steady-state hold")
    parser.add_argument(
        "--drain-timeout", type=float, default=90.0, help="post-hold REMOTE drain timeout"
    )
    parser.add_argument(
        "--sink-host",
        default="127.0.0.1",
        help="interface the correlation sink binds LOCALLY (0.0.0.0 on the load-gen box; loopback "
        "co-located). Must be reachable at the engine's --sink-host delivery target",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="allow the REMOTE /stats poller to use plaintext http to the engine box (a trusted-network "
        "dev/bench setup; loopback never needs it). REQUIRED when the engine API is http, else the poller "
        "fail-closes on the non-loopback URL at drain",
    )
    _add_coord_args(parser)
    parser.add_argument("--report-json", help="write the JSON report to this path")
    args = parser.parse_args(argv)

    import json
    from pathlib import Path

    from messagefoundry.console.client import ApiError

    from harness.load.coord import CoordTimeout, FileDropCoord
    from harness.load.shardcert import run_shardcert_driver

    coord = _coord_from_args(args)
    assert isinstance(coord, FileDropCoord)
    try:
        report = asyncio.run(
            run_shardcert_driver(
                engine_host=args.engine_host,
                aggregate_rate=args.aggregate_rate,
                hold_seconds=args.hold_seconds,
                drain_timeout=args.drain_timeout,
                coord=coord,
                sink_host=args.sink_host,
                allow_insecure=args.insecure,
            )
        )
    except (
        ApiError
    ) as exc:  # plaintext http to a remote engine without --insecure — actionable, not a crash
        print(
            f"shardcert-driver: {exc}\n(hint: pass --insecure for a trusted-network http engine)",
            file=sys.stderr,
        )
        return 2
    except CoordTimeout as exc:
        print(f"shardcert-driver: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render())
    if args.report_json:
        Path(args.report_json).write_text(
            json.dumps(
                {
                    "kind": "shardcert_driver",
                    "verdict": "PASS" if report.ok else "FAIL",
                    "killed_shard": report.killed_shard,
                    "sent": report.sent,
                    "acked": report.acked,
                    "sink_received": report.sink_received,
                    "acked_not_delivered": report.acked_not_delivered,
                    "lane_inversions": report.lane_inversions,
                    "lanes_observed": report.lanes_observed,
                    "lane_repeats": report.lane_repeats,
                    "engine_done": report.engine_done,
                    "engine_dead": report.engine_dead,
                    "in_pipeline_final": report.in_pipeline_final,
                    "drained": report.drained,
                    "drain_seconds": report.drain_seconds,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    return 0 if report.ok else 1


def _run_shardcert_sink(argv: list[str]) -> int:
    import asyncio

    parser = argparse.ArgumentParser(
        prog="harness shardcert-sink",
        description="One SINK-tier process of the WS-C multi-process SIZING drive (PR-C, ADR 0073): bind a "
        "correlation sink over a CONTIGUOUS chunk of the destination-port band, post SINK_BOUND.<i>, absorb "
        "the engine's outbound fan-out until DRIVE_COMPLETE, then post SINK_DONE.<i> with its delivered/order "
        "tally. Binds no engine and drives no load — the coordinator (shardcert-drive) spawns it.",
    )
    parser.add_argument(
        "--sink-host",
        default="127.0.0.1",
        help="interface the correlation sink binds LOCALLY (0.0.0.0 on the load-gen box; loopback "
        "co-located). Must be reachable at the engine's --sink-host delivery target",
    )
    parser.add_argument(
        "--sink-base",
        type=int,
        required=True,
        help="base of the destination-port band (== the engine's advertised sink_base; == dests wide)",
    )
    parser.add_argument(
        "--sink-ports",
        type=int,
        required=True,
        help="width of the destination-port band (set == dests for sizing so each dest binds its own port)",
    )
    parser.add_argument(
        "--sink-index",
        type=int,
        required=True,
        help="which contiguous chunk (0-based) THIS sink binds",
    )
    parser.add_argument(
        "--sink-count",
        type=int,
        required=True,
        help="how many sinks the band is partitioned across (M)",
    )
    _add_coord_args(parser)
    parser.add_argument("--report-json", help="write the JSON report to this path")
    args = parser.parse_args(argv)

    from harness.load.coord import FileDropCoord
    from harness.load.shardcert import run_shardcert_sink

    coord = _coord_from_args(args)
    assert isinstance(coord, FileDropCoord)
    try:
        report = asyncio.run(
            run_shardcert_sink(
                sink_host=args.sink_host,
                sink_base=args.sink_base,
                sink_ports=args.sink_ports,
                sink_index=args.sink_index,
                sink_count=args.sink_count,
                coord=coord,
            )
        )
    except ValueError as exc:  # a bad partition / out-of-range index — fail loud, setup error
        print(f"shardcert-sink: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render())
    if args.report_json:
        import json
        from pathlib import Path

        Path(args.report_json).write_text(
            json.dumps(report.to_json_dict(), indent=2), encoding="utf-8"
        )
    return 0


def _run_shardcert_driver_worker(argv: list[str]) -> int:
    import asyncio

    parser = argparse.ArgumentParser(
        prog="harness shardcert-driver-worker",
        description="One SENDER-tier process of the WS-C multi-process SIZING drive (PR-C, ADR 0073): learn "
        "the topology from SHARDS_READY, own a CONTIGUOUS slice of the G=shards*lanes inbound bands, open one "
        "MLLP connection per owned band, post DRIVER_ARMED.<j>, wait for DRIVE_GO, drive its slice, post "
        "DRIVER_DONE.<j>. Binds no sink and spawns no engine — the coordinator (shardcert-drive) spawns it.",
    )
    parser.add_argument(
        "--engine-host",
        required=True,
        help="the engine box's inbound IP the senders dial (inbound_base + band, learned from SHARDS_READY)",
    )
    parser.add_argument(
        "--aggregate-rate",
        type=float,
        default=40.0,
        help="the WHOLE-FLEET aggregate offered msg/s; this worker drives len(slice)/G of it",
    )
    parser.add_argument("--hold-seconds", type=float, default=20.0, help="steady-state hold")
    parser.add_argument(
        "--driver-index",
        type=int,
        required=True,
        help="which contiguous band slice (0-based) THIS worker owns",
    )
    parser.add_argument(
        "--driver-count",
        type=int,
        required=True,
        help="how many sender-workers the bands are split across (K)",
    )
    _add_coord_args(parser)
    parser.add_argument("--report-json", help="write the JSON report to this path")
    args = parser.parse_args(argv)

    from harness.load.coord import CoordTimeout, FileDropCoord
    from harness.load.shardcert import run_shardcert_driver_worker

    coord = _coord_from_args(args)
    assert isinstance(coord, FileDropCoord)
    try:
        report = asyncio.run(
            run_shardcert_driver_worker(
                engine_host=args.engine_host,
                aggregate_rate=args.aggregate_rate,
                hold_seconds=args.hold_seconds,
                driver_index=args.driver_index,
                driver_count=args.driver_count,
                coord=coord,
            )
        )
    except ValueError as exc:  # a bad band slice / out-of-range index — fail loud, setup error
        print(f"shardcert-driver-worker: {exc}", file=sys.stderr)
        return 2
    except CoordTimeout as exc:
        print(f"shardcert-driver-worker: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render())
    if args.report_json:
        import json
        from pathlib import Path

        Path(args.report_json).write_text(
            json.dumps(report.to_json_dict(), indent=2), encoding="utf-8"
        )
    return 0


def _run_shardcert_drive(argv: list[str]) -> int:
    import asyncio

    parser = argparse.ArgumentParser(
        prog="harness shardcert-drive",
        description="The COORDINATOR of the WS-C multi-process SIZING drive (PR-C, ADR 0073): learn the "
        "topology from SHARDS_READY, spawn K sender-worker + M sink CHILD processes on the load-gen box, "
        "orchestrate the handshake, drain the engine's REMOTE /stats, then aggregate the children's coord "
        "DONE files into a count-balance + engine-store-truth no-loss reconcile. Runs (with its children) "
        "on the load-gen box — NEVER co-located with the engine fleet (the attribution isolation).",
    )
    parser.add_argument(
        "--engine-host",
        required=True,
        help="the engine box's inbound IP the sender-workers dial (learned bands from SHARDS_READY)",
    )
    parser.add_argument(
        "--aggregate-rate",
        type=float,
        default=40.0,
        help="the WHOLE-FLEET aggregate offered msg/s (split across the K sender-workers' band slices)",
    )
    parser.add_argument("--hold-seconds", type=float, default=20.0, help="steady-state hold")
    parser.add_argument(
        "--driver-count",
        type=int,
        default=1,
        help="how many sender-worker child processes to spawn (K)",
    )
    parser.add_argument(
        "--sink-count", type=int, default=1, help="how many sink child processes to spawn (M)"
    )
    parser.add_argument(
        "--sink-host",
        default="127.0.0.1",
        help="interface the sink children bind LOCALLY (0.0.0.0 on the load-gen box; loopback co-located). "
        "Must be reachable at the engine's --sink-host delivery target",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="allow the engine /stats poller to use plaintext http to the REMOTE engine box (a "
        "trusted-network dev/bench setup; loopback never needs it). REQUIRED for a two-box drive whose "
        "engine API is http, else the poller fail-closes on the non-loopback URL after spawning children",
    )
    _add_coord_args(parser)
    parser.add_argument("--report-json", help="write the JSON report to this path")
    args = parser.parse_args(argv)

    from messagefoundry.console.client import ApiError

    from harness.load.coord import CoordTimeout, FileDropCoord
    from harness.load.shardcert import run_shardcert_drive

    coord = _coord_from_args(args)
    assert isinstance(coord, FileDropCoord)
    try:
        report = asyncio.run(
            run_shardcert_drive(
                engine_host=args.engine_host,
                aggregate_rate=args.aggregate_rate,
                hold_seconds=args.hold_seconds,
                driver_count=args.driver_count,
                sink_count=args.sink_count,
                sink_host=args.sink_host,
                coord=coord,
                allow_insecure=args.insecure,
            )
        )
    except (
        ValueError
    ) as exc:  # a mis-sized fleet (partition/slice can't tile) — fail loud, setup error
        print(f"shardcert-drive: {exc}", file=sys.stderr)
        return 2
    except (
        ApiError
    ) as exc:  # plaintext http to a remote engine without --insecure — actionable, not a crash
        print(
            f"shardcert-drive: {exc}\n(hint: pass --insecure for a trusted-network http engine)",
            file=sys.stderr,
        )
        return 2
    except CoordTimeout as exc:
        print(f"shardcert-drive: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render())
    if args.report_json:
        import json
        from pathlib import Path

        Path(args.report_json).write_text(
            json.dumps(report.to_json_dict(), indent=2), encoding="utf-8"
        )
    return 0 if report.ok else 1


# --- PR-C2 turnkey two-box SIZING ceiling ladder (engine box + load-gen box) -------------------------


def _run_shardcert_engine_ladder(argv: list[str]) -> int:
    import asyncio
    import os
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="harness shardcert-engine-ladder",
        description="ENGINE-box half of the TURNKEY two-box SIZING ceiling ladder (PR-C2, ADR 0073): loop "
        "the fixed rung plan (fresh store + run_id per rung), post each rung's store-truth drain gate + "
        "phase timing, honour the drive's LADDER_STOP, and arm the soak rung. Reuses the merged "
        "shardcert-engine primitive per rung. Pair with shardcert-drive-ladder on the load-gen box. Set "
        "MEFOR_DELIVERY_PHASE_TIMING=1 for the send_ack/mark_done split.",
    )
    parser.add_argument(
        "--shards", default="a,b,c,d", help="comma list of shard ids (default a,b,c,d)"
    )
    parser.add_argument(
        "--dests", type=int, default=8, help="shared overlapping outbound destinations"
    )
    parser.add_argument(
        "--lanes-per-shard", type=int, default=1, help="inbound->router->handler chains per shard"
    )
    parser.add_argument(
        "--persistent", action="store_true", help="ADR 0067 persistent outbound (W1 fix)"
    )
    parser.add_argument(
        "--rate-ladder",
        required=True,
        help="ascending INGRESS msg/s ladder — a comma list (24,28,32) or start:stop:step (24:64:4). "
        "Outbound = ingress*dests; must match the drive box's --rate-ladder exactly",
    )
    parser.add_argument(
        "--hold-seconds", type=float, default=60.0, help="per-climb-rung steady-state hold"
    )
    parser.add_argument(
        "--drain-timeout", type=float, default=150.0, help="per-climb-rung post-hold drain"
    )
    parser.add_argument(
        "--soak-hold-seconds", type=float, default=300.0, help="soak hold (>=5 min)"
    )
    parser.add_argument(
        "--soak-drain-timeout", type=float, default=300.0, help="soak post-hold drain"
    )
    parser.add_argument(
        "--sink-port", type=int, required=True, help="BASE sink port the driver binds"
    )
    parser.add_argument(
        "--sink-ports", type=int, default=8, help="sink port band width (== --dests)"
    )
    parser.add_argument(
        "--sink-host", default="127.0.0.1", help="the LOAD-GEN box IP the shards deliver to"
    )
    parser.add_argument(
        "--inbound-bind-host", default="0.0.0.0", help="interface each shard's inbound binds"
    )
    parser.add_argument(
        "--claim-mode",
        default="pooled",
        choices=("pooled", "per_lane"),
        help="MEFOR_PIPELINE_CLAIM_MODE",
    )
    parser.add_argument(
        "--keep-logs-dir",
        default="./shardcert-ladder-nodelogs",
        help="base dir for the persisted per-rung/per-shard node logs (phase-timing source). A per-rung "
        "subdir is created under it. MEFOR_BENCH_KEEP_NODE_LOGS is set per rung",
    )
    parser.add_argument(
        "--store", default="sqlserver", choices=("sqlserver",), help="server store backend LABEL"
    )
    parser.add_argument(
        "--drive-start-timeout",
        type=float,
        default=300.0,
        help="per-rung wait for the drive's DRIVE_START — MUST exceed the drive's K+M child bring-up "
        "(spawns fresh interpreters each rung); a slow/cold load-gen box under this window is mis-read as "
        "'drive unresponsive'. Generous (minutes) by design; the early-stop stays cheap via a bounded poll",
    )
    parser.add_argument(
        "--soak-timeout",
        type=float,
        default=900.0,
        help="how long the engine waits for the drive's LADDER_SOAK after the climb",
    )
    _add_coord_args(parser)
    args = parser.parse_args(argv)

    if args.lanes_per_shard < 1:
        print("--lanes-per-shard must be >= 1", file=sys.stderr)
        return 2

    from harness.load.coord import FileDropCoord
    from harness.load.shardcert import parse_rate_ladder
    from harness.load.shardcert_ladder import run_engine_ladder

    try:
        rates = parse_rate_ladder(args.rate_ladder)
    except ValueError as exc:
        print(f"shardcert-engine-ladder: {exc}", file=sys.stderr)
        return 2

    # Wire the graph-shape env knobs BEFORE the per-rung config discovery reads them (mirrors
    # _run_shardcert_engine — the shape is ambient on os.environ, read at config load).
    os.environ["MEFOR_SHARDCERT_SHARDS"] = args.shards
    os.environ["MEFOR_SHARDCERT_LANES_PER_SHARD"] = str(args.lanes_per_shard)
    os.environ["MEFOR_SHARDCERT_PERSISTENT"] = "1" if args.persistent else "0"

    backend = os.environ.get("MEFOR_STORE_BACKEND", "").strip().lower()
    if backend != args.store:
        print(
            f"--store {args.store} needs MEFOR_STORE_BACKEND={args.store} (+ the MEFOR_STORE_* env); "
            f"got {backend or '(unset)'!r}",
            file=sys.stderr,
        )
        return 2

    coord = _coord_from_args(args)
    assert isinstance(coord, FileDropCoord)
    try:
        result = asyncio.run(
            run_engine_ladder(
                rates=rates,
                dests=args.dests,
                hold_seconds=args.hold_seconds,
                drain_timeout=args.drain_timeout,
                sink_port=args.sink_port,
                sink_ports=args.sink_ports,
                sink_host=args.sink_host,
                inbound_bind_host=args.inbound_bind_host,
                claim_mode=args.claim_mode,
                store_env=_store_env_from_os(),
                base_coord=coord,
                keep_logs_base=Path(args.keep_logs_dir),
                soak_hold_seconds=args.soak_hold_seconds,
                soak_drain_timeout=args.soak_drain_timeout,
                climb_drive_start_timeout=args.drive_start_timeout,
                soak_timeout=args.soak_timeout,
            )
        )
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(result.render())
    return 0


def _run_shardcert_drive_ladder(argv: list[str]) -> int:
    import asyncio
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="harness shardcert-drive-ladder",
        description="LOAD-GEN-box half + CONSOLIDATED REPORT of the turnkey two-box SIZING ceiling ladder "
        "(PR-C2, ADR 0073): loop the same rungs the engine arms, drive each with the multi-process drive "
        "under the drain gate, classify (sustained / collapsed / frozen-tail) by the RELIABLE authorities "
        "only, early-stop at the first collapse (LADDER_STOP), soak the pinned rate, and emit one report "
        "(JSON + human-readable). Runs with its K+M children on the load-gen box — NEVER co-located.",
    )
    parser.add_argument(
        "--engine-host", required=True, help="the engine box's inbound IP the senders dial"
    )
    parser.add_argument(
        "--rate-ladder",
        required=True,
        help="ascending INGRESS msg/s ladder — must match the engine box's --rate-ladder exactly",
    )
    parser.add_argument(
        "--hold-seconds", type=float, default=60.0, help="per-climb-rung steady-state hold"
    )
    parser.add_argument(
        "--drain-timeout", type=float, default=150.0, help="per-climb-rung post-hold drain"
    )
    parser.add_argument(
        "--soak-hold-seconds", type=float, default=300.0, help="soak hold (>=5 min)"
    )
    parser.add_argument(
        "--soak-drain-timeout", type=float, default=300.0, help="soak post-hold drain"
    )
    parser.add_argument(
        "--soak-rate",
        type=float,
        default=None,
        help="pin the soak ingress rate (default: highest sustained rung)",
    )
    parser.add_argument("--no-soak", action="store_true", help="skip the soak (climb only)")
    parser.add_argument(
        "--driver-count",
        type=int,
        default=4,
        help="K sender-worker child processes (K | shards*lanes)",
    )
    parser.add_argument(
        "--sink-count", type=int, default=8, help="M sink child processes (M | dests)"
    )
    parser.add_argument(
        "--sink-host",
        default="127.0.0.1",
        help="interface the sink children bind LOCALLY (0.0.0.0 on the load-gen box)",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="allow the REMOTE /stats poller plaintext http to the engine box (REQUIRED for a two-box http engine)",
    )
    parser.add_argument(
        "--engine-report-timeout",
        type=float,
        default=120.0,
        help="per-rung wait for the engine's ENGINE_RUNG_REPORT (phase timing + soak slope). The rung "
        "VERDICT does not depend on it (that uses the reliable ENGINE_DRAINED gate) — a lost report only "
        "drops the phase timing",
    )
    _add_coord_args(parser)
    parser.add_argument("--report-json", help="write the consolidated JSON report to this path")
    args = parser.parse_args(argv)

    from messagefoundry.console.client import ApiError

    from harness.load.coord import CoordTimeout, FileDropCoord
    from harness.load.shardcert import parse_rate_ladder
    from harness.load.shardcert_ladder import run_drive_ladder

    try:
        rates = parse_rate_ladder(args.rate_ladder)
    except ValueError as exc:
        print(f"shardcert-drive-ladder: {exc}", file=sys.stderr)
        return 2

    coord = _coord_from_args(args)
    assert isinstance(coord, FileDropCoord)
    try:
        report = asyncio.run(
            run_drive_ladder(
                engine_host=args.engine_host,
                rates=rates,
                hold_seconds=args.hold_seconds,
                drain_timeout=args.drain_timeout,
                driver_count=args.driver_count,
                sink_count=args.sink_count,
                sink_host=args.sink_host,
                base_coord=coord,
                allow_insecure=args.insecure,
                soak_hold_seconds=args.soak_hold_seconds,
                soak_drain_timeout=args.soak_drain_timeout,
                soak_rate_override=args.soak_rate,
                do_soak=not args.no_soak,
                engine_rung_report_timeout=args.engine_report_timeout,
            )
        )
    except ValueError as exc:  # a mis-sized fleet / bad ladder — fail loud, setup error
        print(f"shardcert-drive-ladder: {exc}", file=sys.stderr)
        return 2
    except ApiError as exc:  # plaintext http to a remote engine without --insecure
        print(
            f"shardcert-drive-ladder: {exc}\n(hint: pass --insecure for a trusted-network http engine)",
            file=sys.stderr,
        )
        return 2
    except CoordTimeout as exc:
        print(f"shardcert-drive-ladder: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3

    print(report.render())
    if args.report_json:
        Path(args.report_json).write_text(
            json.dumps(report.to_json_dict(), indent=2), encoding="utf-8"
        )
    return report.exit_code


def _launch_gui() -> int:
    from PySide6.QtWidgets import QApplication

    from harness.window import HarnessWindow

    app = QApplication(sys.argv)
    window = HarnessWindow()
    window.resize(1100, 750)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())

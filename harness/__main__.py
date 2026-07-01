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

    # `multishard` is a positional subcommand with its own option set (the flag-based `--connscale`/
    # `--load` style doesn't fit an N-engine sweep), so route it before the shared flag parser.
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "multishard":
        return _run_multishard(raw[1:])

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

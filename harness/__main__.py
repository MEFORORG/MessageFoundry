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

    parser = argparse.ArgumentParser(prog="harness", description="MessageFoundry test harness")
    parser.add_argument(
        "--scenario", help="run this scenario headless and exit (see --list-scenarios)"
    )
    parser.add_argument("--list-scenarios", action="store_true", help="list built-in scenarios")
    parser.add_argument(
        "--load", help="run this load profile (built-in name or path to a .toml) and exit"
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
    if args.load and args.scenario:
        print("--load and --scenario are mutually exclusive", file=sys.stderr)
        return 2
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

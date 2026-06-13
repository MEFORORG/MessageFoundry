"""Test harness entrypoint.

``python -m harness``                 → launch the GUI (Send/Receive/File/Compose/Monitor).
``python -m harness --list-scenarios``→ list the built-in scenarios.
``python -m harness --scenario NAME`` → run one scenario headless against a running engine
                                                and exit 0 (pass) / 1 (fail) — for CI.

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
    parser.add_argument("--engine", default="http://127.0.0.1:8765", help="engine API base URL")
    parser.add_argument("--token", help="bearer token for an auth-enabled engine")
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="seconds to wait for the outcome"
    )
    args = parser.parse_args(argv)

    if args.list_scenarios:
        return _list_scenarios()
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

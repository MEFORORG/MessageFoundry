# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CLI for the parallel-run reconciliation harness (TEST-ENVIRONMENT-PLAN.md §5).

Two subcommands:

* ``capture`` — run a :class:`~harness.reconcile.capture.CaptureSink`: bind MLLP port(s), ACK every
  message, append each to a JSONL capture. Point a MEFOR Test outbound's ``env()`` host/port at it during
  the shadow phase to capture that connection's output. Runs until Ctrl-C.

      python -m harness.reconcile capture --port 2800 --out captures/IB_ACME_ADT.jsonl

* ``compare`` — offline: pair MEFOR's capture against Corepoint's export for one connection (by a
  configurable match key) and diff each pair, normalizing engine-non-deterministic fields. Exits non-zero
  if anything differs, so it can gate a per-connection sign-off.

      python -m harness.reconcile compare --connection IB_ACME_ADT \
        --mefor captures/IB_ACME_ADT.jsonl --corepoint exports/IB_ACME_ADT.hl7 \
        --blank PID-33 --sort-segment NK1 --report-json out/IB_ACME_ADT.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from messagefoundry.config.models import AckMode

from harness.reconcile.compare import DEFAULT_KEY, ReconcileResult, load_messages, reconcile
from harness.reconcile.normalize import NormalizeRules
from harness.reconcile.report import render_json, render_text


def _parse_field(spec: str) -> tuple[str, int]:
    """Parse a ``SEG-FIELD`` token (e.g. ``MSH-10``, ``PID-3``) into ``(segment_id, field_no)``."""
    seg, _, num = spec.partition("-")
    if not seg or not num.isdigit():
        raise argparse.ArgumentTypeError(f"expected SEG-FIELD (e.g. MSH-10), got {spec!r}")
    return (seg.upper(), int(num))


def _rules_from_args(args: argparse.Namespace) -> NormalizeRules:
    return NormalizeRules(
        blank_fields=NormalizeRules().blank_fields | frozenset(args.blank or ()),
        sort_repetition_fields=frozenset(args.sort_repetition or ()),
        sort_segments=frozenset(s.upper() for s in (args.sort_segment or ())),
        ignore_segments=frozenset(s.upper() for s in (args.ignore_segment or ())),
    )


async def _run_capture(args: argparse.Namespace) -> int:
    from harness.reconcile.capture import CaptureSink

    sink = CaptureSink(
        args.out,
        host=args.host,
        ports=tuple(args.port),
        ack_mode=AckMode(args.ack_mode),
    )
    await sink.start()
    print(
        f"capture sink listening on {args.host}:{','.join(map(str, sink.bound_ports))} "
        f"→ {args.out} (Ctrl-C to stop)",
        file=sys.stderr,
    )
    try:
        await asyncio.Event().wait()  # run until cancelled (Ctrl-C)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await sink.stop()
        print(
            f"captured {sink.captured} message(s) ({sink.unparseable} unparseable)", file=sys.stderr
        )
    return 0


def _run_compare(args: argparse.Namespace) -> int:
    result: ReconcileResult = reconcile(
        load_messages(args.mefor),
        load_messages(args.corepoint),
        connection=args.connection,
        key=args.key,
        rules=_rules_from_args(args),
    )
    print(render_text(result))
    if args.report_json:
        Path(args.report_json).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report_json).write_text(
            json.dumps(render_json(result), indent=2), encoding="utf-8"
        )
    return 0 if result.clean else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="harness.reconcile", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    cap = sub.add_parser("capture", help="run an MLLP capture sink for the shadow phase")
    cap.add_argument(
        "--port", type=int, action="append", required=True, help="MLLP port (repeatable)"
    )
    cap.add_argument("--out", required=True, help="JSONL capture file to append to")
    cap.add_argument("--host", default="127.0.0.1")
    cap.add_argument(
        "--ack-mode",
        default="original",
        choices=[m.value for m in AckMode],
        help="ACK mode to send",
    )

    cmp = sub.add_parser(
        "compare", help="offline per-connection reconcile of MEFOR vs Corepoint output"
    )
    cmp.add_argument("--mefor", required=True, help="MEFOR capture (JSONL) / dir / batch file")
    cmp.add_argument("--corepoint", required=True, help="Corepoint export dir / batch file / JSONL")
    cmp.add_argument("--connection", default="<connection>", help="connection label for the report")
    cmp.add_argument(
        "--key", type=_parse_field, default=DEFAULT_KEY, help="match key SEG-FIELD (default MSH-10)"
    )
    cmp.add_argument(
        "--blank",
        type=_parse_field,
        action="append",
        help="extra SEG-FIELD blanked before diff (repeatable)",
    )
    cmp.add_argument(
        "--sort-repetition",
        type=_parse_field,
        action="append",
        help="SEG-FIELD whose ~reps are unordered",
    )
    cmp.add_argument(
        "--sort-segment", action="append", help="segment id whose occurrences are unordered"
    )
    cmp.add_argument("--ignore-segment", action="append", help="segment id dropped from both sides")
    cmp.add_argument("--report-json", help="write the structured report here")

    args = parser.parse_args(argv)
    if args.cmd == "capture":
        return asyncio.run(_run_capture(args))
    return _run_compare(args)


if __name__ == "__main__":
    raise SystemExit(main())

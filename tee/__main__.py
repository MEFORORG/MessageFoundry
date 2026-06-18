# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``python -m tee`` — run the MLLP tee relay, or read back logged NAKs.

Examples::

    # Repoint Epic at :6661; fan out to Corepoint and a shadow MEFOR; log to ./tee.db
    python -m tee run --listen-epic :6661 --corepoint corehost:5000 --mefor meforhost:2575 --db ./tee.db

    # Also receive the Corepoint -> Epic copy feed (add a matching outbound send in Corepoint)
    python -m tee run --listen-epic :6661 --corepoint corehost:5000 --mefor meforhost:2575 \
        --listen-corepoint-copy :6662 --db ./tee.db

    # Parity/compare run: capture Corepoint's OUTPUT only (minimal PHI; test data only)
    python -m tee run --listen-epic :6661 --corepoint corehost:5000 --mefor meforhost:2575 \
        --listen-corepoint-copy :6662 --capture-corepoint-copy --db ./tee.db

    # Show the most recent NAKs / transport errors
    python -m tee naks --db ./tee.db

    # Export the log as JSON for review / AI analysis (metadata only — never message bodies)
    python -m tee export --db ./tee.db --naks-only --out ./tee-review.json

    # Purge the log DB (everything, or older than an age; --captures-only drops just the bodies)
    python -m tee purge --db ./tee.db --before 7d -y

    # Parity-compare MEFOR's transformed output vs Corepoint's (counts are PHI-safe; --show-diffs is PHI)
    python -m tee compare --db ./tee.db --mefor-api http://127.0.0.1:8000 --token TOKEN --since 24h
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from tee import __version__, mefor_api
from tee.correlate import CorepointOutput, CorrelateConfig
from tee.relay import Endpoint, RelayConfig, TeeRelay
from tee.report import build_report
from tee.store import RelayStore

# Shown prominently at every start. ASCII-only so it renders on legacy Windows consoles (cp1252).
_STARTUP_WARNING = """\
================================================================================
  WARNING: TEE RELAY -- FOR TEST DATA ONLY
  This is a parallel-run VALIDATION tool. Do NOT route production PHI through it.
  Point it only at TEST / synthetic feeds and endpoints.
================================================================================"""


def _confirm_test_only(assume_yes: bool) -> bool:
    """Show the test-data-only warning at start and (when interactive) require acknowledgement.

    Returns True to proceed. ``--yes`` skips the prompt; a non-interactive start (service / piped
    stdin) can't prompt, so the printed banner stands as the warning and the start proceeds.
    """
    print(_STARTUP_WARNING, file=sys.stderr, flush=True)
    if assume_yes:
        print("(--yes given; proceeding)\n", file=sys.stderr, flush=True)
        return True
    if sys.stdin is None or not sys.stdin.isatty():
        print("(non-interactive start; banner shown, proceeding)\n", file=sys.stderr, flush=True)
        return True
    try:
        reply = input("Type 'yes' to confirm this feed carries TEST data only: ").strip().lower()
    except EOFError:
        return False
    return reply in ("y", "yes")


def _configure_logging(level: str) -> None:
    """stdlib logging to stderr. The relay never logs message bodies (PHI stays out of the log)."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)sZ %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,
    )
    logging.Formatter.converter = __import__("time").gmtime  # UTC timestamps


def _parse_endpoint(value: str) -> Endpoint:
    """Parse ``host:port`` (host optional → all interfaces). Raises for the CLI on a bad value."""
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            f"expected host:port (host optional, e.g. ':6661' or 'corehost:5000'), got {value!r}"
        )
    host, _, port = value.rpartition(":")
    try:
        port_num = int(port)
    except ValueError:
        raise argparse.ArgumentTypeError(f"port must be an integer in {value!r}") from None
    if not 1 <= port_num <= 65535:
        raise argparse.ArgumentTypeError(f"port {port_num} out of range (1-65535) in {value!r}")
    return (host, port_num)


def _parse_age(spec: str) -> float:
    """A time cutoff (epoch seconds) for purge/export: a relative age ``Nd``/``Nh``/``Nm`` (days/hours/
    minutes ago) or an absolute UTC date ``YYYY-MM-DD``."""
    match = re.fullmatch(r"(\d+)([dhm])", spec)
    if match:
        seconds = int(match.group(1)) * {"d": 86400, "h": 3600, "m": 60}[match.group(2)]
        return time.time() - seconds
    try:
        day = datetime.strptime(spec, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"expected an age like '7d'/'12h'/'30m' or a UTC date 'YYYY-MM-DD', got {spec!r}"
        ) from None
    return day.timestamp()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tee", description="Standalone MLLP tee relay (backlog #14)"
    )
    parser.add_argument("--version", action="version", version=f"tee {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run the relay")
    run.add_argument(
        "--listen-epic",
        required=True,
        type=_parse_endpoint,
        metavar="HOST:PORT",
        help="bind address for the Epic -> Corepoint feed (the tee inbound)",
    )
    run.add_argument(
        "--corepoint",
        required=True,
        type=_parse_endpoint,
        metavar="HOST:PORT",
        help="Corepoint MLLP endpoint (the live production leg)",
    )
    run.add_argument(
        "--mefor",
        required=True,
        type=_parse_endpoint,
        metavar="HOST:PORT",
        help="shadow MessageFoundry MLLP endpoint",
    )
    run.add_argument(
        "--listen-corepoint-copy",
        type=_parse_endpoint,
        metavar="HOST:PORT",
        default=None,
        help="optional bind address for the Corepoint -> Epic copy feed (forwarded to MEFOR)",
    )
    run.add_argument("--db", required=True, metavar="PATH", help="SQLite log database path")
    run.add_argument("--max-frame-bytes", type=int, default=16 * 1024 * 1024)
    run.add_argument("--receive-timeout", type=float, default=60.0)
    run.add_argument("--connect-timeout", type=float, default=10.0)
    run.add_argument("--send-timeout", type=float, default=30.0)
    run.add_argument(
        "--corepoint-attempts",
        type=int,
        default=3,
        help="quick retries on the Corepoint leg before tripping fail-closed",
    )
    run.add_argument("--corepoint-retry-delay", type=float, default=1.0)
    run.add_argument("--mefor-queue-max", type=int, default=1000)
    run.add_argument(
        "--capture-bodies",
        action="store_true",
        help="persist full message bodies for ALL feeds to the DB (test data only — off by default)",
    )
    run.add_argument(
        "--capture-corepoint-copy",
        action="store_true",
        help="persist ONLY the Corepoint-copy feed bodies (Corepoint's output) — the minimal-PHI"
        " posture for a parity/compare run (#14, test data only). Implied by --capture-bodies.",
    )
    run.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="skip the test-data-only confirmation prompt (for unattended/service starts)",
    )
    run.add_argument("--log-level", default="INFO")

    naks = sub.add_parser("naks", help="show recently logged NAKs / transport errors")
    naks.add_argument("--db", required=True, metavar="PATH", help="SQLite log database path")
    naks.add_argument("--limit", type=int, default=50)

    export = sub.add_parser(
        "export", help="export the relay log as JSON (for review / AI analysis)"
    )
    export.add_argument("--db", required=True, metavar="PATH", help="SQLite log database path")
    export.add_argument(
        "--since",
        type=_parse_age,
        default=None,
        metavar="AGE|DATE",
        help="only rows at/after this (e.g. '24h', '2026-06-01')",
    )
    export.add_argument(
        "--before", type=_parse_age, default=None, metavar="AGE|DATE", help="only rows before this"
    )
    export.add_argument("--naks-only", action="store_true", help="only NAK / transport-error rows")
    export.add_argument(
        "--limit", type=int, default=None, metavar="N", help="cap to the most recent N rows"
    )
    export.add_argument(
        "--out", metavar="FILE", default=None, help="write to FILE instead of stdout"
    )

    purge = sub.add_parser("purge", help="delete logged rows (and captured bodies) from the DB")
    purge.add_argument("--db", required=True, metavar="PATH", help="SQLite log database path")
    purge.add_argument(
        "--before",
        type=_parse_age,
        default=None,
        metavar="AGE|DATE",
        help="only purge rows older than this (e.g. '7d', '2026-06-01'); omit to purge EVERYTHING",
    )
    purge.add_argument(
        "--captures-only",
        action="store_true",
        help="drop only the captured message bodies, keep the NAK/leg log",
    )
    purge.add_argument("-y", "--yes", action="store_true", help="skip the confirmation prompt")

    compare = sub.add_parser(
        "compare",
        help="parity-compare MEFOR's transformed output against Corepoint's (#14)",
    )
    compare.add_argument(
        "--db", required=True, metavar="PATH", help="tee SQLite DB (captured bodies)"
    )
    compare.add_argument(
        "--mefor-api",
        required=True,
        metavar="URL",
        help="MEFOR engine API base URL (e.g. http://127.0.0.1:8000)",
    )
    compare.add_argument(
        "--token", required=True, metavar="TOKEN", help="bearer token (needs messages:view_raw)"
    )
    compare.add_argument(
        "--since",
        type=_parse_age,
        default=None,
        metavar="AGE|DATE",
        help="only outputs at/after this (e.g. '24h', '2026-06-01')",
    )
    compare.add_argument(
        "--limit", type=int, default=500, metavar="N", help="max MEFOR messages to scan"
    )
    compare.add_argument("--timeout", type=float, default=30.0, metavar="SEC", help="HTTP timeout")
    compare.add_argument(
        "--out",
        metavar="FILE",
        default=None,
        help="write the JSON report to FILE instead of stdout",
    )
    compare.add_argument(
        "--show-diffs",
        action="store_true",
        help="include per-message field diffs (PHI — TEST DATA ONLY; never commit or send to CI)",
    )
    compare.add_argument(
        "--cacert", metavar="FILE", default=None, help="CA bundle to verify an https engine"
    )
    compare.add_argument(
        "--insecure", action="store_true", help="skip TLS verification (discouraged)"
    )
    compare.add_argument(
        "--dest-alias",
        action="append",
        metavar="COREAPP/COREFAC=MEFAPP/MEFFAC",
        help="canonicalise a Corepoint destination (MSH-5/6) to its MEFOR equivalent; repeatable",
    )

    return parser


async def _run(args: argparse.Namespace) -> int:
    config = RelayConfig(
        listen_epic=args.listen_epic,
        corepoint=args.corepoint,
        mefor=args.mefor,
        db_path=args.db,
        listen_corepoint_copy=args.listen_corepoint_copy,
        max_frame_bytes=args.max_frame_bytes,
        receive_timeout=args.receive_timeout,
        connect_timeout=args.connect_timeout,
        send_timeout=args.send_timeout,
        corepoint_attempts=args.corepoint_attempts,
        corepoint_retry_delay=args.corepoint_retry_delay,
        mefor_queue_max=args.mefor_queue_max,
        capture_bodies=args.capture_bodies,
        capture_corepoint_copy=args.capture_corepoint_copy,
    )
    relay = TeeRelay(config)
    try:
        await relay.serve_forever()
    except asyncio.CancelledError:
        pass
    return 0


async def _naks(args: argparse.Namespace) -> int:
    store = await RelayStore.open(args.db)
    try:
        rows = await store.recent_naks(args.limit)
    finally:
        await store.close()
    if not rows:
        print("no NAKs or transport errors logged")
        return 0
    for row in rows:
        when = datetime.fromtimestamp(row.at, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        code = row.ack_code or row.outcome
        print(
            f"{when}  {row.direction:<17}  {row.leg:<9}  {code:<6}  "
            f"control_id={row.control_id or '-'}  type={row.message_type or '-'}  {row.detail or ''}"
        )
    return 0


async def _export(args: argparse.Namespace) -> int:
    store = await RelayStore.open(args.db)
    try:
        data = await store.export(
            since=args.since, before=args.before, naks_only=args.naks_only, limit=args.limit
        )
    finally:
        await store.close()
    text = json.dumps(data, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"wrote {len(data['rows'])} row(s) to {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


async def _purge(args: argparse.Namespace) -> int:
    scope = "captured bodies only" if args.captures_only else "all logged rows + captured bodies"
    window = "older than the cutoff" if args.before is not None else "EVERYTHING"
    target = f"{scope} ({window}) in {args.db}"
    if not args.yes:
        if sys.stdin is None or not sys.stdin.isatty():
            print(
                f"refusing to purge {target} without confirmation — re-run with -y", file=sys.stderr
            )
            return 1
        try:
            reply = input(f"Purge {target}? Type 'yes' to confirm: ").strip().lower()
        except EOFError:
            reply = ""
        if reply not in ("y", "yes"):
            print("aborted")
            return 0
    store = await RelayStore.open(args.db)
    try:
        log_n, cap_n = await store.purge(before=args.before, captures_only=args.captures_only)
    finally:
        await store.close()
    print(f"purged {log_n} log row(s) and {cap_n} capture row(s)")
    return 0


def _dest_key(spec: str) -> tuple[str, str]:
    parts = spec.split("/")
    return (parts[0], parts[1] if len(parts) > 1 else "")


def _parse_aliases(items: list[str] | None) -> dict[tuple[str, str], tuple[str, str]]:
    aliases: dict[tuple[str, str], tuple[str, str]] = {}
    for item in items or []:
        src, sep, dst = item.partition("=")
        if not sep:
            raise SystemExit(
                f"--dest-alias expects FROM=TO (e.g. COREAPP/COREFAC=MEFAPP/MEFFAC), got {item!r}"
            )
        aliases[_dest_key(src)] = _dest_key(dst)
    return aliases


def _ssl_context_for(args: argparse.Namespace) -> ssl.SSLContext | None:
    """A TLS context for an https engine: default verification, ``--cacert`` to pin a CA, or
    ``--insecure`` to skip verification (discouraged). ``None`` for a plain-http (localhost) engine."""
    if args.insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if args.cacert:
        return ssl.create_default_context(cafile=args.cacert)
    return None


async def _load_captures(db: str, since: float | None) -> list[CorepointOutput]:
    """Corepoint outputs (the ``corepoint_copy`` captures) decoded for comparison."""
    store = await RelayStore.open(db)
    try:
        rows = await store.captures(direction="corepoint_copy", since=since)
    finally:
        await store.close()
    return [
        CorepointOutput(control_id=row.control_id, raw=row.raw.decode("utf-8", errors="replace"))
        for row in rows
    ]


def _compare(args: argparse.Namespace) -> int:
    if args.show_diffs:
        print(
            "WARNING: --show-diffs includes message field values (PHI) — TEST DATA ONLY; "
            "do not commit the report or send it to CI.",
            file=sys.stderr,
        )
    corepoint = asyncio.run(_load_captures(args.db, args.since))
    try:
        get = mefor_api.make_getter(
            args.mefor_api, args.token, timeout=args.timeout, ssl_context=_ssl_context_for(args)
        )
        mefor = mefor_api.fetch_mefor_outputs(get, since=args.since, limit=args.limit)
    except mefor_api.MeforApiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    config = CorrelateConfig(destination_aliases=_parse_aliases(args.dest_alias))
    report = build_report(mefor, corepoint, correlate_config=config, include_diffs=args.show_diffs)
    text = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        s = report["summary"]
        print(
            f"wrote parity report to {args.out}: {s['matched']} matched "
            f"({s['exact']} exact, {s['semantic']} semantic, {s['mismatch']} mismatch), "
            f"{s['missing_on_corepoint']}+{s['missing_on_mefor']} missing",
            file=sys.stderr,
        )
    else:
        print(text)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "run":
        _configure_logging(args.log_level)
        if not _confirm_test_only(args.yes):
            print("aborted: test-data-only confirmation declined", file=sys.stderr)
            return 1
        try:
            return asyncio.run(_run(args))
        except KeyboardInterrupt:
            return 0
    if args.command == "naks":
        return asyncio.run(_naks(args))
    if args.command == "export":
        return asyncio.run(_export(args))
    if args.command == "purge":
        return asyncio.run(_purge(args))
    if args.command == "compare":
        return _compare(args)
    return 2  # unreachable: subparsers are required


if __name__ == "__main__":
    raise SystemExit(main())

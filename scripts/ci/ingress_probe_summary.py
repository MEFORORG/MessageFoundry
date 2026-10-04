#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Turn the ingress probe's ``RESULT`` lines into job-summary rows, as DATA and never as shell.

``ingress-rate-probe.yml`` used to merge the probe's stderr into its stdout, grep every line that
began ``RESULT``, rewrite it into ``P_key=value`` assignments and ``eval`` them. So anything that
reached either stream -- an exception's text, a log line, a value the probe printed -- became shell
code in a job that runs with the repository checked out. Its failure handling was also accidental:
``|| true`` sat on the ``eval`` and a missing key rendered as ``?``, while a probe that exited
non-zero ended the whole step under the ``-e`` that a named ``shell: bash`` adds, losing every later
rate.

This reads only the probe's stdout, piped into it, and copies every line through to its own stdout
so the job log still shows the probe live. It is a pipe rather than a file because the step runs
under Git Bash on the Windows legs, and a native Python reading a POSIX temp path there depends on
MSYS argument conversion. It accepts exactly the two line shapes ``harness/load/ingress_probe.py``
prints:

* a measurement: ``RESULT rate=.. sent=.. acked=.. stranded=.. pct=.. read=.. written=.. sink=..
  backlog=.. ok=.. wall=..``, every key present once and no other;
* a setup failure: ``RESULT rate=.. ERROR=<reason>``, after which the probe stops repeating.

Every value is checked against a pattern for its key before it is written anywhere. A line whose
first word is ``RESULT`` and which matches neither shape, a ``rate`` other than the one offered, or
a row count other than ``--repeat`` (unless an ``ERROR`` row ended the run early) is an error: the
script prints a ``::error`` annotation and exits 1. That is a broken measurement pipeline or a
crashed probe, not a slow runner, so failing it does not contradict the workflow's rule that a
NUMBER moving with runner weather never reds a run.

Exit status: 0 when at least one measurement row was written, 3 when the only row is a setup
failure (the workflow reds the run only if no rate measured anything), 1 on any error above.
"""

from __future__ import annotations

import argparse
import io
import os
import re
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

_INT = re.compile(r"[0-9]+")
_SIGNED_INT = re.compile(r"-?[0-9]+")
_DECIMAL = re.compile(r"[0-9]+(\.[0-9]+)?")
# The probe prints the rate with `:g`, which uses an exponent from 1e6 upward and below 1e-4.
_RATE = re.compile(r"[0-9]+(\.[0-9]+)?(e[+-][0-9]+)?")
_BOOL = re.compile(r"True|False")
_REASON = re.compile(r"[a-z_]{1,64}")

_MEASUREMENT: dict[str, re.Pattern[str]] = {
    "rate": _RATE,
    "sent": _INT,
    "acked": _INT,
    "stranded": _INT,
    "pct": _DECIMAL,
    # `read` and `written` are engine counters taken as a difference against a baseline, so a sign is
    # not malformed. `backlog` is a gauge whose -1 means the engine's metrics were unavailable.
    # `sink` is counted by the client and cannot go below zero.
    "read": _SIGNED_INT,
    "written": _SIGNED_INT,
    "sink": _INT,
    "backlog": _SIGNED_INT,
    "ok": _BOOL,
    "wall": _DECIMAL,
}
_SETUP_FAILURE: dict[str, re.Pattern[str]] = {"rate": _RATE, "ERROR": _REASON}


#: Exit status when the run's only row is a setup failure: not an error, and not a measurement.
SETUP_FAILED_ONLY = 3


class MalformedResult(ValueError):
    """A ``RESULT`` line that is not one of the two shapes the probe prints."""


def parse_line(line: str) -> dict[str, str]:
    """Return the validated key/value pairs of one ``RESULT`` line, or raise MalformedResult."""
    words = line.split()
    if not words or words[0] != "RESULT":
        raise MalformedResult("not a RESULT line")
    pairs: dict[str, str] = {}
    for word in words[1:]:
        key, sep, value = word.partition("=")
        if not sep:
            raise MalformedResult(f"token without '=': {word[:40]!r}")
        if key in pairs:
            raise MalformedResult(f"duplicate key {key[:40]!r}")
        pairs[key] = value
    schema = _SETUP_FAILURE if "ERROR" in pairs else _MEASUREMENT
    if set(pairs) != set(schema):
        raise MalformedResult(
            f"keys {sorted(k[:40] for k in pairs)} are not the expected {sorted(schema)}"
        )
    for key, pattern in schema.items():
        if not pattern.fullmatch(pairs[key]):
            raise MalformedResult(f"{key}= value does not match {pattern.pattern}")
    return pairs


def render_row(pairs: dict[str, str]) -> str:
    """One markdown table row. Safe to write as-is: every cell passed its key's pattern."""
    if "ERROR" in pairs:
        return f"| {pairs['rate']}/s | setup failed: {pairs['ERROR']} | | | | | |"
    p = pairs
    return (
        f"| {p['rate']}/s | {p['sent']} | {p['acked']} | {p['stranded']} | {p['pct']}% "
        f"| {p['read']} | {p['ok']} |"
    )


@dataclass
class Summary:
    """One probe invocation's rows, how many of them are measurements, and what was wrong."""

    rows: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    measured: int = 0


def summarise(text: str, *, rate: float, repeat: int) -> Summary:
    """Parse one probe invocation's stdout."""
    out = Summary()
    ended_early = False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.split(maxsplit=1)[:1] != ["RESULT"]:
            continue
        if ended_early:
            out.errors.append(f"line {number}: a RESULT after the setup failure that ended the run")
            continue
        try:
            pairs = parse_line(line)
        except MalformedResult as exc:
            out.errors.append(f"line {number}: malformed RESULT: {exc}")
            continue
        # Compared as the probe formats it (`:g`), so a large rate it rounds still matches.
        if pairs["rate"] != f"{rate:g}":
            out.errors.append(
                f"line {number}: rate={pairs['rate']} but the probe was offered {rate:g}"
            )
            continue
        out.rows.append(render_row(pairs))
        ended_early = "ERROR" in pairs
        out.measured += not ended_early
    # Each repeat prints exactly one row; a setup failure's row is that repeat's, and ends the run.
    if not out.rows and not out.errors:
        out.errors.append("the probe printed no RESULT line")
    elif not out.errors and (
        len(out.rows) > repeat or (not ended_early and len(out.rows) != repeat)
    ):
        out.errors.append(f"expected {repeat} RESULT rows, found {len(out.rows)}")
    return out


def _escape(data: str) -> str:
    """Escape a workflow-command message, so it stays one annotation (as refused_subjects_check)."""
    return data.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Read the ingress probe's stdout on stdin and append its RESULT rows."
    )
    parser.add_argument("--rate", type=float, required=True, help="the rate the probe was offered")
    parser.add_argument("--repeat", type=int, required=True, help="the probe's --repeat")
    parser.add_argument(
        "--summary",
        type=Path,
        default=None,
        help="markdown file to append rows to (default: $GITHUB_STEP_SUMMARY)",
    )
    args = parser.parse_args(argv)
    summary = args.summary or (
        Path(os.environ["GITHUB_STEP_SUMMARY"]) if os.environ.get("GITHUB_STEP_SUMMARY") else None
    )
    # Neither stream may raise on a byte or a character it cannot map: a stock Windows runner's
    # pipe encoding is cp1252, and a decode or encode error here would end the copy mid-run.
    if isinstance(sys.stdin, io.TextIOWrapper):
        sys.stdin.reconfigure(errors="replace")
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(errors="replace")
    # The copied probe output is untrusted text in the job log: on a runner, workflow-command
    # processing is paused around it, so a line such as `::add-mask::` or `::stop-commands::` is
    # printed rather than executed. The token is unpredictable so the text cannot resume early. This
    # covers the probe's STDOUT; its stderr reaches the log directly and is outside this pause
    # except while it happens to interleave.
    token = uuid.uuid4().hex if os.environ.get("GITHUB_ACTIONS") == "true" else ""
    if token:
        print(f"::stop-commands::{token}", flush=True)
    lines: list[str] = []
    for line in sys.stdin:
        sys.stdout.write(line)
        sys.stdout.flush()
        lines.append(line)
    if token:
        print(f"::{token}::", flush=True)
    result = summarise("".join(lines), rate=args.rate, repeat=args.repeat)
    if result.rows and summary is not None:
        with summary.open("a", encoding="utf-8") as handle:
            handle.writelines(row + "\n" for row in result.rows)
    for row in result.rows:
        print(row)
    for error in result.errors:
        print(f"::error title=ingress probe RESULT::{_escape(f'rate {args.rate:g}: {error}')}")
    if result.errors:
        return 1
    return 0 if result.measured else SETUP_FAILED_ONLY


if __name__ == "__main__":
    raise SystemExit(main())

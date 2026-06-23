# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CLI for the WIN2025 acceptance harness.

``python -m harness.acceptance``                       → run probes + the backing pytest suites, print
                                                          a per-row summary, exit 0 (no FAIL/ERROR) / 1.
``python -m harness.acceptance --no-pytest``           → probes only (fast host check; no suite run).
``python -m harness.acceptance --section A,B``         → run only those matrix sections.
``python -m harness.acceptance --report-md r.md --report-csv r.csv``
                                                       → also write Markdown / CSV reports.
``python -m harness.acceptance --xlsx WIN2025-TEST-MATRIX.xlsx``
                                                       → write each verdict back into the workbook's
                                                          Status column (needs openpyxl).

Exit codes: 0 = no FAIL/ERROR (MANUAL/SKIP are not failures), 1 = at least one FAIL/ERROR, 2 = bad
usage / write error.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from harness.acceptance.matrix import SECTIONS
from harness.acceptance.report import (
    exit_code,
    render_console,
    render_csv,
    render_markdown,
    write_xlsx_status,
)
from harness.acceptance.runner import run_matrix


def main(argv: list[str] | None = None) -> int:
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass

    parser = argparse.ArgumentParser(
        prog="harness.acceptance",
        description="Run the Windows Server 2025 on-server acceptance matrix.",
    )
    parser.add_argument(
        "--no-pytest",
        action="store_true",
        help="run probes only; skip the backing pytest suites (PYTEST rows report SKIP)",
    )
    parser.add_argument(
        "--section", help="comma-separated section letters to run (e.g. A,B,C); default = all"
    )
    parser.add_argument("--report-md", help="write the Markdown report to this path")
    parser.add_argument("--report-csv", help="write the CSV report to this path")
    parser.add_argument(
        "--xlsx", help="write each verdict back into this matrix workbook's Status column"
    )
    args = parser.parse_args(argv)

    include_sections = None
    if args.section:
        include_sections = [s.strip().upper() for s in args.section.split(",") if s.strip()]
        unknown = [s for s in include_sections if s not in SECTIONS]
        if unknown:
            print(
                f"unknown section(s): {', '.join(unknown)}; choices: {', '.join(SECTIONS)}",
                file=sys.stderr,
            )
            return 2

    results = run_matrix(run_pytest=not args.no_pytest, include_sections=include_sections)

    print(render_console(results))

    if args.report_md:
        Path(args.report_md).write_text(render_markdown(results), encoding="utf-8")
    if args.report_csv:
        Path(args.report_csv).write_text(render_csv(results), encoding="utf-8")
    if args.xlsx:
        try:
            n = write_xlsx_status(results, Path(args.xlsx))
        except (RuntimeError, OSError) as exc:
            print(f"xlsx write-back failed: {exc}", file=sys.stderr)
            return 2
        print(f"  wrote {n} verdict(s) into {args.xlsx}", file=sys.stderr)

    return exit_code(results)


if __name__ == "__main__":
    raise SystemExit(main())

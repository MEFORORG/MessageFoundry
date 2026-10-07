# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Spike S-1: count lens rows by kind over every non-helper module in samples/config.

Runs `python -m messagefoundry lens parse <module> --json --contract 2` on each top-level `.py` under
samples/config whose name does not start with `_` (the loader skips those), and prints a table of row
kinds per role. A `code` row is the read-only passthrough; every other kind is a typed row the Steps
view can render and (for editable kinds) edit.

Usage: python theia-spike/scripts/row_census.py [samples/config]
"""

from __future__ import annotations

import collections
import json
import pathlib
import subprocess
import sys


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "samples/config")
    by_role: dict[str, collections.Counter[str]] = collections.defaultdict(collections.Counter)
    lines_by_role: dict[str, collections.Counter[str]] = collections.defaultdict(
        collections.Counter
    )
    per_module: list[tuple[str, int, int, int]] = []
    for mod in sorted(root.glob("*.py")):
        if mod.name.startswith("_"):
            continue
        proc = subprocess.run(  # nosec B603 - fixed argv from sys.executable, no shell
            [
                sys.executable,
                "-m",
                "messagefoundry",
                "lens",
                "parse",
                str(mod),
                "--json",
                "--contract",
                "2",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        if proc.returncode != 0:
            print(f"{mod.name}: lens parse exit {proc.returncode}: {proc.stderr.strip()[:200]}")
            continue
        data = json.loads(proc.stdout)
        typed = code = 0
        handlers = data.get("handlers", [])
        for h in handlers:
            role = h.get("role", "handler")
            for row in h.get("rows", []):
                kind = row.get("kind", "?")
                by_role[role][kind] += 1
                lines_by_role[role][kind] += int(row["line_end"]) - int(row["line_start"]) + 1
                if kind == "code":
                    code += 1
                else:
                    typed += 1
        per_module.append((mod.name, len(handlers), typed, code))

    print("| Module | Defs | Typed rows | Code rows | Typed share |")
    print("|---|---|---|---|---|")
    for name, defs, typed, code in per_module:
        total = typed + code
        share = f"{100 * typed / total:.0f}%" if total else "n/a"
        print(f"| {name} | {defs} | {typed} | {code} | {share} |")
    print()
    print("| Role | Kind | Rows | Source lines |")
    print("|---|---|---|---|")
    for role in sorted(by_role):
        for kind, n in sorted(by_role[role].items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"| {role} | {kind} | {n} | {lines_by_role[role][kind]} |")
    all_rows = sum(sum(c.values()) for c in by_role.values())
    all_code = sum(c["code"] for c in by_role.values())
    if all_rows:
        print()
        print(
            f"Total rows {all_rows}; code {all_code} ({100 * all_code / all_rows:.1f}%); "
            f"typed {all_rows - all_code} ({100 * (all_rows - all_code) / all_rows:.1f}%)"
        )
        all_lines = sum(sum(c.values()) for c in lines_by_role.values())
        code_lines = sum(c["code"] for c in lines_by_role.values())
        print(
            f"Total row lines {all_lines}; code {code_lines} ({100 * code_lines / all_lines:.1f}%)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

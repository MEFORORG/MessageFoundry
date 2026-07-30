"""Measure what the Steps view actually projects over a config estate (BACKLOG #239).

WHY THIS EXISTS. [ADR 0089](../../docs/adr/0089-recognition-first-lens-native-idioms.md) §1
measured a real estate -- 87 files, 486 `msg`-manipulating functions, 3,852 statements -- and found
**~66% of projected rows opaque** with **100% of handlers rendering zero editable action rows**;
Phase A moved that to ~42% editable. §5 states the scan is "a **repeatable** coverage check --
re-running it after each phase measures the coverage lift and surfaces the shrinking residual".
Phase A, the ADR 0106 palette, ADR 0108's fan-out and ADR 0104's picker have all shipped since, and
nobody has re-run it. Whether to build the next Steps-view increment, or to stop, turns on that
number.

WHAT IT MEASURES, AND WHY NOT WITH ITS OWN PARSER. ADR 0089's original scan classified statements
with its own `ast` walk. This one drives the SHIPPED `messagefoundry lens parse --json` instead, so
the answer describes what the Steps view REALLY renders today rather than a second implementation
of the grammar that could drift from it. The lens is the product surface under evaluation; asking
it directly is the only way the number stays honest as the grammar moves.

  opaque   = `code` rows + `control` rows (ADR 0089 §1's "opaque code/UNRECOGNIZED control").
             A recognized `control` row is still counted opaque: `stepsView.ts` renders control
             rows read-only ("`code`/`control` rows stay read-only ... visibly disabled"), so it is
             opaque to EDITING even where the grammar recognized it. `--strict-control` narrows
             this to unrecognized control rows only, which is the looser reading.
  editable = action / lookup / send -- the kinds that expose enabled param inputs.

PHI. `lens parse` is a static `ast` parse that never imports or executes a config module, and no
message ever enters this path. The scan reads only code and emits only counts and file names, so it
is safe to run against a production estate. Pass `--hash-names` when sending results anywhere.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
from collections import Counter
from pathlib import Path

EDITABLE = frozenset({"action", "lookup", "send"})

# A real estate keeps its own .venv beside the config modules, so a naive rglob walks thousands of
# site-packages files, spawns a CLI call for each, and buries the estate's own numbers. Any path
# component matching these is skipped, as is any dot-directory.
SKIP_DIRS = frozenset({"__pycache__", "site-packages", "node_modules", "build", "dist"})


def config_modules(root: Path) -> list[Path]:
    """Every `.py` under ``root`` that is plausibly a config module."""
    return sorted(
        py
        for py in root.rglob("*.py")
        if not any(
            part in SKIP_DIRS or (part.startswith(".") and part not in {".", ".."})
            for part in py.relative_to(root).parts
        )
    )


def parse_module(py: Path, python: str, cwd: Path) -> tuple[dict | None, str]:
    """Return (parsed JSON, error). `encoding=` is REQUIRED, not cosmetic.

    `text=True` alone decodes with the LOCALE default, which is cp1252 on a stock Windows box;
    config modules are UTF-8, so the decode raises inside subprocess's reader thread and stdout
    comes back None -- a refusal that reads as "this estate has no handlers".
    """
    proc = subprocess.run(  # nosec B603 - fixed argv, no shell, interpreter is operator-supplied
        [python, "-m", "messagefoundry", "lens", "parse", str(py), "--json"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=cwd,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or "").strip().splitlines()
        return None, (tail[-1] if tail else f"exit {proc.returncode}")
    try:
        return json.loads(proc.stdout), ""
    except json.JSONDecodeError as exc:
        return None, f"non-JSON output ({exc})"


def classify_code_row(first_stmt: str) -> str:
    """Bucket an opaque `code` row by the shape of its first statement.

    A HEURISTIC on source text, not a parse -- it exists to answer one question the row contract
    cannot: how much of the opaque mass is a delegating call into a helper module, i.e. how much
    ADR 0089's Phase D (helper descent) would convert without widening the grammar at all. Buckets
    are shapes; no source is ever emitted, only counts.
    """
    line = first_stmt.strip()
    if not line or line.startswith("#"):
        return "comment/blank"
    if line.startswith(("import ", "from ")):
        return "import"
    if line.startswith("return"):
        return "return"
    if line.startswith(("try", "except", "finally", "with", "raise", "while", "assert", "yield")):
        return "exception/other construct"
    if line.startswith("msg."):
        return "unrecognized msg API"
    head, sep, rest = line.partition("=")
    if sep and not head.rstrip().endswith(("=", "!", "<", ">")) and head.strip().isidentifier():
        return "assignment from call" if "(" in rest else "assignment (literal/expr)"
    if "(" in line and line.split("(", 1)[0].replace(".", "_").isidentifier():
        return "bare helper call"
    return "other"


def _label(py: Path, root: Path, hash_names: bool) -> str:
    rel = py.relative_to(root).as_posix()
    if not hash_names:
        return rel
    return f"<{hashlib.sha256(rel.encode()).hexdigest()[:12]}>.py"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("config_dir", type=Path, help="directory of config modules to scan")
    ap.add_argument("--python", default=sys.executable, help="interpreter with messagefoundry")
    ap.add_argument("--cwd", type=Path, default=Path.cwd(), help="working dir for the CLI call")
    ap.add_argument(
        "--strict-control",
        action="store_true",
        help="count only UNRECOGNIZED control rows as opaque (recognized control is not opaque)",
    )
    ap.add_argument("--hash-names", action="store_true", help="hash file names in the output")
    ap.add_argument("--json", dest="as_json", action="store_true", help="emit JSON")
    args = ap.parse_args(argv)

    if not args.config_dir.is_dir():
        print(f"not a directory: {args.config_dir}", file=sys.stderr)
        return 2

    kinds: Counter[str] = Counter()
    causes: Counter[str] = Counter()
    files = handlers = zero_editable = fully_typed = 0
    code_per_handler: list[int] = []
    opaque_per_handler: list[int] = []
    refusals: list[dict[str, str]] = []

    for py in config_modules(args.config_dir):
        files += 1
        out, err = parse_module(py, args.python, args.cwd)
        if out is None:
            refusals.append({"file": _label(py, args.config_dir, args.hash_names), "reason": err})
            continue
        try:
            src = py.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            src = []
        for handler in out.get("handlers", []):
            handlers += 1
            rows = handler.get("rows", [])
            n_edit = n_opaque = n_code = 0
            for row in rows:
                if row.get("kind") == "code":
                    start = row.get("line_start")
                    end = row.get("line_end", start)
                    stmt = ""
                    if isinstance(start, int) and src:
                        for raw in src[start - 1 : (end if isinstance(end, int) else start)]:
                            if raw.strip() and not raw.strip().startswith("#"):
                                stmt = raw
                                break
                    causes[classify_code_row(stmt)] += 1
                kind = row.get("kind", "?")
                if kind == "control" and not row.get("recognized", True):
                    kind = "control (unrecognized)"
                kinds[kind] += 1
                if kind in EDITABLE:
                    n_edit += 1
                    continue
                if kind == "code":
                    n_code += 1
                # A recognized control row counts as opaque unless --strict-control.
                if kind != "control" or not args.strict_control:
                    n_opaque += 1
            if n_edit == 0:
                zero_editable += 1
            if rows and n_opaque == 0:
                fully_typed += 1
            code_per_handler.append(n_code)
            opaque_per_handler.append(n_opaque)

    total = sum(kinds.values())
    opaque = kinds["code"] + kinds["control (unrecognized)"]
    if not args.strict_control:
        opaque += kinds["control"]
    editable = sum(count for kind, count in kinds.items() if kind in EDITABLE)

    result = {
        "corpus": str(args.config_dir),
        "files_scanned": files,
        "parse_refused": len(refusals),
        "handlers": handlers,
        "rows": total,
        "row_kinds": dict(kinds.most_common()),
        "opaque_rows": opaque,
        "editable_rows": editable,
        "opaque_pct": round(100.0 * opaque / total, 1) if total else None,
        "editable_pct": round(100.0 * editable / total, 1) if total else None,
        "handlers_zero_editable": zero_editable,
        "handlers_fully_typed": fully_typed,
        "median_code_rows_per_handler": statistics.median(code_per_handler)
        if code_per_handler
        else None,
        "max_code_rows_in_one_handler": max(code_per_handler, default=None),
        "strict_control": args.strict_control,
        "refusals": refusals,
    }

    if args.as_json:
        print(json.dumps(result, indent=2))
        return 0

    def pct(n: int, d: int) -> str:
        return f"{(100.0 * n / d):.1f}%" if d else "n/a"

    print(f"corpus             : {args.config_dir}")
    print(f"files scanned      : {files}   (parse-refused: {len(refusals)})")
    print(f"handlers projected : {handlers}")
    print(f"rows projected     : {total}")
    print("\nrow kinds:")
    for kind, count in kinds.most_common():
        print(f"  {kind:<24} {count:>6}  {pct(count, total)}")
    print(f"\nOPAQUE rows   : {opaque:>6}  {pct(opaque, total)}")
    print(f"EDITABLE rows : {editable:>6}  {pct(editable, total)}")
    print(
        f"\nhandlers with ZERO editable rows : {zero_editable}/{handlers} {pct(zero_editable, handlers)}"
    )
    print(
        f"handlers 100% typed (no opaque)  : {fully_typed}/{handlers} {pct(fully_typed, handlers)}"
    )
    if code_per_handler:
        print(f"median `code` rows per handler   : {statistics.median(code_per_handler)}")
        print(f"max `code` rows in one handler   : {max(code_per_handler)}")
    if opaque_per_handler:
        print(f"median OPAQUE rows per handler   : {statistics.median(opaque_per_handler)}")
        print(f"max OPAQUE rows in one handler   : {max(opaque_per_handler)}")
    if causes:
        total_code = sum(causes.values())
        print("\nwhy `code` rows are opaque (first-statement shape, heuristic):")
        for cause, count in causes.most_common():
            print(f"  {cause:<30} {count:>5}  {pct(count, total_code)}")
        descent = causes["bare helper call"] + causes["assignment from call"]
        print(
            f"  -> helper-descent candidates    : {descent:>5}  {pct(descent, total_code)} of code rows"
        )
    if refusals:
        print("\nparse refusals (whole-file: the lens steps aside to the text editor):")
        for refusal in refusals:
            print(f"  {refusal['file']}: {refusal['reason']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

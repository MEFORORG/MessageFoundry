#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""CI behavioural regression gate for the ADR 0144 Increment-3 Semgrep handler-security rules.

Deterministic + cross-platform (used instead of ``semgrep --test``, which crashes on Windows in its
path-pairing): scan the annotated fixtures and assert that every rule fires EXACTLY on the lines its
``# ruleid:`` annotations name and nowhere else, so an ``# ok`` case (at least ``log.debug`` /
``msg.control_id`` / parameterized ``db_lookup``) that fires fails it, and that the per-rule totals
match the pinned counts. A non-empty semgrep ``errors`` array fails it too, since a rule semgrep could
not load still yields parseable JSON. Requires ``semgrep`` on PATH; run in the security.yml semgrep
job.
"""

from __future__ import annotations

import collections
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[2]
_RULES = _ROOT / "messagefoundry" / "security" / "semgrep" / "handler-security.yml"
_FIXTURE = _ROOT / "tests" / "fixtures" / "handler_taint" / "handler-security.py"
# Findings per rule over the fixture; a case deleted from the fixture alone then reds this gate.
_EXPECTED: collections.Counter[str] = collections.Counter(
    {
        "mf-handler-phi-to-log": 9,
        "mf-handler-ambient-subprocess": 1,
        "mf-handler-ambient-os-exec": 2,
        "mf-handler-ambient-deserialization": 1,
        "mf-handler-ambient-eval-exec": 1,
        "mf-handler-sqli-db-lookup": 10,
        "mf-handler-phi-to-file": 9,
    }
)


def main() -> int:
    # Semgrep's built-in default .semgrepignore excludes tests/, so a repo scan of the fixture finds 0.
    # Scan a copy in a temp dir (outside the tests tree, not a git repo) so it is actually analyzed.
    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy(_FIXTURE, Path(tmp) / _FIXTURE.name)
        # nosec B603 B607 - fixed argv, no shell. The `noqa` covers ruff's copy of these rules; bandit
        # does not read noqa, so both annotations are needed now that CI scans scripts/ too.
        proc = subprocess.run(  # noqa: S603 — fixed args, no shell  # nosec B603 B607
            ["semgrep", "--config", str(_RULES), "--json", "--metrics", "off", tmp],  # noqa: S607
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = None
    failure = check(payload, read_fixture())
    if failure is not None:
        failure += f" (rc={proc.returncode}):\n{proc.stderr[:2000]}"
        print(failure, file=sys.stderr)
        return 1
    got = collections.Counter(_rule(r) for r in payload["results"])
    print(f"handler-taint rules fire exactly as annotated: {dict(got)}")
    return 0


def check(payload: object, fixture: str) -> str | None:
    """Why semgrep's ``--json`` ``payload`` over ``fixture`` fails this gate, or ``None``.

    A non-empty ``errors`` array fails it even though JSON parsed (BACKLOG #5463): semgrep reports a
    rule it could not load, or a file it could not parse, there and still exits with results, so a
    broken rule would otherwise read as one that matched nothing it was not annotated for. Every
    level fails it, a warning included, on purpose: the fixture is valid Python and the rules are
    ours, so any entry there means the run did not analyse what the annotations describe."""
    if not isinstance(payload, dict):
        return "semgrep produced no JSON object"
    errors = payload.get("errors")
    if errors:
        return f"semgrep reported errors, so its results prove nothing: {json.dumps(errors)[:2000]}"
    results = payload.get("results")
    if not isinstance(results, list):
        return "semgrep produced no JSON results"
    # Every finding must sit on the line its `# ruleid:` annotation names, checked first so a failure
    # names the line. Equal counts alone could hide a miss offset by an over-match elsewhere.
    want, _ok = annotated_findings(fixture)
    try:
        hit = {(_rule(r), int(r["start"]["line"])) for r in results}
    except (KeyError, TypeError, ValueError) as exc:
        return f"semgrep produced a result this gate cannot read: {exc!r}"
    if hit != want:
        return (
            f"handler-taint rules REGRESSED: missed {sorted(want - hit)}, "
            f"unannotated {sorted(hit - want)}"
        )
    got = collections.Counter(_rule(r) for r in results)
    if got != _EXPECTED:
        return f"handler-taint rules REGRESSED: got {dict(got)} != expected {dict(_EXPECTED)}"
    return None


def _rule(result: dict[str, Any]) -> str:
    """A finding's rule id without the path prefix semgrep puts on ``check_id``."""
    return str(result["check_id"]).split(".")[-1]


def read_fixture() -> str:
    """The fixture's text with its line endings as stored. ``Path.read_text`` would translate a lone
    ``\\r`` into a line break that semgrep does not count, shifting every later line."""
    return _FIXTURE.read_bytes().decode("utf-8")


_ANNOTATION = re.compile(r"^\s*#\s*(ruleid|ok):\s*([\w-]+)\s*$")


def annotated_findings(text: str) -> tuple[set[tuple[str, int]], set[tuple[str, int]]]:
    """The (rule id, line) pairs the fixture's ``# ruleid:`` and ``# ok:`` comment lines name. Each
    annotation applies to the next line that is not itself an annotation, the semgrep --test
    convention. Lines are counted on ``\\n`` only, as semgrep counts them; ``str.splitlines`` would
    also break on characters such as U+2028 inside a string literal and shift every later line."""
    lines = text.split("\n")
    want: set[tuple[str, int]] = set()
    ok: set[tuple[str, int]] = set()
    pending: list[tuple[str, str]] = []
    for number, line in enumerate(lines, start=1):
        match = _ANNOTATION.match(line)
        if match:
            pending.append((match.group(1), match.group(2)))
            continue
        for kind, rule in pending:
            (want if kind == "ruleid" else ok).add((rule, number))
        pending = []
    return want, ok


if __name__ == "__main__":
    raise SystemExit(main())

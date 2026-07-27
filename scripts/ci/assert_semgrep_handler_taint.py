#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CI behavioural regression gate for the ADR 0144 Increment-3 Semgrep handler-security rules.

Deterministic + cross-platform (used instead of ``semgrep --test``, which crashes on Windows in its
path-pairing): scan the annotated fixtures and assert that the two recovered false-negatives
(inter-statement taint + aliased-import) and the other rules fire EXACTLY as annotated — and, by count
equality, that the ``# ok`` cases (``log.debug`` / ``msg.control_id`` / parameterized ``db_lookup``) do
NOT. Requires ``semgrep`` on PATH; run in the security.yml semgrep job.
"""

from __future__ import annotations

import collections
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_RULES = _ROOT / "messagefoundry" / "security" / "semgrep" / "handler-security.yml"
_FIXTURE = _ROOT / "tests" / "fixtures" / "handler_taint" / "handler-security.py"
# The expected finding count per rule over the fixtures. phi-to-log = 2 (inter-statement body +
# log.log(level, body)); control_id / debug / params-dict are `# ok` and MUST contribute 0.
_EXPECTED: collections.Counter[str] = collections.Counter(
    {
        "mf-handler-phi-to-log": 2,
        "mf-handler-ambient-subprocess": 1,
        "mf-handler-ambient-deserialization": 1,
        "mf-handler-ambient-eval-exec": 1,
        "mf-handler-sqli-db-lookup": 1,
        "mf-handler-phi-to-file": 1,
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
        results = json.loads(proc.stdout)["results"]
    except (json.JSONDecodeError, KeyError):
        print(
            f"semgrep produced no JSON (rc={proc.returncode}):\n{proc.stderr[:2000]}",
            file=sys.stderr,
        )
        return 1
    got = collections.Counter(r["check_id"].split(".")[-1] for r in results)
    if got != _EXPECTED:
        print(
            f"handler-taint rules REGRESSED: got {dict(got)} != expected {dict(_EXPECTED)}",
            file=sys.stderr,
        )
        return 1
    print(f"handler-taint rules fire exactly as annotated: {dict(got)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

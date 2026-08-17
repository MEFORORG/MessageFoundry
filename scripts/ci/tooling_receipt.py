#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Receipt for the ``tooling`` CI job: prove the harness tier actually EXECUTED.

**The failure this exists for is a green job that ran nothing.** The tier is selected by a pytest
marker applied in ``tests/conftest.py`` from ``tests/tooling_manifest.txt``. A marker typo, a renamed
manifest, or a collection hook that silently stops firing all produce the same observable: zero
selected tests and a passing job. pytest exits 5 on "no tests collected", which ``-q`` renders as one
line nobody reads, and the job's own exit status cannot tell "the suite passed" from "there was no
suite".

**COUNT WHAT EXECUTED, NOT WHAT WAS COLLECTED.** The first version of this check grepped
``--collect-only``, and pytest COLLECTS skipif-marked tests -- verified against a synthetic file whose
every test was skipped: it reported "2 tests collected". 18 of the tier's manifest entries carry a
module-level skipif on ``os.name``/``sys.platform`` and hold 337 tests, so on a leg where those skip,
the collect-based check would print a healthy ~1,800 and pass while a fifth of the tier did nothing. A
receipt that cannot separate green-because-it-ran from green-because-it-skipped is not a receipt.

**The floor is deliberately loose.** It is a dead-marker backstop, not a coverage assertion. Sizing it
tight against the current population would redden every time the tier legitimately grows or a platform
gate moves, and a gate that cries wolf gets suppressed rather than fixed. Coverage drift is
``tests/test_tooling_partition.py``'s job, on evidence; this one only asserts the mechanism fired.

Reads the junit the run itself produced, so the number reported is the number that happened.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# defusedxml, not xml.etree: stdlib ElementTree resolves external entities, so parsing an untrusted
# document is an XXE read primitive. This report is produced by our own pytest run on our own runner,
# so the practical exposure is nil -- but "the input happens to be trustworthy today" is exactly the
# premise that rots, and the repo already ships defusedxml as a core dependency. Bandit blocks the
# stdlib call (B405/B314) and it is right to; the fix is the safe parser, not a nosec.
from defusedxml import ElementTree as ET


def count(report: Path) -> tuple[int, int]:
    """Return (executed, skipped). A testcase with a ``<skipped>`` child did not run."""
    tree = ET.parse(report)
    executed = skipped = 0
    for case in tree.iter("testcase"):
        if case.find("skipped") is not None:
            skipped += 1
        else:
            executed += 1
    return executed, skipped


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--report", type=Path, required=True, help="junit xml the run produced")
    ap.add_argument(
        "--min-executed", type=int, default=1000, help="dead-marker floor, not a target"
    )
    args = ap.parse_args()

    if not args.report.is_file():
        # Absent report means pytest died before writing one, OR the path is wrong. Either way the
        # receipt cannot vouch for anything, and silence here would defeat its whole purpose.
        print(f"::error::no junit report at {args.report} -- the tier's result cannot be verified")
        return 1

    executed, skipped = count(args.report)
    print(f"tooling tests EXECUTED: {executed}   skipped: {skipped}")
    if executed < args.min_executed:
        print(
            f"::error::the tooling marker EXECUTED only {executed} tests (floor {args.min_executed}) "
            f"-- the partition is not being applied; check tests/tooling_manifest.txt and the "
            f"pytest_collection_modifyitems hook in tests/conftest.py that reads it"
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

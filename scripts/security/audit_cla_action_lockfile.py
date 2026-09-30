#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Report a NEW advisory against the vendored CLA action's declared closure (BACKLOG #1578).

WHAT THIS EXISTS FOR. The provenance gate (``build_cla_action_provenance.py``) detects CHANGE in
``.github/actions/cla-assistant-lite/``, not vulnerabilities. This script audits the vendored
``upstream-package-lock.json`` with ``npm audit``, and ``security.yml``'s ``cla-action-audit`` job
runs it on the daily cron.

WHY A BASELINE. The lockfile is a frozen 2021-era tree that does not audit clean, and moving a pin
means rebuilding the bundle with a Node toolchain this repository does not carry. So the run fails
only on an advisory NOT in :data:`BASELINE_PATH`. Adding an entry there is the acknowledgement, in a
reviewed diff, the role ``--ignore-vuln`` plays for ``pip-audit``. The baseline file says its first
entries were recorded as found, not triaged.

THE FALSE CLEAN THIS GUARDS AGAINST. Measured 2026-09-29: ``npm audit --package-lock-only`` with the
lockfile and NO ``package.json`` exits 0, reports zero vulnerabilities, and counts 6 dependencies.
npm builds the tree from the manifest, so without one it audits almost nothing. A pass therefore
needs all three of these, and the first and third are the live positive controls, checked on every
run's real output:

1. **Coverage.** npm's dependency count equals the lockfile's entry count.
2. **No new advisory.** Every reported advisory is in the baseline.
3. **No stale entry.** Every baselined advisory is still reported. The bundle is KNOWN to carry
   these, so an audit that stops reporting them has stopped looking, whatever its exit code says.

WHAT THIS PROVES, AND WHERE. Check 3 shows on each run that the audit sees the known-vulnerable
packages in the bundle's closure. Check 2 turns any advisory it sees beyond the baseline into a red;
``tests/test_cla_action_advisory_gate.py`` shows that offline by dropping a real advisory from the
baseline over a recorded audit. Together they are the ledger row's acceptance: a known-vulnerable
dependency in that bundle WOULD be reported.

WHAT A PASS DOES NOT PROVE. Each run prints the provenance record's limitation sentence. The short
form: the lockfile audit covers the DECLARED dependencies of the pinned commit, not what the bundle
was built from. And since the tree is not clean, a pass says only that nothing beyond the
acknowledged advisories applies.

WHY A TEMPORARY DIRECTORY. GitHub's dependency graph ingests any file named ``package-lock.json`` in
the repository, so the stock-named copy npm needs is written only to a directory deleted afterwards.

THE RETRY IS A THIRD COPY, AND COPIES DRIFT. ``npm audit`` exits non-zero on a finding and on a
transport error alike, so a report counts as a verdict only when it carries a ``metadata`` block,
and running out of retries fails. The same loop is inline bash twice in ``security.yml``, in the
``npm-audit`` job and the ``dependency-and-secret-scan`` composite, for ``ide/``. Nothing keeps this
one in step with those two::

    python scripts/security/audit_cla_action_lockfile.py                  audit live (needs npm)
    python scripts/security/audit_cla_action_lockfile.py --report a.json  judge a saved report

Stdlib only, like the provenance script beside it.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeGuard

# This file is ``<repo>/scripts/security/audit_cla_action_lockfile.py``, so the root is two up.
REPO_ROOT = Path(__file__).resolve().parents[2]

#: The vendored lockfile, and the provenance record whose limitation sentence each run prints. The
#: provenance script names both too; a test holds the two spellings equal.
LOCK_PATH = ".github/actions/cla-assistant-lite/upstream-package-lock.json"
RECORD_PATH = ".github/actions/cla-assistant-lite/provenance.cdx.json"

#: The acknowledged advisories. OUTSIDE the action directory on purpose: the provenance gate treats
#: that directory as an allowlist and reports any file its record does not name.
BASELINE_PATH = "security/cla-action-advisories.toml"

#: How many times to ask the registry before failing closed, as in the ``ide/`` npm-audit step.
ATTEMPTS = 5

#: Seconds one ``npm audit`` call may take. Five of these plus the 150 s of back-off must fit inside
#: the job's ``timeout-minutes``, or the runner kills the job before it can print why it failed.
NPM_TIMEOUT = 60

#: A GitHub advisory id. npm names each advisory by a URL ending in one.
_GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")

#: One acknowledged or reported advisory: (advisory id, affected package name).
Finding = tuple[str, str]

#: Runs ``npm audit`` in a directory and returns its stdout and stderr. Injected so tests need no npm.
Runner = Callable[[Path], tuple[str, str]]


def lock_entry_count(lock: dict[str, Any]) -> int:
    """How many installed packages the lockfile declares. The root entry (key ``""``) is not one."""
    return sum(1 for key in lock["packages"] if key)


def manifest_for(lock: dict[str, Any]) -> dict[str, Any]:
    """The ``package.json`` npm needs, copied from the lockfile's own root entry, not written here."""
    root = lock["packages"][""]
    fields = (
        "name",
        "version",
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    )
    return {field: root[field] for field in fields if field in root}


def is_verdict(report: object) -> TypeGuard[dict[str, Any]]:
    """True when *report* is an audit verdict, not a transport error.

    A verdict carries ``metadata.vulnerabilities`` and ``metadata.dependencies``. npm's error object
    (``{"message": ..., "error": {...}}``) carries neither.
    """
    if not isinstance(report, dict):
        return False
    metadata = report.get("metadata")
    return (
        isinstance(metadata, dict)
        and isinstance(metadata.get("vulnerabilities"), dict)
        and isinstance(metadata.get("dependencies"), dict)
        and isinstance(report.get("vulnerabilities"), dict)
    )


def _advisory_id(via: dict[str, Any]) -> str:
    """The GHSA id from an advisory's URL, or npm's numeric id when the URL names none."""
    match = _GHSA.search(str(via.get("url", "")))
    return match.group(0) if match else f"npm-{via.get('source')}"


def findings(report: dict[str, Any]) -> dict[Finding, dict[str, str]]:
    """Every advisory the report names, keyed by (id, package), with what a reader needs to triage.

    npm lists a package under ``vulnerabilities`` both for its own advisories and for depending on a
    vulnerable package. Only the ``via`` entries that are objects are advisories; a string entry
    names the dependency the problem came through, and counting it would report one advisory once
    per path to it.
    """
    found: dict[Finding, dict[str, str]] = {}
    for entry in report["vulnerabilities"].values():
        for via in entry.get("via", []):
            if not isinstance(via, dict):
                continue
            key = (_advisory_id(via), str(via.get("name")))
            found[key] = {
                "severity": str(via.get("severity", "")),
                "title": str(via.get("title", "")),
                "url": str(via.get("url", "")),
            }
    return found


def load_baseline(path: Path) -> set[Finding]:
    """The acknowledged advisories. A malformed or duplicated entry raises rather than being skipped.

    A skipped entry would widen the gate silently. A duplicate usually means two people acknowledged
    one advisory, and one of the reasons is then dead text.
    """
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    entries = data.get("advisory")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: no [[advisory]] entries")
    baseline: set[Finding] = set()
    for index, entry in enumerate(entries):
        ident, package = entry.get("id"), entry.get("package")
        if not (isinstance(ident, str) and ident and isinstance(package, str) and package):
            raise ValueError(f"{path}: advisory entry {index} needs a non-empty id and package")
        if not (_GHSA.fullmatch(ident) or re.fullmatch(r"npm-\d+", ident)):
            raise ValueError(f"{path}: advisory entry {index} has an unrecognised id {ident!r}")
        if (ident, package) in baseline:
            raise ValueError(f"{path}: {ident} for {package} is listed twice")
        baseline.add((ident, package))
    return baseline


def evaluate(
    report: dict[str, Any],
    reported: dict[Finding, dict[str, str]],
    baseline: set[Finding],
    expected_entries: int,
) -> list[str]:
    """Every reason this report fails the gate. An empty list is a pass.

    *reported* is ``findings(report)``, passed in so one run computes it once.
    """
    problems: list[str] = []
    audited = report["metadata"]["dependencies"].get("total")
    if audited != expected_entries:
        problems.append(
            f"COVERAGE: npm audited {audited} dependencies but the lockfile declares "
            f"{expected_entries}. The audit did not see the tree, so its result says nothing."
        )
    for ident, package in sorted(set(reported) - baseline):
        detail = reported[(ident, package)]
        problems.append(
            f"NEW ADVISORY, not in {BASELINE_PATH}: {ident} in {package} "
            f"({detail['severity']}) {detail['title']} {detail['url']}"
        )
    for ident, package in sorted(baseline - set(reported)):
        problems.append(
            f"STALE BASELINE ENTRY: {ident} in {package} is acknowledged but no longer reported. "
            "The tree is frozen, so either the advisory was withdrawn or the audit stopped seeing "
            "the package. Find out which before removing the entry."
        )
    return problems


def run_npm_audit(
    lock_bytes: bytes,
    manifest: dict[str, Any],
    runner: Runner,
    attempts: int = ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any] | None:
    """Audit *lock_bytes* in a throwaway directory. Returns the verdict, or None if none came back."""
    with tempfile.TemporaryDirectory(prefix="cla-action-audit-") as scratch:
        workdir = Path(scratch)
        (workdir / "package-lock.json").write_bytes(lock_bytes)
        (workdir / "package.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        for attempt in range(1, attempts + 1):
            stdout, stderr = runner(workdir)
            try:
                report = json.loads(stdout)
            except json.JSONDecodeError:
                report = None
            if is_verdict(report):
                print(f"advisory database answered (attempt {attempt})")
                return report
            print(f"attempt {attempt}: no verdict from the advisory database; retrying")
            print(stderr[:400])
            if attempt < attempts:
                sleep(attempt * 15)
    return None


def npm_runner(workdir: Path) -> tuple[str, str]:
    """Run ``npm audit`` for real. Exit status is ignored: :func:`is_verdict` decides."""
    npm = shutil.which("npm")
    if npm is None:
        return "", "npm is not on PATH"
    try:
        done = subprocess.run(  # nosec B603 - fixed argv, no shell
            [npm, "audit", "--package-lock-only", "--json"],
            cwd=workdir,
            capture_output=True,
            text=True,
            timeout=NPM_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return "", f"npm audit took longer than {NPM_TIMEOUT} s"
    return done.stdout, done.stderr


def _limitation(root: Path) -> str:
    """The provenance record's limitation sentence, read from the record rather than restated."""
    record = json.loads((root / RECORD_PATH).read_text(encoding="utf-8"))
    for entry in record["metadata"]["properties"]:
        if entry["name"] == "messagefoundry:provenance:limitation":
            return str(entry["value"])
    raise ValueError(f"{RECORD_PATH} carries no limitation sentence")


_WHAT_TO_DO = """\
What to do about a NEW ADVISORY. The tree cannot be fixed here: moving a pin means rebuilding the
bundle, which needs a Node toolchain this repository does not carry.
1. Triage it against where the bundle runs: .github/workflows/cla.yml, on pull_request_target and
   on a matching issue_comment, holding a repository token. A package the lockfile marks dev is
   upstream build toolchain rather than a declared runtime dependency.
2. If it is reachable and serious, the remedy is replacing or re-vendoring the action, not this file.
3. Otherwise acknowledge it: add an [[advisory]] entry to {baseline} in a reviewed pull request.
   The entry is the record that somebody read it."""


def main(
    argv: list[str] | None = None,
    runner: Runner = npm_runner,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--report", type=Path, help="judge a saved `npm audit --json` report")
    parser.add_argument("--root", type=Path, default=REPO_ROOT, help="repository root")
    args = parser.parse_args(argv)
    root: Path = args.root

    lock_bytes = (root / LOCK_PATH).read_bytes()
    lock = json.loads(lock_bytes)
    expected = lock_entry_count(lock)
    baseline = load_baseline(root / BASELINE_PATH)

    report: object
    if args.report is not None:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        if not is_verdict(report):
            print(f"::error::{args.report} is not an audit verdict")
            return 2
    else:
        report = run_npm_audit(lock_bytes, manifest_for(lock), runner, sleep=sleep)
        if not is_verdict(report):
            print(f"::error::No verdict from the npm advisory database after {ATTEMPTS} attempts.")
            print("::error::Failing closed: this is not evidence of a clean tree.")
            return 2

    reported = findings(report)
    problems = evaluate(report, reported, baseline, expected)
    print(
        f"{LOCK_PATH}: {expected} lockfile entries, {len(reported)} advisories reported, "
        f"{len(baseline)} acknowledged in {BASELINE_PATH}."
    )
    print(f"SCOPE: {_limitation(root)}")
    if problems:
        for problem in problems:
            print(f"::error::{problem}")
        print(_WHAT_TO_DO.format(baseline=BASELINE_PATH))
        return 1
    print("PASS: coverage matched, every acknowledged advisory was seen, and no new one appeared.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Report a NEW advisory against the vendored CLA action's declared closure (BACKLOG #1578).

WHAT THIS EXISTS FOR. ``.github/actions/cla-assistant-lite/`` vendors a compiled bundle, and the
upstream lockfile it was built from sits beside it as ``upstream-package-lock.json``. Until this
script, nothing ran an advisory audit over that lockfile: the provenance gate
(``build_cla_action_provenance.py``) detects CHANGE, not vulnerabilities, so a new advisory reached
somebody only if a person went looking. This script is the audit, and ``security.yml``'s
``cla-action-audit`` job runs it on the daily cron.

WHY A BASELINE. The lockfile is a frozen 2021-era tree, and it does not audit clean: the first
reading (2026-09-29) found 35 advisories. None can be fixed here, because moving a pin means
rebuilding the bundle with a Node toolchain this repository does not carry. So a plain
``npm audit`` would be red forever, and a gate that is always red reports nothing. The baseline in
:data:`BASELINE_PATH` lists the advisories already known, and only one NOT in it fails the run.
Adding an entry is the acknowledgement, in a reviewed diff -- the same role ``--ignore-vuln`` plays
for ``pip-audit``.

A BASELINE ENTRY IS A RECORD, NOT A TRIAGE. The first 35 were recorded as found. Nobody has yet
judged whether each is reachable in the bundle's runtime path. The baseline file says so too.

THREE THINGS MUST ALL HOLD FOR A PASS, because a clean-looking audit can mean the audit saw nothing.
Measured while building this: ``npm audit --package-lock-only`` in a directory holding the lockfile
and NO ``package.json`` exits 0 and reports ZERO vulnerabilities. npm builds the tree from the
manifest, finds no dependencies, and audits almost nothing. That is a gate whose success cannot be
told from its absence, which is exactly what the ledger row asks to avoid. So:

1. **Coverage.** The audit's own dependency count must equal the lockfile's entry count. The run
   without a manifest counted 6; the real run counts every entry.
2. **No new advisory.** Every reported advisory is in the baseline.
3. **No stale entry.** Every baseline advisory is still reported. This is the positive control on
   live data: the bundle is KNOWN to carry these, so an audit that stops reporting them has stopped
   looking, whatever its exit code says.

On top of those, :func:`plant_control` removes one baselined advisory from the baseline in memory and
requires the check to report it as new. That is the ledger row's acceptance, demonstrated on every
run: a known-vulnerable dependency inside that bundle WOULD be reported.

WHAT A PASS DOES NOT PROVE. The provenance record states it, and this script prints it on every run
rather than restating it: a clean audit of the lockfile proves the DECLARED dependencies of the
pinned commit clean, not that the bundle was built from them. A pass here says less than that, since
the tree is not clean. It says no advisory beyond the acknowledged ones applies to what the lockfile
declares.

WHY A TEMPORARY DIRECTORY. GitHub's dependency graph ingests any file named ``package-lock.json`` in
the repository. The lockfile is committed under another name for that reason, so the stock-named
copy npm needs is written only to a directory that is deleted afterwards.

RETRIED, BECAUSE A REGISTRY HICCUP IS NOT AN AUDIT VERDICT. This copies the ``ide/`` npm-audit step:
``npm audit`` exits non-zero both on a finding and on a transport error, so the discriminator is the
report's ``metadata`` block, which a verdict carries and a transport error does not. Exhausting the
retries FAILS. It never passes::

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
from typing import Any

# This file is ``<repo>/scripts/security/audit_cla_action_lockfile.py``, so the root is two up.
REPO_ROOT = Path(__file__).resolve().parents[2]

#: The vendored lockfile, and the provenance record whose limitation sentence each run prints.
LOCK_PATH = ".github/actions/cla-assistant-lite/upstream-package-lock.json"
RECORD_PATH = ".github/actions/cla-assistant-lite/provenance.cdx.json"

#: The acknowledged advisories. OUTSIDE the action directory on purpose: the provenance gate treats
#: that directory as an allowlist and reports any file its record does not name.
BASELINE_PATH = "security/cla-action-advisories.toml"

#: How many times to ask the registry before failing closed, as in the ``ide/`` npm-audit step.
ATTEMPTS = 5

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
    """The ``package.json`` npm needs, taken from the lockfile's own root entry.

    Without it npm audits almost nothing and reports a clean tree (module docstring). Taking the
    fields from the lockfile, rather than writing them here, keeps this a copy of the upstream
    manifest and not a second definition of it.
    """
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


def is_verdict(report: object) -> bool:
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
    if not isinstance(entries, list):
        raise ValueError(f"{path}: no [[advisory]] entries")
    baseline: set[Finding] = set()
    for index, entry in enumerate(entries):
        ident, package = entry.get("id"), entry.get("package")
        if not isinstance(ident, str) or not isinstance(package, str) or not ident or not package:
            raise ValueError(f"{path}: advisory entry {index} needs a non-empty id and package")
        if not (_GHSA.fullmatch(ident) or re.fullmatch(r"npm-\d+", ident)):
            raise ValueError(f"{path}: advisory entry {index} has an unrecognised id {ident!r}")
        if (ident, package) in baseline:
            raise ValueError(f"{path}: {ident} for {package} is listed twice")
        baseline.add((ident, package))
    return baseline


def evaluate(report: dict[str, Any], baseline: set[Finding], expected_entries: int) -> list[str]:
    """Every reason this report fails the gate. An empty list is a pass."""
    problems: list[str] = []
    audited = report["metadata"]["dependencies"].get("total")
    if audited != expected_entries:
        problems.append(
            f"COVERAGE: npm audited {audited} dependencies but the lockfile declares "
            f"{expected_entries}. The audit did not see the tree, so its result says nothing."
        )
    reported = findings(report)
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


def plant_control(report: dict[str, Any], baseline: set[Finding], expected_entries: int) -> str:
    """Remove one reported advisory from the baseline and require the check to call it new.

    Returns an empty string when the control fired, and the reason otherwise. It runs on the same
    report the gate just judged, so it shows this run's data can red the gate, not only a fixture.
    """
    known = sorted(set(findings(report)) & baseline)
    if not known:
        return "CONTROL: no baselined advisory was reported, so there is nothing to plant."
    ident, package = known[0]
    problems = evaluate(report, baseline - {known[0]}, expected_entries)
    if any(p.startswith("NEW ADVISORY") and ident in p and package in p for p in problems):
        return ""
    return f"CONTROL: dropping {ident} ({package}) from the baseline did not red the check."


def run_npm_audit(
    lock_bytes: bytes,
    runner: Runner,
    attempts: int = ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any] | None:
    """Audit *lock_bytes* in a throwaway directory. Returns the verdict, or None if none came back."""
    manifest = manifest_for(json.loads(lock_bytes))
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
                assert isinstance(report, dict)
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
    done = subprocess.run(  # nosec B603 - fixed argv, no shell
        [npm, "audit", "--package-lock-only", "--json"],
        cwd=workdir,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
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
   on a matching issue_comment, holding a repository token. A dev-toolchain package is not in the
   bundle's runtime path at all.
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
    expected = lock_entry_count(json.loads(lock_bytes))
    baseline = load_baseline(root / BASELINE_PATH)

    if args.report is not None:
        report: object = json.loads(args.report.read_text(encoding="utf-8"))
        if not is_verdict(report):
            print(f"::error::{args.report} is not an audit verdict")
            return 2
    else:
        report = run_npm_audit(lock_bytes, runner, sleep=sleep)
        if report is None:
            print(f"::error::No verdict from the npm advisory database after {ATTEMPTS} attempts.")
            print("::error::Failing closed: this is not evidence of a clean tree.")
            return 2
    assert isinstance(report, dict)

    problems = evaluate(report, baseline, expected)
    control = plant_control(report, baseline, expected)
    if control:
        problems.append(control)

    reported = findings(report)
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
    print("PASS: no advisory beyond the acknowledged ones, and the planted control fired.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

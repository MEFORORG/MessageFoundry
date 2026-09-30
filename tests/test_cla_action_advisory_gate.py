# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The advisory gate over the vendored CLA action's declared closure (BACKLOG #1578).

THE ACCEPTANCE, quoted from the ledger row: *demonstrate that a known-vulnerable dependency inside
that bundle would be reported. A gate whose success cannot be distinguished from its absence is the
thing to avoid here.* So most tests below are controls: each plants one failure the gate exists to
catch and requires the gate to name it.

NO NETWORK. The report the gate judges is a real ``npm audit --json`` reading taken on 2026-09-29
against the vendored lockfile, recorded under ``tests/fixtures/cla_action_audit/``. The live call is
replaced by an injected runner, so nothing here needs npm.

THE FALSE CLEAN IS A RECORDED READING, NOT A GUESS. Run in a directory holding the lockfile and no
``package.json``, ``npm audit --package-lock-only`` exited 0 with zero vulnerabilities and counted 6
dependencies. :data:`_NO_MANIFEST_REPORT` is that output, verbatim. The gate must fail it even with
an EMPTY baseline, or it would pass on an audit that saw nothing.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = REPO_ROOT / "scripts" / "security" / "audit_cla_action_lockfile.py"
_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "cla_action_audit" / "npm-audit-2026-09-29.json"


def _load_module() -> ModuleType:
    """Load the standalone CI script by path; it is not part of the ``messagefoundry`` package."""
    spec = importlib.util.spec_from_file_location("audit_cla_action_lockfile", _SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load_module()

#: npm 11.5.2's output with the lockfile present and no package.json, recorded 2026-09-29.
_NO_MANIFEST_REPORT: dict[str, Any] = {
    "auditReportVersion": 2,
    "vulnerabilities": {},
    "metadata": {
        "vulnerabilities": {
            "info": 0,
            "low": 0,
            "moderate": 0,
            "high": 0,
            "critical": 0,
            "total": 0,
        },
        "dependencies": {
            "prod": 3,
            "dev": 3,
            "optional": 1,
            "peer": 0,
            "peerOptional": 0,
            "total": 6,
        },
    },
}

#: npm's stdout when the advisory endpoint cannot be reached, recorded 2026-09-29.
_TRANSPORT_ERROR = json.dumps(
    {
        "message": "request to https://127.0.0.1:9/-/npm/v1/security/advisories/bulk failed, "
        "reason: connect ECONNREFUSED 127.0.0.1:9",
        "error": {"summary": "", "detail": ""},
    }
)

#: A runtime dependency's advisory, used as the planted "new" finding.
_LODASH = ("GHSA-r5fr-rjxr-66jc", "lodash")


def _report() -> dict[str, Any]:
    report: dict[str, Any] = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    return report


def _lock() -> dict[str, Any]:
    lock: dict[str, Any] = json.loads((REPO_ROOT / gate.LOCK_PATH).read_text(encoding="utf-8"))
    return lock


def _expected() -> int:
    count: int = gate.lock_entry_count(_lock())
    return count


def _as_toml(baseline: set[tuple[str, str]]) -> str:
    return "".join(
        f'[[advisory]]\nid = "{ident}"\npackage = "{package}"\n\n'
        for ident, package in sorted(baseline)
    )


@pytest.fixture
def root(tmp_path: Path) -> Path:
    """A throwaway root holding the three files the script reads, with a baseline matching the fixture."""
    for relative in (gate.LOCK_PATH, gate.RECORD_PATH):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO_ROOT / relative, destination)
    baseline = tmp_path / gate.BASELINE_PATH
    baseline.parent.mkdir(parents=True, exist_ok=True)
    baseline.write_text(_as_toml(set(gate.findings(_report()))), encoding="utf-8")
    return tmp_path


def _replay(*outputs: str) -> tuple[list[Path], Any]:
    """A runner that returns *outputs* in order, repeating the last, and records each workdir."""
    seen: list[Path] = []

    def runner(workdir: Path) -> tuple[str, str]:
        seen.append(workdir)
        return outputs[
            min(len(seen), len(outputs)) - 1
        ], "npm error audit endpoint returned an error"

    return seen, runner


# --- The recorded reading ---------------------------------------------------------------------


def test_the_recorded_report_audited_the_whole_lockfile() -> None:
    """The fixture is a verdict over every lockfile entry, which is what makes it a fair subject."""
    report = _report()

    assert gate.is_verdict(report)
    assert report["metadata"]["dependencies"]["total"] == _expected()
    assert _expected() > 100, "the lockfile parsed to almost nothing; check the counter"


def test_the_recorded_report_names_a_runtime_advisory_in_the_bundle() -> None:
    """lodash is a declared runtime dependency, not dev toolchain, and the reading reports it."""
    lock = _lock()

    assert _LODASH in gate.findings(_report())
    assert "lodash" in lock["packages"][""]["dependencies"]
    assert not lock["packages"]["node_modules/lodash"].get("dev", False)


def test_a_package_reached_only_through_a_dependency_carries_no_advisory_of_its_own() -> None:
    """String ``via`` entries are dependency paths, not advisories, and are not counted.

    ``@octokit/rest`` is listed in the report only because it depends on vulnerable packages, so
    counting its string ``via`` entries would invent advisories against it.
    """
    report = _report()
    found = gate.findings(report)

    assert all(isinstance(v, str) for v in report["vulnerabilities"]["@octokit/rest"]["via"])
    assert "@octokit/rest" not in {package for _, package in found}
    assert all(ident.startswith("GHSA-") for ident, _ in found)


# --- The acceptance: a known-vulnerable dependency WOULD be reported --------------------------


def test_a_baseline_matching_the_reading_passes() -> None:
    report = _report()

    assert gate.evaluate(report, set(gate.findings(report)), _expected()) == []


def test_an_unacknowledged_advisory_in_the_bundle_is_reported() -> None:
    """THE ACCEPTANCE. Drop lodash's advisory from the baseline and the gate names it as new."""
    report = _report()
    baseline = set(gate.findings(report)) - {_LODASH}

    problems = gate.evaluate(report, baseline, _expected())

    assert len(problems) == 1, problems
    assert problems[0].startswith("NEW ADVISORY")
    assert _LODASH[0] in problems[0] and "lodash" in problems[0]


def test_the_planted_control_fires_on_the_real_reading() -> None:
    """The control every CI run carries. Empty means it fired."""
    report = _report()

    assert gate.plant_control(report, set(gate.findings(report)), _expected()) == ""


def test_the_planted_control_reports_when_it_has_nothing_to_plant() -> None:
    assert gate.plant_control(_NO_MANIFEST_REPORT, set(), _expected()).startswith("CONTROL")


def test_an_acknowledged_advisory_no_longer_reported_fails() -> None:
    """A stale entry reds, because a frozen tree that stops reporting a known advisory is suspect."""
    report = _report()
    baseline = set(gate.findings(report)) | {("GHSA-2222-3333-4444", "left-pad")}

    problems = gate.evaluate(report, baseline, _expected())

    assert len(problems) == 1, problems
    assert problems[0].startswith("STALE BASELINE ENTRY") and "left-pad" in problems[0]


# --- The false clean: success must be distinguishable from absence ---------------------------


def test_the_no_manifest_false_clean_fails_even_with_an_empty_baseline() -> None:
    """THE DISCRIMINATOR. npm exited 0 and reported nothing, and the gate still says it saw nothing."""
    assert gate.is_verdict(_NO_MANIFEST_REPORT), "it is a verdict in shape, which is the trap"

    problems = gate.evaluate(_NO_MANIFEST_REPORT, set(), _expected())

    assert any(p.startswith("COVERAGE") for p in problems), problems


def test_the_no_manifest_false_clean_also_reports_every_known_advisory_missing() -> None:
    """With the real baseline, the same reading fails on coverage AND on every stale entry."""
    baseline = set(gate.findings(_report()))

    problems = gate.evaluate(_NO_MANIFEST_REPORT, baseline, _expected())

    assert sum(p.startswith("STALE") for p in problems) == len(baseline)


def test_the_manifest_is_taken_from_the_lockfile_root() -> None:
    """The fix for the false clean: npm gets the upstream manifest, copied, not rewritten here."""
    lock = _lock()
    manifest = gate.manifest_for(lock)

    assert manifest["dependencies"] == lock["packages"][""]["dependencies"]
    assert manifest["devDependencies"] == lock["packages"][""]["devDependencies"]


# --- Transport errors are not verdicts, and running out of retries fails ----------------------


def test_a_transport_error_is_not_a_verdict() -> None:
    assert not gate.is_verdict(json.loads(_TRANSPORT_ERROR))
    assert not gate.is_verdict(None)
    assert not gate.is_verdict([])


def test_the_audit_retries_and_then_fails_closed() -> None:
    seen, runner = _replay(_TRANSPORT_ERROR)
    sleeps: list[float] = []
    lock_bytes = (REPO_ROOT / gate.LOCK_PATH).read_bytes()

    assert gate.run_npm_audit(lock_bytes, runner, sleep=sleeps.append) is None
    assert len(seen) == gate.ATTEMPTS
    assert sleeps == [15, 30, 45, 60]


def test_a_retry_that_gets_a_verdict_returns_it() -> None:
    seen, runner = _replay(_TRANSPORT_ERROR, "not json", _FIXTURE.read_text(encoding="utf-8"))
    lock_bytes = (REPO_ROOT / gate.LOCK_PATH).read_bytes()

    report = gate.run_npm_audit(lock_bytes, runner, sleep=lambda _s: None)

    assert report == _report()
    assert len(seen) == 3


def test_the_audit_directory_holds_the_verbatim_lockfile_and_is_deleted() -> None:
    """npm sees the lockfile byte for byte under the stock name, and nothing stock-named survives."""
    lock_bytes = (REPO_ROOT / gate.LOCK_PATH).read_bytes()
    observed: dict[str, Any] = {}

    def runner(workdir: Path) -> tuple[str, str]:
        observed["dir"] = workdir
        observed["lock"] = (workdir / "package-lock.json").read_bytes()
        observed["manifest"] = (workdir / "package.json").read_bytes()
        return _FIXTURE.read_text(encoding="utf-8"), ""

    gate.run_npm_audit(lock_bytes, runner)

    assert observed["lock"] == lock_bytes
    assert json.loads(observed["manifest"]) == gate.manifest_for(json.loads(lock_bytes))
    assert not observed["dir"].exists()


# --- The command line --------------------------------------------------------------------------


def test_main_passes_on_the_recorded_reading(root: Path) -> None:
    _, runner = _replay(_FIXTURE.read_text(encoding="utf-8"))

    assert gate.main(["--root", str(root)], runner=runner) == 0


def test_main_reds_on_a_new_advisory(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    baseline = set(gate.findings(_report())) - {_LODASH}
    (root / gate.BASELINE_PATH).write_text(_as_toml(baseline), encoding="utf-8")
    _, runner = _replay(_FIXTURE.read_text(encoding="utf-8"))

    assert gate.main(["--root", str(root)], runner=runner) == 1
    assert _LODASH[0] in capsys.readouterr().out


def test_main_fails_closed_without_a_verdict(root: Path) -> None:
    seen, runner = _replay(_TRANSPORT_ERROR)

    assert gate.main(["--root", str(root)], runner=runner, sleep=lambda _s: None) == 2
    assert len(seen) == gate.ATTEMPTS


def test_main_judges_a_saved_report(root: Path, tmp_path: Path) -> None:
    saved = tmp_path / "no-manifest.json"
    saved.write_text(json.dumps(_NO_MANIFEST_REPORT), encoding="utf-8")

    assert gate.main(["--root", str(root), "--report", str(_FIXTURE)]) == 0
    assert gate.main(["--root", str(root), "--report", str(saved)]) == 1


def test_main_prints_the_record_limitation(root: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The scope sentence comes from the provenance record, so the two cannot disagree."""
    gate.main(["--root", str(root), "--report", str(_FIXTURE)])

    assert "does NOT prove this bundle was built from them" in capsys.readouterr().out


# --- The committed baseline --------------------------------------------------------------------


def test_the_committed_baseline_loads() -> None:
    assert gate.load_baseline(REPO_ROOT / gate.BASELINE_PATH)


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ('[[advisory]]\nid = "GHSA-2222-3333-4444"\n', "non-empty id and package"),
        ('[[advisory]]\nid = "CVE-2021-1"\npackage = "x"\n', "unrecognised id"),
        (
            '[[advisory]]\nid = "GHSA-2222-3333-4444"\npackage = "x"\n'
            '[[advisory]]\nid = "GHSA-2222-3333-4444"\npackage = "x"\n',
            "listed twice",
        ),
        ("", "no [[advisory]] entries"),
    ],
)
def test_a_malformed_baseline_raises(tmp_path: Path, body: str, message: str) -> None:
    """A skipped entry would widen the gate silently, so a bad one stops the run instead."""
    path = tmp_path / "baseline.toml"
    path.write_text(body, encoding="utf-8")

    with pytest.raises(ValueError, match=message.replace("[", r"\[").replace("]", r"\]")):
        gate.load_baseline(path)


# --- The wiring --------------------------------------------------------------------------------


def test_the_scheduled_job_runs_the_live_audit() -> None:
    """The job runs the script with no ``--report``, so it audits live rather than a saved file."""
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(
        (REPO_ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    )
    job = workflow["jobs"]["cla-action-audit"]
    runs = [str(step.get("run", "")) for step in job["steps"]]

    assert any(
        "scripts/security/audit_cla_action_lockfile.py" in run and "--report" not in run
        for run in runs
    )
    assert any("setup-node" in str(step.get("uses", "")) for step in job["steps"])

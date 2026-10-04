# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ingress probe's RESULT lines are parsed as data, and no workflow evals or sources command output.

``ingress-rate-probe.yml`` once merged the probe's stderr into its stdout and ``eval``-ed every line
that began ``RESULT``, so any text reaching either stream became shell code.
``scripts/ci/ingress_probe_summary.py`` replaced that. This
file pins the parser's grammar and the workflow-wide absence of at least the shapes it replaced.

The screen is NOT a proof that no workflow executes untrusted text. It sees at least ``eval``,
``source``/``.`` of a process or command substitution, and PowerShell's ``Invoke-Expression``. It
does not see ``bash -c "$x"``, ``pwsh -Command $x``, or sourcing a FILE: ``quality-advisory.yml``
sources ``c901-delta.env`` and ``mutmut-counts.env``, which it writes itself from digit-only counts,
a merge-base SHA and fixed strings.

The round trip against the probe's real output is in ``tests/test_ingress_probe_signed_in.py``,
because that file imports the harness and so runs on the engine legs, where a change to
``harness/load/ingress_probe.py`` is tested. This file is tooling and does not.
"""

from __future__ import annotations

import importlib.util
import io
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "ci" / "ingress_probe_summary.py"
_WORKFLOWS = _ROOT / ".github" / "workflows"
_PROBE_WORKFLOW = _WORKFLOWS / "ingress-rate-probe.yml"

_GOOD = (
    "RESULT rate=60 sent=90 acked=44 stranded=46 pct=51.1 read=52 written=104 sink=104 "
    "backlog=0 ok=True wall=7.31"
)


def _load() -> ModuleType:
    """Import the script by path -- ``scripts/`` is not a package."""
    spec = importlib.util.spec_from_file_location("ingress_probe_summary_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registered before it runs: @dataclass resolves the module's namespace through sys.modules.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


summary = _load()


def _split(result: Any) -> tuple[list[str], list[str]]:
    return result.rows, result.errors


def test_a_measurement_line_renders_its_row() -> None:
    rows, errors = _split(summary.summarise(_GOOD + "\n", rate=60.0, repeat=1))
    assert errors == []
    assert rows == ["| 60/s | 90 | 44 | 46 | 51.1% | 52 | True |"]


def test_a_setup_failure_row_ends_the_run_without_failing_it() -> None:
    text = "ingress probe: noise\nRESULT rate=60 ERROR=provision_failed\n"
    rows, errors = _split(summary.summarise(text, rate=60.0, repeat=3))
    assert errors == []
    assert rows == ["| 60/s | setup failed: provision_failed | | | | | |"]


@pytest.mark.parametrize(
    "line",
    [
        # Shell metacharacters in a value: the line the old `eval` would have executed.
        _GOOD.replace("sent=90", "sent=$(touch${IFS}/tmp/pwned)"),
        _GOOD.replace("ok=True", "ok=True;id"),
        _GOOD.replace("pct=51.1", "pct=`id`"),
        # Grammar violations.
        _GOOD + " extra=1",
        _GOOD.replace(" wall=7.31", ""),
        _GOOD + " sent=91",
        _GOOD.replace("ok=True", "ok=yes"),
        _GOOD.replace("backlog=0", "backlog"),
        "RESULT rate=60 ERROR=Provision Failed",
        "RESULT rate=60 ERROR=x;id",
        "RESULT rate=60 sent=1 ERROR=provision_failed",
    ],
)
def test_a_malformed_line_is_refused(line: str) -> None:
    with pytest.raises(summary.MalformedResult):
        summary.parse_line(line)
    rows, errors = _split(summary.summarise(line + "\n", rate=60.0, repeat=1))
    assert rows == [] and len(errors) == 1


def test_no_result_line_fails() -> None:
    rows, errors = _split(
        summary.summarise("Traceback (most recent call last):\n", rate=60.0, repeat=1)
    )
    assert rows == [] and errors == ["the probe printed no RESULT line"]


def test_too_few_rows_fails() -> None:
    rows, errors = _split(summary.summarise(_GOOD + "\n", rate=60.0, repeat=3))
    assert len(rows) == 1 and errors == ["expected 3 RESULT rows, found 1"]


def test_a_row_for_another_rate_fails() -> None:
    _, errors = _split(summary.summarise(_GOOD + "\n", rate=150.0, repeat=1))
    assert len(errors) == 1 and "offered 150" in errors[0]


def test_a_result_after_a_setup_failure_fails() -> None:
    text = "RESULT rate=60 ERROR=provision_failed\n" + _GOOD + "\n"
    _, errors = _split(summary.summarise(text, rate=60.0, repeat=3))
    assert len(errors) == 1 and "after the setup failure" in errors[0]


def test_lines_that_merely_mention_result_are_ignored() -> None:
    text = "RESULTS follow\n  RESULT_X=1\n" + _GOOD + "\n"
    rows, errors = _split(summary.summarise(text, rate=60.0, repeat=1))
    assert errors == [] and len(rows) == 1


def test_main_copies_stdin_appends_the_summary_and_reports(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    out = tmp_path / "summary.md"
    monkeypatch.setattr(sys, "stdin", io.StringIO("probe chatter\n" + _GOOD + "\n"))
    assert summary.main(["--rate", "60", "--repeat", "1", "--summary", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == "| 60/s | 90 | 44 | 46 | 51.1% | 52 | True |\n"
    assert "probe chatter" in capsys.readouterr().out

    monkeypatch.setattr(sys, "stdin", io.StringIO("RESULT rate=60 sent=$(id)\n"))
    assert summary.main(["--rate", "60", "--repeat", "1", "--summary", str(out)]) == 1
    printed = capsys.readouterr().out
    assert "::error title=ingress probe RESULT::" in printed
    assert "$(id)" not in printed.split("::error", 1)[1], "the raw value reached the annotation"


# --- The workflow-wide screen -------------------------------------------------------------------

# A run line that executes text as shell: at least `eval`, `source`/`.` of a process substitution or
# of a command substitution, and PowerShell's Invoke-Expression. Only whole-line comments are skipped:
# stripping an inline one needs quote tracking, and a false positive here is cheaper than a miss.
_EXECUTES_TEXT = re.compile(
    r"(?:^|[\s;&|({`'\"])"
    r"(?:eval\s|(?:source|\.)\s+<\(|(?:source|\.)\s+\"?\$\(|Invoke-Expression\b|iex\b)",
    re.IGNORECASE,
)


def _yaml() -> Any:
    """PyYAML, for the workflow-reading tests only, so the grammar tests run without it."""
    return pytest.importorskip("yaml")


def _run_bodies(workflow: Any) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for job_id, job in (workflow.get("jobs") or {}).items():
        for index, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict) and isinstance(step.get("run"), str):
                found.append((f"{job_id}[{index}] {step.get('name', '')}", step["run"]))
    return found


def _offending_lines(body: str) -> list[str]:
    hits = []
    for line in body.splitlines():
        if not line.lstrip().startswith("#") and _EXECUTES_TEXT.search(line):
            hits.append(line.strip())
    return hits


def test_the_screen_catches_the_shape_it_replaced() -> None:
    """Positive control: the exact line removed from ingress-rate-probe.yml, and its siblings."""
    removed = (
        "  eval \"$(echo \"$line\" | tr ' ' '\\n' | grep '=' | sed 's/^/P_/')\" 2>/dev/null || true"
    )
    for body in (
        removed,
        "source <(python tool.py)",
        '. "$(mktemp)"',
        "x=1; eval $OUT",
        "Invoke-Expression (tool.exe)",
        "iex($env:OUT)",
        "result=`eval $cmd`",
        "bash -c 'eval \"$x\"'",
    ):
        assert _offending_lines(body), body
    assert _offending_lines('echo "Step #1"; eval "$z"'), "an inline ` #` must not hide the eval"
    for body in ("# eval is forbidden here", "echo evaluate", "python -m retrieval"):
        assert not _offending_lines(body), body


def test_no_workflow_step_evals_or_sources_command_output() -> None:
    workflows = sorted([*_WORKFLOWS.glob("*.yml"), *_WORKFLOWS.glob("*.yaml")])
    assert _PROBE_WORKFLOW in workflows
    offenders = []
    for path in workflows:
        for where, body in _run_bodies(_yaml().safe_load(path.read_text(encoding="utf-8"))):
            offenders += [f"{path.name} {where}: {hit}" for hit in _offending_lines(body)]
    assert offenders == [], "\n".join(offenders)


def test_the_probe_step_parses_stdout_only_through_the_summary_script() -> None:
    workflow = _yaml().safe_load(_PROBE_WORKFLOW.read_text(encoding="utf-8"))
    (body,) = [b for _, b in _run_bodies(workflow) if "harness.load.ingress_probe" in b]
    # Join `\`-continued lines so the whole probe pipeline is one string.
    commands = body.replace("\\\n", " ").splitlines()
    pipeline = next(line for line in commands if "harness.load.ingress_probe" in line)
    for merge in ("2>&1", "|&", "/dev/stdout"):
        assert merge not in body, f"stderr must never reach the parser ({merge})"
    assert "| python scripts/ci/ingress_probe_summary.py" in pipeline
    # The parser's status is PIPESTATUS[1], taken in the `||` so -e cannot end the sweep first.
    assert pipeline.rstrip().endswith('|| status=("${PIPESTATUS[@]}")'), pipeline
    assert 'case "${status[1]}" in' in body and 'case "${status[0]}" in' in body
    assert "grep '^RESULT'" not in body
    assert re.search(r'exit "\$bad"\s*$', body), "a failed parse must fail the step"


def test_a_setup_failure_alone_exits_3_and_a_measurement_exits_0(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The workflow reds a sweep in which no rate measured anything; this status is how it knows."""
    out = tmp_path / "summary.md"
    args = ["--rate", "60", "--repeat", "3", "--summary", str(out)]
    monkeypatch.setattr(sys, "stdin", io.StringIO("RESULT rate=60 ERROR=engine_did_not_start\n"))
    assert summary.main(args) == summary.SETUP_FAILED_ONLY == 3
    monkeypatch.setattr(
        sys, "stdin", io.StringIO(_GOOD + "\nRESULT rate=60 ERROR=engine_did_not_start\n")
    )
    assert summary.main(args) == 0


def test_engine_counter_differences_may_be_negative() -> None:
    assert summary.parse_line(_GOOD.replace("read=52", "read=-3"))["read"] == "-3"
    with pytest.raises(summary.MalformedResult):
        summary.parse_line(_GOOD.replace("sent=90", "sent=-1"))


def test_more_rows_than_repeats_fails_even_after_a_setup_failure() -> None:
    text = _GOOD + "\nRESULT rate=60 ERROR=provision_failed\n"
    _, errors = _split(summary.summarise(text, rate=60.0, repeat=1))
    assert errors == ["expected 1 RESULT rows, found 2"]


def test_on_a_runner_the_copied_output_cannot_issue_workflow_commands(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setattr(sys, "stdin", io.StringIO("::add-mask::x\nRESULT rate=60 sent=1\n"))
    assert summary.main(["--rate", "60", "--repeat", "1", "--summary", str(tmp_path / "s")]) == 1
    lines = capsys.readouterr().out.splitlines()
    stop = next(i for i, line in enumerate(lines) if line.startswith("::stop-commands::"))
    token = lines[stop].removeprefix("::stop-commands::")
    resume = lines.index(f"::{token}::")
    assert stop < lines.index("::add-mask::x") < resume
    assert any(line.startswith("::error ") for line in lines[resume:]), "the annotation must fire"

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The nightly-failure notice must fire on the right runs, and only those.

THE DEFECT THIS EXISTS FOR. A scheduled run's failure reported nowhere. Measured 2026-07-30: the
``load test (smoke, sqlserver)`` legs had been red for FOUR consecutive nights and nothing surfaced it;
5 of the last 14 nightlies had failed. A nightly is not a PR context, and the one thing that could
carry it onto a merge path -- the ``CI gate`` roll-up -- correctly treats a SKIPPED leg as a pass,
because those legs do not run on PRs at all. So the server-DB store, load/throughput and service-smoke
suites (exactly what the three required ``test`` legs SKIP) could break invisibly.

``.github/workflows/nightly-notice.yml`` turns that silence into one deduplicated issue. This module
pins the structural ways it could quietly stop working, and then EXECUTES the parts that decide.

TWO HALVES, AND THE SPLIT IS THE POINT (BACKLOG #318). Delivery is GitHub's: it matches the completed
run's ``name:`` against ``workflows:`` and dispatches. Nothing here can drive that, and a
``workflow_run`` workflow only triggers from the **default branch**, so it cannot even fire on the PR
that edits it — that half is unverifiable until it is on ``main``, and the structural assertions below
are what can honestly be said about it before it ships.

The DECISION is this repository's, and it is shell: the job's ``if:`` gate and the step's ``run:``
body choose whether a completed run becomes an issue, which issue, and whether an existing one closes.
That half IS driven here, under ``bash -e`` against a stubbed ``gh``, because "the watch list contains
the string DAST" is a much weaker claim than "a red DAST nightly produces a DAST issue and a green CI
nightly does not close it". BACKLOG #318 recorded this notice as the fix for a detector that could not
report; a test asserting the config text and not the behaviour would be the same defect one level up.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import NamedTuple

import pytest
from _bash_resolver import explain_returncode, probe_env, require_bash

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOWS = _REPO / ".github" / "workflows"
_NOTICE = _WORKFLOWS / "nightly-notice.yml"
_CI = _WORKFLOWS / "ci.yml"


def _load(path: Path) -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _on(doc: dict) -> dict:
    """The `on:` block. PyYAML parses a bare ``on:`` key as the BOOLEAN True, so reading ``doc["on"]``
    returns None and every assertion below would pass against nothing."""
    block = doc.get(True, doc.get("on"))
    assert isinstance(block, dict), f"could not read the `on:` block — got {block!r}"
    return block


def test_it_keys_on_the_ci_workflow_s_actual_name() -> None:
    """``workflow_run`` matches on the workflow's ``name:``, not its filename.

    Rename `ci.yml`'s `name:` and this notice silently never fires again — no error, no run, just
    permanent silence. That is the same failure mode the notice exists to fix, so it gets a guard.
    """
    watched = _on(_load(_NOTICE))["workflow_run"]["workflows"]
    ci_name = _load(_CI).get("name")
    assert ci_name, "ci.yml has no `name:` — workflow_run has nothing to key on"
    assert ci_name in watched, (
        f"nightly-notice.yml watches {watched} but ci.yml is named {ci_name!r}. A workflow_run trigger "
        "matches on the workflow NAME; a mismatch means the notice never fires again, silently."
    )


def test_it_also_watches_the_security_workflow() -> None:
    """security.yml's daily cron carries jobs no PR can trigger, so its failures need this notice too."""
    watched = _on(_load(_NOTICE))["workflow_run"]["workflows"]
    sec_name = _load(_WORKFLOWS / "security.yml").get("name")
    assert sec_name, "security.yml has no `name:` — workflow_run has nothing to key on"
    assert sec_name in watched, (
        f"nightly-notice.yml watches {watched} but security.yml is named {sec_name!r}. Its "
        "schedule-only jobs — released-line-audit above all — would then fail into silence."
    )


def test_it_also_watches_the_dast_workflow() -> None:
    """DAST needs this more than either of the others (BACKLOG #318).

    ``dast.yml`` has NO ``pull_request`` trigger at all -- deliberately -- so before this widening a
    genuine authorization finding surfaced in the Actions tab and nowhere else. An authenticated
    security sweep reporting into the void is the exact shape this notice exists to end.
    """
    watched = _on(_load(_NOTICE))["workflow_run"]["workflows"]
    dast_name = _load(_WORKFLOWS / "dast.yml").get("name")
    assert dast_name, "dast.yml has no `name:` -- workflow_run has nothing to key on"
    assert dast_name in watched, (
        f"nightly-notice.yml watches {watched} but dast.yml is named {dast_name!r}. Its findings "
        "would then reach nobody, which is the gap BACKLOG #318 recorded."
    )


def test_every_watched_workflow_exists_and_can_actually_fire() -> None:
    """A watched name that no workflow answers to, or that has no cron, is dead config reading as
    coverage.

    The notice job gates on ``workflow_run.event == 'schedule'``, so a watched workflow with no
    ``schedule:`` trigger can never satisfy it -- the name sits in the list looking like protection
    and matches nothing, forever, silently. That is the same failure the notice exists to fix, one
    level up, so it is asserted for EVERY watched name rather than per workflow.
    """
    watched = _on(_load(_NOTICE))["workflow_run"]["workflows"]
    assert watched, "the watch list is empty"

    by_name: dict[str, Path] = {}
    for path in sorted(_WORKFLOWS.glob("*.yml")):
        name = _load(path).get("name")
        if isinstance(name, str):
            by_name.setdefault(name, path)
    # Positive control: the scan must actually be reading workflows, or every assertion below would
    # be vacuous against an empty map.
    assert len(by_name) > 5, f"the workflow scan found only {len(by_name)} named files"

    for name in watched:
        path = by_name.get(name)
        assert path is not None, (
            f"nightly-notice.yml watches {name!r} but no workflow in {_WORKFLOWS.name}/ is named that. "
            f"A workflow_run trigger matches on the NAME, so this entry can never fire. "
            f"Names present: {sorted(by_name)}"
        )
        triggers = _on(_load(path))
        assert "schedule" in triggers, (
            f"nightly-notice.yml watches {name!r} ({path.name}) but that workflow has no `schedule:` "
            "trigger. The notice job only fires when the completed run's event was `schedule`, so "
            "this entry can never match -- dead config that reads as coverage."
        )


def test_the_issue_body_names_the_workflow_that_failed() -> None:
    """The TITLE was always derived from the completed workflow; the BODY was not.

    It opened with a hardcoded "CI failed" whatever had run, so a red Security run produced an issue
    whose first line named the wrong workflow. Harmless-looking, and exactly the kind of thing a
    reader uses to decide what broke. Widening the watch list to a third workflow made it worse
    rather than introducing it.
    """
    body = "\n".join(
        str(s.get("run", "")) for s in _load(_NOTICE)["jobs"]["notice"]["steps"] if "run" in s
    )
    assert body, "the notice job has no `run:` step to inspect"
    assert "Nightly (scheduled) $WF_NAME failed." in body, (
        "the issue body does not name the workflow that actually failed. It must read from $WF_NAME, "
        "the same value the title is derived from, or it will assert the wrong workflow broke."
    )
    assert "Nightly (scheduled) CI failed." not in body, (
        "the body still hardcodes CI, so a Security or DAST failure opens an issue naming CI."
    )


def test_it_only_reacts_to_scheduled_runs() -> None:
    """Without this gate every PR and push failure opens an issue.

    `workflow_run` fires for EVERY completion of the watched workflow regardless of what triggered it.
    A PR failure is already visible on the PR, so alerting there is noise — and noise is how an alert
    stops being read, which would defeat the whole point.
    """
    job = _load(_NOTICE)["jobs"]["notice"]
    condition = str(job.get("if", ""))
    assert "workflow_run.event" in condition and "'schedule'" in condition, (
        f"the notice job's `if:` is {condition!r} — it must gate on "
        "`github.event.workflow_run.event == 'schedule'`. Without it, every PR/push CI failure opens "
        "or comments on an issue."
    )


def test_it_is_least_privilege() -> None:
    """`issues: write` is scoped to the one job that needs it; the workflow default stays read-only."""
    doc = _load(_NOTICE)
    assert doc.get("permissions") == {"contents": "read"}, (
        f"top-level permissions are {doc.get('permissions')!r}; keep the default read-only so a new job "
        "added here cannot inherit write scope by accident."
    )
    job_perms = doc["jobs"]["notice"].get("permissions")
    assert job_perms == {"issues": "write"}, (
        f"the notice job's permissions are {job_perms!r}. It needs exactly `issues: write` — nothing "
        "more, and it must be declared at the JOB so the rest of the file stays read-only."
    )


def test_it_pulls_in_no_third_party_actions() -> None:
    """Nothing to SHA-pin, nothing to rot.

    The step uses the preinstalled `gh` CLI. If a `uses:` ever appears here it must be SHA-pinned like
    every other action in this repo, so this fails and forces that decision rather than letting an
    unpinned tag arrive in a workflow holding `issues: write`.
    """
    steps = _load(_NOTICE)["jobs"]["notice"]["steps"]
    used = [s["uses"] for s in steps if "uses" in s]
    assert not used, (
        f"nightly-notice.yml now uses third-party action(s) {used} in a job with `issues: write`. "
        "SHA-pin them and update this test deliberately."
    )


def test_it_distinguishes_failure_from_cancelled() -> None:
    """A cancelled nightly is not a break, and reporting it as one trains the reader to ignore this.

    Asserted against the script text because the branch logic is shell: the point is that `cancelled`
    and `skipped` take the no-op path rather than falling into the failure branch.
    """
    body = "\n".join(
        str(s.get("run", "")) for s in _load(_NOTICE)["jobs"]["notice"]["steps"] if "run" in s
    )
    assert body, "the notice job has no `run:` step to inspect"
    assert '"$CONCLUSION" != "failure"' in body, (
        "the script does not explicitly narrow to CONCLUSION == failure. Without that, a `cancelled` "
        "nightly (a superseded or manually-stopped run) is reported as a break."
    )
    assert '"$CONCLUSION" = "success"' in body, (
        "the script has no success branch, so the issue never closes itself and becomes a permanent "
        "nag — an alert that is always on is the same as no alert."
    )


# ---------------------------------------------------------------------------------------------------
# Behavioural: the shipped `if:` gate and the shipped `run:` body, EXECUTED
#
# Everything above reads YAML and asserts on strings. That is the right instrument for the wiring and
# the wrong one for the decision: a watch list containing "DAST" says nothing about what happens when
# a DAST run completes, and BACKLOG #318 filed this notice precisely because a detector that cannot
# report is worthless. So the gate is evaluated against event payloads, and the step body is run under
# `bash -e` -- the shell Actions applies by default -- against a `gh` stub that records what it was
# asked to do.
#
# The stub is what makes this a measurement rather than a rehearsal. The title matching lives inside
# `gh --jq`, not in the shell, so the stub reads the title OUT of the `--jq` expression the script
# built and answers from a canned set of open issues. That turns "which issue did this run look for?"
# into an observation, which is the one question the cross-workflow isolation rows below turn on.
# ---------------------------------------------------------------------------------------------------

#: Field and record separators for the stub's journal. A `gh issue create --body` argument is
#: MULTI-LINE, so a line-per-call journal cannot be parsed back unambiguously; ASCII 0x1e/0x1d exist
#: for exactly this and appear in none of the values under test.
_ARG_SEP = "\x1e"
_CALL_SEP = "\x1d"

#: The env the harness supplies. Keys are asserted to equal the step's OWN `env:` keys by
#: `test_the_harness_supplies_exactly_the_inputs_the_step_declares`, so an input added to the workflow
#: reds here instead of aborting the body under `set -u` with a message about the harness.
_FIXTURE_ENV = {
    "GH_TOKEN": "stub-token-never-used",
    "GH_REPO": "example/messagefoundry",
    "CONCLUSION": "",  # supplied per row
    "RUN_URL": "https://example.invalid/actions/runs/424242",
    "RUN_STARTED": "2026-09-04T05:00:00Z",
    "HEAD_SHA": "0123456789abcdef0123456789abcdef01234567",
    "WF_NAME": "",  # supplied per row
}

_GH_STUB = r"""#!/usr/bin/env bash
# Journal FIRST, in every arm, so even the call that answers nothing proves it was made.
{
  printf '%s\036' "$@"
  printf '\035'
} >> '@JOURNAL@'

if [ "${1:-}" = "issue" ] && [ "${2:-}" = "list" ]; then
  expr=''
  while [ "$#" -gt 0 ]; do
    if [ "$1" = '--jq' ]; then expr="${2:-}"; fi
    shift
  done
  # Real `gh` filters with its embedded jq. Rather than reimplement that, read back the title the
  # script asked for -- and REFUSE, loudly, if the query is no longer the shape this can read. A stub
  # that silently answered "no match" to a query it did not understand would report every row as
  # "opened a new issue" and look like agreement.
  marker='select(.title == "'
  case "$expr" in
    *"$marker"*) ;;
    *)
      printf 'STUB: the --jq expression carries no %s...: %s\n' "$marker" "$expr" >&2
      exit 3
      ;;
  esac
  rest="${expr#*"$marker"}"
  q='"'
  want="${rest%%"$q"*}"
  printf '%s\n' "$want" >> '@SEARCHED@'
  case "$want" in
@CASES@
    *) : ;;
  esac
  exit 0
fi
exit 0
"""


class NoticeRun(NamedTuple):
    """What the shipped body did, and what it said while doing it.

    `stdout`/`stderr` are carried because a failing row's most useful sentence is the script's own --
    it echoes `commented on #N`, `opened a new issue` or `nightly concluded '<x>'` -- and a harness
    that captures those and drops them turns a one-line diagnosis into a bisect.
    """

    rc: int
    stdout: str
    stderr: str
    calls: list[list[str]]
    searched_for: list[str]


def _notice_step() -> dict:
    """The single `run:` step of the notice job, asserted to be single.

    A second `run:` step would mean this harness executes a fragment of the decision while reporting
    on all of it.
    """
    steps = [s for s in _load(_NOTICE)["jobs"]["notice"]["steps"] if "run" in s]
    assert len(steps) == 1, (
        f"expected exactly one `run:` step in the notice job, found {len(steps)}"
    )
    return steps[0]


def _gh_journal(tmp_path: Path) -> Path:
    """Where the stub records its argv -- OUTSIDE the stub directory.

    `_assert_the_stub_won` asks every file in the stub directory to resolve as a command, so a journal
    sitting beside `gh` would be reported as a bypassed stub.
    """
    return tmp_path / "gh.calls"


def _gh_searched(tmp_path: Path) -> Path:
    return tmp_path / "gh.searched"


def _gh_stub(tmp_path: Path, open_issues: dict[str, int]) -> Path:
    """A `gh` on PATH that answers `issue list` from `open_issues` and records every call."""
    stub_dir = tmp_path / "ghstub"
    stub_dir.mkdir()
    cases = "\n".join(
        f"    {shlex.quote(title)}) printf '%s\\n' {number} ;;"
        for title, number in open_issues.items()
    )
    script = (
        _GH_STUB.replace("@JOURNAL@", _gh_journal(tmp_path).as_posix())
        .replace("@SEARCHED@", _gh_searched(tmp_path).as_posix())
        .replace("@CASES@", cases)
    )
    stub = stub_dir / "gh"
    stub.write_text(script, encoding="utf-8", newline="\n")
    stub.chmod(0o755)
    return stub_dir


def _assert_the_stub_won(bash: str, stub_dir: Path, env: dict[str, str]) -> None:
    """Prepending a directory to PATH is not the same as the stub being CHOSEN, and the gap is silent.

    A real `gh` is on PATH on plenty of developer boxes and on every GitHub runner, and it would
    answer with a live API call against whatever repository the environment points at. Asked by
    RESOLUTION (`command -v`) rather than by reading `$PATH` back, because reading the string back
    would only confirm what this function just set.
    """
    out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [bash, "-c", "command -v gh || echo MISSING-gh"],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
        check=False,
    )
    resolved = out.stdout.strip()
    assert stub_dir.name in resolved.replace("\\", "/"), (
        f"the `gh` stub did NOT win in the child environment -- `command -v gh` resolved to "
        f"{resolved!r}. The body would have run against the REAL gh (and the live GitHub API), so "
        f"any verdict from it is about nothing. Stub dir: {stub_dir}. Bash: {bash}."
    )


def _read_calls(tmp_path: Path) -> list[list[str]]:
    journal = _gh_journal(tmp_path)
    if not journal.exists():
        return []
    calls: list[list[str]] = []
    for record in journal.read_text(encoding="utf-8").split(_CALL_SEP):
        if not record:
            continue
        args = record.split(_ARG_SEP)
        assert args[-1] == "", f"malformed gh journal record: {record!r}"
        calls.append(args[:-1])
    return calls


def _run_notice(
    tmp_path: Path,
    *,
    workflow: str,
    conclusion: str,
    open_issues: dict[str, int] | None = None,
) -> NoticeRun:
    """Execute the SHIPPED `run:` body verbatim under `bash -e`."""
    # NOT `shutil.which("bash")` (BACKLOG #1216): that answers whether A bash exists, not whether the
    # one found shares this process's filesystem namespace and preserves the PATH order the stub
    # depends on. On Windows it resolves the WSL launcher, and every row would fail for a reason
    # unrelated to the workflow.
    bash = require_bash(tmp_path)
    body = str(_notice_step()["run"])
    # Executing the body VERBATIM is only sound while it interpolates nothing: a `${{ }}` would be
    # substituted by Actions and left literal here, so this harness would stop running what CI runs.
    assert "${{" not in body, (
        "the notice body interpolates an Actions expression, so this harness is no longer executing "
        "what CI executes"
    )
    script = tmp_path / "notice.sh"
    script.write_text(body, encoding="utf-8", newline="\n")

    stub_dir = _gh_stub(tmp_path, open_issues or {})
    env = probe_env(Path(bash), dict(os.environ))
    env.update({k: v for k, v in _FIXTURE_ENV.items() if v})
    env["CONCLUSION"] = conclusion
    env["WF_NAME"] = workflow
    env["PATH"] = f"{stub_dir.as_posix()}{os.pathsep}{env.get('PATH', '')}"
    _assert_the_stub_won(bash, stub_dir, env)

    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [bash, "-e", script.as_posix()],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    searched_file = _gh_searched(tmp_path)
    searched = (
        searched_file.read_text(encoding="utf-8").splitlines() if searched_file.exists() else []
    )
    return NoticeRun(proc.returncode, proc.stdout, proc.stderr, _read_calls(tmp_path), searched)


def _diagnostic(run: NoticeRun) -> str:
    """The child's own words. An empty stream says so, because a silent child and a harness that
    dropped its output are different faults with the same appearance."""
    return (
        f"\n--- rc: {run.rc} ({explain_returncode(run.rc, 'the notice body')})"
        f"\n--- stdout ---\n{run.stdout.strip() or '(no stdout)'}"
        f"\n--- stderr ---\n{run.stderr.strip() or '(no stderr)'}"
        f"\n--- gh calls ---\n{run.calls or '(none)'}"
        f"\n--- titles searched for ---\n{run.searched_for or '(none)'}"
    )


def _opt(argv: list[str], flag: str) -> str:
    """The value following `flag` in a recorded argv."""
    assert flag in argv, f"{flag} not in {argv}"
    return argv[argv.index(flag) + 1]


def _writes(run: NoticeRun) -> list[list[str]]:
    """Every gh call that CHANGES something. `issue list` is a read and is excluded."""
    return [c for c in run.calls if len(c) >= 2 and c[0] == "issue" and c[1] != "list"]


def _ok(run: NoticeRun) -> None:
    assert run.rc == 0, f"the notice body aborted under `bash -e`{_diagnostic(run)}"


def test_the_harness_supplies_exactly_the_inputs_the_step_declares() -> None:
    """The fixture env must be the step's env, or the rows below measure a different script.

    The body runs under `set -u`, so an input ADDED to the workflow aborts it -- loudly, but with a
    message about an unbound variable rather than about the workflow. An input REMOVED is the quieter
    half: the harness would keep supplying it and nothing would notice.
    """
    declared = set(_notice_step().get("env") or {})
    assert declared == set(_FIXTURE_ENV), (
        f"the step declares env {sorted(declared)} but this harness supplies "
        f"{sorted(_FIXTURE_ENV)}. Update `_FIXTURE_ENV` deliberately."
    )


def test_a_red_dast_nightly_opens_an_issue_that_names_dast(tmp_path: Path) -> None:
    """THE ROW BACKLOG #318 EXISTS FOR: a DAST finding must reach a person.

    Not "the watch list contains DAST" -- the shipped script, run, producing an `issue create` whose
    title, label and body are the DAST ones.
    """
    run = _run_notice(tmp_path, workflow="DAST", conclusion="failure", open_issues={})
    _ok(run)
    creates = [c for c in run.calls if c[:2] == ["issue", "create"]]
    assert len(creates) == 1, f"expected exactly one `gh issue create`{_diagnostic(run)}"
    argv = creates[0]
    assert _opt(argv, "--title") == "Nightly DAST is failing", _diagnostic(run)
    assert _opt(argv, "--label") == "bug", _diagnostic(run)
    body = _opt(argv, "--body")
    assert "Nightly (scheduled) DAST failed." in body, (
        f"the issue body does not name DAST as the workflow that failed{_diagnostic(run)}"
    )
    assert _FIXTURE_ENV["RUN_URL"] in body and _FIXTURE_ENV["HEAD_SHA"] in body, (
        f"the body omits the run link or the commit -- the two things a reader acts on"
        f"{_diagnostic(run)}"
    )
    assert run.searched_for == ["Nightly DAST is failing"], _diagnostic(run)


def test_a_second_red_dast_nightly_comments_instead_of_opening_a_duplicate(tmp_path: Path) -> None:
    """Dedup is what keeps this readable across a run of red nights."""
    run = _run_notice(
        tmp_path,
        workflow="DAST",
        conclusion="failure",
        open_issues={"Nightly DAST is failing": 4242},
    )
    _ok(run)
    assert [c[:3] for c in _writes(run)] == [["issue", "comment", "4242"]], _diagnostic(run)
    assert "Nightly (scheduled) DAST failed." in _opt(_writes(run)[0], "--body"), _diagnostic(run)


def test_a_green_dast_nightly_closes_the_dast_issue(tmp_path: Path) -> None:
    """An alert that is always on is the same as no alert, so recovery must close it."""
    run = _run_notice(
        tmp_path,
        workflow="DAST",
        conclusion="success",
        open_issues={"Nightly DAST is failing": 4242},
    )
    _ok(run)
    assert ["issue", "close", "4242"] in [c[:3] for c in _writes(run)], _diagnostic(run)
    commented = _opt(next(c for c in _writes(run) if c[1] == "comment"), "--body")
    assert "DAST is green again" in commented, _diagnostic(run)


@pytest.mark.parametrize("conclusion", ["cancelled", "skipped", "timed_out"])
def test_a_dast_run_that_did_not_fail_writes_nothing(conclusion: str, tmp_path: Path) -> None:
    """A cancelled nightly is usually superseded or manually stopped. Reporting it as a break trains
    the reader to ignore this, which is the failure mode the notice exists to end."""
    run = _run_notice(tmp_path, workflow="DAST", conclusion=conclusion, open_issues={})
    _ok(run)
    assert _writes(run) == [], f"a {conclusion!r} run wrote something{_diagnostic(run)}"


def test_a_green_ci_nightly_cannot_close_the_dast_issue(tmp_path: Path) -> None:
    """THE ISOLATION CONTROL, and the reason the title is derived rather than hardcoded.

    Widening the watch list to three workflows created a way for one signal to silence another: a
    single shared issue title would let a green nightly CI close the issue a red DAST run opened, and
    the DAST finding would vanish with nothing anywhere reporting a problem. This row fails against
    exactly that defect -- the DAST issue is open, CI is green, and nothing may touch it.
    """
    run = _run_notice(
        tmp_path,
        workflow="CI",
        conclusion="success",
        open_issues={"Nightly DAST is failing": 4242},
    )
    _ok(run)
    assert _writes(run) == [], (
        f"a GREEN CI nightly touched an issue opened by a RED DAST run{_diagnostic(run)}"
    )
    assert run.searched_for == ["Nightly CI is failing"], (
        f"the script searched for {run.searched_for} -- it must key on the workflow that COMPLETED, "
        f"or the three signals share one issue{_diagnostic(run)}"
    )
    assert "no open issue" in run.stdout, _diagnostic(run)


def test_a_red_dast_nightly_does_not_comment_on_cis_issue(tmp_path: Path) -> None:
    """The same isolation in the other direction: a red DAST run must not append to CI's issue."""
    run = _run_notice(
        tmp_path,
        workflow="DAST",
        conclusion="failure",
        open_issues={"Nightly CI is failing": 7},
    )
    _ok(run)
    assert [c[:2] for c in _writes(run)] == [["issue", "create"]], _diagnostic(run)
    assert "7" not in [c[2] for c in _writes(run) if len(c) > 2], _diagnostic(run)


#: The job's `if:` is `<github path> == '<literal>'` and nothing more. Anything else must reach a
#: human rather than be guessed at, so this pattern is the whole accepted grammar.
_IF_CONDITION = re.compile(
    r"^\s*(?P<lhs>github(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*==\s*'(?P<rhs>[^']*)'\s*$"
)


def _gate_fires(condition: str, workflow_run: dict[str, str]) -> bool:
    """Evaluate the job's shipped `if:` against a `workflow_run` payload.

    DELIBERATELY NOT a general Actions expression evaluator -- a second, silently different
    implementation of that language is worth less than nothing. It accepts one shape and refuses
    everything else, so rewriting the gate reds here and gets read rather than silently passing
    against an approximation.
    """
    match = _IF_CONDITION.match(condition)
    assert match is not None, (
        f"the notice job's `if:` is {condition!r}, which is not the `<path> == '<literal>'` shape "
        f"this evaluator accepts. Re-read the gate and update this test deliberately -- do not widen "
        f"the evaluator into a general Actions expression engine."
    )
    node: object = {"github": {"event": {"workflow_run": workflow_run}}}
    for part in match.group("lhs").split("."):
        assert isinstance(node, dict) and part in node, (
            f"the gate reads `{match.group('lhs')}`, and this payload has no {part!r}"
        )
        node = node[part]
    return node == match.group("rhs")


@pytest.mark.parametrize(
    ("event", "expected"),
    [
        # The DAST cron. Without this the whole chain is dead however the watch list reads.
        ("schedule", True),
        # dast.yml's other two arms. A tag push and a manual dispatch are both watched by a human who
        # asked for them, so an issue there is noise -- and noise is how an alert stops being read.
        ("push", False),
        ("workflow_dispatch", False),
    ],
)
def test_the_gate_passes_a_scheduled_dast_run_and_only_that(event: str, expected: bool) -> None:
    """dast.yml carries THREE triggers, and only one of them may reach the issue-writing body."""
    condition = str(_load(_NOTICE)["jobs"]["notice"].get("if", ""))
    payload = {"name": "DAST", "event": event, "conclusion": "failure"}
    assert _gate_fires(condition, payload) is expected, (
        f"a DAST run triggered by {event!r} -> gate fires {not expected}, expected {expected}"
    )

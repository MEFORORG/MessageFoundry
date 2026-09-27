# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

from tests._workflow_contexts import context_of, jobs_of, on_block

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOWS = _REPO / ".github" / "workflows"
_NOTICE = _WORKFLOWS / "nightly-notice.yml"
_CI = _WORKFLOWS / "ci.yml"


def _load(path: Path) -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _on(doc: dict) -> dict:
    """The `on:` block, via the SHARED reader rather than another hand-rolled copy.

    The reasoning lives with the reader, in ``tests/_workflow_contexts.on_block``.

    IT IS NOT YET THE ONLY COPY, and saying so matters more than the tidy claim. At least seven other
    test modules still hand-roll the same dance in at least three spellings that do not agree on the
    quoted ``"on":`` case. This module was migrated because it is the one under change; migrating the
    rest is a filed follow-up, unallocated. A reader here should not infer the sweep happened.
    """
    return on_block(doc)


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


def test_it_also_watches_the_stalled_prs_workflow() -> None:
    """A detector whose own failure hides itself is worse than the defect it was built to catch.

    ``stalled-prs.yml`` is schedule-and-dispatch only, so it can never report on a pull request, and
    it reports on OTHER pull requests -- so a run that stopped producing a report is indistinguishable
    from a day with nothing to report. It FAILED THREE MORNINGS RUNNING (2026-09-03, 09-04 and 09-05;
    runs 33753049186, 33870995359, 33962763074) and nothing anywhere said so.
    """
    watched = _on(_load(_NOTICE))["workflow_run"]["workflows"]
    stalled_name = _load(_WORKFLOWS / "stalled-prs.yml").get("name")
    assert stalled_name, "stalled-prs.yml has no `name:` -- workflow_run has nothing to key on"
    assert stalled_name in watched, (
        f"nightly-notice.yml watches {watched} but stalled-prs.yml is named {stalled_name!r}. Its "
        "daily red would then reach nobody, and its silence reads exactly like a clean sweep."
    )


def test_it_also_watches_the_required_workflow_state_workflow() -> None:
    """BACKLOG #1450: the branch-protection reconciles had a detector and no consumer.

    Why that workflow's cron needed a consumer is recorded once, in ``nightly-notice.yml``'s own
    header; the drift incident that measured the cost is recorded once, in
    ``scripts/ci/check_required_contexts_drift.py``'s docstring.

    IT IS NOT A DUPLICATE OF
    ``test_required_contexts_drift.py::test_the_scheduled_red_of_this_checker_reaches_a_person``, and
    the difference is the SUBJECT rather than the assertion. That row follows the drift SCRIPT: move
    the ``accurate`` step into some other watched workflow and it is satisfied. This row follows the
    FILE, which also carries ``reachable`` -- a job that runs no such script and would then be left
    scheduled, advisory and unwatched, with nothing red. Neither covers the other's move.
    """
    watched = _on(_load(_NOTICE))["workflow_run"]["workflows"]
    state_name = _load(_WORKFLOWS / "required-workflow-state.yml").get("name")
    assert state_name, (
        "required-workflow-state.yml has no `name:` -- workflow_run has nothing to key on"
    )
    assert state_name in watched, (
        f"nightly-notice.yml watches {watched} but required-workflow-state.yml is named "
        f"{state_name!r}. Its cron would then go red with no pull request, label or notice carrying "
        "it -- the alerting gap BACKLOG #1450 recorded, which is NOT fixed by adding a second "
        "detector."
    )


def test_the_shared_on_reader_handles_every_workflow_in_this_repository() -> None:
    """The corpus arm. ``on:`` has three value spellings and this repository already uses two.

    ``_on`` above delegates to ``tests/_workflow_contexts.on_block``, which is a SHARED reader -- the
    natural next caller is a sweep over every workflow, e.g. the coverage guard
    ``nightly-notice.yml``'s own header records as the next defect. An earlier revision of that reader
    asserted ``isinstance(block, dict)`` and would have raised on ``dependabot-auto-merge.yml``, whose
    ``on:`` is the bare string ``pull_request``.

    Asserted over the real directory rather than over invented documents, because the point is that
    the reader survives what is actually checked in.

    BOTH EXTENSIONS. GitHub Actions reads `.yaml` as well as `.yml`, so a `*.yml` glob would let a
    `.yaml` workflow sit outside the corpus while the test name claims the whole repository -- the
    positive control would still pass, because it only proves the glob found files, not that it was
    aimed at the population. There are no `.yaml` workflows today; the glob is for when there are.
    """
    paths = sorted([*_WORKFLOWS.glob("*.yml"), *_WORKFLOWS.glob("*.yaml")])
    # Positive control: an empty glob would make every assertion below vacuous.
    assert len(paths) > 5, f"the workflow scan found only {len(paths)} files"
    for path in paths:
        triggers = _on(_load(path))
        assert triggers, f"{path.name} parsed to an empty `on:` block, so it can never run"


#: One arm label of the shipped `case "$WF_NAME" in`, e.g. `    "DAST")`.
_CASE_ARM = re.compile(r'^"([^"]+)"\)$')


def _case_arms() -> dict[str, str]:
    """Arm label -> the prose that arm puts in the issue body, AS THE READER WILL SEE IT.

    Read out of the SHIPPED script rather than restated here, so an arm added or renamed is covered
    without touching this helper. Comment lines are dropped: they never reach a reader.

    TWO NORMALISATIONS, AND SKIPPING EITHER MAKES EVERY "is this text in the body?" CHECK A FALSE
    NEGATIVE -- which is the quiet direction, because the assertion still passes when the text leaked.
    Backticks are backslash-escaped inside the double-quoted shell string and arrive unescaped; the
    assignment's opening ``DETAIL="`` and its closing quote are shell syntax and reach nobody.
    Indentation is deliberately NOT stripped: the sub-bullets are indented in the issue too, so
    trimming here would stop these matching the body they were read from.
    """
    arms: dict[str, str] = {}
    label: str | None = None
    buf: list[str] = []
    for raw in str(_notice_step()["run"]).splitlines():
        line = raw.strip()
        if (match := _CASE_ARM.match(line)) is not None:
            label, buf = match.group(1), []
        elif label is not None and line == ";;":
            arms[label] = "\n".join(buf).removesuffix('"').replace("\\`", "`")
            label, buf = None, []
        elif label is not None and line and not line.startswith("#"):
            buf.append(line.removeprefix('DETAIL="') if line.startswith('DETAIL="') else raw)
    # Positive control, keyed to the WATCH LIST rather than to a constant. A literal `>= 4` written
    # beside a five-arm block is a quorum the population has already passed: delete an arm and it
    # still holds. test_every_case_arm_names_a_watched_workflow asserts the two sets are equal, so
    # this only has to catch the parser silently matching nothing.
    assert arms, "the `case` block parsed to no arms at all -- the arm expression stopped matching"
    return arms


def _arm_lines() -> dict[str, frozenset[str]]:
    """Every SUBSTANTIVE line of each arm, for screening one arm's text out of another's issue.

    EVERY LINE, NOT ONE FINGERPRINT, AND THAT IS A MEASUREMENT RATHER THAN A PREFERENCE. The first
    version of this screened on each arm's single longest line. Pasting the branch-protection remedy
    into the DAST arm -- a plausible edit, and exactly the defect the screen exists for -- left the
    suite GREEN, because the pasted text was not the line the fingerprint happened to pick. A screen
    built from one case finds one shape.

    Short lines are dropped: a line like ``edit.`` is shared prose, not evidence of a leak.
    """
    raw = {
        label: frozenset(ln.strip() for ln in text.splitlines() if len(ln.strip()) >= 40)
        for label, text in _case_arms().items()
    }
    # A line two arms share is not evidence of a leak, so it is DROPPED from the screen rather than
    # forbidden. Requiring the arms to be pairwise disjoint would put a constraint on the shipped
    # alert prose -- two detectors can honestly be described by the same sentence -- and would report
    # a correct body as a leak. What must hold is that each arm keeps something of its own.
    unique = {
        label: own - frozenset().union(*(o for k, o in raw.items() if k != label))
        for label, own in raw.items()
    }
    bare = sorted(label for label, own in unique.items() if not own)
    assert not bare, (
        f"the {bare} arm(s) have no line of their own, so a leak into another workflow's issue would "
        f"be invisible to this screen. Give each arm one distinctive sentence."
    )
    return unique


def test_the_case_arms_and_the_watch_list_are_the_same_set() -> None:
    """The arm labels are workflow NAMES, and nothing else ties them to the watch list.

    ``workflow_run`` matches on a workflow's ``name:``. Rename a watched workflow and the watch-list
    guards above red, so somebody updates the list -- and this ``case`` arm, a hundred lines down in a
    shell string, keeps the old literal, matches nothing, and every issue from then on ships with no
    detail at all. No error, no red, just a quietly less useful alert.

    BOTH DIRECTIONS, because they fail differently and only one of them is loud. An arm with no
    watched workflow is dead text. A watched workflow with no arm is the live half: it opens issues
    that say a nightly failed and nothing about what that hides, which is most of what a reader came
    for -- and adding a sixth entry to the list is exactly the moment it happens. The mirror of this
    is what ``failure-signal.yml`` enforces for its own list, and what this file's header calls "dead
    config that reads as coverage".
    """
    watched = set(_on(_load(_NOTICE))["workflow_run"]["workflows"])
    arms = set(_case_arms())
    assert arms == watched, (
        f"the issue body's `case` arms and the watch list have drifted apart.\n"
        f"  arms with no watched workflow (dead text): {sorted(arms - watched)}\n"
        f"  watched with no arm (issues ship with no detail): {sorted(watched - arms)}\n"
        f"An arm label is a workflow NAME, so it must track that workflow's `name:`."
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
    for wf_path in sorted(_WORKFLOWS.glob("*.yml")):
        name = _load(wf_path).get("name")
        if isinstance(name, str):
            by_name.setdefault(name, wf_path)
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

    # BACKLOG #1450 made the body's detail per-workflow via `case "$WF_NAME"`. Both directions are
    # asserted, and the NEGATIVE one is the load-bearing half: generalising an arm to `*)` reds
    # nothing by itself, it just puts three other workflows' prose in front of the reader of one.
    #
    # SCREENED AGAINST EVERY ARM, not against one known-bad phrase. A `"branch protection" not in
    # body` check would be satisfied by any future arm that happens not to use those two words, which
    # is a screen built from one case rather than from the property.
    arms = _arm_lines()
    seen = {line.strip() for line in body.splitlines()}
    # SUBSET, matching the sibling row for Required workflow state. A non-empty intersection would
    # pass on PARTIAL delivery -- a lost continuation line in a multi-line arm -- and the two rows
    # would then hold the same property to different strengths for no reason.
    assert arms["DAST"] <= seen, (
        f"the DAST arm did not reach a DAST issue in full{_diagnostic(run)}"
    )
    leaked = {
        label: sorted(lines & (seen - arms["DAST"]))
        for label, lines in arms.items()
        if label != "DAST"
    }
    leaked = {label: found for label, found in leaked.items() if found}
    assert not leaked, (
        f"a DAST issue carries {sorted(leaked)}'s detail -- an arm has been generalised, the case "
        f"dispatch dropped, or text pasted into the wrong arm: {leaked}{_diagnostic(run)}"
    )


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


def test_a_workflow_with_no_case_arm_still_gets_a_readable_body(tmp_path: Path) -> None:
    """The `*)` path is live code, and an earlier draft of it shipped a truncated sentence.

    The per-workflow detail replaced one static paragraph, and the first version ended the line above
    it with "Here that covers" for every workflow to complete. An unmatched name left `DETAIL` empty,
    so the issue read "...appears nowhere else. Here that covers" and then stopped. The static
    paragraph it replaced always read as a whole sentence; the dispatch removed that guarantee.

    `test_the_case_arms_and_the_watch_list_are_the_same_set` keeps that state from lasting, but it is
    exactly the state a sixth watch-list entry starts in -- so the degraded form has to be readable
    rather than merely rare.
    """
    run = _run_notice(tmp_path, workflow="Unwatched Example", conclusion="failure", open_issues={})
    _ok(run)
    body = _opt([c for c in run.calls if c[:2] == ["issue", "create"]][0], "--body")
    assert "Nightly (scheduled) Unwatched Example failed." in body, _diagnostic(run)
    assert "Here that covers" not in body, (
        f"the body carries a sentence lead-in with nothing completing it{_diagnostic(run)}"
    )
    seen = {line.strip() for line in body.splitlines()}
    leaked = {label: sorted(lines & seen) for label, lines in _arm_lines().items()}
    leaked = {label: found for label, found in leaked.items() if found}
    assert not leaked, (
        f"an unmatched workflow received {sorted(leaked)}'s detail: {leaked}{_diagnostic(run)}"
    )
    # Still the two things a reader acts on, and still self-closing.
    assert _FIXTURE_ENV["RUN_URL"] in body and _FIXTURE_ENV["HEAD_SHA"] in body, _diagnostic(run)
    assert "closes itself when a" in body, _diagnostic(run)


def _watched_except_dast() -> list[str]:
    """Every watched workflow but DAST, read from the file rather than listed here.

    The isolation rows below hold a DAST issue open and check that no OTHER watched workflow's green
    run touches it, so the parameters ARE the watch list minus DAST. Hardcoding two of them would
    leave the rest untested and give a sixth entry no coverage and no red -- the same hand-maintained
    coupling the rest of this module derives its way out of.
    """
    return [w for w in _on(_load(_NOTICE))["workflow_run"]["workflows"] if w != "DAST"]


@pytest.mark.parametrize("workflow", _watched_except_dast())
def test_a_green_nightly_cannot_close_another_workflows_issue(
    workflow: str, tmp_path: Path
) -> None:
    """THE ISOLATION CONTROL, and the reason the title is derived rather than hardcoded.

    Widening the watch list created a way for one signal to silence another: a single shared issue
    title would let a green nightly close the issue a red DAST run opened, and the DAST finding would
    vanish with nothing anywhere reporting a problem. This row fails against exactly that defect --
    the DAST issue is open, the other workflow is green, and nothing may touch it.

    PARAMETRIZED OVER THE WATCH LIST RATHER THAN COPIED PER WORKFLOW. The property belongs to the
    SCRIPT, not to any one entry, so a fresh copy per addition measures one claim at N depths -- and
    the first such copy had already dropped the `no open issue` assertion below.
    """
    run = _run_notice(
        tmp_path,
        workflow=workflow,
        conclusion="success",
        open_issues={"Nightly DAST is failing": 4242},
    )
    _ok(run)
    assert _writes(run) == [], (
        f"a GREEN {workflow} nightly touched an issue opened by a RED DAST run{_diagnostic(run)}"
    )
    assert run.searched_for == [f"Nightly {workflow} is failing"], (
        f"the script searched for {run.searched_for} -- it must key on the workflow that COMPLETED, "
        f"or every watched signal shares one issue{_diagnostic(run)}"
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


def test_a_red_required_workflow_state_nightly_opens_an_issue_that_names_it(tmp_path: Path) -> None:
    """THE ROW BACKLOG #1450 EXISTS FOR, asked as behaviour rather than as config.

    "the watch list contains Required workflow state" is the weaker claim, and the one a reader
    mistakes for the fix. This runs the shipped body and asserts the red becomes an `issue create`
    carrying the two things a reader acts on -- the run link and the commit.

    IT ALSO ASSERTS BOTH REMEDIES, which is not decoration here. The workflow carries TWO jobs and
    this notice fires on the RUN's conclusion, so it cannot say which failed -- and their remedies are
    not interchangeable. A red `accurate` means the checked-in file and branch protection disagree,
    and editing the FILE is a pull request while editing PROTECTION to match a stale file can arm a
    context that never reports and wedge every pull request. A red `reachable` means a required
    context's workflow cannot report at all, which no edit to that file fixes. A body naming only the
    first would hand half of its readers a remedy that does nothing and forbid the one that works.
    A notice that delivers and misdirects is worse than one that does not deliver.

    THE NAME COMES FROM THE WORKFLOW FILE, not from a literal repeated here, so a rename cannot leave
    this row passing against a `case` arm that no longer matches.
    """
    workflow = str(_load(_WORKFLOWS / "required-workflow-state.yml")["name"])
    run = _run_notice(tmp_path, workflow=workflow, conclusion="failure", open_issues={})
    _ok(run)
    creates = [c for c in run.calls if c[:2] == ["issue", "create"]]
    assert len(creates) == 1, f"expected exactly one `gh issue create`{_diagnostic(run)}"
    argv = creates[0]
    assert _opt(argv, "--title") == f"Nightly {workflow} is failing", _diagnostic(run)
    assert _opt(argv, "--label") == "bug", _diagnostic(run)
    assert run.searched_for == [f"Nightly {workflow} is failing"], _diagnostic(run)
    body = _opt(argv, "--body")
    assert f"Nightly (scheduled) {workflow} failed." in body, (
        f"the issue body does not name the workflow that actually failed{_diagnostic(run)}"
    )
    assert _FIXTURE_ENV["RUN_URL"] in body and _FIXTURE_ENV["HEAD_SHA"] in body, (
        f"the body omits the run link or the commit -- the two things a reader acts on"
        f"{_diagnostic(run)}"
    )
    assert _arm_lines()[workflow] <= {line.strip() for line in body.splitlines()}, (
        f"the `case` arm for {workflow!r} did not reach the issue in full, so a reader loses part of "
        f"the remedy. Its label is a workflow NAME and must track this file's `name:`{_diagnostic(run)}"
    )
    # THE WEDGE WARNING, asserted as a literal on purpose. The subset check above proves the arm
    # arrived whole; it cannot prove the arm still SAYS this, because rewording the sentence changes
    # both sides together. This is the one instruction whose loss is not a worse alert but a wedged
    # repository, so it is pinned to text rather than derived.
    assert "Do NOT edit branch protection" in body, (
        f"the body does not warn against the one remedy that can wedge every pull request in the "
        f"repository{_diagnostic(run)}"
    )
    # The `reachable` remedy, which the file edit above does NOT fix. Asserted by the job's CONTEXT
    # string (its `name:`, else its key) via the shared resolver, never `job.get("name", "")` -- an
    # empty default is a substring of every body, so an unnamed job would pass vacuously.
    for job_key, job in jobs_of("required-workflow-state.yml").items():
        reported = context_of(job_key, job)
        assert reported, f"{job_key!r} resolves to an empty context string"
        assert reported in body, (
            f"the body never names the {job_key!r} job, so a reader cannot tell which of the two "
            f"reconciles failed -- and their remedies differ{_diagnostic(run)}"
        )


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

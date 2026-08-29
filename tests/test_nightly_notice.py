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
pins the structural ways it could quietly stop working -- at least the ones checkable before it ships.

WHAT CANNOT BE TESTED HERE, stated rather than papered over. A ``workflow_run`` workflow only triggers
from the **default branch**, so this one cannot fire on the PR that adds it — its end-to-end behaviour
is unverifiable until it is on ``main``. That is a property of the trigger, not a gap in diligence, and
it is precisely why the *structural* invariants below are worth pinning: they are the parts that can be
checked before it ships.
"""

from __future__ import annotations

from pathlib import Path

import pytest

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

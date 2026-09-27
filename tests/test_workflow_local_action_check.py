# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The workflow local-action gate must trip on both failure modes and stay silent on neither.

A gate with only failure arms passes on its own DELETION, so the silent arm is the one that makes
the others mean anything. The checker's own ``--self-test`` asserts the same thing from inside; this
file asserts it from outside, and additionally pins the live tree so the gate cannot quietly stop
covering the repository it was written for.
"""

from __future__ import annotations

import datetime
import importlib.util
import pathlib
import subprocess
import sys

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SCRIPT = _ROOT / "scripts" / "quality" / "workflow_local_action_check.py"


def _load():
    spec = importlib.util.spec_from_file_location("workflow_local_action_check", _SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["workflow_local_action_check"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write(root: pathlib.Path, body: str) -> None:
    wf = root / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "probe.yml").write_text(body, encoding="utf-8")


def _action(root: pathlib.Path, rel: str) -> None:
    d = root / rel
    d.mkdir(parents=True, exist_ok=True)
    (d / "action.yml").write_text("name: probe\n", encoding="utf-8")


_WITH_CHECKOUT = """\
name: probe
on: [push]
jobs:
  j:
    steps:
      - uses: actions/checkout@aaaa
      - uses: ./.github/actions/thing
"""

_NO_CHECKOUT = """\
name: probe
on: [push]
jobs:
  j:
    steps:
      - uses: ./.github/actions/thing
"""


def test_the_self_test_passes_as_a_subprocess() -> None:
    """Run it the way CI does, so an import-time break cannot hide behind a direct call."""
    r = subprocess.run(
        [sys.executable, str(_SCRIPT), "--self-test"], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_a_missing_local_action_trips(tmp_path: pathlib.Path) -> None:
    _write(tmp_path, _WITH_CHECKOUT)  # checkout present, action absent
    problems, files, seen = _load().check_tree(tmp_path)
    assert files == 1 and seen == 1, (files, seen)
    assert problems and "no action.yml" in " ".join(problems), problems


def test_a_present_action_with_no_checkout_trips(tmp_path: pathlib.Path) -> None:
    """The exact shape of the 2026-08-29 breakage: the action was vendored, the checkout was not."""
    _write(tmp_path, _NO_CHECKOUT)
    _action(tmp_path, ".github/actions/thing")
    problems, _, seen = _load().check_tree(tmp_path)
    assert seen == 1
    assert problems and "no actions/checkout" in " ".join(problems), problems


def test_the_silent_arm_stays_silent_and_still_looks(tmp_path: pathlib.Path) -> None:
    """MUST NOT TRIP -- and must still have SEEN the reference.

    Reporting zero problems having examined nothing is the failure this whole gate is about, so the
    count is asserted alongside the silence.
    """
    _write(tmp_path, _WITH_CHECKOUT)
    _action(tmp_path, ".github/actions/thing")
    problems, files, seen = _load().check_tree(tmp_path)
    assert problems == [], problems
    assert (files, seen) == (1, 1), (files, seen)


def test_a_commented_out_uses_is_not_code(tmp_path: pathlib.Path) -> None:
    """Three separate scanners in this repository were wrong on 2026-08-28 by reading prose as code."""
    _write(
        tmp_path,
        "name: probe\non: [push]\njobs:\n  j:\n    steps:\n"
        "      # uses: ./.github/actions/ghost\n"
        "      - uses: some/remote@bbbb # ./also-not-a-path\n",
    )
    problems, _, seen = _load().check_tree(tmp_path)
    assert seen == 0, "a comment and a trailing-comment path must not be read as local uses"
    assert problems == []


def test_an_empty_tree_is_not_a_pass(tmp_path: pathlib.Path) -> None:
    """No workflows means nothing was examined, which the CLI must report as a failure."""
    r = subprocess.run(
        [sys.executable, str(_SCRIPT), "--root", str(tmp_path)], capture_output=True, text=True
    )
    assert r.returncode == 1, r.stdout
    assert "NOTHING WAS EXAMINED" in r.stdout


def test_the_live_repository_is_covered() -> None:
    """Pin that the gate still SEES this repo's workflows.

    Without this, deleting the .github/workflows glob would leave every arm above green while the
    gate covered nothing in the tree it ships with.
    """
    _, files, _ = _load().check_tree(_ROOT)
    assert files >= 10, f"expected the repo's workflow set, scanned {files}"


# --- runs.using (BACKLOG #1868) ---------------------------------------------------------------
#
# Before #1868 nothing read `runs.using`, and the Node 20 deadline on the vendored CLA action rested
# on a person opening ADR 0034. Each failure arm below is paired with a case that must stay silent,
# for the reason the module docstring gives: a gate with only failure arms passes on its deletion.
#
# EVERY TEST HERE PASSES AN EXPLICIT DATE, derived from the table. The CI step runs on the real
# clock, and that is where a revisit date bites. A unit test on the real clock would instead make
# every past commit's suite unreproducible once the date passes.

_CURRENT, _DUE = min(_load()._NODE_RUNTIME_REVISIT.items(), key=lambda kv: kv[1])
_BEFORE_REVISIT = _DUE - datetime.timedelta(days=1)


def _runtime(root: pathlib.Path, using_block: str) -> None:
    _write(root, _WITH_CHECKOUT)
    d = root / ".github" / "actions" / "thing"
    d.mkdir(parents=True, exist_ok=True)
    (d / "action.yml").write_text(f"name: probe\nruns:\n{using_block}", encoding="utf-8")


@pytest.mark.parametrize("retired", ["node12", "node16", "node20"])
def test_a_retired_runtime_trips(tmp_path: pathlib.Path, retired: str) -> None:
    _runtime(tmp_path, f'  using: "{retired}"\n  main: i.js\n')
    problems, read = _load().check_runtimes(tmp_path, today=_BEFORE_REVISIT)
    assert read == {"./.github/actions/thing": retired}, read
    assert problems and "removed" in problems[0], problems


def test_the_retired_message_offers_only_runtimes_still_current(tmp_path: pathlib.Path) -> None:
    """After a revisit date passes, the message must not send the author to a runtime that the
    next run refuses."""
    _runtime(tmp_path, "  using: node20\n  main: i.js\n")
    early, _ = _load().check_runtimes(tmp_path, today=_BEFORE_REVISIT)
    late, _ = _load().check_runtimes(tmp_path, today=_DUE)
    assert f"Declare {_CURRENT}" in early[0], early
    assert f"Declare {_CURRENT}" not in late[0], late


def test_a_current_runtime_passes_and_is_read_past_a_comment_naming_node20(
    tmp_path: pathlib.Path,
) -> None:
    """The silent arm, in the vendored file's own shape: a comment naming the old value sits above
    the real key. A reader that kept comments would report node20 here."""
    _runtime(tmp_path, f'  # upstream declares "node20"\n  using: "{_CURRENT}"\n  main: i.js\n')
    problems, read = _load().check_runtimes(tmp_path, today=_BEFORE_REVISIT)
    assert read == {"./.github/actions/thing": _CURRENT}, read
    assert problems == [], problems


def test_only_a_direct_child_of_runs_is_read(tmp_path: pathlib.Path) -> None:
    """A nested `using:` that comes first must not stand in for the real one."""
    _runtime(tmp_path, f"  env:\n    using: {_CURRENT}\n  using: node20\n  main: i.js\n")
    problems, read = _load().check_runtimes(tmp_path, today=_BEFORE_REVISIT)
    assert read == {"./.github/actions/thing": "node20"}, read
    assert problems, problems


def test_the_runtime_is_compared_without_case(tmp_path: pathlib.Path) -> None:
    """`Node20` must be refused as node20, not reported as an unknown runtime to add to the table."""
    _runtime(tmp_path, "  using: Node20\n  main: i.js\n")
    problems, read = _load().check_runtimes(tmp_path, today=_BEFORE_REVISIT)
    assert read == {"./.github/actions/thing": "node20"}, read
    assert problems and "removed" in problems[0], problems


def test_a_quoted_top_level_key_ends_the_runs_block() -> None:
    """Otherwise a `using:` under the NEXT mapping is read as the runtime."""
    text = "runs:\n  main: x\n'branding':\n  using: node24\n"
    assert _load().read_runs_using(text) is None


def test_the_cli_warns_before_the_revisit_date_and_still_passes(tmp_path: pathlib.Path) -> None:
    _runtime(tmp_path, f"  using: {_CURRENT}\n  main: i.js\n")
    r = _cli(tmp_path)  # one day before the revisit date
    assert r.returncode == 0, r.stdout + r.stderr
    assert "WARNING" in r.stdout and "1 day(s) away" in r.stdout, r.stdout


def test_a_current_runtime_trips_on_its_revisit_date_and_not_the_day_before(
    tmp_path: pathlib.Path,
) -> None:
    _runtime(tmp_path, f"  using: {_CURRENT}\n  main: i.js\n")
    assert _load().check_runtimes(tmp_path, today=_BEFORE_REVISIT)[0] == []
    late, _ = _load().check_runtimes(tmp_path, today=_DUE)
    assert late and "revisit date" in late[0], late


def test_an_unlisted_node_runtime_is_refused(tmp_path: pathlib.Path) -> None:
    """Fail closed, so adding a new runtime forces somebody to give it a revisit date."""
    _runtime(tmp_path, "  using: node26\n  main: i.js\n")
    problems, _ = _load().check_runtimes(tmp_path, today=_BEFORE_REVISIT)
    assert problems and "does not know" in problems[0], problems


def test_a_missing_runs_using_is_refused(tmp_path: pathlib.Path) -> None:
    _runtime(tmp_path, "  main: i.js\n")
    problems, read = _load().check_runtimes(tmp_path, today=_BEFORE_REVISIT)
    assert read == {"./.github/actions/thing": None}, read
    assert problems and "no runs.using" in problems[0], problems


def test_a_composite_action_passes(tmp_path: pathlib.Path) -> None:
    _runtime(tmp_path, "  using: composite\n  steps: []\n")
    problems, read = _load().check_runtimes(tmp_path, today=_BEFORE_REVISIT)
    assert (problems, read) == ([], {"./.github/actions/thing": "composite"})


def _cli(root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), "--root", str(root), "--today", _BEFORE_REVISIT.isoformat()],
        capture_output=True,
        text=True,
    )


def test_the_cli_exits_1_on_a_runtime_problem_alone(tmp_path: pathlib.Path) -> None:
    """The exit code is what blocks a merge. Checkout present, action present: the ONLY problem is
    the runtime, so a CLI that printed it and exited 0 would pass here if this test did not exist."""
    _runtime(tmp_path, "  using: node20\n  main: i.js\n")
    r = _cli(tmp_path)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "./.github/actions/thing=node20" in r.stdout, r.stdout


def test_the_cli_exits_0_on_a_fully_clean_tree(tmp_path: pathlib.Path) -> None:
    """The silent arm for the WHOLE gate, both checks at once."""
    _runtime(tmp_path, f"  using: {_CURRENT}\n  main: i.js\n")
    r = _cli(tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"./.github/actions/thing={_CURRENT}" in r.stdout, r.stdout


def test_the_live_cla_action_is_read_and_passes() -> None:
    """Pin the real target, and print what was read beside the verdict.

    The deleted `archived-uses` rule reported clean for weeks after the reference it watched went
    local, because it had nothing left to read. So the READ value is asserted, not only the silence.
    """
    mod = _load()
    problems, read = mod.check_runtimes(_ROOT, today=_BEFORE_REVISIT)
    declared = read.get("./.github/actions/cla-assistant-lite")
    # Any runtime still in the table, not a named one, so following the gate's own fix message
    # (move the action, add a row) does not break this test.
    assert declared in mod._NODE_RUNTIME_REVISIT, read
    assert problems == [], problems
    r = _cli(_ROOT)
    assert r.returncode == 0, r.stdout + r.stderr
    assert f"./.github/actions/cla-assistant-lite={declared}" in r.stdout, r.stdout

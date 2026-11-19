# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5448: the tripwire reads git's ``--config-env`` and ``--attr-source`` global options.

``Find-GitTripwires`` in ``scripts/hooks/afk-tripwire.ps1`` recorded a ``core.hooksPath`` override only
in its ``-c`` form, and skipped a separate value only after the options in its two-token list. Measured
on git 2.55.0.windows.5: ``git --config-env <key>=<ENVVAR> ...`` and ``git --attr-source <tree> ...`` are
both accepted with the value in the NEXT argument, as well as in the ``=`` form. So:

* ``git --config-env core.hooksPath=VAR commit ...`` pointed the hooks elsewhere and was not recorded;
* ``git --config-env x=VAR push --force`` resolved its subcommand to ``x=VAR``, and the push went
  unrecorded; ``--attr-source <tree>`` did the same.

The fix keeps origin/main's parse beside the corrected one and records what either sees, so no act
origin/main recorded goes unrecorded. ``--shallow-file`` also takes a separate value; ``--exec-path``
takes none. A ``-c``/``--config-env`` override of ``include.path``, ``includeIf.*`` or ``alias.*`` is
recorded beside ``core.hooksPath``.

The hit arm and the pass arm are both here, for the reason ``tests/test_afk_tripwire.py`` gives: a hook
that trips on everything passes the first alone. This is a new file so this row's PR edits no shared
test file; the harness is the same one ``tests/test_afk_tripwire.py`` uses.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from tests._fake_gh import ROOT, Sandbox, make_sandbox

HOOK = ROOT / "scripts" / "hooks" / "afk-tripwire.ps1"

pytestmark = pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")


@pytest.fixture
def sb(tmp_path: Path) -> Sandbox:
    return make_sandbox(tmp_path)


def _run(sb: Sandbox, command: str) -> str | None:
    payload = json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "sess-trip-5448"}
    )
    proc = sb.run(HOOK, stdin=payload, CLAUDE_CODE_REMOTE="true")
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    if not proc.stdout.strip():
        return None
    out: dict[str, Any] = json.loads(proc.stdout)
    assert "permissionDecision" not in out["hookSpecificOutput"], "the tripwire must not decide"
    context: str = out["hookSpecificOutput"]["additionalContext"]
    return context


MUST_HIT = [
    pytest.param(
        "git --config-env=core.hooksPath=NOHOOKS commit -m x",
        "core.hooksPath",
        id="config-env-equals-hooks-path",
    ),
    pytest.param(
        "git --config-env core.hooksPath=NOHOOKS commit -m x",
        "core.hooksPath",
        id="config-env-separate-hooks-path",
    ),
    pytest.param(
        "git --config-env Core.HooksPath=NOHOOKS commit -m x",
        "core.hooksPath",
        id="config-env-key-case-folded",
    ),
    pytest.param(
        "git --config-env user.name=GN push --force origin b",
        "git push --force",
        id="config-env-separate-then-push-force",
    ),
    pytest.param(
        "git --attr-source HEAD reset --hard",
        "git reset --hard",
        id="attr-source-separate-then-reset-hard",
    ),
    pytest.param(
        "git --attr-source=HEAD push --force origin b",
        "git push --force",
        id="attr-source-equals-then-push-force",
    ),
    # A tripwire only tightens: origin/main's parse, which skips no value after --attr-source, reads
    # `reset` as the subcommand here and records it, so the corrected parse must not lose that record.
    pytest.param(
        "git --attr-source reset log --hard",
        "git reset --hard",
        id="old-parse-record-kept-attr-source",
    ),
    pytest.param(
        "git --config-env reset log --hard",
        "git reset --hard",
        id="old-parse-record-kept-config-env",
    ),
    # --shallow-file takes its value as the next argument (measured on git 2.55.0).
    pytest.param(
        "git --shallow-file x push --force origin b",
        "git push --force",
        id="shallow-file-separate-then-push-force",
    ),
    # --exec-path takes no separate value: alone it prints the path and exits, so the word after it
    # is not its value. Reading `push` as the subcommand over-records, which a tripwire may do.
    pytest.param(
        "git --exec-path push --force origin b",
        "git push --force",
        id="exec-path-takes-no-separate-value",
    ),
    pytest.param(
        "git --config-env=user.name=GN push --force origin b",
        "git push --force",
        id="config-env-equals-then-push-force",
    ),
    # Overrides that can bypass hooks or run another command as surely as core.hooksPath.
    pytest.param(
        # git refuses a relative include from the command line, so the path is absolute.
        "git -c include.path=/tmp/evil.cfg commit -m x",
        "include.path",
        id="c-include-path",
    ),
    pytest.param(
        "git --config-env includeIf.gitdir:/r/.path=V commit -m x",
        "includeIf",
        id="config-env-include-if",
    ),
    pytest.param(
        "git -c remote.origin.mirror=true push origin",
        "remote mirror or push refspec",
        id="c-remote-mirror",
    ),
    # The value is an environment variable's name, so whether the refspec forces is unseen.
    pytest.param(
        "git --config-env=remote.origin.push=V push origin",
        "remote mirror or push refspec",
        id="config-env-remote-push-value-unseen",
    ),
    # A valueless `-c` key is boolean true, so this is a mirror push.
    pytest.param(
        "git -c remote.origin.mirror push origin",
        "remote mirror or push refspec",
        id="c-remote-mirror-valueless",
    ),
    pytest.param(
        "git -c remote.origin.push=+refs/heads/*:refs/heads/* push origin",
        "remote mirror or push refspec",
        id="c-remote-push-plus-refspec",
    ),
    pytest.param(
        "git -c alias.ci=commit ci -m x",
        "alias",
        id="c-alias",
    ),
    pytest.param(
        "git --config-env=Alias.ci=V ci -m x",
        "alias",
        id="config-env-equals-alias",
    ),
]

MUST_PASS = [
    pytest.param("git --config-env user.name=GN push origin b", id="config-env-plain-push"),
    pytest.param("git --config-env=user.email=EM commit -m x", id="config-env-other-key"),
    pytest.param("git --attr-source HEAD status", id="attr-source-status"),
    # git option names are case-sensitive: git refuses `--CONFIG-ENV=...` as an unknown option, so it
    # sets nothing. Only the config key folds case.
    pytest.param("git --CONFIG-ENV=core.hooksPath=V commit -m x", id="config-env-name-case-kept"),
    pytest.param("git -c includes.path=x commit -m x", id="c-key-only-looks-like-include"),
    pytest.param(
        "git -c remote.origin.push=refs/heads/b:refs/heads/b push origin",
        id="c-remote-push-plain-refspec",
    ),
]


@pytest.mark.parametrize(("command", "act"), MUST_HIT)
def test_each_config_env_or_attr_source_act_trips(sb: Sandbox, command: str, act: str) -> None:
    context = _run(sb, command)
    assert context is not None, f"{command!r} did not trip"
    assert act in context and "Class C" in context


def test_an_option_value_is_never_named_as_the_subcommand(sb: Sandbox) -> None:
    # origin/main's parse reads the value of --shallow-file as the subcommand; the record names acts,
    # never command text, so the path must not reach the note.
    context = _run(sb, "git --shallow-file /srv/shallow-marker/x commit --no-verify -m x")
    assert context is not None
    assert "git commit --no-verify" in context
    assert "shallow-marker" not in context


@pytest.mark.parametrize("command", MUST_PASS)
def test_an_ordinary_command_behind_these_options_does_not_trip(sb: Sandbox, command: str) -> None:
    assert _run(sb, command) is None

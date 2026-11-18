# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5450: the blanket-stage guard skips the value of ``--config-env`` and ``--attr-source``.

``Resolve-GitSubcommand`` in ``scripts/hooks/block-blanket-git-stage.ps1`` skipped a separate value only
after the global options in its list. Measured on git 2.55.0.windows.5: ``git --config-env <key>=<VAR>``
and ``git --attr-source <tree>`` both accept the value as the NEXT argument. Without a skip, the value
was read as the subcommand, and two shapes of blanket stage passed:

* a value that names a READ-ONLY subcommand (``git --attr-source status add -A``, with a ref named
  ``status``) resolved to ``status`` and was suppressed as read-only;
* any other value left the arguments to be read from the BLANKED view, where a quoted flag
  (``git --config-env x=V add "-A"``) is blanked away.

Code review of this change found two more of the same shape. ``--shallow-file`` takes its value as the
next argument too, and is closed here. A QUOTED value after any listed option is blanked into two
tokens, so its closing quote is read as the subcommand; that one is STILL OPEN, pinned below as
``xfail(strict=True)`` rows so a repair shows up as an unexpected pass.

Each blanket row sits beside a scoped control that must stay allowed. The guard is driven the way
``tests/test_blanket_stage_guard.py`` drives it, through the shared helpers there; this is a new file so
this row's PR edits no shared test file.
"""

from __future__ import annotations

import shutil

import pytest

from tests.test_blanket_stage_guard import assert_allowed, bash, run_guard
from tests.test_worktree_gate import assert_denied

# A pytestmark in an imported module does not apply here, so the pwsh skip is declared again.
pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)

BLANKET = [
    pytest.param("git --attr-source status add -A", id="attr-source-value-names-read-only"),
    pytest.param("git --attr-source log add .", id="attr-source-value-names-log-pathspec"),
    pytest.param('git --attr-source HEAD add "-A"', id="attr-source-quoted-flag"),
    pytest.param('git --config-env user.name=GN add "-A"', id="config-env-quoted-flag"),
    pytest.param('git --config-env user.name=GN stage "."', id="config-env-quoted-pathspec"),
    pytest.param("git --config-env user.name=GN add -A", id="config-env-plain-flag"),
    # --shallow-file takes its value as the next argument too (git 2.55.0).
    pytest.param("git --shallow-file status add -A", id="shallow-file-value-names-read-only"),
    pytest.param('git --shallow-file x add "-A"', id="shallow-file-quoted-flag"),
]

SCOPED = [
    pytest.param("git --attr-source HEAD add src/x.py", id="attr-source-scoped"),
    pytest.param('git --config-env user.name=GN add "src/x.py"', id="config-env-scoped-quoted"),
    # The direction this change moves from deny to allow, pinned: git runs `log` here, which
    # cannot stage, and the guard used to read `HEAD` as the subcommand and deny on the word `add`.
    pytest.param("git --attr-source HEAD log add -A", id="attr-source-then-read-only-subcommand"),
    # The reverted quote-skip loop denied these scoped stages; they must stay allowed.
    pytest.param('git -C "." add src/x.py', id="dash-C-quoted-dot-scoped"),
    pytest.param("git --shallow-file x add src/x.py", id="shallow-file-scoped"),
]


# STILL OPEN (see Resolve-GitSubcommand's comment): a quoted value is blanked into two tokens.
_QUOTED_VALUE_OPEN = pytest.mark.xfail(
    strict=True, reason="a quoted global-option value is split by the blanked view (still open)"
)
QUOTED_VALUE_STILL_ALLOWED = [
    pytest.param('git --config-env "user.name=GN" add "-A"', id="config-env-quoted-value"),
    pytest.param("git --attr-source 'status' add '-A'", id="attr-source-single-quoted-value"),
    pytest.param('git -C "D:/repo" add "."', id="dash-C-quoted-value-quoted-pathspec"),
    pytest.param('git --config-env="a=B" add "-A"', id="config-env-equals-quoted-value"),
]


@pytest.mark.parametrize("command", QUOTED_VALUE_STILL_ALLOWED)
@_QUOTED_VALUE_OPEN
def test_a_quoted_value_still_hides_a_quoted_blanket_flag(command: str) -> None:
    assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize("command", BLANKET)
def test_a_blanket_stage_behind_config_env_or_attr_source_is_denied(command: str) -> None:
    assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize("command", SCOPED)
def test_a_scoped_or_read_only_command_behind_them_is_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command)))

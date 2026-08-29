# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1069: a QUOTED disarm key was blanked before rule 3c could see it.

``Get-ScannableSegments`` builds each segment's ``Scan`` through ``Remove-QuotedSpans``, which blanks
every closed quoted span. Rule 3c matched the danger key against ``Scan``. So quoting the key erased it
before the disarm regex ran, and **quoting an argument is ordinary** -- this needed no unusual spelling
and disarmed the ledger, claim and leak commit gates for every worktree at once.

THE FIX IS A BARE-WORD UNMASK, NOT A RAW-TEXT MATCH. Matching the raw text instead would refuse a commit
message that quotes the rule's own name, and this workstream writes such messages constantly. The
discriminator is WHITESPACE: prose has it and stays masked, a config key does not and becomes visible.

EVERY DENY ROW HERE IS PAIRED WITH THE UNQUOTED CONTROL BELOW. Without it an ALLOW cannot be told from a
probe that never reached a governed repo -- the first version of this file reported the unquoted control
as ALLOW, which would have read as a far larger finding than the real one. It was a broken probe.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.test_worktree_gate import run_gate
from tests.test_worktree_gate_control_plane import repo, shell  # noqa: F401

#: The unquoted spelling. Denied before this fix and after it, so it is a KNOWN-ANSWER control on the
#: probe itself rather than a test of the fix.
UNQUOTED_CONTROL = "git config core.hooksPath /dev/null"

#: Every spelling BACKLOG #1069 measured as ALLOW on the shipped gate. All five deny now.
QUOTED_DISARMS = [
    'git -c "core.hooksPath=/dev/null" commit -m x',
    "git -c 'core.hooksPath=/dev/null' commit -m x",
    'git config "core.hooksPath" /dev/null',
    "git config 'core.hooksPath' '/dev/null'",
    'git config --add "core.hooksPath" /dev/null',
]

#: Prose that NAMES the danger key inside a quoted commit message. These are the false denies a
#: raw-text match would have introduced, and they are the reason the carve-out is bare-word-only.
PROSE_MUST_STILL_ALLOW = [
    'git commit -m "do not set core.hooksPath in a worktree"',
    "git commit -m 'BACKLOG #1069: core.hooksPath was invisible when quoted'",
    'git commit -m "see rule 3c and its core.hooksPath disarm list"',
]


def test_the_unquoted_key_is_denied(repo: SimpleNamespace) -> None:  # noqa: F811
    """THE CONTROL EVERY OTHER ROW DEPENDS ON. If this allows, the probe never reached a governed repo
    and every ALLOW in this file is meaningless rather than reassuring."""
    assert run_gate(shell(UNQUOTED_CONTROL, cwd=repo.primary), repo.repos) is not None, (
        "the UNQUOTED disarm key was allowed -- the probe is broken, so nothing else here is a reading"
    )


@pytest.mark.parametrize("command", QUOTED_DISARMS)
def test_a_quoted_disarm_key_is_seen(repo: SimpleNamespace, command: str) -> None:  # noqa: F811
    assert run_gate(shell(command, cwd=repo.primary), repo.repos) is not None, (
        f"FAIL-OPEN: quoting the key hid it from rule 3c -- {command}"
    )


@pytest.mark.parametrize("command", PROSE_MUST_STILL_ALLOW)
def test_prose_naming_the_key_is_not_denied(repo: SimpleNamespace, command: str) -> None:  # noqa: F811
    assert run_gate(shell(command, cwd=repo.primary), repo.repos) is None, (
        f"FALSE DENY: a commit message that merely NAMES the key was refused -- {command}"
    )


def test_a_QUOTED_MULTI_WORD_alias_value_is_still_invisible(repo: SimpleNamespace) -> None:  # noqa: F811
    """PINNED AS AN ALLOW ON PURPOSE. THIS IS AN OPEN HOLE, NOT A PASSING PROPERTY.

    ``-c 'alias.ci=commit --no-verify'`` disarms the hooks and is still not seen, because its value
    contains a SPACE -- so the bare-word carve-out cannot reach it without re-admitting the prose false
    deny the tests above pin. Quoting is that value's only writable spelling, so the whole class is open.

    IT IS PINNED SO A LATER CHANGE CANNOT CLOSE IT SILENTLY OR CLAIM IT WAS NEVER THERE. If someone
    builds a real argument tokeniser, this test SHOULD fail, and the correct response is to invert it
    together with BACKLOG #1069's banner -- not to delete it. The one pass that attempted that tokeniser
    acquired five new fail-opens, which is why the narrow carve-out shipped instead.
    """
    assert (
        run_gate(
            shell("git -c 'alias.ci=commit --no-verify' ci -m x", cwd=repo.primary), repo.repos
        )
        is None
    ), (
        "the multi-word alias spelling now DENIES. That is progress, not a regression -- invert this "
        "test and BACKLOG #1069's banner together rather than deleting either."
    )

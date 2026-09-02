# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1082: rule 3c's deny text named a mechanism a ``--global``/``--system`` write does not use.

**THE VERDICT WAS ALWAYS CORRECT AND DOES NOT MOVE HERE.** ``git config --global core.hooksPath <dir>``
aimed at a governed repo is refused, and should be: git falls back to the per-user scope when the
repository does not set the key, so the write can still disarm the checkout **by inheritance**. An
earlier filing of this as a FALSE DENY was withdrawn by three independent verifiers who measured the
hook genuinely not firing afterwards. Flipping rule 3c to ALLOW would have been a fail-open.

What was wrong is the SENTENCE. It said the write *"would change the SHARED git configuration of
<repo>"*, and it does not -- it writes ``~/.gitconfig`` or the machine-wide file.

**EVERY TEST HERE ASSERTS THE EMITTED STRING, NOT THE VERDICT.** That is forced, not stylistic: the
verdict is identical before and after, so a row ending in a bare ``assert_denied`` cannot see this
defect at all, and a mutant that reinstated the old sentence would pass such a row unchanged.

**NOTHING IN THE MESSAGE MAY REASSURE.** A round-4 candidate printed *"This does NOT change the shared
configuration"* and three verifiers graded it BLOCKING: ``Get-ScannableSegments`` splits on lines and
``Write-Deny`` exits on the first hit, so on a multi-line command whose LATER segment does a local
write, that reassurance would print over a real disarm. The negative rows below pin its absence.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.test_worktree_gate import assert_denied, run_gate
from tests.test_worktree_gate_control_plane import repo, shell  # noqa: F401

SCOPED = [
    ("global", "git config --global core.hooksPath /dev/null"),
    ("system", "git config --system core.hooksPath /dev/null"),
]

#: Phrases that must never appear in a scoped deny. The first is the false mechanism this item is
#: about; the rest are the reassurance shapes graded BLOCKING in round 4.
FORBIDDEN_IN_SCOPED = [
    "SHARED git configuration",
    "does NOT change",
    "is harmless",
    "safe to run",
]


@pytest.mark.parametrize("scope,command", SCOPED)
def test_a_scoped_write_is_still_denied(repo: SimpleNamespace, scope: str, command: str) -> None:  # noqa: F811
    """THE VERDICT ARM. Kept separate from the wording arms so a future change that fixed the sentence
    by ALLOWING the write fails here rather than passing quietly."""
    assert run_gate(shell(command, cwd=repo.primary), repo.repos) is not None, (
        f"--{scope} disarm write was ALLOWED. The verdict must not move: git inherits from that scope "
        "when the repository does not set the key, so the write can still disarm this checkout."
    )


@pytest.mark.parametrize("scope,command", SCOPED)
def test_a_scoped_deny_does_not_claim_the_repo_config_changed(
    repo: SimpleNamespace,  # noqa: F811
    scope: str,
    command: str,
) -> None:
    reason = assert_denied(run_gate(shell(command, cwd=repo.primary), repo.repos))
    for phrase in FORBIDDEN_IN_SCOPED:
        assert phrase not in reason, (
            f"--{scope} deny text contains {phrase!r}. Either it names a mechanism this write does not "
            "use, or it reassures -- and a reassurance prints over a real disarm when a later segment "
            f"of a multi-line command does a local write.\n\n{reason}"
        )


@pytest.mark.parametrize("scope,command", SCOPED)
def test_a_scoped_deny_names_the_scope_and_the_inheritance(
    repo: SimpleNamespace,  # noqa: F811
    scope: str,
    command: str,
) -> None:
    """Say what IS true: which file is written, and why it is refused anyway."""
    reason = assert_denied(run_gate(shell(command, cwd=repo.primary), repo.repos))
    assert f"--{scope}" in reason, f"the deny text does not name the scope it refused\n\n{reason}"
    assert "inherit" in reason.lower() or "falls back" in reason.lower(), (
        f"the deny text does not say WHY a write to another file is refused\n\n{reason}"
    )


def test_a_repository_scope_write_still_says_SHARED(repo: SimpleNamespace) -> None:  # noqa: F811
    """THE CONTROL. The original sentence is CORRECT for a repository-scope write and must survive
    unchanged -- otherwise this fix would have traded one false sentence for another."""
    reason = assert_denied(
        run_gate(shell("git config core.hooksPath /dev/null", cwd=repo.primary), repo.repos)
    )
    assert "SHARED git configuration" in reason, (
        f"the repository-scope wording was changed; it was already true and should not move\n\n{reason}"
    )

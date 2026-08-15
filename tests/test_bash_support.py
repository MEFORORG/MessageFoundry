# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Controls for ``tests/_bash_support``.

**These moved here WITH the helpers they guard (BACKLOG #1272), and that pairing is the point.** The
resolver was promoted out of ``test_merge_gate_controls`` so three sibling modules could stop calling
``shutil.which("bash")``. A promotion that left the controls behind would have produced a helper that
looks identical, is now used in four places instead of one, and **is no longer proven anywhere** --
which is the same non-propagation defect #1272 exists to fix, arriving through the fix for it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from _pytest.outcomes import Failed

from tests._bash_support import CANNOT_RUN_CODES, require_bash, require_shell, shell_sees


def test_the_bash_namespace_probe_rejects_an_interpreter_that_cannot_see_the_fixture(
    tmp_path: Path,
) -> None:
    """NEGATIVE CONTROL OF THE RESOLVER, and it exists because this code already shipped the bug once.

    MEASURED 2026-08-10. The first version resolved bash with ``shutil.which("bash")`` and passed it an
    ABSOLUTE Windows path. Under a Git Bash parent it passed; run from PowerShell, where PATH resolves
    ``bash`` to ``C:\\Windows\\System32\\bash.exe`` -- the WSL launcher, a different filesystem
    namespace -- every hygiene control failed with exit 127 and the backslashes eaten. So the control's
    verdict was a fact about PATH ORDER, which is precisely the ambient-environment green the wave-2
    incident warned about, one variable over.

    Two things fixed it and both are asserted here rather than described: the candidate is derived from
    ``git`` (which ships bash beside it) and then made to READ A FILE this process wrote, and callers
    invoke by a RELATIVE path so no namespace conversion is involved at all.

    A candidate that cannot read the token must be rejected. ``sys.executable`` stands in for one: it
    is a real, runnable program that is not a shell, so the probe must refuse it while accepting the
    resolved bash in the same call.

    **RE-MEASURED 2026-08-14 on the same box**, which is why the helper was promoted: with the WSL
    launcher first on PATH, three modules still using ``shutil.which`` produced 19 failures; with Git
    Bash first, the same tree at the same commit produced 47 passed. Nothing changed but PATH order.
    """
    assert not shell_sees(Path(sys.executable), tmp_path), (
        "the namespace probe accepted a non-shell interpreter, so it cannot reject a bash that is "
        "looking at the wrong filesystem either"
    )
    assert shell_sees(Path(require_bash(tmp_path)), tmp_path)


def test_require_shell_probes_EVERY_name_rather_than_stopping_at_the_first(tmp_path: Path) -> None:
    """THE MULTI-NAME CONTRACT, and it is the correction that made this helper general (#1216).

    ``test_installed_coord_hooks`` resolves ``shutil.which("sh") or shutil.which("bash")`` -- ``sh``
    FIRST. A helper that only ever proved *bash* usable would repair that file **by accident** on a box
    where ``sh`` happens to be absent, and leave it broken wherever an UNUSABLE ``sh`` sits on PATH,
    because ``sh`` would win the ``or`` and never be probed at all. Builder 3 measured exactly that
    shape on this box: ``which("sh")`` finds nothing, so it falls through to a ``bash`` that resolves
    to the WSL launcher.

    So the property is *every name is probed*, not *the first name decides*. A first name that yields
    no usable candidate must not abort the search -- asserted here with a name no machine can satisfy,
    which is the only way to exercise the fall-through deterministically on any platform.
    """
    resolved = require_shell(tmp_path, "mf-not-a-real-shell", "bash")
    assert shell_sees(Path(resolved), tmp_path), (
        "require_shell returned an interpreter that cannot read this process's files"
    )
    # POSITIVE CONTROL for the assertion above: the same call with only the impossible name MUST fail.
    # Without it, a require_shell that silently returned something unprobed would pass the line above
    # whenever the fallback happened to work anyway.
    with pytest.raises(Failed):
        require_shell(tmp_path, "mf-not-a-real-shell")


def test_the_cannot_run_codes_do_not_swallow_a_real_syntax_error() -> None:
    """The 126/127-versus-2 split, asserted rather than described.

    ``bash`` exits 126/127 when it cannot RUN what it was handed and **2** when it read the file and
    the syntax is bad. A caller testing only ``returncode != 0`` conflates them, which is how one
    unresolvable path presented as 160 syntax errors that did not exist. If ``2`` ever entered this
    set, every real syntax error would be reclassified as a harness fault and silently stop failing --
    the failure this split exists to prevent, inverted.
    """
    assert 2 not in CANNOT_RUN_CODES, "a genuine syntax error must never read as a harness failure"
    assert {126, 127} == CANNOT_RUN_CODES

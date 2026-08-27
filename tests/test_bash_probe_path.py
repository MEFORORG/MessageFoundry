# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The bash probe rejected a working interpreter when coreutils was absent from PATH (BACKLOG #1373).

``bash_sees`` runs ``cat mf_bash_probe.txt`` and returns a bare bool. Under a PATH without the
ordinary utilities -- which is what PowerShell and cmd supply -- bash exits **127**, and the probe
reported that as "this interpreter cannot see my filesystem".

***THE FILE ALREADY KNEW.*** ``BASH_HARNESS_FAILURE = 127`` sits at module scope under a comment
saying 127 is "a finding about the HARNESS" and that conflating it "lets a broken harness impersonate
a failing test", and ``explain_returncode`` implements exactly that distinction 77 lines below the
probe that ignores it. This is not an oversight; it is a distinction built deliberately and then
dropped at one call.

***MEASURED, ONE VARIABLE.*** Same interpreter, same filesystem, same probe file, only PATH moved::

    PATH = the interpreter's own directory      True
    PATH = empty                                False      <- a working bash, rejected
    PATH = C:\\Windows\\System32                 False      <- a working bash, rejected

And end to end under the real condition -- Git's ``cmd`` on PATH so ``git`` resolves, but not its
``usr/bin``, so no coreutils -- ``require_bash`` RAISED on the shipped code and returns
``Git/usr/bin/bash.exe`` here.

***THE FIX IS AN ENV CHANGE AND NOT A COMMAND CHANGE, WHICH IS THE WHOLE REASON IT IS SAFE.*** The
obvious alternative -- swap ``cat`` for a bash builtin -- is precisely the change whose behaviour
against the WSL launcher is unsettled, and the row for #1216 says not to resolve that in either
direction until somebody measures it. Appending a directory to PATH cannot touch it: a working WSL
resolves ``cat`` from its own rootfs and ignores the Windows PATH entirely. That argument holds by
construction, on machines this suite will never run on.

***WHAT IS DELIBERATELY NOT TESTED HERE: THE WSL LAUNCHER.*** Driving
``C:\\Windows\\System32\\bash.exe`` on this box produced a UTF-16LE Windows RPC error -- the launcher
never started -- so a verdict measured against it would be about RPC, not about filesystem
namespaces. A test that pinned it would pin the wrong mechanism and would pass or fail on whether WSL
happens to be installed. The synthetic cases below are host-independent.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from _bash_resolver import (
    BASH_HARNESS_FAILURE,
    bash_sees,
    probe_env,
    require_bash,
)


@pytest.fixture(scope="module")
def real_bash(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A bash this process can actually drive. Resolved through the thing under test on purpose --
    if it cannot find one, every row below is meaningless and should error rather than pass."""
    return Path(require_bash(tmp_path_factory.mktemp("resolve")))


# --- the defect ------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "label,path_value",
    [
        ("empty", ""),
        (
            "windows-only, no coreutils",
            r"C:\Windows\System32" if os.name == "nt" else "/nonexistent",
        ),
    ],
)
def test_a_working_bash_is_accepted_without_coreutils_on_PATH(
    real_bash: Path, tmp_path: Path, label: str, path_value: str
) -> None:
    """THE DEFECT ITSELF. Before the fix both of these returned False and 26 test ids failed."""
    assert bash_sees(real_bash, tmp_path, {"PATH": path_value}), (
        f"a working bash was rejected with PATH={label!r}. The probe is answering 'is coreutils on "
        "PATH', not 'does this interpreter share my filesystem'"
    )


def test_the_returncode_is_carried_out_of_the_probe(real_bash: Path, tmp_path: Path) -> None:
    """The row's named fix: route the probe's returncode through the handler already present.

    Asserted on the INTERNAL, because that is where the distinction has to exist -- a bool cannot
    carry it, and a caller that only sees a bool is the defect.
    """
    from _bash_resolver import _probe

    saw, code = _probe(real_bash, tmp_path, {"PATH": ""})
    assert saw is True and code == 0, f"expected a clean probe, got saw={saw} code={code}"


# --- the invariant the fix must not break ------------------------------------------------------------


def test_a_callers_prepended_entry_still_wins(real_bash: Path, tmp_path: Path) -> None:
    """THE PAIRED ARM, and it is the one that fails if the fix PREPENDS instead of appending.

    ``bash_preserves_path_order`` exists because Git ships ``curl.exe`` in ``mingw64/bin`` and a stub
    that lost to it sent a release-age check to the live network. If this fix put the interpreter's
    own directory at the HEAD, it would shadow every stub a caller prepends and defeat that control
    silently -- the test would still pass, because that control checks the caller's own prepend, and
    this one checks that ours does not displace it.
    """
    stub = tmp_path / "stubdir"
    stub.mkdir()
    env = probe_env(real_bash, {"PATH": str(stub)})
    head = env["PATH"].split(os.pathsep)[0]
    assert head == str(stub), (
        f"probe_env moved the caller's entry off the head of PATH: {env['PATH']!r}. It must APPEND."
    )
    assert str(real_bash.parent) in env["PATH"].split(os.pathsep), (
        "probe_env did not add the interpreter's own directory at all"
    )


def test_the_interpreters_directory_is_appended_to_an_empty_path(real_bash: Path) -> None:
    """An empty PATH must not become a leading separator, which some shells read as the cwd."""
    env = probe_env(real_bash, {"PATH": ""})
    assert env["PATH"] == str(real_bash.parent), f"got {env['PATH']!r}"


# --- the negative control --------------------------------------------------------------------------


def test_something_that_is_not_a_shell_is_still_rejected(tmp_path: Path) -> None:
    """ANTI-VACUITY. If the fix made ``bash_sees`` return True for anything, every row above passes
    for the wrong reason. The Python interpreter is a real executable that is not a shell."""
    assert not bash_sees(Path(sys.executable), tmp_path), (
        "bash_sees accepted a non-shell -- the probe now approves anything and proves nothing"
    )


def test_a_probe_that_cannot_run_reports_a_HARNESS_fault_not_a_namespace_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE MESSAGE, and it is the half a reader acts on.

    When every candidate exits 127 the probe never ran, so nothing observed says anything about any
    interpreter's filesystem namespace. The old text asserted one anyway -- and it is the expensive
    kind of wrong: it names WSL and namespaces, so a reader goes looking at interpreter paths instead
    of at PATH, which is where the fault actually is.
    """
    import _bash_resolver

    fake = tmp_path / "always127.cmd" if os.name == "nt" else tmp_path / "always127.sh"
    fake.write_text("exit 127\n", encoding="utf-8")
    monkeypatch.setattr(_bash_resolver, "bash_candidates", lambda: [fake])
    monkeypatch.setattr(_bash_resolver, "_probe", lambda *a, **k: (False, BASH_HARNESS_FAILURE))

    with pytest.raises(RuntimeError) as excinfo:
        require_bash(tmp_path)
    msg = str(excinfo.value)
    assert "HARNESS fault" in msg, f"the 127 case does not name a harness fault:\n{msg}"
    assert "no bash on this machine can read a file" not in msg, (
        f"the 127 case still asserts a namespace failure it did not observe:\n{msg}"
    )


def test_a_genuine_namespace_failure_still_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE OTHER HALF OF THE PAIR. A candidate that RAN and simply could not read the file is a real
    namespace verdict, and that message must survive -- otherwise the fix would have traded one
    misleading message for another."""
    import _bash_resolver

    monkeypatch.setattr(_bash_resolver, "bash_candidates", lambda: [Path(sys.executable)])
    monkeypatch.setattr(_bash_resolver, "_probe", lambda *a, **k: (False, 1))

    with pytest.raises(RuntimeError) as excinfo:
        require_bash(tmp_path)
    assert "no bash on this machine can read a file" in str(excinfo.value)


# --- end to end ------------------------------------------------------------------------------------


def test_a_child_script_can_find_the_utilities_it_needs(real_bash: Path, tmp_path: Path) -> None:
    """THE WIDER HALF THE ROW WARNS ABOUT: a probe-only fix leaves the CHILD failing at 127.

    The shipped gate steps run ``tr``, ``grep`` and ``sort``. Finding an interpreter is not enough if
    the script it runs cannot find those, so ``probe_env`` is what the callers hand to the child too.
    """
    script = tmp_path / "needs_utils.sh"
    script.write_text("printf 'a)b' | tr ')' '\\n' | grep -c .\n", encoding="utf-8")
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, test-local script
        [str(real_bash), str(script)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=probe_env(real_bash, {"PATH": ""}),
    )
    assert proc.returncode == 0, (
        f"a child script could not find its utilities: rc={proc.returncode} stderr={proc.stderr!r}"
    )
    assert proc.stdout.strip() == "2", f"unexpected output: {proc.stdout!r}"

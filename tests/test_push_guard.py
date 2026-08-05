"""Tests for the push guard (scripts/hooks/push_guard.py).

Since the MEFORORG cutover this repository IS the published artifact -- a push to ``main`` is
publication, immediately, with no publish step left to catch anything. Server-side branch protection
requires a PR and a set of required status checks; the count is deliberately not repeated here,
because it rots (``.github/required-contexts.txt`` is the checked-in claim, and this file is one of
the claim files ``tests/test_required_contexts.py`` scans for exactly that). Those checks gate
MERGING a pull request, not the push these tests exercise.

``enforce_admins`` was ON from 2026-07-28 but is OFF again as of 2026-07-29 -- the documented escape
hatch in the hook's own HISTORY note -- so for an admin protection does not apply to a direct push at
all, and this hook is the ONLY thing refusing it, exactly as when it was first written. An earlier
revision of this docstring called it "defence-in-depth"; that rested on the same false premise the
hook's own deny message carried, that the server would refuse the push anyway. It covers
``cla-signatures`` either way, which branch protection does not. The realistic trigger is unchanged:
one click on VS Code's Sync button while the current branch happens to be ``main``.

Every test feeds the script the EXACT stdin contract git uses for a pre-push hook —
``<local ref> <local sha> <remote ref> <remote sha>``, one line per ref — so what is asserted is the
interface git will actually invoke, not a convenience wrapper.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
_GUARD = _REPO / "scripts" / "hooks" / "push_guard.py"
_INSTALLER = _REPO / "scripts" / "coord" / "install-git-hooks.ps1"

_SHA = "a" * 40
_ZERO = "0" * 40


def _run(refs: str, env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = None
    if env_extra:
        import os

        env = {**os.environ, **env_extra}
    return subprocess.run(
        [sys.executable, str(_GUARD)],
        input=refs,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_a_direct_push_to_main_is_refused() -> None:
    r = _run(f"refs/heads/x {_SHA} refs/heads/main {_ZERO}\n")
    assert r.returncode == 1, r.stderr
    assert "REFUSED" in r.stderr


def test_deleting_main_is_refused() -> None:
    """A deletion has an all-zero LOCAL sha. Deleting main is worse than pushing to it."""
    r = _run(f"refs/heads/x {_ZERO} refs/heads/main {_SHA}\n")
    assert r.returncode == 1, r.stderr
    assert "DELETE" in r.stderr


def test_the_cla_signature_branch_is_protected() -> None:
    """Written by the CLA Assistant action, never by a human — and every PR wedges if it is damaged."""
    r = _run(f"refs/heads/x {_SHA} refs/heads/cla-signatures {_ZERO}\n")
    assert r.returncode == 1, r.stderr


def test_an_ordinary_branch_push_is_allowed() -> None:
    """The control. Without this, a guard that refused EVERYTHING would look identical to a working one."""
    r = _run(f"refs/heads/x {_SHA} refs/heads/feature-y {_ZERO}\n")
    assert r.returncode == 0, r.stderr
    assert r.stderr.strip() == ""


def test_a_mixed_push_is_refused_because_one_ref_is_protected() -> None:
    """`git push --all` sends every ref at once; one protected ref must sink the whole push."""
    r = _run(
        f"refs/heads/a {_SHA} refs/heads/feature-y {_ZERO}\n"
        f"refs/heads/b {_SHA} refs/heads/main {_ZERO}\n"
    )
    assert r.returncode == 1, r.stderr


def test_the_escape_hatch_works_and_says_so() -> None:
    """Deliberately NOT --no-verify: a distinct variable is greppable in shell history, and cannot be
    reached by the muscle memory that skips every other hook at once."""
    r = _run(
        f"refs/heads/x {_SHA} refs/heads/main {_ZERO}\n",
        {"MEFOR_ALLOW_DIRECT_PUSH": "1"},
    )
    assert r.returncode == 0, r.stderr
    assert "ALLOWED" in r.stderr


def test_malformed_stdin_does_not_crash_the_push() -> None:
    """git sends nothing at all for some invocations. Fail OPEN on garbage rather than wedging pushes —
    the guard exists to stop an accident, and crashing on unexpected input would BE one."""
    r = _run("not four fields\n\n")
    assert r.returncode == 0, r.stderr


# --------------------------------------------------------------------------------------------------
# WIRING. The tests above prove the logic. None of them notices if nothing ever installs the hook —
# the same gap that let the ledger gate sit silently un-invoked (see test_ledger_check.py).
# --------------------------------------------------------------------------------------------------


def test_the_installer_wires_the_push_guard() -> None:
    src = _INSTALLER.read_text(encoding="utf-8")
    assert "push_guard.py" in src, "installer never copies the guard into .git/hooks"
    assert "WriteAllText($prePush" in src, "installer never writes the pre-push hook"
    # It must refuse to clobber someone else's pre-push hook, and remove its own on -Uninstall.
    assert "Refusing to overwrite it" in src
    assert "Remove-Item -LiteralPath $prePush" in src, "-Uninstall must remove the push guard"

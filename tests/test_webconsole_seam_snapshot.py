# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The enforced version-skew HANDSHAKE for the web console seam (Option B, ADR 0065).

Regenerates the engine-side seam-contract snapshot (``scripts/webconsole_seam_snapshot.py``) and
diffs it against the checked-in golden. Any incompatible change to the contract the separately-
versioned ``messagefoundry-webconsole`` package depends on — a renamed handler field, a re-signatured
``api.security`` dep or ``AuthService`` method, or a renamed field on a DTO the console renders (which
breaks render, not import, so mypy alone misses it) — changes the snapshot and FAILS here until the
seam is bumped on both sides and the golden refreshed. This gate is the sole backstop against a
FUTURE engine's unbumped, render-breaking DTO rename, so it must stay comprehensive and blocking.
"""

from __future__ import annotations

import difflib
import importlib.util
import os
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO_ROOT / "scripts" / "webconsole_seam_snapshot.py"
_GOLDEN = _REPO_ROOT / "tests" / "golden" / "webconsole_seam.snapshot"

# Pure ASCII, deliberately. The previous text carried U+2014, which renders as a replacement
# character on a cp1252 console -- the developer-facing half of BACKLOG #1221. It also said "bump
# ENGINE_UI_SEAM", which is no longer a thing anyone does: the seam is DERIVED (#1220), so the
# remediation is to regenerate it, and a message naming an action that no longer exists is how a
# gate teaches the wrong repair.
_FAILURE_HINT = (
    "webconsole seam drift: the engine/console contract changed but ENGINE_UI_SEAM did not.\n"
    "\n"
    "If the change is INTENTIONAL, do BOTH of these in the SAME commit:\n"
    "  1. python scripts/webconsole_seam_snapshot.py --write\n"
    "       (rewrites ENGINE_UI_SEAM in messagefoundry/api/_ui_seam.py and refreshes\n"
    "        tests/golden/webconsole_seam.snapshot)\n"
    "  2. set the console's accepted seam to the SAME value, BY HAND:\n"
    "       messagefoundry_webconsole/__init__.py\n"
    '         SUPPORTED_ENGINE_SEAMS: frozenset[str] = frozenset({"<the new value>"})\n'
    "     The console is a separately built wheel holding exactly ONE seam (BACKLOG #279), so a\n"
    "     forgotten update is not a warning: a deploying site gets a hard startup refusal.\n"
    "\n"
    "If you did NOT intend a contract change, this gate is doing its job. Fix the change.\n"
    "Never hand-edit the constant to silence it."
)


# Pure ASCII, like _FAILURE_HINT above and for the same reason. Named separately because it teaches a
# DIFFERENT repair: _FAILURE_HINT says the contract moved, this says the instrument is reading the
# wrong tree, and offering the first for the second is what sends a reader to re-derive a gate that
# was already right.
_ANCHOR_HINT = """\
scripts/webconsole_seam_snapshot.py must resolve `messagefoundry` from the repository it lives in,
not from whatever sys.path offers (BACKLOG #1439). Keep the anchor near the top of it:

    _REPO_ROOT = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(_REPO_ROOT))

ABOVE the `from messagefoundry...` imports. Python puts the SCRIPT's directory on sys.path[0], never
the caller's cwd, so without it the import falls through to site-packages -- which in a worktree with
no .venv of its own is the PRIMARY checkout's editable install, a different tree. Same rule as
scripts/coord/alloc.ps1 (BACKLOG #1060) and the siblings under scripts/bench and scripts/tray.

Do NOT repair this by setting PYTHONPATH at the call site: that fixes one caller and leaves the
script wrong for every other one, including the by-hand run docs/WEBCONSOLE-PACKAGE.md prescribes."""


def _build_snapshot() -> str:
    """Load the generator script by path (scripts/ is not an importable package) and run it."""
    spec = importlib.util.spec_from_file_location("_webconsole_seam_snapshot", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snapshot: str = module.build_snapshot()
    return snapshot


def _build_digest() -> str:
    """The digest as THIS process derives it, for comparison against a by-path subprocess run."""
    spec = importlib.util.spec_from_file_location("_webconsole_seam_digest", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["_webconsole_seam_digest"] = module
    spec.loader.exec_module(module)
    digest: str = module.contract_digest()
    return digest


def test_webconsole_seam_snapshot_matches_golden() -> None:
    current = _build_snapshot()
    golden = _GOLDEN.read_text(encoding="utf-8")
    if current != golden:
        diff = "".join(
            difflib.unified_diff(
                golden.splitlines(keepends=True),
                current.splitlines(keepends=True),
                fromfile="tests/golden/webconsole_seam.snapshot",
                tofile="scripts/webconsole_seam_snapshot.py (current)",
            )
        )
        raise AssertionError(f"{_FAILURE_HINT}\n\n{diff}")


def test_console_supports_exactly_the_engine_seam() -> None:
    """The console accepts ONE seam — the engine's (BACKLOG #279, option (b)).

    This is the enforcement half of narrowing the range. A seam bump has always required editing BOTH
    constants (a new seam was never in the old set either), but nothing FAILED when the console side
    was forgotten — the mismatch surfaced at a customer's startup as UiSeamMismatch. Now it fails
    here, in CI, on the commit that bumps the engine.

    If cross-seam support is ever wanted again, re-widen SUPPORTED_ENGINE_SEAMS **and** land the CI
    matrix that installs the MIN and MAX supported engine builds. Deleting this test to allow a range
    would restore exactly the untested claim #279 was filed against.
    """
    from messagefoundry.api._ui_seam import ENGINE_UI_SEAM
    from messagefoundry_webconsole import SUPPORTED_ENGINE_SEAMS

    expected = frozenset({ENGINE_UI_SEAM})
    assert expected == SUPPORTED_ENGINE_SEAMS, (
        f"console supports {sorted(SUPPORTED_ENGINE_SEAMS)} but the engine ships seam "
        f"{ENGINE_UI_SEAM}. Bumping ENGINE_UI_SEAM requires updating "
        "messagefoundry_webconsole.SUPPORTED_ENGINE_SEAMS in the SAME commit."
    )


def test_assert_engine_seam_refuses_any_other_seam() -> None:
    """The gate must reject ANY seam that is not this engine's.

    This replaces a ``ENGINE_UI_SEAM +/- 1`` test that could not survive #1220: the seam is a digest
    now, so "one older" and "one newer" do not exist. That test is the reason the constant is a
    ``str`` rather than a truncated integer -- under an int digest ``ENGINE_UI_SEAM - 1`` would still
    evaluate, the assertion would still PASS, and its own docstring ("one seam older AND one newer")
    would have quietly become false. A passing test making a claim the value no longer supports is
    the same defect class #1220 was filed against.

    The intent BACKLOG #279 put in the original survives: exactly one seam is accepted, and every
    other value is refused in both directions of the handshake."""
    import pytest

    from messagefoundry.api._ui_seam import ENGINE_UI_SEAM
    from messagefoundry_webconsole import UiSeamMismatch, assert_engine_seam

    assert_engine_seam(ENGINE_UI_SEAM)  # the matching engine mounts

    truncated = ENGINE_UI_SEAM[:-1]
    for skew in ("", "0", truncated, ENGINE_UI_SEAM + "0", "f" * len(ENGINE_UI_SEAM)):
        with pytest.raises(UiSeamMismatch):
            assert_engine_seam(skew)


def test_the_stored_seam_equals_the_derived_digest() -> None:
    """THE GATE. ``ENGINE_UI_SEAM`` is a digest of the discovered contract surface, so a contract
    change that forgets the constant fails here.

    This is what removes the hand-chosen number: two branches changing different parts of the surface
    derive different values, and their MERGED surface derives a third matching neither, so the merge
    reds instead of auto-merging clean under one seam (BACKLOG #1220)."""
    from messagefoundry.api._ui_seam import ENGINE_UI_SEAM

    spec = importlib.util.spec_from_file_location("_seam_gen_gate", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["_seam_gen_gate"] = module
    spec.loader.exec_module(module)

    assert module.contract_digest() == ENGINE_UI_SEAM, _FAILURE_HINT


def test_the_digest_does_not_depend_on_the_seam_it_produces() -> None:
    """ANTI-CIRCULARITY. The seam must not feed its own digest, or the gate is vacuous.

    Asserted by MOVING the constant and requiring the digest to hold still -- not by checking that
    the seam's text is absent from the digest input. A substring check would be defeated by a short
    or coincidental value (the snapshot header already contains the literal ``0065``), which is
    exactly the kind of check that looks like proof and is not."""
    import messagefoundry.api._ui_seam as seam_module

    spec = importlib.util.spec_from_file_location("_seam_gen_circ", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["_seam_gen_circ"] = module
    spec.loader.exec_module(module)

    before = module.contract_digest()
    original = seam_module.ENGINE_UI_SEAM
    try:
        seam_module.ENGINE_UI_SEAM = "deadbeefdeadbeef"  # type: ignore[misc]
        module.ENGINE_UI_SEAM = "deadbeefdeadbeef"
        assert module.contract_digest() == before
    finally:
        seam_module.ENGINE_UI_SEAM = original  # type: ignore[misc]
        module.ENGINE_UI_SEAM = original


def test_the_digest_moves_when_a_rendered_dto_gains_a_field() -> None:
    """MADE TO FAIL ON PURPOSE. The gate is evidence only if it can see the class of change it
    exists to catch.

    The historical control is commit 40a4d5d9: it added a REQUIRED ``scope`` field to
    ``UploadedFileList``, which the console renders unconditionally, and the seam did NOT move.
    Adding a field must move the digest now."""
    from pydantic import create_model

    from messagefoundry.api import models

    spec = importlib.util.spec_from_file_location("_seam_gen_mutate", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["_seam_gen_mutate"] = module
    spec.loader.exec_module(module)

    before = module.contract_digest()
    original = models.UploadedFileList
    try:
        models.UploadedFileList = create_model(  # type: ignore[misc]
            "UploadedFileList",
            __base__=original,
            proof_field=(str, "x"),
        )
        assert module.contract_digest() != before
    finally:
        models.UploadedFileList = original  # type: ignore[misc]

    assert module.contract_digest() == before  # and it restores exactly


def _digest_by_path(env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    """Run the generator THE WAY A HUMAN RUNS IT: by path, as its own process.

    ``cwd`` is deliberately NOT the repo root and ``PYTHONPATH`` is deliberately scrubbed. Both are
    the rescues that hid BACKLOG #1439: under pytest the root is already on ``sys.path``, so the
    in-process loads above cannot see the defect at all, and a subprocess that inherited either one
    would pass for a reason that has nothing to do with the script.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, str(_SCRIPT), "--digest"],
        capture_output=True,
        text=True,
        cwd=tempfile.gettempdir(),
        env=env,
    )


def test_the_script_run_by_path_computes_the_same_digest() -> None:
    """The SCRIPT and the TEST must derive one value (BACKLOG #1439).

    They are two instruments reading one contract, and they used to be able to disagree silently.
    ``sys.path[0]`` is the SCRIPT's directory, never the caller's cwd, so ``scripts/`` led the path
    and ``import messagefoundry`` fell through to site-packages -- in a worktree with no ``.venv``,
    the primary checkout's, via its path-based editable install. Measured 2026-09-03: ``--write``
    printed the primary tree's digest, rewrote both files with it and reported SUCCESS, while the
    golden test kept failing against the worktree digest the script had never computed. Nothing was
    louder than the word "rewrote", so the conclusion on offer was that this gate was broken.
    """
    result = _digest_by_path()
    assert result.returncode == 0, f"the script failed to run by path:\n{result.stderr}"
    assert result.stdout.strip() == _build_digest(), (
        "the script and this test derive DIFFERENT digests, so they are reading different trees.\n"
        f"  script (run by path): {result.stdout.strip()}\n"
        f"  this test (in-process): {_build_digest()}\n"
        f"{_ANCHOR_HINT}"
    )


def test_the_script_prefers_its_own_repo_over_an_earlier_path_entry() -> None:
    """MADE TO FAIL ON PURPOSE. Delete the ``sys.path`` insert and this test reds.

    The test above cannot carry that weight alone: on a hosted runner there is exactly ONE engine
    tree, so an unanchored script finds the right one by luck and agrees with everything. This test
    supplies the second tree itself -- a decoy ``messagefoundry`` package on ``PYTHONPATH``, which
    for a by-path invocation sits AHEAD of site-packages and BEHIND an explicit ``sys.path.insert(0,
    repo_root)``. So the decoy wins if and only if the anchor is gone, on any machine.

    A test whose environment cannot produce the failure is not evidence that the failure is absent.
    """
    with tempfile.TemporaryDirectory() as tmp:
        decoy = Path(tmp) / "messagefoundry"
        decoy.mkdir()
        (decoy / "__init__.py").write_text(
            'raise ImportError("DECOY engine tree: the script resolved messagefoundry from '
            'PYTHONPATH instead of its own repository (BACKLOG #1439)")\n',
            encoding="utf-8",
        )
        result = _digest_by_path({"PYTHONPATH": tmp})

    assert result.returncode == 0, (
        f"the decoy engine tree won: the script is no longer anchored to its own repository.\n"
        f"{_ANCHOR_HINT}\n\n{result.stderr}"
    )
    assert result.stdout.strip() == _build_digest()

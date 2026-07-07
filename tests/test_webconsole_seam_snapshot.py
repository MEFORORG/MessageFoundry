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
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO_ROOT / "scripts" / "webconsole_seam_snapshot.py"
_GOLDEN = _REPO_ROOT / "tests" / "golden" / "webconsole_seam.snapshot"

_FAILURE_HINT = (
    "the webconsole seam contract changed — bump ENGINE_UI_SEAM in api/_ui_seam.py AND "
    "messagefoundry_webconsole.SUPPORTED_ENGINE_SEAMS, then refresh "
    "tests/golden/webconsole_seam.snapshot via scripts/webconsole_seam_snapshot.py."
)


def _build_snapshot() -> str:
    """Load the generator script by path (scripts/ is not an importable package) and run it."""
    spec = importlib.util.spec_from_file_location("_webconsole_seam_snapshot", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    snapshot: str = module.build_snapshot()
    return snapshot


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

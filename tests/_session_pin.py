# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Write the session pin ``scripts/hooks/_hookinput.ps1`` reads, as a launch would.

A hook answers for a linked worktree only when a pin says the session started there (rule 4 in the
helper's header). The tests that drive a hook from the primary with a worktree ``cwd`` seed one here,
so each test states the session's worktree rather than relying on an earlier hook run.

The name is the first eight bytes of SHA-256 over the session id, as hex, under the common dir's
``ccx-session-root``. The helper's own tests pin the same layout through a real SessionStart.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path


def pin_path(start: Path, session_id: str) -> Path:
    common = subprocess.run(
        ["git", "-C", str(start), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    key = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:16]
    return Path(common) / "ccx-session-root" / key


def seed_pin(start: Path, worktree: Path, session_id: str) -> Path:
    """Record that ``session_id`` started in ``worktree``. Returns the pin's path."""
    pin = pin_path(start, session_id)
    pin.parent.mkdir(parents=True, exist_ok=True)
    pin.write_text(os.path.realpath(worktree), encoding="utf-8")
    return pin

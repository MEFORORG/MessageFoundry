# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Write the audit row a ``POST /dr/activate`` on this host leaves, for a test that boots a DR box
under ``[dr].activate = true`` (BACKLOG #5965). The engine resumes only such an activation, so a
test of the resumed box's behaviour starts from one. ``tests/test_dr_boot_resume.py`` proves the
resume against a real activation; this only stands in for one."""

from __future__ import annotations

import json
import socket
from pathlib import Path

from messagefoundry.store import MessageStore


async def record_prior_activation(db: Path) -> None:
    """Record, in the store at ``db``, a ``dr.activate`` row made on this host at the default
    threshold and not released."""
    store = await MessageStore.open(db)
    try:
        await store.record_audit(
            "dr.activate",
            actor="alice",
            detail=json.dumps({"node": socket.gethostname(), "threshold": "critical"}),
            now=1.0,
        )
    finally:
        await store.close()

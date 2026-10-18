# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read one pending request's ``release_blocked`` off ``GET /approvals`` (BACKLOG #3189, #3192).

Shared by the suites that check the queue predicts a release the gate refuses, so the listing's
shape is read in one place."""

from __future__ import annotations

from typing import Any

import httpx


async def release_blocked(c: httpx.AsyncClient, approval_id: str, headers: dict[str, str]) -> Any:
    """The ``release_blocked`` of the one listed request with ``approval_id``."""
    r = await c.get("/approvals", headers=headers)
    assert r.status_code == 200, r.text
    [entry] = [e for e in r.json()["approvals"] if e["id"] == approval_id]
    return entry["release_blocked"]

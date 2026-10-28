# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one reader of ``auth.logout`` audit rows the sign-out tests share (BACKLOG #3749 item 9).

The engine suite and the web console suite each used to carry their own copy.
"""

from __future__ import annotations

import json
from typing import Any


async def logout_rows(store: Any) -> list[tuple[object, object, object]]:
    """Each ``auth.logout`` row, newest first, as its actor, client address and
    ``detail.outcome``."""
    return [
        (row["actor"], row["client"], json.loads(str(row["detail"] or "{}")).get("outcome"))
        for row in await store.list_audit(action="auth.logout")
    ]


async def logout_details(store: Any) -> list[dict[str, object]]:
    """Each ``auth.logout`` row's whole ``detail``, newest first."""
    return [
        json.loads(str(row["detail"] or "{}"))
        for row in await store.list_audit(action="auth.logout")
    ]

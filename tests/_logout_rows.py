# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one reader of ``auth.logout`` audit rows the sign-out tests share (BACKLOG #3749 item 9).

The engine suite and the web console suite each used to carry their own copy.
"""

from __future__ import annotations

import json
from typing import Any

from messagefoundry.auth.service import AUTHORITY_SEAL_FAILED_ACTION


async def logout_rows(
    store: Any, *, limit: int | None = None
) -> list[tuple[object, object, object]]:
    """Each ``auth.logout`` row, newest first, as its actor, client address and
    ``detail.outcome``. ``limit``, when given, is passed to ``list_audit``."""
    extra = {} if limit is None else {"limit": limit}
    return [
        (row["actor"], row["client"], json.loads(str(row["detail"] or "{}")).get("outcome"))
        for row in await store.list_audit(action="auth.logout", **extra)
    ]


async def temp_password_expired_rows(store: Any) -> list[tuple[object, object, object]]:
    """Each ``auth.temp_password_expired`` row, newest first, as its actor, client address and
    whole ``detail``: the row a sign-out writes when it ends a session whose temporary credential
    lapsed (BACKLOG #3749)."""
    return [
        (row["actor"], row["client"], json.loads(str(row["detail"] or "{}")))
        for row in await store.list_audit(action="auth.temp_password_expired")
    ]


async def seal_failed_details(store: Any) -> list[dict[str, object]]:
    """Each integrity-failure report row's whole ``detail``, newest first: the row a gate writes
    when it ends a session that fails its seal or its account's epoch, and which a sign-out or a
    sign-in's supersession does not write (BACKLOG #2592, #3749)."""
    return [
        json.loads(str(row["detail"] or "{}"))
        for row in await store.list_audit(action=AUTHORITY_SEAL_FAILED_ACTION)
    ]


async def logout_details(store: Any) -> list[dict[str, object]]:
    """Each ``auth.logout`` row's whole ``detail``, newest first."""
    return [
        json.loads(str(row["detail"] or "{}"))
        for row in await store.list_audit(action="auth.logout")
    ]

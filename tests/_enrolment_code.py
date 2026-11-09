# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0207 for tests that enrol a directory account's first factor on an unstamped session.

Since ADR 0207 such a binding step needs a single-use enrolment code an Administrator issued. A test
whose subject is something else (the directory re-check, the factor-binding rule, the sign-in
baseline) issues one here and passes it, so it keeps testing what it tested. The codes are minted by
the engine itself; nothing here is a real credential.
"""

from __future__ import annotations

from typing import Any

from messagefoundry.auth.service import EnrolmentCodeIssueRefused


async def enrolment_code_for(service: Any, user_id: str) -> str | None:
    """A fresh code for ``user_id``'s first factor, or ``None`` where none is issued: a local
    account, a disabled one, or one that already holds a factor. Issued as the host command would
    issue it, so no Administrator account is needed and no spent notice is written."""
    try:
        issued = await service.issue_enrolment_code(
            user_id, actor="test-host", issuer_id=None, via="host"
        )
    except EnrolmentCodeIssueRefused:
        return None
    return str(issued.code)

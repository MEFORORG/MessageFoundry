# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``SessionRecord.from_mapping`` reads the ``seal`` cell as text (BACKLOG #6718 item 2).

``RoleRow``, ``ApprovalRow`` and ``UserRow`` read their seal with ``str(... or "")``; the session
reader passed the cell through, so a seal cell SQLite hands back as a BLOB, after an edit outside
the store, left a ``SessionRecord.seal`` that is not a ``str``. Synthetic values only.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.store.store import SessionRecord


def _row(seal: object) -> dict[str, Any]:
    return {
        "token_hash": "t" * 64,
        "user_id": "u-6718",
        "created_at": 1.0,
        "expires_at": 3.0,
        "last_used_at": 2.0,
        "revoked_at": None,
        "client": "198.51.100.7",
        "reauth_at": None,
        "mfa_verified_at": None,
        "auth_mechanism": "password",
        "idp_auth_time": None,
        "user_epoch": 0,
        "global_epoch": 0,
        "seal": seal,
    }


def test_a_blob_seal_cell_reads_as_text() -> None:
    seal = SessionRecord.from_mapping(_row(b"mfseal:v1:k:ab")).seal
    assert isinstance(seal, str)


@pytest.mark.parametrize(("cell", "expected"), [("mfseal:v1:k:ab", "mfseal:v1:k:ab"), (None, "")])
def test_a_text_or_null_seal_cell_reads_as_before(cell: object, expected: str) -> None:
    """The control: a text seal is kept as it is and a NULL one reads as empty."""
    assert SessionRecord.from_mapping(_row(cell)).seal == expected

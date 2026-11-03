# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every restore notice says what a restore rolls back from one statement (BACKLOG #5094).

The ``store_restored`` alert, the ``restore`` summary, its age refusal and the
``--allow-old-archive`` help each used to carry their own list: disables, deletes, role changes and
resets. That left out at least self-service password changes, MFA and passkey removals, notify-email
changes, AD maps, custom roles and channel scopes, so an operator acting on the notice after a
restore would leave a removed factor live. Each now carries
:data:`messagefoundry.restore_notice.RESTORE_ROLLBACK_NOTICE` whole, and the adopter guide's
restore section names every class it lists.
"""

from __future__ import annotations

import argparse
import re
import time
from pathlib import Path

import pytest

from messagefoundry.__main__ import _build_parser
from messagefoundry.pipeline.alerts import store_restored_detail
from messagefoundry.pipeline.dr_backup import (
    BackupError,
    _refuse_an_old_archive,
    restored_accounts_notice,
)
from messagefoundry.restore_notice import RESTORE_ROLLBACK_CLASSES, RESTORE_ROLLBACK_NOTICE

_GUIDE = Path(__file__).resolve().parent.parent / "docs" / "EARLY-ADOPTER-GUIDE.md"


def _flat(text: str) -> str:
    """``text`` with every run of whitespace made one space, so a wrapped line still matches."""
    return re.sub(r"\s+", " ", text)


def test_the_statement_names_the_classes_the_old_notices_left_out() -> None:
    # The finding's list, as words the statement must carry. Each is a change a restore undoes.
    for word in (
        "disable",
        "delete",
        "role change",
        "password reset",
        "password change",
        "self-service",
        "MFA",
        "passkey",
        "removal",
        "enrolment",
        "recovery code",
        "notify-email",
        "custom role",
        "channel scope",
        "AD group",
    ):
        assert word in RESTORE_ROLLBACK_NOTICE, word
    # A floor, not a census: the restore replaces the whole store.
    assert "at least" in RESTORE_ROLLBACK_NOTICE
    assert "must be re-applied by hand" in RESTORE_ROLLBACK_NOTICE
    for cls in RESTORE_ROLLBACK_CLASSES:
        assert cls in RESTORE_ROLLBACK_NOTICE


def test_the_alert_carries_the_statement() -> None:
    detail = store_restored_detail(
        archive_created_at=1_000_000.0,
        last_audit_at=999_000.0,
        restored_at=1_000_000.0 + 3 * 86400,
        revoked=2,
    )
    assert RESTORE_ROLLBACK_NOTICE in detail
    # The reason column keeps about the first 200 characters, so the age and the count lead.
    assert detail.index("3.0 days old") < detail.index("2 session(s)") < 200


def test_the_cli_summary_carries_the_statement() -> None:
    assert RESTORE_ROLLBACK_NOTICE in restored_accounts_notice(0)


def test_the_age_refusal_carries_the_statement() -> None:
    with pytest.raises(BackupError) as info:
        _refuse_an_old_archive(
            archive_created_at=None, last_audit_at=None, max_age_seconds=86400.0, now=time.time()
        )
    assert RESTORE_ROLLBACK_NOTICE in str(info.value)


def test_the_allow_old_archive_help_carries_the_statement() -> None:
    parser, _dispatch = _build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    restore = sub.choices["restore"]
    flag = next(a for a in restore._actions if "--allow-old-archive" in a.option_strings)
    assert flag.help is not None
    assert RESTORE_ROLLBACK_NOTICE in flag.help


def test_the_guide_names_every_class() -> None:
    guide = _flat(_GUIDE.read_text(encoding="utf-8"))
    for cls in RESTORE_ROLLBACK_CLASSES:
        assert cls in guide, cls

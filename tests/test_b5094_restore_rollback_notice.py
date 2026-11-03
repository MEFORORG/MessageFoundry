# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every restore notice says what a restore rolls back from one statement (BACKLOG #5094).

The ``store_restored`` alert, the ``restore`` summary, its age refusal and the
``--allow-old-archive`` help each used to carry their own list: disables, deletes, role changes and
resets. That left out at least self-service password changes, MFA and passkey removals, notify-email
changes, AD maps, custom roles and channel scopes, so an operator acting on the notice after a
restore would leave a removed factor live. Each now carries
:data:`messagefoundry.restore_notice.RESTORE_ROLLBACK_NOTICE` whole, or, where there is no room for
it, :data:`messagefoundry.restore_notice.RESTORE_NOTICE_POINTER`, which names the command that
prints it. The adopter guide's restore section names every class it lists.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import logging
import re
import time
from pathlib import Path

import pytest

from messagefoundry.__main__ import _build_parser, main
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink, _body
from messagefoundry.pipeline.alerts import (
    STORE_RESTORED_SUBJECT,
    LoggingAlertSink,
    store_restored_detail,
)
from messagefoundry.pipeline.dr_backup import (
    BackupError,
    _refuse_an_old_archive,
    restored_accounts_notice,
)
from messagefoundry.restore_notice import (
    RESTORE_NOTICE_POINTER,
    RESTORE_ROLLBACK_CLASSES,
    RESTORE_ROLLBACK_NOTICE,
)
from messagefoundry.store.store import MessageStore
from tests.test_alert_sinks import _drain, _RecordingTransport

_ROOT = Path(__file__).resolve().parent.parent
_GUIDE = _ROOT / "docs" / "EARLY-ADOPTER-GUIDE.md"
_LEAF = _ROOT / "messagefoundry" / "restore_notice.py"


def _flat(text: str) -> str:
    """``text`` with every run of whitespace made one space, so a wrapped line still matches."""
    return re.sub(r"\s+", " ", text)


def _unwrapped(text: str) -> str:
    """``text`` as argparse wrapped it, unwrapped: argparse breaks a line after a word's hyphen
    (``self-`` then ``service``), and the notice has no hyphen with a space after it."""
    return re.sub(r"-\s+", "-", _flat(text))


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
        "lock",
        "OIDC",
        "dual-control",
        "Messages received",
        "reject it",
        "before users can reach",
        # Round 4: what an operator can do about the reach, and what a restore brings back
        # rather than undoes.
        "[api].host on loopback",
        "admin-unlock",
        "admin-revoke-sessions",
        "delivered again",
        "after_read = leave",
        "duplicates",
        "vault_transit bound attestation",
        "withdraw-transit-bound",
    ):
        assert word in RESTORE_ROLLBACK_NOTICE, word
    # A floor, not a census: the restore replaces the whole store.
    assert "at least" in RESTORE_ROLLBACK_NOTICE
    assert "must be re-applied by hand" in RESTORE_ROLLBACK_NOTICE


_RESTORED_AT = 1_000_000.0 + 3 * 86400


def _detail(created: float | None = 1_000_000.0, revoked: int = 2) -> str:
    return store_restored_detail(
        archive_created_at=created,
        last_audit_at=999_000.0,
        restored_at=_RESTORED_AT,
        revoked=revoked,
    )


def test_the_alert_detail_points_at_the_statement() -> None:
    detail = _detail()
    assert RESTORE_NOTICE_POINTER in detail
    assert "3.0 days old" in detail and "2 session(s)" in detail
    # The notice rides the event as its own key, so the detail stays short enough for the column.
    assert RESTORE_ROLLBACK_NOTICE not in detail


def test_the_pointer_names_a_command_that_prints_the_statement(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The pointer must resolve on an installed engine through every alert path, a custom email
    template and a muted rule included: ``restore --help`` needs no config, store or engine."""
    assert RESTORE_NOTICE_POINTER.startswith("messagefoundry restore --help ")
    with pytest.raises(SystemExit) as info:
        main(["restore", "--help"])
    assert info.value.code == 0
    assert _unwrapped(RESTORE_ROLLBACK_NOTICE) in _unwrapped(capsys.readouterr().out)


async def test_the_notifier_event_carries_the_statement_whole() -> None:
    """The webhook JSON and the default email body are built from the event's keys, so the
    notice rides as its own key beside the short detail."""
    transport = _RecordingTransport("t")
    sink = NotifierAlertSink([transport])
    sink.store_restored(STORE_RESTORED_SUBJECT, detail=_detail(), last_audit_at="unknown")
    await _drain(sink)
    (event,) = transport.events
    assert event["rollback_notice"] == RESTORE_ROLLBACK_NOTICE
    assert event["detail"] == _detail()
    assert f"rollback_notice: {RESTORE_ROLLBACK_NOTICE}" in _body(event)


def test_the_logging_sink_logs_the_statement_whole(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().store_restored(
            STORE_RESTORED_SUBJECT, detail=_detail(), last_audit_at="unknown"
        )
    assert RESTORE_ROLLBACK_NOTICE in caplog.text and RESTORE_NOTICE_POINTER in caplog.text


@pytest.mark.parametrize(
    ("created", "revoked", "age"),
    [
        (1_000_000.0, 2, "3.0 days old"),
        (None, 9_999_999, "of unknown age"),
        # The longest age written as a number, and a crafted manifest time past it.
        (_RESTORED_AT - 99_999 * 86400, 9_999_999, "99999.0 days old"),
        (-1e300, 9_999_999, "over 99999 days old"),
    ],
    ids=["short", "unknown-age-longest-count", "longest-age-longest-count", "crafted-age"],
)
def test_the_stored_alert_reason_keeps_age_count_and_pointer_whole(
    tmp_path: Path, created: float | None, revoked: int, age: str
) -> None:
    """The alert instance's reason column keeps only about the first 200 characters of the
    detail: written and read back through the store, the age, the count and the pointer must
    survive whole (BACKLOG #2614 put the age and the count first for this)."""
    detail = _detail(created, revoked)

    async def _kept() -> str | None:
        store = await MessageStore.open(tmp_path / "msg.db")
        try:
            await store.upsert_alert_instance(
                event_type="store_restored",
                connection=STORE_RESTORED_SUBJECT,
                severity="warning",
                reason=detail,
            )
            (row,) = await store.list_active_alert_instances(allowed_channels=None)
            return row.reason
        finally:
            await store.close()

    kept = asyncio.run(_kept())
    assert kept is not None and len(kept) < len(detail)  # control: the column did cut it
    whole = (
        f"Started on a store restored from an archive {age}; {revoked} session(s) revoked. "
        f"Re-apply what it undid: {RESTORE_NOTICE_POINTER}"
    )
    assert kept.startswith(whole), kept


def test_the_cli_summary_carries_the_statement() -> None:
    assert RESTORE_ROLLBACK_NOTICE in restored_accounts_notice(0)


def test_the_age_refusal_leads_with_nothing_written_and_points_at_the_statement() -> None:
    with pytest.raises(BackupError) as info:
        _refuse_an_old_archive(
            archive_created_at=None, last_audit_at=None, max_age_seconds=86400.0, now=time.time()
        )
    refusal = str(info.value)
    assert refusal.startswith("Nothing was written: ")
    assert refusal.endswith(RESTORE_NOTICE_POINTER)
    assert "re-applied by hand" in refusal
    # Short: the refusal points at the statement rather than carrying it.
    assert len(refusal) < 300 and RESTORE_ROLLBACK_NOTICE not in refusal


def test_the_allow_old_archive_help_carries_the_statement() -> None:
    parser, _dispatch = _build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    restore = sub.choices["restore"]
    flag = next(a for a in restore._actions if "--allow-old-archive" in a.option_strings)
    assert flag.help is not None
    assert RESTORE_ROLLBACK_NOTICE in flag.help
    # argparse %-formats help when it renders it, so a "%" in the notice would break --help.
    assert "must be re-applied by hand" in _flat(restore.format_help())


def test_the_guide_restore_section_names_every_class() -> None:
    guide = _flat(_GUIDE.read_text(encoding="utf-8"))
    start = guide.index("**What a restore rolls back")
    section = guide[start : guide.index("**`restore` refuses", start)]
    for cls in RESTORE_ROLLBACK_CLASSES:
        assert cls in section, cls


def test_the_statement_is_a_leaf() -> None:
    # The CLI builds its parser from it on every run, and the startup import budget that names it
    # is advisory on 3.14, so an import added here is refused here.
    tree = ast.parse(_LEAF.read_text(encoding="utf-8"))
    imports = [n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))]
    assert [getattr(n, "module", None) for n in imports] == ["__future__"]

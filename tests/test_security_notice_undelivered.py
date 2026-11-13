# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2383 (ASVS 6.3.7, 6.3.5): a security notice the relay's queue drops, or whose send
fails, leaves an audit row naming the account and the notice kind.

The SMTP send is faked, so nothing reaches the network. Each test reads the rows back through the
store's ``list_audit``, the read ``GET /audit`` serves, over a real in-memory store.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, cast

import pytest

from messagefoundry.auth.audit_visibility import (
    HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE,
    LOCK_NOTICE_UNDELIVERED_ACTION,
)
from messagefoundry.auth.notifications import (
    ACCOUNT_LOCKED,
    EMAIL_CHANGED,
    PASSWORD_CHANGED,
    TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
    SecurityEvent,
)
from messagefoundry.pipeline.security_notify import (
    SECURITY_NOTICE_UNDELIVERED_ACTION,
    SecurityEventNotifier,
)
from messagefoundry.store.base import AuditStore
from messagefoundry.store.store import MessageStore

_SEND = "messagefoundry.pipeline.security_notify.send_plain_email"


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    try:
        yield s
    finally:
        await s.close()


def _notifier(store: MessageStore) -> SecurityEventNotifier:
    return SecurityEventNotifier(
        host="smtp.example.org", port=25, sender="mf@example.org", audit=store
    )


async def _undelivered(store: MessageStore) -> list[tuple[str, str, dict[str, Any]]]:
    rows = await store.list_audit(limit=50)
    return [
        (str(r["action"]), str(r["actor"]), json.loads(r["detail"]))
        for r in rows
        if str(r["action"]) in (SECURITY_NOTICE_UNDELIVERED_ACTION, LOCK_NOTICE_UNDELIVERED_ACTION)
    ]


async def test_a_failed_send_writes_an_audit_row_without_the_address(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(**_: Any) -> None:
        raise OSError("relay down: 550 new@example.net rejected")

    monkeypatch.setattr(_SEND, boom)
    notifier = _notifier(store)
    notifier.start()
    # An EMAIL_CHANGED carries an address in its detail, so the no-leak check has something to find.
    await notifier.notify(
        SecurityEvent(
            EMAIL_CHANGED,
            username="bob",
            email="old@example.org",
            detail={"new_email": "new@example.net"},
        )
    )
    await notifier.aclose()

    assert await _undelivered(store) == [
        (
            SECURITY_NOTICE_UNDELIVERED_ACTION,
            "bob",
            {"notice": "email_changed", "reason": "send_failed"},
        )
    ]
    # Only the fields the notifier wrote: the row hash and the timestamp are random hex and digits.
    written = str([(r["actor"], r["detail"]) for r in await store.list_audit(limit=50)])
    assert "example" not in written and "550" not in written and "OSError" not in written


async def test_a_full_queue_writes_an_audit_row(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(_SEND, lambda **kw: sent.append(kw))
    notifier = _notifier(store)
    # One slot and no worker yet, so the second notice finds the queue full.
    notifier._queue = asyncio.Queue(maxsize=1)
    await notifier.notify(SecurityEvent(PASSWORD_CHANGED, username="amy", email="amy@x.test"))
    await notifier.notify(SecurityEvent(PASSWORD_CHANGED, username="ben", email="ben@x.test"))
    notifier.start()
    await notifier.aclose()

    # amy's notice went out, so only ben's is recorded: the row is not written for every notice.
    assert [kw["recipients"] for kw in sent] == [["amy@x.test"]]
    assert await _undelivered(store) == [
        (
            SECURITY_NOTICE_UNDELIVERED_ACTION,
            "ben",
            {"notice": "password_changed", "reason": "queue_full"},
        )
    ]


async def test_a_lost_lock_notice_is_recorded_under_the_hidden_action(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lock notice is recorded too, under an action a reader without ``users:manage`` never
    reads (BACKLOG #1131): the row is written only when a lock landed."""

    def boom(**_: Any) -> None:
        raise OSError("relay down")

    monkeypatch.setattr(_SEND, boom)
    notifier = _notifier(store)
    notifier._queue = asyncio.Queue(maxsize=1)
    await notifier.notify(SecurityEvent(ACCOUNT_LOCKED, username="lock-a", email="a@x.test"))
    await notifier.notify(SecurityEvent(ACCOUNT_LOCKED, username="lock-b", email="b@x.test"))
    notifier.start()
    await notifier.aclose()  # drains lock-a, whose send fails

    assert sorted(await _undelivered(store)) == [
        (
            LOCK_NOTICE_UNDELIVERED_ACTION,
            "lock-a",
            {"notice": "account_locked", "reason": "send_failed"},
        ),
        (
            LOCK_NOTICE_UNDELIVERED_ACTION,
            "lock-b",
            {"notice": "account_locked", "reason": "queue_full"},
        ),
    ]
    filtered = await store.list_audit(limit=50, exclude=HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE)
    assert [r for r in filtered if str(r["action"]) == LOCK_NOTICE_UNDELIVERED_ACTION] == []


async def test_a_delivered_notice_writes_no_row_and_no_audit_writer_writes_nothing(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(_SEND, lambda **_: None)
    notifier = _notifier(store)
    notifier.start()
    await notifier.notify(SecurityEvent(PASSWORD_CHANGED, username="amy", email="amy@x.test"))
    await notifier.aclose()
    assert await _undelivered(store) == []

    def boom(**_: Any) -> None:
        raise OSError("relay down")

    monkeypatch.setattr(_SEND, boom)
    offline = SecurityEventNotifier(host="smtp.example.org", port=25, sender="mf@example.org")
    offline.start()
    await offline.notify(SecurityEvent(PASSWORD_CHANGED, username="amy", email="amy@x.test"))
    await offline.aclose()
    assert await _undelivered(store) == []


async def test_a_failed_record_write_is_logged_and_swallowed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class _BrokenAudit:
        async def record_view(
            self, message_id: str, *, actor: str | None = None, now: float | None = None
        ) -> None:
            raise AssertionError("the notifier never records a view")

        async def record_audit(
            self,
            action: str,
            *,
            actor: str | None = None,
            channel_id: str | None = None,
            detail: str | None = None,
            client: str | None = None,
            now: float | None = None,
        ) -> None:
            raise RuntimeError("store closed")

    def boom(**_: Any) -> None:
        raise OSError("relay down")

    monkeypatch.setattr(_SEND, boom)
    notifier = SecurityEventNotifier(
        host="smtp.example.org",
        port=25,
        sender="mf@example.org",
        audit=cast(AuditStore, _BrokenAudit()),
    )
    notifier.start()
    await notifier.notify(SecurityEvent(ACCOUNT_LOCKED, username="lock-a", email="a@x.test"))
    await notifier.notify(SecurityEvent(PASSWORD_CHANGED, username="amy", email="amy@x.test"))
    await notifier.aclose()
    lines = [r.getMessage() for r in caplog.records if "could not be recorded" in r.getMessage()]
    # One line, for amy's notice. A lock notice writes no line of its own, so a lone line for it
    # would tell a logs:view reader that a lock landed (BACKLOG #1131).
    assert lines == [
        "an undelivered security notice could not be recorded in the audit log (RuntimeError)"
    ]
    assert "amy" not in lines[0] and "password_changed" not in lines[0]


async def test_an_issuer_reminder_row_names_the_holder(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The issuer is the recipient, so without the holder the row could not say whose credential
    the lost reminder was about."""

    def boom(**_: Any) -> None:
        raise OSError("relay down")

    monkeypatch.setattr(_SEND, boom)
    notifier = _notifier(store)
    notifier.start()
    await notifier.notify(
        SecurityEvent(
            TEMPORARY_CREDENTIAL_EXPIRING_FOR_ISSUER,
            username="root",
            email="root@x.test",
            detail={"expires_at": 1.5, "holder": "alice"},
        )
    )
    await notifier.aclose()
    assert await _undelivered(store) == [
        (
            SECURITY_NOTICE_UNDELIVERED_ACTION,
            "root",
            {
                "holder": "alice",
                "notice": "temporary_credential_expiring_issuer",
                "reason": "send_failed",
            },
        )
    ]


async def test_a_full_queue_does_not_wait_on_the_audit_write(store: MessageStore) -> None:
    """``notify`` runs on the sign-in and admin paths, so the queue-full record goes off it."""
    gate = asyncio.Event()

    class _SlowAudit:
        async def record_view(
            self, message_id: str, *, actor: str | None = None, now: float | None = None
        ) -> None:
            raise AssertionError("the notifier never records a view")

        async def record_audit(
            self,
            action: str,
            *,
            actor: str | None = None,
            channel_id: str | None = None,
            detail: str | None = None,
            client: str | None = None,
            now: float | None = None,
        ) -> None:
            await gate.wait()
            await store.record_audit(action, actor=actor, detail=detail)

    notifier = SecurityEventNotifier(
        host="smtp.example.org",
        port=25,
        sender="mf@example.org",
        audit=cast(AuditStore, _SlowAudit()),
    )
    notifier._queue = asyncio.Queue(maxsize=1)
    await notifier.notify(SecurityEvent(PASSWORD_CHANGED, username="amy", email="amy@x.test"))
    await asyncio.wait_for(
        notifier.notify(SecurityEvent(PASSWORD_CHANGED, username="ben", email="ben@x.test")), 1.0
    )
    assert await _undelivered(store) == []
    gate.set()
    # Empty the queue before the worker starts: no relay is faked here, so amy's send would fail.
    notifier._queue = asyncio.Queue(maxsize=1)
    notifier.start()
    await notifier.aclose()  # waits for the queue-full record
    assert [(a, actor) for a, actor, _ in await _undelivered(store)] == [
        (SECURITY_NOTICE_UNDELIVERED_ACTION, "ben")
    ]


# --- BACKLOG #5634: the offline commands record a notice whose send failed --------------------


def test_admin_reset_totp_records_a_notice_whose_send_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``admin-reset-totp`` sends its notice after the swap's store has closed, so the notice opens
    the store again for its record. Before the fix the notifier had no audit sink at all, and a
    sink pointing at the swap's closed store would have failed and been swallowed."""
    import base64
    import time

    import messagefoundry.__main__ as cli
    from messagefoundry.auth import totp
    from tests.test_admin_reset_totp import _ADMIN, _seed, _with_store

    monkeypatch.chdir(tmp_path)
    db = tmp_path / "reset.db"
    _seed(db, email="admin@example.invalid")
    new_secret = base64.b32encode(b"undelivered-notice-new").decode("ascii")

    def enrol(**_kwargs: object) -> tuple[str, str, float]:
        at = time.time()
        return totp.new_enrolment(new_secret), totp.totp(new_secret, now=at), at

    monkeypatch.setattr(cli, "_enrol_totp_at_terminal", enrol)
    monkeypatch.setattr(cli, "_show_on_terminal", lambda _text: None)

    def boom(**_: Any) -> None:
        raise OSError("relay down")

    monkeypatch.setattr(_SEND, boom)
    cfg = tmp_path / "service.toml"
    cfg.write_text(
        '[alerts]\nemail_smtp_host = "smtp.example.invalid"\nemail_from = "mefor@example.invalid"\n',
        encoding="utf-8",
    )
    argv = ["admin-reset-totp", "--username", _ADMIN, "--db", str(db)]
    assert cli.main([*argv, "--service-config", str(cfg), "--json"]) == 0

    assert _with_store(db, _undelivered) == [
        (
            SECURITY_NOTICE_UNDELIVERED_ACTION,
            _ADMIN,
            {"notice": "mfa_enabled", "reason": "send_failed"},
        )
    ]


async def test_the_reopening_sink_opens_nothing_for_a_sent_notice_and_survives_a_failed_open(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5634: ``admin-reset-totp``'s sink opens the store only to write the row. A sent
    notice opens nothing, and a store that will not open costs the record, never the notice."""
    from messagefoundry.__main__ import _ReopeningNoticeAudit

    opens: list[str] = []

    async def no_store() -> MessageStore:
        opens.append("open")
        raise OSError("store gone")

    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(_SEND, lambda **kw: sent.append(kw))
    notifier = SecurityEventNotifier(
        host="smtp.example.org",
        port=25,
        sender="mf@example.org",
        audit=_ReopeningNoticeAudit(no_store),
    )
    notifier.start()
    await notifier.notify(SecurityEvent(PASSWORD_CHANGED, username="amy", email="amy@x.test"))
    await notifier.aclose()
    assert len(sent) == 1 and opens == []

    def boom(**_: Any) -> None:
        raise OSError("relay down")

    monkeypatch.setattr(_SEND, boom)
    failing = SecurityEventNotifier(
        host="smtp.example.org",
        port=25,
        sender="mf@example.org",
        audit=_ReopeningNoticeAudit(no_store),
    )
    failing.start()
    await failing.notify(SecurityEvent(PASSWORD_CHANGED, username="amy", email="amy@x.test"))
    await failing.aclose()
    assert opens == ["open"]
    assert [
        r.getMessage() for r in caplog.records if "could not be recorded" in r.getMessage()
    ] == ["an undelivered security notice could not be recorded in the audit log (OSError)"]

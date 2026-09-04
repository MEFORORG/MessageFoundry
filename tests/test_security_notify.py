# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WP-L3-05: per-user security-event email notifier (pipeline/security_notify.py).

The SMTP send is faked (``send_plain_email`` monkeypatched) so nothing hits the network — we assert
the email is built to the AFFECTED user's address, with a PHI-free subject/body, and that an event with
no deliverable address is skipped.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from messagefoundry.auth.notifications import (
    ACCOUNT_LOCKED,
    EMAIL_CHANGED,
    PASSWORD_CHANGED,
    SecurityEvent,
)
from messagefoundry.config.settings import AlertsSettings
from messagefoundry.pipeline.security_notify import (
    SecurityEventNotifier,
    _build_body,
    security_notifier_from_settings,
)


def test_factory_returns_none_without_smtp() -> None:
    # No SMTP host/sender configured → no email push (the /me/security-events feed still records).
    assert security_notifier_from_settings(AlertsSettings()) is None


def test_factory_builds_with_smtp() -> None:
    n = security_notifier_from_settings(
        AlertsSettings(email_smtp_host="smtp.example.org", email_from="mf@example.org")
    )
    assert isinstance(n, SecurityEventNotifier)


async def test_notify_emails_the_affected_user(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "messagefoundry.pipeline.security_notify.send_plain_email",
        lambda **kw: sent.append(kw),
    )
    notifier = SecurityEventNotifier(host="smtp.example.org", port=25, sender="mf@example.org")
    notifier.start()
    await notifier.notify(
        SecurityEvent(
            ACCOUNT_LOCKED,
            username="bob",
            email="bob@example.org",
            client_ip="10.0.0.4",
            detail={"failed_attempts": 5},
        )
    )
    await notifier.aclose()  # drains the queued event (sent before the stop sentinel)

    assert len(sent) == 1
    call = sent[0]
    assert call["recipients"] == ["bob@example.org"]  # the user, not an ops list
    assert "locked" in call["subject"].lower()
    assert "10.0.0.4" in call["body"]  # source IP surfaced to the owner
    # PHI-free + no message data; only the user's own account details.
    assert "MSH|" not in call["body"] and "PID|" not in call["body"]


async def test_notify_skips_when_user_has_no_email(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "messagefoundry.pipeline.security_notify.send_plain_email",
        lambda **kw: sent.append(kw),
    )
    notifier = SecurityEventNotifier(host="smtp.example.org", port=25, sender="mf@example.org")
    notifier.start()
    await notifier.notify(SecurityEvent(PASSWORD_CHANGED, username="bob", email=None))
    await asyncio.sleep(0)  # give the loop a tick
    await notifier.aclose()
    assert sent == []  # no deliverable address → no email


async def test_notify_send_failure_is_swallowed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**kw: Any) -> None:
        raise OSError("smtp down")

    monkeypatch.setattr("messagefoundry.pipeline.security_notify.send_plain_email", boom)
    notifier = SecurityEventNotifier(host="smtp.example.org", port=25, sender="mf@example.org")
    notifier.start()
    await notifier.notify(SecurityEvent(ACCOUNT_LOCKED, username="bob", email="bob@example.org"))
    # A failing SMTP send must not propagate or wedge the background task — aclose still completes.
    await notifier.aclose()


def test_body_says_the_address_was_removed_when_there_is_no_new_one() -> None:
    """BACKLOG #1139 (ASVS 6.3.7): an EMAIL_CHANGED carrying no ``new_email`` is a REMOVAL. Saying
    only "was changed" and then omitting the new value reads as a truncated notice.

    WHAT THE ARM MAY CLAIM HAS NARROWED TWICE, and the second narrowing is the column split. An early
    version promised this was the LAST notice the address would ever get; that was scoped back to the
    account, because ``users.email`` carries no UNIQUE constraint and ``admin_user_update`` applies no
    ``_externally_managed`` guard. **The split falsifies even the scoped claim**: the removal reaches
    the profile mirror, and this notice went to ``users.notify_email``, which no clear can strip. So
    the arm now makes NO forward-looking claim at all -- it reports what changed, plus the one thing
    the schema guarantees. Asserting a promise the schema contradicts is the SDS-3.7 shape, which is
    why this test pins the absence of one rather than its wording.
    """
    body = _build_body(SecurityEvent(EMAIL_CHANGED, username="bob", email="old@example.org"))
    assert "removed" in body.lower()
    # It says WHICH address was removed -- the profile one -- so the reader is not left to infer that
    # the address receiving this mail has been stripped.
    assert "profile" in body.lower()
    assert "notification address" in body.lower()
    # The negative half, and the reason the test exists: no forecast about future notices.
    assert "no further" not in body.lower()
    assert "last security notice" not in body.lower()


def test_body_names_the_new_address_on_a_repoint_and_does_not_say_removed() -> None:
    """Positive control for the test above: the repoint arm must keep naming the new address and
    must NOT claim a removal — otherwise the removal wording could be emitted unconditionally."""
    body = _build_body(
        SecurityEvent(
            EMAIL_CHANGED,
            username="bob",
            email="old@example.org",
            detail={"new_email": "new@example.org"},
        )
    )
    assert "New email on file: new@example.org" in body
    assert "removed" not in body.lower()

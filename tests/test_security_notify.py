# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""WP-L3-05: per-user security-event email notifier (pipeline/security_notify.py).

The SMTP send is faked (``send_plain_email`` monkeypatched) so nothing hits the network — we assert
the email is built to the AFFECTED user's address, with a PHI-free subject/body, and that an event with
no deliverable address is skipped.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest

from messagefoundry.auth.notifications import (
    ACCOUNT_LOCKED,
    EMAIL_CHANGED,
    RECOVERY_CODE_USED,
    SecurityEvent,
)
from messagefoundry.config.settings import AlertsSettings
from messagefoundry.pipeline.security_notify import (
    SecurityEventNotifier,
    _build_body,
    security_notifier_from_settings,
)

# The module's own logger, named once so the capture filter and the module cannot drift apart.
_NOTIFY_LOGGER = "messagefoundry.pipeline.security_notify"


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


async def test_notify_skips_and_reports_when_the_account_has_no_address(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """No deliverable address means no email, and the drop must SAY SO (BACKLOG #1139, ASVS 6.3.7).

    "Nothing was sent" holds identically whether the drop speaks or not, so asserting only that
    cannot see the difference. The record count below is the assertion that separates them; the
    reasoning for warning at all lives once, on the branch itself in ``security_notify.py``.
    """
    sent: list[dict[str, Any]] = []
    monkeypatch.setattr(
        "messagefoundry.pipeline.security_notify.send_plain_email",
        lambda **kw: sent.append(kw),
    )
    notifier = SecurityEventNotifier(host="smtp.example.org", port=25, sender="mf@example.org")
    # start()/aclose() are a pair with the monkeypatch above: without a running drain, a regression
    # that ENQUEUED instead of dropping would leave the item undrained and `sent == []` would still
    # pass. No sleep() tick is needed -- the drop returns before _enqueue, so nothing is queued.
    notifier.start()
    with caplog.at_level(logging.WARNING, logger=_NOTIFY_LOGGER):
        # Driven with an EMAIL_CHANGED because its detail carries an ADDRESS. The no-leak assertion
        # at the bottom is only load-bearing if there is something there to leak.
        await notifier.notify(
            SecurityEvent(
                EMAIL_CHANGED,
                username="bootstrap-admin",
                email=None,
                detail={"new_email": "repointed@example.net"},
            )
        )
    await notifier.aclose()

    assert sent == []  # the drop is reported, not repaired: still no email
    dropped = [r for r in caplog.records if r.name == _NOTIFY_LOGGER]
    assert len(dropped) == 1, "an undeliverable notice must be reported exactly once, not swallowed"
    message = dropped[0].getMessage()
    # Names WHICH notice and WHOSE account, so the operator can act on it.
    assert EMAIL_CHANGED in message
    assert "bootstrap-admin" in message
    # Never event.detail: on this event type it holds an email address.
    assert "repointed@example.net" not in message


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


def test_body_says_a_directory_repoint_came_from_the_directory() -> None:
    """BACKLOG #1139 (ASVS 6.3.7): where the change came from decides what the reader can DO. A
    directory-driven repoint is not editable in the console, so an unexplained one reads as a
    compromise the holder cannot find a cause for."""
    body = _build_body(
        SecurityEvent(
            EMAIL_CHANGED,
            username="jdoe",
            email="old@example.org",
            detail={"new_email": "new@example.org", "source": "directory"},
        )
    )
    assert "directory" in body.lower()


def test_body_omits_the_directory_line_for_a_console_change() -> None:
    """Control for the test above: a console-driven repoint carries no source, so the sentence must
    not appear -- otherwise it would be emitted unconditionally and be false half the time."""
    body = _build_body(
        SecurityEvent(
            EMAIL_CHANGED,
            username="bob",
            email="old@example.org",
            detail={"new_email": "new@example.org"},
        )
    )
    assert "directory" not in body.lower()


def test_body_states_the_remaining_recovery_code_count() -> None:
    """BACKLOG #1139 (ASVS 6.3.7): spending a recovery code permanently deletes a stored credential.
    The count is what makes the notice actionable; the code and its hash never appear."""
    body = _build_body(
        SecurityEvent(RECOVERY_CODE_USED, username="bob", email="bob@x", detail={"remaining": 3})
    )
    assert "Recovery codes remaining: 3" in body
    assert "spent" in body.lower()
    assert "last recovery code" not in body.lower()  # only the zero arm says that


def test_body_warns_when_the_last_recovery_code_is_spent() -> None:
    body = _build_body(
        SecurityEvent(RECOVERY_CODE_USED, username="bob", email="bob@x", detail={"remaining": 0})
    )
    assert "Recovery codes remaining: 0" in body
    assert "last recovery code" in body.lower()

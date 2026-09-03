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
    RECOVERY_CODE_USED,
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
    only "was changed" and then omitting the new value reads as a truncated notice. THE SCOPE OF THE
    CLAIM IS THE POINT: an earlier version promised this was the LAST notice the address would ever
    get and asserted it, pinning a claim two shipped paths falsify -- ``users.email`` has no
    UNIQUE constraint, and ``admin_user_update`` has no ``_externally_managed`` guard."""
    body = _build_body(SecurityEvent(EMAIL_CHANGED, username="bob", email="old@example.org"))
    assert "removed" in body.lower()
    assert "about this account" in body.lower()
    # The negative half: it must not promise anything about the address BEYOND this account.
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

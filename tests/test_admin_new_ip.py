# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Admin-interface defense-in-depth: the new-client-IP contextual-risk signal (WP-L3-13, ASVS 8.4.2).

When ``[auth].admin_new_ip_step_up`` is on, a step-up (sensitive admin) request arriving from a client
address the session has not verified from is treated as higher-risk: it audits + notifies and FORCES a
fresh step-up, which a successful ``POST /me/reauth`` from that address clears (re-anchoring the
session). It is step-up-forcing only — it never changes an RBAC decision. Since vault BACKLOG #2620
the PHI reads and the paced writes refuse on it too; the base gate, which the monitoring polls ride,
never asks. It defaults ON since BACKLOG #288; turning it off, and a single-host loopback deployment,
are no-ops (the request and the session share one address).
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from _totp_clock import pin_totp_clock
from fastapi import Depends, FastAPI, Request

import messagefoundry.auth.service as service_module
from messagefoundry.api import create_app
from messagefoundry.api.security import (
    require_reauth_only,
    require_reauth_only_action,
    require_step_up,
    require_step_up_action,
    spend_step_up_action,
)
from messagefoundry.auth import Role, totp
from messagefoundry.auth.identity import ALL_CHANNELS, Identity
from messagefoundry.auth.notifications import NEW_ADDRESS_REVERIFY, SecurityEvent
from messagefoundry.auth.service import (
    _NEW_IP_LOG_KEY_MAX,
    _NEW_IP_OVER_CAP_LOG_MAX,
    _NEW_IP_PER_SESSION_MAX,
    _NEW_IP_REPEAT_LOG_SECONDS,
    _NEW_IP_UNPARSED_LOG_KEY,
    STEP_UP_ACTION_ADMIN_USER_UPDATE,
    STEP_UP_ACTION_SESSION_TERMINATE,
    AuthService,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_admin, create_local_user_chosen
from tests._bound_proof import prove

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)
NEW_USER = {
    "username": "newbie",
    "roles": ["viewer"],
    "email": "newbie@example.org",
}


class _FakeNotifier:
    """Captures the out-of-band security events instead of emailing them."""

    def __init__(self) -> None:
        self.events: list[SecurityEvent] = []

    async def notify(self, event: SecurityEvent) -> None:
        self.events.append(event)


async def _enabled_admin(service: AuthService, *, client: str) -> tuple[str, Identity]:
    """Create an enabled admin (no forced first-login rotation) + a live session from ``client``."""
    uid = await create_local_user_chosen(
        service,
        username="boss",
        password=PW,
        display_name=None,
        email="boss@example.test",
        roles=[Role.ADMINISTRATOR.value],
        actor="t",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    out = await service.login("boss", PW, client=client)
    assert out.ok and out.token is not None and out.identity is not None
    return out.token, out.identity


# --- service / store unit ----------------------------------------------------
def test_on_by_default() -> None:
    """BACKLOG #288 (owner ruling 2026-09-26): the signal ships ON; off is a named loosening."""
    assert AuthSettings().admin_new_ip_step_up is True


async def test_explicitly_disabled_is_a_noop() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=False), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        notifier.events.clear()  # setup's ACCOUNT_CREATED notice (BACKLOG #315), not under test
        # Even a wildly different address is a no-op while the feature is off.
        assert await service.flag_new_client_ip(token, "10.9.9.9", path="/users") is False
        assert notifier.events == []
    finally:
        await store.close()


async def test_new_ip_flags_audits_and_notifies() -> None:
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        notifier.events.clear()  # setup's ACCOUNT_CREATED notice (BACKLOG #315), not under test
        # Same address → not new; no side effects.
        assert await service.flag_new_client_ip(token, "10.1.1.1", path="/users") is False
        assert notifier.events == []
        # A different address → flagged, audited, and notified.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert any(
            e.event_type == NEW_ADDRESS_REVERIFY and e.client_ip == "10.2.2.2"
            for e in notifier.events
        )
        rows = await store.list_audit(limit=20)
        [flagged] = [r for r in rows if r["action"] == "auth.new_address_reverify_required"]
        # Vault BACKLOG #3197: the address is in the client column, not only in the detail, so a
        # search or export by address finds the row.
        assert flagged["client"] == "10.2.2.2"
        assert json.loads(flagged["detail"])["seen_ip"] == "10.2.2.2"
    finally:
        await store.close()


async def test_missing_baseline_and_bad_tokens_not_flagged() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        uid = await create_local_user_chosen(
            service,
            username="x",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.VIEWER.value],
            actor="t",
        )
        # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
        # fixture still stands for an operator who has been provisioned; the channel axis itself
        # is exercised in tests/test_channel_rbac.py.
        await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
        # A session with no recorded login address is never penalized (avoids spurious friction).
        await store.create_session(
            token_hash=hash_token("noip"), user_id=uid, expires_at=2e12, client=None
        )
        assert await service.flag_new_client_ip("noip", "10.2.2.2", path="/x") is False
        # Missing / unknown tokens are never flagged.
        assert await service.flag_new_client_ip(None, "10.2.2.2", path="/x") is False
        assert await service.flag_new_client_ip("nope", "10.2.2.2", path="/x") is False
    finally:
        await store.close()


async def test_reauth_reanchors_session_to_the_new_ip() -> None:
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Re-verifying from the new address re-anchors the session, clearing the signal. The
        # re-auth also re-keys the session (ASVS 7.2.4), and `_rekey_token_state` carries the
        # new-IP dedupe across — so the follow-up checks run on the ROTATED token.
        reauthed = await service.reauth(identity, PW, token=token, client="10.2.2.2")
        assert reauthed.ok is True and reauthed.token is not None
        token = reauthed.token
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is False
        # The original address is now the unexpected one.
        assert await service.flag_new_client_ip(token, "10.1.1.1", path="/users") is True
    finally:
        await store.close()


async def test_repeat_from_same_new_ip_is_deduped() -> None:
    """The step-up is forced on every hit, but the audit row + out-of-band notice fire only once per
    (session, new-IP) — a replayed token can't inflate the audit log / notifications. A genuinely
    different address re-emits."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        # First hit from a new address → flagged, audited, notified.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Repeat from the SAME address → still forces step-up, but no new audit row / notice.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        actions = [r["action"] for r in await store.list_audit(limit=50)]
        assert actions.count("auth.new_address_reverify_required") == 1
        assert sum(1 for e in notifier.events if e.event_type == NEW_ADDRESS_REVERIFY) == 1
        # A DIFFERENT new address is a distinct event → re-emits.
        assert await service.flag_new_client_ip(token, "10.3.3.3", path="/users") is True
        actions = [r["action"] for r in await store.list_audit(limit=50)]
        assert actions.count("auth.new_address_reverify_required") == 2
        assert sum(1 for e in notifier.events if e.event_type == NEW_ADDRESS_REVERIFY) == 2
    finally:
        await store.close()


async def test_repeat_warning_is_held_to_one_per_session_per_interval(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RED when: every refused repeat from an already-reported address writes its own WARNING
    line (vault BACKLOG #3052 item 16), so a token replayed in a loop floods the general log. The
    refusal itself must stay on every request, and the line comes back once the interval passes.
    Past the cap, each address's FIRST sighting must still log with its address, because that
    line is its only record, while its repeats share the interval (review round 1: the past-the-cap
    line was a flood of its own). A rotation carries the throttle to the new token."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True

        def repeat_lines() -> int:
            return sum("already flagged" in r.getMessage() for r in caplog.records)

        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for _ in range(5):
                assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            assert repeat_lines() == 1
            # The interval passes (moved back on the record, not on the clock the loop runs on).
            state = service._new_ip_logged[hash_token(token)]
            assert state.last_line is not None
            state.last_line -= _NEW_IP_REPEAT_LOG_SECONDS + 1
            assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            assert repeat_lines() == 2
            # Past the cap: a first sighting logs with its address, its repeats are held back.
            for i in range(_NEW_IP_PER_SESSION_MAX):
                assert await service.flag_new_client_ip(token, f"10.3.3.{i}", path="/users")
            caplog.clear()
            for _ in range(3):
                assert await service.flag_new_client_ip(token, "10.4.4.4", path="/users") is True
            assert await service.flag_new_client_ip(token, "10.5.5.5", path="/users") is True
            past_cap = [
                r.getMessage() for r in caplog.records if "past the per-session" in r.getMessage()
            ]
            assert len(past_cap) == 2 and "10.4.4.4" in past_cap[0] and "10.5.5.5" in past_cap[1]
        # A rotation moves the throttle with the session, as it moves the dedupe.
        new_hash = hash_token("rotated-token")
        service._rekey_token_state(hash_token(token), new_hash)
        assert service._new_ip_logged.get(new_hash) is state
        assert hash_token(token) not in service._new_ip_logged
    finally:
        await store.close()


async def test_the_past_cap_first_sighting_record_is_bounded() -> None:
    """RED when: the past-the-cap first-sighting record keeps the text of an address that does not
    parse, or keeps more than ``_NEW_IP_OVER_CAP_LOG_MAX`` keys, for a session (vault BACKLOG #3052
    review finding 7). On a proxied hop the address is attacker-supplied text, so up to 4096
    sessions could each hold 64 keys of whatever length the sender chose. Every unparseable or
    over-long address must share one sentinel, and a parseable one is kept at its canonical text."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        for i in range(_NEW_IP_PER_SESSION_MAX + 1):
            assert await service.flag_new_client_ip(token, f"10.3.3.{i}", path="/users") is True
        for i in range(200):
            junk = f"not-an-address-{i}-" + "x" * 500
            assert await service.flag_new_client_ip(token, junk, path="/users") is True
        # An IPv6 scope id is the sender's text, short or long, so the key drops it (review round
        # 2: "::%<text>" parses as an address; vault BACKLOG #3773 item 2: dropping it rather than
        # folding to the sentinel keeps link-local peers distinct).
        for scoped in ("fe80::1%" + "s" * (2 * _NEW_IP_LOG_KEY_MAX), "::%\n<evil>"):
            assert await service.flag_new_client_ip(token, scoped, path="/users") is True
        state = service._new_ip_logged[hash_token(token)]
        assert state.over_cap_logged == {_NEW_IP_UNPARSED_LOG_KEY, "fe80::1", "::"}
        for i in range(2 * _NEW_IP_OVER_CAP_LOG_MAX):
            assert await service.flag_new_client_ip(token, f"10.4.{i}.1", path="/users") is True
        assert len(state.over_cap_logged) == _NEW_IP_OVER_CAP_LOG_MAX
        assert all(len(key) <= _NEW_IP_LOG_KEY_MAX for key in state.over_cap_logged)
        assert "10.4.0.1" in state.over_cap_logged
    finally:
        await store.close()


async def test_a_refused_request_past_the_cap_writes_no_row_or_notice(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RED when: a request past the per-session cap writes an audit row or a notice, or is not
    refused (vault BACKLOG #3052 review finding 2). Past the cap the shipped code before this item
    wrote no row and no notice for any further address; the log throttle must not change that, for
    the first ``_NEW_IP_OVER_CAP_LOG_MAX`` such addresses or for any past them. Each of those first
    sightings logs its address; past them the lines share the session's interval."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        reported = [f"10.3.3.{i}" for i in range(_NEW_IP_PER_SESSION_MAX + 1)]
        for seen in reported:
            assert await service.flag_new_client_ip(token, seen, path="/users") is True
        assert await _new_ip_rows(store) == reported
        past = [f"10.5.{i // 250}.{i % 250}" for i in range(_NEW_IP_OVER_CAP_LOG_MAX + 40)]
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for seen in past:
                assert await service.flag_new_client_ip(token, seen, path="/users") is True
        assert await _new_ip_rows(store) == reported
        assert sum(1 for e in notifier.events if e.event_type == NEW_ADDRESS_REVERIFY) == len(
            reported
        )
        lines = [r.getMessage() for r in caplog.records if "past the per-session" in r.getMessage()]
        assert len(lines) == _NEW_IP_OVER_CAP_LOG_MAX + 1
        assert all(
            line.endswith(f"seen_ip={seen}")
            for seen, line in zip(past[:_NEW_IP_OVER_CAP_LOG_MAX], lines, strict=False)
        )
    finally:
        await store.close()


async def test_a_held_back_warning_writes_a_debug_count(caplog: pytest.LogCaptureFixture) -> None:
    """RED when: a WARNING the throttle holds back leaves no line at all (vault BACKLOG #3052
    review finding 4). Each held-back repeat writes a DEBUG line with the count held back since the
    session's last interval line, and the next WARNING carries the count as ``held_back``, so it
    shows at INFO too. A past-the-cap first sighting carries it and starts it over, so summing
    ``held_back`` counts each held-back line once (vault BACKLOG #3773 item 1)."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True

        def counts() -> list[str]:
            return [
                r.getMessage().split("suppressed=")[1].split()[0]
                for r in caplog.records
                if "held back" in r.getMessage() and r.levelname == "DEBUG"
            ]

        with caplog.at_level("DEBUG", logger="messagefoundry.auth.service"):
            for _ in range(4):
                assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            assert counts() == ["1", "2", "3"]
            state = service._new_ip_logged[hash_token(token)]
            assert state.last_line is not None
            state.last_line -= _NEW_IP_REPEAT_LOG_SECONDS + 1
            caplog.clear()
            assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            assert any(r.getMessage().endswith("held_back=3") for r in caplog.records)
            assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            assert counts() == ["1"]
            # Past the cap, a first sighting carries the count and starts it over.
            for i in range(_NEW_IP_PER_SESSION_MAX):
                assert await service.flag_new_client_ip(token, f"10.3.3.{i}", path="/users")
            caplog.clear()
            assert await service.flag_new_client_ip(token, "10.6.6.6", path="/users") is True
            assert any("held_back=1 seen_ip=10.6.6.6" in r.getMessage() for r in caplog.records)
            assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            assert counts() == ["1"]
    finally:
        await store.close()


def _refusals_on_record(records: list[logging.LogRecord]) -> int:
    """How many refused new-address requests the WARNING lines account for: each per-request line
    is one, and every line's ``held_back`` adds the requests held back before it."""
    total = 0
    for record in records:
        if record.levelno < logging.WARNING:
            continue
        message = record.getMessage()
        if "already flagged" in message or "past the per-session" in message:
            total += 1
        if "held_back=" in message:
            total += int(message.split("held_back=")[1].split()[0])
    return total


async def test_a_trailing_burst_is_counted_when_the_interval_ends(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: repeats the throttle holds back, with no later request from the session, are never
    written at WARNING (vault BACKLOG #3773 item 1). Main wrote a WARNING for each refused request,
    so once the interval ends the WARNING lines must account for every one of them, whatever the
    timing of the burst."""
    monkeypatch.setattr(service_module, "_NEW_IP_REPEAT_LOG_SECONDS", 0.2)
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for _ in range(5):
                assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            # The flush is due at most 0.2 s after the last interval line, so it runs first.
            await asyncio.sleep(0.6)
        assert _refusals_on_record(caplog.records) == 5
        assert service._new_ip_logged[hash_token(token)].suppressed == 0
    finally:
        await store.close()


async def test_summing_held_back_counts_each_refusal_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RED when: a past-the-cap first sighting reports the held-back count without starting it
    over, so the next interval line reports the same lines again (vault BACKLOG #3773 item 1)."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        for i in range(_NEW_IP_PER_SESSION_MAX + 1):
            assert await service.flag_new_client_ip(token, f"10.3.3.{i}", path="/users") is True
        refused = 0
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for _ in range(4):
                assert await service.flag_new_client_ip(token, "10.3.3.0", path="/users") is True
                refused += 1
            assert await service.flag_new_client_ip(token, "10.6.6.6", path="/users") is True
            refused += 1
            state = service._new_ip_logged[hash_token(token)]
            assert state.last_line is not None
            state.last_line -= _NEW_IP_REPEAT_LOG_SECONDS + 1
            assert await service.flag_new_client_ip(token, "10.3.3.0", path="/users") is True
            refused += 1
        assert _refusals_on_record(caplog.records) == refused
    finally:
        await store.close()


async def test_a_reanchor_writes_the_held_back_count(caplog: pytest.LogCaptureFixture) -> None:
    """RED when: a re-verification drops the session's log throttle with lines still held back,
    so those refusals are never written at WARNING (vault BACKLOG #3773 item 1)."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for _ in range(4):
                assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            service._restart_new_ip_dedupe(hash_token(token))
        assert _refusals_on_record(caplog.records) == 4
        assert hash_token(token) not in service._new_ip_logged
    finally:
        await store.close()


async def test_an_evicted_throttle_writes_the_held_back_count(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the oldest session's log throttle is evicted with lines still held back, so those
    refusals are never written at WARNING (vault BACKLOG #3773 item 1)."""
    monkeypatch.setattr(service_module, "_NEW_IP_DEDUP_MAX", 2)
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for _ in range(4):
                assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            for i in range(service_module._NEW_IP_DEDUP_MAX):
                service._new_ip_log_due(f"other-session-{i}")
        assert hash_token(token) not in service._new_ip_logged
        assert _refusals_on_record(caplog.records) == 4
    finally:
        await store.close()


async def test_shutdown_writes_the_held_back_count(caplog: pytest.LogCaptureFixture) -> None:
    """RED when: the shutdown drain leaves lines held back unwritten, so a burst in the engine's
    last interval is never written at WARNING (vault BACKLOG #3773 item 1)."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for _ in range(4):
                assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
            await service.close_background()
        assert _refusals_on_record(caplog.records) == 4
    finally:
        await store.close()


async def test_link_local_peers_past_the_cap_stay_distinct(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RED when: every IPv6 address with a scope id shares the one sentinel, so a second link-local
    peer on a direct bind (``fe80::b%eth0`` after ``fe80::a%eth0``) gets no first sighting of its
    own (vault BACKLOG #3773 item 2). The scope id is the sender's text, so the key drops it
    rather than keeping it."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        for i in range(_NEW_IP_PER_SESSION_MAX + 1):
            assert await service.flag_new_client_ip(token, f"10.3.3.{i}", path="/users") is True
        # An interval line first, so a peer that shared a first sighting would be held back.
        assert await service.flag_new_client_ip(token, "10.3.3.0", path="/users") is True
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for peer in ("fe80::a%eth0", "fe80::b%eth0"):
                assert await service.flag_new_client_ip(token, peer, path="/users") is True
        lines = [r.getMessage() for r in caplog.records if "past the per-session" in r.getMessage()]
        assert len(lines) == 2
        assert lines[0].endswith("seen_ip=fe80::a%eth0")
        assert lines[1].endswith("seen_ip=fe80::b%eth0")
        state = service._new_ip_logged[hash_token(token)]
        assert state.over_cap_logged == {"fe80::a", "fe80::b"}
    finally:
        await store.close()


async def _new_ip_rows(store: MessageStore) -> list[str]:
    """The ``seen_ip`` of every ``auth.new_address_reverify_required`` row, oldest first."""
    rows = await store.list_audit(action="auth.new_address_reverify_required", limit=100)
    return [json.loads(str(r["detail"]))["seen_ip"] for r in reversed(rows)]


async def test_alternating_new_addresses_audit_once_each() -> None:
    """BACKLOG #2159: the dedupe holds a SET per session, not the last address. Alternating between
    two new addresses used to write a row and a notice on every switch."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        for seen in ("10.2.2.2", "10.3.3.3", "10.2.2.2", "10.3.3.3", "10.2.2.2"):
            assert await service.flag_new_client_ip(token, seen, path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2", "10.3.3.3"]
        assert sum(1 for e in notifier.events if e.event_type == NEW_ADDRESS_REVERIFY) == 2
    finally:
        await store.close()


async def test_a_reanchor_starts_the_dedupe_over() -> None:
    """BACKLOG #2159: after a re-verification moves the anchor, an address flagged before it is a new
    event again. It used to stay suppressed, so the forced step-up left no audit row."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Re-verify from a THIRD address: the session is now anchored there.
        reauthed = await service.reauth(identity, PW, token=token, client="10.3.3.3")
        assert reauthed.ok is True and reauthed.token is not None
        token = reauthed.token
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2", "10.2.2.2"]
    finally:
        await store.close()


async def test_a_reanchor_back_to_the_same_address_still_starts_over() -> None:
    """The anchor includes ``reauth_at``, not the address alone. Anchored at A, flag B, re-verify from
    B, then from A again: the anchor ADDRESS is A both times, but B was re-verified in between, so a
    later request from B is a new event and writes a row."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        for client in ("10.2.2.2", "10.1.1.1"):
            reauthed = await service.reauth(identity, PW, token=token, client=client)
            assert reauthed.ok is True and reauthed.token is not None
            token = reauthed.token
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2", "10.2.2.2"]
    finally:
        await store.close()


async def test_ipv4_mapped_ipv6_is_the_same_host() -> None:
    """BACKLOG #2159: ``_same_host`` folds ``::ffff:a.b.c.d`` to ``a.b.c.d``, as the sign-in signal
    already did. A bind change between ``0.0.0.0`` and ``::`` must not trip the signal, and one new
    host seen in both forms is one audit row."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.0.0.5")
        assert await service.flag_new_client_ip(token, "::ffff:10.0.0.5", path="/users") is False
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await service.flag_new_client_ip(token, "::ffff:10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2"]
    finally:
        await store.close()


def test_same_host_folds_mapped_loopback_and_case() -> None:
    assert AuthService._same_host("::ffff:10.0.0.5", "10.0.0.5")
    assert AuthService._same_host("::ffff:127.0.0.1", "::1")
    assert AuthService._same_host("2001:DB8::1", "2001:db8::1")
    assert AuthService._same_host("not-an-address", "not-an-address")
    assert not AuthService._same_host("10.0.0.5", "10.0.0.6")
    assert not AuthService._same_host("::ffff:10.0.0.5", "::ffff:10.0.0.6")
    assert not AuthService._same_host("not-an-address", "::1")


async def test_one_epoch_audits_at_most_the_per_session_cap() -> None:
    """The signal runs on every sensitive request, so one session audits at most
    ``_NEW_IP_PER_SESSION_MAX`` addresses between re-verifications, plus ONE row carrying
    ``cap_reached`` that names the first address past the cap. After that the step-up is still
    forced; only the row and the notice are held back. A re-verification gives the cap back."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        addresses = [f"10.9.0.{n}" for n in range(1, _NEW_IP_PER_SESSION_MAX + 3)]
        for _ in range(2):
            for seen in addresses:
                assert await service.flag_new_client_ip(token, seen, path="/users") is True
        reported = addresses[: _NEW_IP_PER_SESSION_MAX + 1]
        assert await _new_ip_rows(store) == reported
        assert sum(1 for e in notifier.events if e.event_type == NEW_ADDRESS_REVERIFY) == len(
            reported
        )
        details = [
            json.loads(str(r["detail"]))
            for r in await store.list_audit(action="auth.new_address_reverify_required", limit=100)
        ]
        capped = [d for d in details if "cap_reached" in d]
        assert [d["seen_ip"] for d in capped] == [addresses[_NEW_IP_PER_SESSION_MAX]]
        assert capped[0]["cap_reached"] == _NEW_IP_PER_SESSION_MAX
        # The holder's notice for that address says so too; the eight before it do not.
        sent = [e for e in notifier.events if e.event_type == NEW_ADDRESS_REVERIFY]
        assert [e.client_ip for e in sent if e.detail.get("cap_reached")] == [
            addresses[_NEW_IP_PER_SESSION_MAX]
        ]
        # Re-verifying from the anchor opens a new epoch with a fresh cap.
        reauthed = await service.reauth(identity, PW, token=token, client="10.1.1.1")
        assert reauthed.ok is True and reauthed.token is not None
        assert await service.flag_new_client_ip(reauthed.token, addresses[-1], path="/users")
        assert await _new_ip_rows(store) == [*reported, addresses[-1]]
    finally:
        await store.close()


def test_every_reanchor_restarts_the_dedupe() -> None:
    """Each function that re-anchors a session (``mark_session_reauthed``) also restarts the
    new-address dedupe. A new re-verification leg that forgot would leave addresses reported
    before it suppressed after it, which is the gap BACKLOG #2159 closed."""
    source = Path(inspect.getfile(AuthService)).read_text(encoding="utf-8")
    tree = ast.parse(source)
    anchoring: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            called = {
                n.func.attr
                for n in ast.walk(node)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            }
            if "mark_session_reauthed" in called:
                anchoring[node.name] = called
    assert len(anchoring) >= 3, sorted(anchoring)  # control: the probe finds the known legs
    missing = sorted(
        name for name, called in anchoring.items() if "_restart_new_ip_dedupe" not in called
    )
    assert missing == [], missing


def test_the_per_session_cap_is_the_value_security_md_states() -> None:
    """SECURITY.md item 6 gives the cap as a number an operator can read. Move both together."""
    assert _NEW_IP_PER_SESSION_MAX == 8
    text = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text("utf-8")
    assert "at most **eight** addresses (`_NEW_IP_PER_SESSION_MAX`" in " ".join(text.split())


async def test_a_rotation_without_a_reverification_keeps_the_dedupe() -> None:
    """A rotation that proves nothing (a passkey assertion, an enrolment confirm) leaves
    ``reauth_at`` alone, so the epoch and its flags carry across to the new token."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        rotated = await service._rotate_session_token(token)
        assert rotated is not None
        assert await service.flag_new_client_ip(rotated, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2"]
    finally:
        await store.close()


async def test_a_failed_audit_write_does_not_mark_the_address_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If the row is not written, the next request from that address must try again rather than
    be suppressed for the rest of the epoch."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        real_audit = service._audit

        async def failing_audit(*args: object, **kwargs: object) -> None:
            raise RuntimeError("transient store fault")

        monkeypatch.setattr(service, "_audit", failing_audit)
        with pytest.raises(RuntimeError):
            await service.flag_new_client_ip(token, "10.2.2.2", path="/users")
        monkeypatch.setattr(service, "_audit", real_audit)
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2"]
    finally:
        await store.close()


async def test_a_reanchor_resets_without_reading_the_clock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The reset rides the re-anchor call, not ``reauth_at``: a wall clock stepped BACK between two
    re-verifications must still start the dedupe over."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, identity = await _enabled_admin(service, client="10.1.1.1")
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        real_time = time.time
        for client, skew in (("10.2.2.2", -100.0), ("10.1.1.1", -50.0)):
            monkeypatch.setattr(time, "time", lambda skew=skew: real_time() + skew)
            reauthed = await service.reauth(identity, PW, token=token, client=client)
            assert reauthed.ok is True and reauthed.token is not None
            token = reauthed.token
        monkeypatch.setattr(time, "time", real_time)
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        assert await _new_ip_rows(store) == ["10.2.2.2", "10.2.2.2"]
    finally:
        await store.close()


async def test_the_sign_in_notice_debounce_folds_ipv4_mapped() -> None:
    """The sign-in signal's notice debounce keys on the host, as its comparison does, so one host
    seen as ``::ffff:a.b.c.d`` and then ``a.b.c.d`` gets one notice per window, not two."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        assert service._login_new_ip_notice_due("u1", "::ffff:10.9.9.9") is True
        assert service._login_new_ip_notice_due("u1", "10.9.9.9") is False
        assert service._login_new_ip_notice_due("u1", "10.9.9.8") is True
    finally:
        await store.close()


async def test_loopback_addresses_treated_as_same_host() -> None:
    """A dual-stack loopback box (session anchored at ::1, a later request from 127.0.0.1) is one host
    — the feature stays a true no-op on loopback even when enabled. A real address is still new."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        uid = await create_local_user_chosen(
            service,
            username="x",
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.ADMINISTRATOR.value],
            actor="t",
        )
        # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
        # fixture still stands for an operator who has been provisioned; the channel axis itself
        # is exercised in tests/test_channel_rbac.py.
        await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
        await store.create_session(
            token_hash=hash_token("lb"), user_id=uid, expires_at=2e12, client="::1"
        )
        assert await service.flag_new_client_ip("lb", "127.0.0.1", path="/users") is False
        assert await service.flag_new_client_ip("lb", "::1", path="/users") is False
        # A genuine non-loopback address is still flagged.
        assert await service.flag_new_client_ip("lb", "10.0.0.5", path="/users") is True
    finally:
        await store.close()


async def test_verify_mfa_reanchors_session_to_the_new_ip(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Completing the second factor (TOTP) from a new address re-anchors the session, like reauth — so
    an MFA-required admin who roamed clears the new-IP signal with one credential proof, not two."""
    store = await MessageStore.open(":memory:")
    try:
        # The login-to-MFA floor is off: this enrols on the session it just signed in, which the floor
        # covers (BACKLOG #2389), and the test is about the re-anchor, not the floor.
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True, mfa_verify_min_elapsed_seconds=0)
        )
        admin = await create_admin(service)
        out = await service.login(admin.username, admin.password, client="10.1.1.1")
        assert out.ok and out.identity is not None and out.token is not None
        identity, token = out.identity, out.token
        enroll = await service.begin_mfa_enrollment(identity)
        # Pin the TOTP clock so the enrollment confirm and the later verify_mfa sit in distinct steps
        # (enrollment now consumes the activating step, BACKLOG #1021).
        t0 = 1_000_000.0
        pin_totp_clock(monkeypatch, t0)
        enrolled = await service.confirm_mfa_enrollment(
            identity, totp.totp(enroll.secret, now=t0), token=token, client="10.1.1.1"
        )
        assert enrolled.ok and enrolled.token is not None
        token = enrolled.token  # the confirm re-keyed the session (ASVS 7.2.4)
        # Roam to a new address → flagged.
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is True
        # Completing MFA from the new address re-anchors the session (parity with reauth), using a code
        # in a strictly later step than enrollment consumed.
        t1 = t0 + totp.DEFAULT_PERIOD
        pin_totp_clock(monkeypatch, t1)
        code = totp.totp(enroll.secret, now=t1)
        verified = await service.verify_mfa(token, code, client="10.2.2.2")
        assert verified.ok is True and verified.token is not None
        token = verified.token
        assert await service.flag_new_client_ip(token, "10.2.2.2", path="/users") is False
    finally:
        await store.close()


# --- API enforcement ---------------------------------------------------------
@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "newip.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


def _client_for(app: FastAPI, ip: str) -> httpx.AsyncClient:
    """A client of ``app`` whose requests originate from ``ip`` (set on the ASGI scope)."""
    transport = httpx.ASGITransport(app=app, client=(ip, 12345))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


def _client_at(engine: Engine, service: AuthService, ip: str) -> httpx.AsyncClient:
    """An API client whose requests originate from ``ip`` (set on the ASGI scope)."""
    return _client_for(create_app(engine, auth=service), ip)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def _add_admin(service: AuthService, username: str) -> None:
    user_id = await create_local_user_chosen(
        service,
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.ADMINISTRATOR.value],
        actor="test",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(user_id, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id,
        password_hash=user.password_hash,
        must_change_password=False,
        password_generated=False,
    )


async def _login_token(c: httpx.AsyncClient, username: str = "boss") -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    assert r.status_code == 200, r.text
    return str(r.json()["token"])


async def test_admin_route_from_new_ip_forces_step_up_then_clears(engine: Engine) -> None:
    # New-client-IP step-up test (admin route), not an MFA test: pin require_mfa=False so the admin's
    # step-up op isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0, admin_new_ip_step_up=True, require_mfa=False
        ),
    )
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        # From the SAME address the fresh login may act (network-location + step-up freshness hold).
        assert (await a.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201
    # Same token, a DIFFERENT client address → forced step-up.
    n2 = {"username": "n2", "roles": ["viewer"], "email": "n2@example.org"}
    async with _client_at(engine, service, "10.9.9.9") as b:
        blocked = await b.post("/users", headers=_auth(token), json=n2)
        assert blocked.status_code == 403
        assert blocked.headers.get("X-Step-Up-Required") == "1"
        # A base-gate route from the new address is NOT blocked: the base gate never asks. Since
        # vault BACKLOG #2620 the PHI reads and the paced writes do ask, and refuse (see the tests
        # below); this route is neither.
        assert (await b.get("/auth/me", headers=_auth(token))).status_code == 200
        # Re-verifying from the new address re-anchors the session; the admin op then succeeds.
        ok = await b.post("/me/reauth", headers=_auth(token), json={"password": PW})
        assert ok.status_code == 200
        token = str(ok.json()["token"])  # the re-auth re-keyed the session (ASVS 7.2.4)
        assert (await b.post("/users", headers=_auth(token), json=n2)).status_code == 201


async def test_known_ip_with_feature_on_is_unobtrusive(engine: Engine) -> None:
    # New-client-IP step-up test (admin route), not an MFA test: pin require_mfa=False so the admin's
    # step-up op isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(engine.store, AuthSettings(admin_new_ip_step_up=True, require_mfa=False))
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        # Same address throughout → no extra friction beyond the normal login step-up freshness.
        assert (await a.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201


async def test_explicitly_disabled_new_ip_does_not_force_step_up(engine: Engine) -> None:
    service = AuthService(engine.store, AuthSettings(admin_new_ip_step_up=False, require_mfa=False))
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
    async with _client_at(engine, service, "10.9.9.9") as b:
        # Feature off → the new address is irrelevant; the fresh login's step-up still holds → 201.
        assert (await b.post("/users", headers=_auth(token), json=NEW_USER)).status_code == 201


async def test_new_ip_never_overrides_rbac(engine: Engine) -> None:
    """A viewer lacking ``users:manage`` is denied for *permission* — RBAC runs before the step-up /
    IP logic, so the IP signal neither grants nor is even consulted (it never changes an authz
    decision)."""
    # New-client-IP step-up test (admin route), not an MFA test: pin require_mfa=False so the admin's
    # step-up op isn't blocked first by the BACKLOG #187 secure default (require_mfa now ON).
    service = AuthService(engine.store, AuthSettings(admin_new_ip_step_up=True, require_mfa=False))
    await service.initialize()
    uid = await create_local_user_chosen(
        service,
        username="viewer1",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.VIEWER.value],
        actor="t",
    )
    # BACKLOG #1152: an unset channel scope now DENIES. Grant the estate explicitly so this
    # fixture still stands for an operator who has been provisioned; the channel axis itself
    # is exercised in tests/test_channel_rbac.py.
    await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
    user = await service.store.get_user(uid)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        uid, password_hash=user.password_hash, must_change_password=False, password_generated=False
    )
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a, "viewer1")
    async with _client_at(engine, service, "10.9.9.9") as b:
        denied = await b.post("/users", headers=_auth(token), json=NEW_USER)
        assert denied.status_code == 403
        # Missing permission — NOT a step-up / MFA prompt.
        assert denied.headers.get("X-Step-Up-Required") is None
        assert denied.headers.get("X-MFA-Required") is None


# --- vault BACKLOG #2620: the PHI reads and the paced writes ask too ---------------------------


def _new_ip_service(engine: Engine, **over: object) -> AuthService:
    settings: dict[str, object] = {
        "admin_write_min_interval_seconds": 0,
        "admin_new_ip_step_up": True,
        "require_mfa": False,
    }
    settings.update(over)
    return AuthService(engine.store, AuthSettings(**settings))  # type: ignore[arg-type]


_ADT = "MSH|^~\\&|S|F|R|RF|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"
#: The paced write's body: resetting every counter touches no message.
_RESET_ALL: dict[str, object] = {"all": True}


async def _seed_message(engine: Engine) -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=_ADT,
        deliveries=[("archive", _ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )


def _replayed(mid: str) -> tuple[tuple[str, str, dict[str, object] | None], ...]:
    """The architecture review's probe, widened: the message list, a raw body, the dead-letter
    list, the log tail, and two paced writes. The connection name names no connection, so the
    control's 404 proves the gate let the request through to the handler."""
    return (
        ("GET", "/messages", None),
        ("GET", f"/messages/{mid}/raw", None),
        ("GET", "/dead-letters", None),
        ("GET", "/logs/tail", None),
        ("POST", "/connections/IB_NONE/start", None),
        ("POST", "/statistics/reset", _RESET_ALL),
    )


async def test_a_token_replayed_from_a_second_address_is_refused_on_phi_and_paced(
    engine: Engine,
) -> None:
    """RED when: a bearer token signed in at one address reads a message body, lists messages or
    calls a paced write from another with no step-up (vault BACKLOG #2620, the architecture
    review's probe). The same token from the sign-in address is the control: it is never refused
    with the step-up header. A base-gate route from the new address still answers, because the
    monitoring polls ride it."""
    service = _new_ip_service(engine)
    await service.initialize()
    await _add_admin(service, "boss")
    mid = await _seed_message(engine)
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        for method, path, body in _replayed(mid):
            r = await a.request(method, path, headers=_auth(token), json=body)
            assert r.headers.get("X-Step-Up-Required") is None, (method, path, r.status_code)
    async with _client_at(engine, service, "10.9.9.9") as b:
        for method, path, body in _replayed(mid):
            r = await b.request(method, path, headers=_auth(token), json=body)
            assert r.status_code == 403, (method, path, r.status_code)
            assert r.headers.get("X-Step-Up-Required") == "1", (method, path)
        assert (await b.get("/connections", headers=_auth(token))).status_code == 200
        # One row for the address, whichever gate saw it first (BACKLOG #2159's dedupe).
        assert isinstance(engine.store, MessageStore)
        assert await _new_ip_rows(engine.store) == ["10.9.9.9"]
        # A re-verification from the new address re-anchors the session, and the reads pass.
        ok = await b.post("/me/reauth", headers=_auth(token), json={"password": PW})
        assert ok.status_code == 200
        token = str(ok.json()["token"])
        assert (await b.get("/messages", headers=_auth(token))).status_code == 200
        raw = await b.get(f"/messages/{mid}/raw", headers=_auth(token))
        assert raw.status_code == 200 and raw.json()["raw"]


async def test_filling_the_notification_address_from_a_second_address_is_refused(
    engine: Engine,
) -> None:
    """RED when: ``POST /me/notify-email`` from a host the session has not verified from fills the
    address with no step-up, while its console twin ``POST /ui/account/notify-address`` is refused
    (vault BACKLOG #3052 item 6). A replayed token would otherwise choose where the holder's
    security notices go. The re-verification from the new address is the control: the same body
    then sets the address, so the refusal is the gate's and not the handler's."""
    service = _new_ip_service(engine)
    await service.initialize()
    await _add_admin(service, "boss")
    user = await service.store.get_user_by_username("boss")
    assert user is not None and not user.notify_email
    body = {"email": "boss@example.test"}
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
    async with _client_at(engine, service, "10.9.9.9") as b:
        r = await b.post("/me/notify-email", headers=_auth(token), json=body)
        assert (r.status_code, r.headers.get("X-Step-Up-Required")) == (403, "1"), r.text
        user = await service.store.get_user_by_username("boss")
        assert user is not None and not user.notify_email
        ok = await b.post("/me/reauth", headers=_auth(token), json={"password": PW})
        assert ok.status_code == 200
        token = str(ok.json()["token"])
        r = await b.post("/me/notify-email", headers=_auth(token), json=body)
        assert r.status_code == 200, r.text
    user = await service.store.get_user_by_username("boss")
    assert user is not None and user.notify_email == "boss@example.test"


async def test_filling_the_notification_address_is_paced(engine: Engine) -> None:
    """RED when: ``POST /me/notify-email`` is not paced (vault BACKLOG #3052 review finding 6).
    Under the base gate a second fill at once answers 409, because the first set the address; under
    ``require_paced`` it answers 429 with a ``Retry-After`` before the handler runs."""
    service = _new_ip_service(engine, admin_write_min_interval_seconds=10.0)
    await service.initialize()
    await _add_admin(service, "boss")
    body = {"email": "boss@example.test"}
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        first = await a.post("/me/notify-email", headers=_auth(token), json=body)
        assert first.status_code == 200, first.text
        again = await a.post("/me/notify-email", headers=_auth(token), json=body)
        assert again.status_code == 429, again.text
        assert again.headers.get("Retry-After")


async def test_a_confined_session_from_a_second_address_still_has_a_way_out(
    engine: Engine,
) -> None:
    """RED when: a session confined to setting its notification address, calling from a host it
    has not verified from, is left with no way out (vault BACKLOG #3052 item 6, review round 1).
    With a notice channel wired the account is confined; ``POST /me/notify-email`` is refused with the
    step-up answer, ``POST /me/reauth`` must stay reachable and re-anchor, and the fill then
    lands. Any other route stays confined, which is the control that the confinement is live."""
    service = AuthService(
        engine.store,
        AuthSettings(
            admin_write_min_interval_seconds=0, admin_new_ip_step_up=True, require_mfa=False
        ),
        security_notifier=_FakeNotifier(),
    )
    await service.initialize()
    await _add_admin(service, "boss")
    body = {"email": "boss@example.test"}
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
    async with _client_at(engine, service, "10.9.9.9") as b:
        confined = await b.get("/users", headers=_auth(token))
        assert (confined.status_code, confined.headers.get("X-Notify-Email-Required")) == (403, "1")
        r = await b.post("/me/notify-email", headers=_auth(token), json=body)
        assert (r.status_code, r.headers.get("X-Step-Up-Required")) == (403, "1"), r.text
        ok = await b.post("/me/reauth", headers=_auth(token), json={"password": PW})
        assert ok.status_code == 200, ok.text
        token = str(ok.json()["token"])
        r = await b.post("/me/notify-email", headers=_auth(token), json=body)
        assert r.status_code == 200, r.text


async def test_a_refusal_for_a_new_address_charges_no_budget(engine: Engine) -> None:
    """RED when: the new-address refusal runs after the PHI-read or admin-write charge, so a stolen
    token refused in a loop spends the holder's budget (vault BACKLOG #2620, the BACKLOG #1973
    rule). With a budget of one, the holder still reads and writes once after the refusals."""
    service = _new_ip_service(
        engine, phi_read_rate_limit_per_actor=1, admin_write_rate_limit_per_actor=1
    )
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
    async with _client_at(engine, service, "10.9.9.9") as b:
        for _ in range(3):
            assert (await b.get("/messages", headers=_auth(token))).status_code == 403
            assert (
                await b.post("/statistics/reset", headers=_auth(token), json=_RESET_ALL)
            ).status_code == 403
    async with _client_at(engine, service, "10.0.0.1") as a:
        assert (await a.get("/messages", headers=_auth(token))).status_code == 200
        assert (
            await a.post("/statistics/reset", headers=_auth(token), json=_RESET_ALL)
        ).status_code == 200


async def test_the_phi_and_paced_gates_ask_nothing_with_the_signal_off(engine: Engine) -> None:
    """The named loosening still turns the whole check off: ``admin_new_ip_step_up = false``."""
    service = _new_ip_service(engine, admin_new_ip_step_up=False)
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
    async with _client_at(engine, service, "10.9.9.9") as b:
        assert (await b.get("/messages", headers=_auth(token))).status_code == 200
        r = await b.post("/statistics/reset", headers=_auth(token), json=_RESET_ALL)
        assert r.status_code == 200
    assert isinstance(engine.store, MessageStore)
    assert await _new_ip_rows(engine.store) == []


async def test_an_http_reveal_from_a_second_address_is_refused(engine: Engine) -> None:
    """RED when: a ``reveal`` on a monitoring list route, a PHI read admitted by ``_admit_reveal``
    rather than ``require_phi_read``, answers a token replayed from a new address (vault BACKLOG
    #2620, review round 1). The same list without ``reveal`` still answers: it rides the base gate."""
    service = _new_ip_service(engine)
    await service.initialize()
    await _add_admin(service, "boss")
    async with _client_at(engine, service, "10.0.0.1") as a:
        token = await _login_token(a)
        control = await a.get("/events", params={"reveal": 1}, headers=_auth(token))
        assert control.headers.get("X-Step-Up-Required") is None, control.status_code
    async with _client_at(engine, service, "10.9.9.9") as b:
        for path in ("/events", "/alerts/active"):
            r = await b.get(path, params={"reveal": 1}, headers=_auth(token))
            assert (r.status_code, r.headers.get("X-Step-Up-Required")) == (403, "1"), path
        assert (await b.get("/events", headers=_auth(token))).status_code == 200


# --- vault BACKLOG #3052 item 13: each of the four step-up factories asks --------------------------

#: Five cases over the four JSON step-up factories in ``api/security.py``: each with the action its
#: proof is bound to (``None`` for the two that read the session window), and whether the route
#: spends the proof itself. Each factory asks the new-address question inline, so a case pins only
#: its own factory. ``require_step_up_action`` asks in two branches, so it has two cases: its
#: ``proof_in_route=True`` branch asks before the route's own spend.
_STEP_UP_FACTORIES = {
    "require_step_up": (require_step_up, None, False),
    "require_reauth_only": (require_reauth_only, None, False),
    "require_step_up_action": (
        lambda: require_step_up_action(STEP_UP_ACTION_ADMIN_USER_UPDATE),
        STEP_UP_ACTION_ADMIN_USER_UPDATE,
        False,
    ),
    "require_step_up_action-proof_in_route": (
        lambda: require_step_up_action(STEP_UP_ACTION_ADMIN_USER_UPDATE, proof_in_route=True),
        STEP_UP_ACTION_ADMIN_USER_UPDATE,
        True,
    ),
    "require_reauth_only_action": (
        lambda: require_reauth_only_action(STEP_UP_ACTION_SESSION_TERMINATE),
        STEP_UP_ACTION_SESSION_TERMINATE,
        False,
    ),
}


@pytest.mark.parametrize("name", sorted(_STEP_UP_FACTORIES))
async def test_each_step_up_factory_refuses_a_new_address_holding_a_fresh_proof(
    engine: Engine, name: str
) -> None:
    """RED when: one of the four step-up factories, in either branch, stops asking whether the
    request comes from a new address (vault BACKLOG #3052 item 13; PR 2048's mutation run skipped
    all four). The caller
    holds the proof the factory wants, a fresh sign-in window or a grant bound to its action, so
    the address is the only reason left to refuse. The control spends the same proof from the
    sign-in address and passes, so the refusal is not a stale proof.

    A probe route is mounted on each factory directly, because ``require_reauth_only`` guards no
    shipped route and the others share theirs with other gates."""
    make_gate, action, spends = _STEP_UP_FACTORIES[name]
    service = _new_ip_service(engine)
    await service.initialize()
    await _add_admin(service, "boss")
    app = create_app(engine, auth=service)

    gate = Depends(make_gate())

    async def probe(request: Request, _: Identity = gate) -> dict[str, str]:
        if spends:
            assert action is not None
            await spend_step_up_action(request, action)
        return {"ok": "1"}

    app.add_api_route("/test/step-up-probe", probe, methods=["POST"])

    async def proof(c: httpx.AsyncClient, token: str) -> str:
        """A fresh grant bound to ``action``; the sign-in window already serves the others."""
        return token if action is None else await prove(c, token, PW, action)

    async with _client_for(app, "10.0.0.1") as a:
        token = await proof(a, await _login_token(a))
        control = await a.post("/test/step-up-probe", headers=_auth(token))
        assert control.status_code == 200, (name, control.status_code, control.text)
        token = await proof(a, token)
    async with _client_for(app, "10.9.9.9") as b:
        r = await b.post("/test/step-up-probe", headers=_auth(token))
        assert (r.status_code, r.headers.get("X-Step-Up-Required")) == (403, "1"), (name, r.text)
        assert r.headers.get("X-Step-Up-Action") == action, name
    assert isinstance(engine.store, MessageStore)
    assert await _new_ip_rows(engine.store) == ["10.9.9.9"], name

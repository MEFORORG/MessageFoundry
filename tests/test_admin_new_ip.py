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
import hashlib
import inspect
import io
import json
import logging
import random
import re
import time
from collections.abc import AsyncIterator, Callable
from pathlib import Path

import httpx
import pytest
from _totp_clock import pin_totp_clock
from fastapi import Depends, FastAPI, Request

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
    _NEW_IP_LOG_FIELD_MAX,
    _NEW_IP_PER_SESSION_MAX,
    _NEW_IP_TEXT_MAX,
    _NEW_IP_TEXT_PREFIX,
    STEP_UP_ACTION_ADMIN_USER_UPDATE,
    STEP_UP_ACTION_SESSION_TERMINATE,
    AuthService,
    _address_log_field,
    _bounded_address_text,
    _new_ip_path_field,
)
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.controlchars import scrub_log_argument
from messagefoundry.logging_setup import (
    UNREADABLE_LOG_VALUE,
    _install_phi_filters,
    redact_log_value,
    redacted_log_field,
)
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

    async def notify(self, event: SecurityEvent) -> bool:
        self.events.append(event)
        return True


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


async def _new_ip_rows(store: MessageStore) -> list[str]:
    """The ``seen_ip`` of every ``auth.new_address_reverify_required`` row, oldest first."""
    rows = await store.list_audit(action="auth.new_address_reverify_required", limit=100)
    return [json.loads(str(r["detail"]))["seen_ip"] for r in reversed(rows)]


async def test_each_refused_request_writes_its_own_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RED when: a refused request that is not a first sighting writes no WARNING of its own, as
    under a per-session throttle. Why that throttle was declined is in docs/SECURITY.md,
    "Administrative-interface defense-in-depth"."""
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
        repeats = 7
        forged = "10.8.8.8\nforged line"
        past_cap = ["10.5.5.5", "10.5.5.5", "10.6.6.6", "10.5.5.5", "10.7.7.7", forged]
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for _ in range(repeats):
                assert await service.flag_new_client_ip(token, "10.3.3.0", path="/users") is True
            for seen in past_cap:
                assert await service.flag_new_client_ip(token, seen, path="/users") is True
        warnings = [
            r.getMessage()
            for r in caplog.records
            if r.levelno == logging.WARNING
            and r.getMessage().startswith("a request from a new client address must re-verify")
        ]
        assert len(warnings) == repeats + len(past_cap)
        assert sum("already flagged" in line for line in warnings) == repeats
        over = [line for line in warnings if "past the per-session" in line]
        assert [line.split("seen_ip=", 1)[1].split(" path=", 1)[0] for line in over] == [
            f'"{seen}"' for seen in past_cap[:-1]
        ] + [_address_log_field(forged)]
        assert _address_log_field(forged).startswith('"unparsed-sha256-')
        assert not any("\n" in line for line in over)
        assert await _new_ip_rows(store) == reported
        assert sum(1 for e in notifier.events if e.event_type == NEW_ADDRESS_REVERIFY) == len(
            reported
        )
    finally:
        await store.close()


#: One ``key="value"`` field; neither field writer puts a quote inside a value.
_FIELD = r'([a-z_]+)="([^"]*)"'


def _logged_fields(line: str) -> list[tuple[str, str]]:
    """The ``key="value"`` fields after the colon of a new-address WARNING, in order, read as a
    log reader would. Refuses a line that is anything but such fields joined by single spaces, so
    a field a filter erased, merged or ran past fails here."""
    rest = line.split(": ", 1)[1]
    assert re.fullmatch(f"{_FIELD}(?: {_FIELD})*", rest), line
    return re.findall(_FIELD, rest)


#: Paths that tried to write a field of their own (BACKLOG #3770). The second is the one the review
#: measured: the credential scrub filters read the backslash before a JSON-escaped quote as part of
#: the token's value, so ``quote_log_text`` closed early on a configured sink. The rest end on a
#: label a credential scrub reads as the start of a quoted value, open a quoted value, or start a
#: PHI or credential pattern that runs to the end of the line (an HL7 segment, an XML element, an
#: ODBC brace, a ``MEFOR_`` name), or hold an HL7 separator on each side of a space, which the
#: ``%XX`` escape joined into one run the HL7 pass erased, key and all. One is a plain path, which
#: must log unchanged.
_FORGING_PATHS = (
    '/users seen_ip=10.6.6.6 held_back=99 "x\\',
    '/users token=a" seen_ip=10.6.6.6 z="',
    "/x token=",
    "/x password:",
    "/x/password:",
    "/api/auth/bearer",
    "/x password='a seen_ip=10.6.6.6 '",
    "/x code=a&state=b seen_ip=10.6.6.6",
    "/x code=SECRETVALUE",
    "/PID|x",
    "/a|b|c",
    "/x<given>abc",
    "/x;pwd={abc",
    "/x/password={a",
    "/MEFOR_X=abc",
    "/plain/path-with.dots-and-hyphens",
    "/x:colon",
    "/x%20password:",
    "/a&" + "b" * 300,
    "/a~b c~d",
    "/a|b c|d",
    "/a%7Cb c%7Cd",
    "/x 19-01-01",
    "/é12-34-5678",
    "/ꄣ-45-6789",
    "/" + "19800101é/" * 30,
    "/" + "x" * 230 + "/19800505" + "9" * 50,
    "/x\x01DOE%5EJANE%5EQ",
    "/u" + "\U0001f600" * 300,
    "/u" + "x" * 5000,
)

#: A seen text over ``_NEW_IP_TEXT_MAX`` that holds a tab. The shipped handlers leave its bounded
#: text unchanged; at 9dc628aa47 the extra tab-to-space round rewrote it in the past-cap context,
#: so its prefix and its plain digest reached the path field.
_LONG_SEEN = "hunter2\tpw" + "x" * 70

#: Seen texts that do not parse: one with a tab, which only that tab round rewrites; a name, which
#: the PHI pass rewrites; and ``_LONG_SEEN``.
_HOSTILE_SEEN = ("hunter2\tpw", "DOE JANE hunter2", _LONG_SEEN)

#: Seen addresses a forwarded header could carry, each with what the past-cap line must log for
#: it: an address in its canonical form, or a fixed token and a digest, never the text (BACKLOG
#: #3770). The first two are the review's: ``%20`` read as a label start by the credential scrub,
#: which took the closing quote and the ``path=`` key, and ``a|b c|d``, which the ``%XX`` escape
#: joined into one HL7 run that erased ``seen_ip=`` with its value.
_FORGING_SEEN = (
    ("x%20password=<redacted>/users", None),
    ("a|b c|d", None),
    ("x password:", None),
    ('10.6.6.6" path="/forged', None),
    ("10.6.6.6 held_back=99", None),
    ("fe80::1%eth0 path=x", "fe80::1-zone-sha256-"),
    ("2001:DB8:0:0:0:0:0:1", "2001:db8::1"),
    ("10.7.7.7", "10.7.7.7"),
    *((seen, None) for seen in _HOSTILE_SEEN),
)

#: Paths the forge test logs with every seen address above, so it can check that a path has one
#: spelling, the repeat line's, wherever the past-cap line does not log the unreadable placeholder.
_PATHS_FOR_EVERY_SEEN = ("/users", "/a b", "/x/password:", "/x code=SECRETVALUE")

#: What a path field may hold: the escape's kept characters and ``_uXXXX_`` units, the two
#: placeholders, and a cut mark with its checksum. Written from the escape's contract, not from the
#: code under test.
_PATH_FIELD = r"(?:[A-Za-z0-9./-]|_u[0-9A-F]{4}_|<redacted>|\[redacted\])*(?:_%crc32x[0-9a-f]{8})?"


#: The path field's value when it cannot be read apart from its context, unquoted.
_UNREADABLE = UNREADABLE_LOG_VALUE
_UNREADABLE_FIELD = f'"{UNREADABLE_LOG_VALUE}"'


def _unescaped(text: str) -> str:
    return re.sub(r"_u([0-9A-F]{4})_", lambda m: chr(int(m.group(1), 16)), text)


def _seen_leaks(seen: str, path: str, field: str) -> list[str]:
    """What of ``seen`` the path ``field`` holds that ``path`` does not: a word of three or more
    letters or digits, the ``seen_ip`` key, or a plain SHA-256 prefix of the text. The placeholders
    are the field's own spelling, so their words do not count."""
    if field == _UNREADABLE:
        return []
    decoded = _unescaped(field).replace("<redacted>", " ").replace("[redacted]", " ")
    words = set(re.findall(r"[A-Za-z0-9]{3,}", seen)) - set(re.findall(r"[A-Za-z0-9]+", path))
    leaks = [word for word in sorted(words) if word in decoded]
    if "seen_ip" in decoded and "seen_ip" not in path:
        leaks.append("seen_ip")
    digest = hashlib.sha256(seen.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    if digest in decoded:
        leaks.append(digest)
    return leaks


def _two_shipped_handlers() -> tuple[list[io.StringIO], list[logging.Handler]]:
    """Two handlers, each with the shipped filter chain, so the second reads what the first
    rewrote: the filters rewrite the record in place."""
    streams = [io.StringIO(), io.StringIO()]
    handlers: list[logging.Handler] = []
    for stream in streams:
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        _install_phi_filters(handler)
        handlers.append(handler)
    return streams, handlers


def test_a_bounded_address_is_always_longer_than_its_bound() -> None:
    """RED when: the bound and its prefix are edited so the replacement fits under the bound, so a
    short address text spelled like ``<prefix>...sha256:<hex>`` could read as the bounded form of a
    longer one (BACKLOG #3772)."""
    assert _NEW_IP_TEXT_PREFIX + len("...sha256:") + 64 > _NEW_IP_TEXT_MAX


async def test_a_path_cannot_forge_a_field_of_the_new_address_warnings() -> None:
    """RED when: the request path or the seen address can close its field on the line a shipped
    handler writes, so a path holding a space, a quote or a credential label writes a field of its
    own; or the seen address carries its own text into the line, so it can merge with or erase the
    path; or a field is longer than its bound after its escape; or a redaction placeholder is
    escaped out of its searchable spelling (BACKLOG #3770). The lines are read through two handlers,
    each carrying the shipped filter chain (``_install_phi_filters``), not from the record."""
    streams, handlers = _two_shipped_handlers()
    logger = logging.getLogger("messagefoundry.auth.service")
    level = logger.level
    for handler in handlers:
        logger.addHandler(handler)
    logger.setLevel(logging.WARNING)
    store = await MessageStore.open(":memory:")
    cases: list[tuple[str, str | None, str]] = [
        (f"10.9.9.{i}", f"10.9.9.{i}", path) for i, path in enumerate(_FORGING_PATHS)
    ]
    cases += [(seen, want, path) for seen, want in _FORGING_SEEN for path in _PATHS_FOR_EVERY_SEEN]
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")
        for i in range(_NEW_IP_PER_SESSION_MAX + 1):
            assert await service.flag_new_client_ip(token, f"10.3.3.{i}", path="/users") is True
        for stream in streams:
            stream.truncate(0)
            stream.seek(0)
        for seen, _, path in cases:
            assert await service.flag_new_client_ip(token, "10.3.3.0", path=path) is True
            assert await service.flag_new_client_ip(token, seen, path=path) is True
    finally:
        for handler in handlers:
            logger.removeHandler(handler)
            handler.close()
        logger.setLevel(level)
        await store.close()
    first, second = ([ln for ln in s.getvalue().splitlines() if ln] for s in streams)
    # The second handler re-filters what the first wrote, and changes nothing.
    assert first == second
    lines = first
    # The control: every case wrote both of its lines.
    assert len(lines) == 2 * len(cases)
    fields: dict[str, set[str]] = {}
    for i, (seen, want, path) in enumerate(cases):
        repeat, over = (_logged_fields(line) for line in lines[2 * i : 2 * i + 2])
        assert [key for key, _ in over] == ["seen_ip", "path"], lines[2 * i + 1]
        assert [key for key, _ in repeat] == ["path"], lines[2 * i]
        # The past-cap line logs the repeat line's path field or the unreadable placeholder, in
        # the escape's alphabet, and the seen address reaches no part of it.
        assert over[1][1] in (repeat[0][1], _UNREADABLE), (lines[2 * i], lines[2 * i + 1])
        for field in (repeat[0][1], over[1][1]):
            assert re.fullmatch(_PATH_FIELD, field) or field == _UNREADABLE, field
            assert not _seen_leaks(seen, path, field), lines[2 * i + 1]
            if field != _UNREADABLE:
                fields.setdefault(path, set()).add(field)
        logged_ip = over[0][1]
        if want is None:
            assert re.fullmatch("unparsed-sha256-[0-9a-f]{16}", logged_ip), lines[2 * i + 1]
        else:
            assert logged_ip.startswith(want), lines[2 * i + 1]
        assert len(over[1][1]) <= _NEW_IP_LOG_FIELD_MAX
    # One path has one spelling, whatever the seen address and the line.
    assert all(len(spellings) == 1 for spellings in fields.values()), fields
    bearer = _FORGING_PATHS.index("/api/auth/bearer")
    # The repeat line logs it; on the past-cap line a bearer label takes ``seen_ip=`` as its
    # value, so the seen text is rewritten and the boundary is unknown.
    assert [_logged_fields(line)[-1][1] for line in lines[2 * bearer : 2 * bearer + 2]] == [
        "/api/auth/bearer",
        _UNREADABLE,
    ]
    assert "SECRETVALUE" not in "\n".join(lines)
    assert "JANE" not in "\n".join(lines)
    plain = _FORGING_PATHS.index("/plain/path-with.dots-and-hyphens")
    assert _logged_fields(lines[2 * plain + 1]) == [
        ("seen_ip", f"10.9.9.{plain}"),
        ("path", _FORGING_PATHS[plain]),
    ]
    # Placeholders keep their spelling, so a search for them finds the line.
    token_line = lines[2 * _FORGING_PATHS.index("/x code=SECRETVALUE") + 1]
    assert _logged_fields(token_line)[1][1] == "/x_u0020_code_u003D_<redacted>"
    # The HL7 pass takes ``path=`` with the path, so the boundary is unknown.
    hl7_line = lines[2 * _FORGING_PATHS.index("/a|b|c") + 1]
    assert _logged_fields(hl7_line)[1][1] == _UNREADABLE
    longest = _FORGING_PATHS.index("/u" + "x" * 5000)
    assert "_%crc32x" in _logged_fields(lines[2 * longest + 1])[1][1]


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


#: The longest text :func:`_bounded_address_text` returns: a 24-character prefix, ``...sha256:``
#: and a 64-hex digest. Pinned here rather than derived, so a change to the form is seen.
_BOUNDED_TEXT_CEILING = 98


def _long_address(n: int) -> str:
    """Caller-supplied text that does not parse as an address. Every one shares a prefix far past the
    bound and differs only at the end, so a naive truncation would fold them all into one key."""
    return "x" * 200 + f"-{n}"


def test_bounded_address_text_keeps_addresses_and_bounds_the_rest() -> None:
    """RED when: a valid address is rewritten, two long strings sharing a prefix collide, or long
    text comes back unbounded (BACKLOG #3772)."""
    longest_ipv6 = "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255"
    assert len(longest_ipv6) == 45
    for address in ("10.2.2.2", "::1", "2001:db8::1", longest_ipv6, "", "not-an-address"):
        assert _bounded_address_text(address) == address
    at_bound = "y" * _NEW_IP_TEXT_MAX
    assert _bounded_address_text(at_bound) == at_bound
    bounded = [_bounded_address_text(_long_address(n)) for n in range(3)]
    assert len(set(bounded)) == 3
    assert all(_NEW_IP_TEXT_MAX < len(b) <= _BOUNDED_TEXT_CEILING for b in bounded)
    assert _bounded_address_text(_long_address(0)) == bounded[0]
    # A lone surrogate, which plain UTF-8 refuses, still bounds, to text UTF-8 can encode.
    surrogates = _bounded_address_text("\ud800" * 500)
    assert len(surrogates) <= _BOUNDED_TEXT_CEILING
    surrogates.encode("utf-8")
    # An IPv6 zone id is unbounded text inside a valid address, so it is bounded too.
    assert len(_bounded_address_text("fe80::1%" + "z" * 500)) <= _BOUNDED_TEXT_CEILING


async def test_long_address_text_is_bounded_in_the_dedupe_and_the_past_cap_record(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RED when: ``_new_ip_seen`` holds the raw caller text, or the rows (seen_ip, known_ip, the
    client column), the notices or the past-cap log line carry it unbounded (BACKLOG #3772). The
    texts share a long prefix, so the test also fails if the bound folds distinct texts into one key.
    The session itself is anchored at long text too, which is what ``known_ip`` carries."""
    store = await MessageStore.open(":memory:")
    try:
        notifier = _FakeNotifier()
        service = AuthService(
            store, AuthSettings(admin_new_ip_step_up=True), security_notifier=notifier
        )
        await service.initialize()
        anchor = "a" * 200
        token, _ = await _enabled_admin(service, client=anchor)
        texts = [_long_address(n) for n in range(_NEW_IP_PER_SESSION_MAX + 2)]
        with caplog.at_level("WARNING", logger="messagefoundry.auth.service"):
            for seen in texts:
                assert await service.flag_new_client_ip(token, seen, path="/users") is True
        keys = service._new_ip_seen[hash_token(token)]
        assert len(keys) == _NEW_IP_PER_SESSION_MAX + 1
        assert all(len(k) <= _BOUNDED_TEXT_CEILING for k in keys)
        rows = await store.list_audit(action="auth.new_address_reverify_required", limit=100)
        assert len(rows) == _NEW_IP_PER_SESSION_MAX + 1
        seen_ips = {json.loads(str(r["detail"]))["seen_ip"] for r in rows}
        assert seen_ips == {_bounded_address_text(t) for t in texts[: _NEW_IP_PER_SESSION_MAX + 1]}
        capped = [r for r in rows if "cap_reached" in json.loads(str(r["detail"]))]
        assert len(capped) == 1
        assert json.loads(str(capped[0]["detail"]))["seen_ip"] == _bounded_address_text(
            texts[_NEW_IP_PER_SESSION_MAX]
        )
        assert {r["client"] for r in rows} == seen_ips
        assert {json.loads(str(r["detail"]))["known_ip"] for r in rows} == {
            _bounded_address_text(anchor)
        }
        sent = [e for e in notifier.events if e.event_type == NEW_ADDRESS_REVERIFY]
        assert len(sent) == _NEW_IP_PER_SESSION_MAX + 1
        assert {e.client_ip for e in sent} == seen_ips
        assert {e.detail["known_ip"] for e in sent} == {_bounded_address_text(anchor)}
        over = [
            r.getMessage()
            for r in caplog.records
            if r.levelno == logging.WARNING and "past the per-session" in r.getMessage()
        ]
        assert [line.split("seen_ip=", 1)[1].split(" path=", 1)[0] for line in over] == [
            _address_log_field(texts[-1])
        ]
    finally:
        await store.close()


async def test_a_failed_audit_write_discards_the_bounded_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: the key the ``finally`` discards is not the bounded key the dedupe added, so a long
    address whose row failed stays marked as reported (BACKLOG #3772, #2159)."""
    store = await MessageStore.open(":memory:")
    try:
        service = AuthService(store, AuthSettings(admin_new_ip_step_up=True))
        await service.initialize()
        token, _ = await _enabled_admin(service, client="10.1.1.1")

        async def failing_audit(*args: object, **kwargs: object) -> None:
            raise RuntimeError("transient store fault")

        monkeypatch.setattr(service, "_audit", failing_audit)
        with pytest.raises(RuntimeError):
            await service.flag_new_client_ip(token, _long_address(0), path="/users")
        assert service._new_ip_seen[hash_token(token)] == set()
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


def test_a_redaction_that_raises_logs_a_placeholder_not_an_exception(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """RED when: a redaction pass that raises escapes ``redacted_log_field``, so a log argument
    built inside the new-address gate fails the request it was only describing; or the failure is
    swallowed with no record, or its record carries the value."""
    import messagefoundry.logging_setup as logging_setup

    def _boom(text: str, **_: str) -> str:
        raise RuntimeError(text)

    monkeypatch.setattr(logging_setup, "redact_log_value", _boom)
    monkeypatch.setattr(logging_setup, "_UNLOGGABLE_REPORTED", set())
    with caplog.at_level(logging.ERROR, logger="messagefoundry.logging_setup"):
        got = redacted_log_field("/users/SECRETVALUE", _NEW_IP_LOG_FIELD_MAX)
    assert got == '"unloggable-RuntimeError"'
    errors = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    assert errors and all("RuntimeError" in m and "SECRETVALUE" not in m for m in errors)


#: Every C0 control and DEL, each before a percent-encoded HL7 name: the PHI pass skips the encoded
#: run in text that is not printable, so on main only a second handler, reading the first one's
#: escaped text, hid the name, and with a tab, which that escape keeps, no handler did (BACKLOG
#: #3770).
_CONTROL_HL7_PATHS = tuple(
    f"/x{chr(c)}DOE{sep}JANE{sep}Q"
    for c in [*range(0x20), 0x7F]
    for sep in ("%5E", "%7C", "%7E", "%26")
)

# What these tests check of ``_new_ip_path_field`` (BACKLOG #3770), kept here rather than in its
# docstring, which states only the guarantee.
#
# - No path word main hid prints in the path field more often than in main's path span, as the
#   strict baseline ``_hides_no_less_than_main`` counts it. Its words are ASCII letter and digit
#   runs of three or more, so a shorter or non-ASCII token is not counted. It can report a false
#   red for a path whose word main printed, paired with a seen text whose tail main wrote a third
#   way; ``_KNOWN_FALSE_RED`` pins two such paths, not the whole class. It runs over the paths main
#   hid, each with every ``_BASELINE_SEEN`` text; the quote-closing, control-character and
#   raw-in-line vectors, each with one seen text; and a seeded corpus, each path with one. Only the
#   raw-in-line vectors reach the check's raw-tail form.
# - An ordinary path stays readable with each ``_REWRITTEN_SEEN`` text, and the two raw-in-line
#   paths stay readable with the encoded HL7 seen text their line leaves raw.
# - Over a seeded corpus, a path the repeat line reads blanks on the past-cap line only where main's
#   own past-cap line was not the repeat value or main's repeat-line span, then the seen text raw
#   or as written alone. Its seen texts hold no encoded run beside a tab, which blanks a path
#   while main wrote that form; so it bounds the blanking only for the seen texts it reads.
# - Not tested, at least: a third handler; a Unicode space separator before an encoded HL7 name,
#   which the pre-#3770 lines printed too; a seen text no vector names; and a pass that, in the
#   past-cap line, hides the end of the path and writes that end back, followed by exactly
#   ``seen_ip=`` and the seen text, as it was or as the passes write it alone.

#: Paths whose words main's last shipped handler hid on at least one of main's two WARNING lines.
#: The first five put a label, a date or a name after a tab, with a value split by an escaped line
#: break. The next three are the review's: a tab before a credential label glued on by a ``%XX``
#: code, which a tab-to-space round in place of main's second round unhid; and two whose value main
#: hid only because ``seen_ip=`` followed the path on its past-cap line. The rest glue a bearer
#: label to an encoded HL7 run with another ``%XX`` code, after a tab.
_MAIN_HID_PATHS = (
    "/x\tpassword:\tabc\nSECRETVALUE",
    "/x Bearer\tabc\nSECRETVALUE",
    "/\tcode=\x0b.1234567/",
    "/\tcode=-\r1980-01-01secret:",
    "/DOB:\tpassword=Bearer|\nJane",
    "/\ta%7Cb%7Cc%2Cbearer abc\nSECRET",
    '/~:Authorization: "name": JANE678919800101bearer ',
    '/mrn "name": DOEa%7Cb%7Ccsession=bearer \xa0',
    "/\ta%7Cb%7Cc%3BBearer tok98765\nSECRET",
    "/\tx%5Ey%5Ez%20bearer abc\rSECRET",
    "/\ta%7Cb%7Cc%2FBearer tok98765\rSECRET",
    "/\tx%5Ey%5Ez%3Abearer abc\nSECRET",
)

_REPEAT_HEAD = (
    "a request from a new client address must re-verify; the address was already flagged since "
    "the session's last re-verification (audit suppressed): path="
)
_OVER_HEAD = (
    "a request from a new client address must re-verify; the address is past the per-session cap "
    f"of {_NEW_IP_PER_SESSION_MAX} (audit suppressed): "
)


#: Seen addresses the baseline reads main's past-cap line with: two addresses and
#: ``_HOSTILE_SEEN``.
_BASELINE_SEEN = ("10.0.0.1", *_HOSTILE_SEEN, "2001:DB8:0:0:0:0:0:1")

#: A path that opens a quoted credential value and a seen text that closes it: main's past-cap
#: line hid the rest of the path as that value, which a reading of the path alone does not. The
#: last three are the review's (round-ea896ecc): the seen text writes the path's own tail back
#: after the quote, which a check of the value's prefix alone let through.
_QUOTE_CLOSING_SEEN = (
    ("/x password='hunter2 more words", "x'"),
    ('/x token="abc def ghi', 'q"'),
    ("/x password='hunter2 more", "x' hunter2 more"),
    ("/x password='hunter2 SECRETTAIL", "x' SECRETTAIL 1"),
    ("/x password='hunter2 more", "x' more junk"),
    ("/x password='hunter2 SECRETTAIL", "x' SECRETTAIL seen_ip=1"),
)


def _sink_lines(fmt: str, *args: object) -> list[str]:
    """What each of two shipped handlers writes for one WARNING."""
    streams, handlers = _two_shipped_handlers()
    logger = logging.getLogger("tests.control_hl7")
    logger.propagate = False
    for handler in handlers:
        logger.addHandler(handler)
    try:
        logger.warning(fmt, *args)
    finally:
        for handler in handlers:
            logger.removeHandler(handler)
            handler.close()
        logger.propagate = True
    written = [s.getvalue() for s in streams]
    # The control: each sink wrote the one line.
    assert all(text.count("\n") == 1 and text.endswith("\n") for text in written), written
    return written


def _last_sink_line(fmt: str, *args: object) -> str:
    """What the last of two shipped handlers writes for one WARNING, without its line break."""
    return _sink_lines(fmt, *args)[-1].rstrip("\n")


def _seen_tail(seen_text: str) -> str:
    """The pre-#3770 past-cap line's tail after the path, with the seen text as main logged it."""
    return " seen_ip=" + scrub_log_argument(seen_text)


def _hides_no_less_than_main(path: str, seen: str = "10.0.0.1") -> list[str]:
    """The words of ``path`` that a sink of this branch's matching line prints in its path field,
    escapes decoded, more often than main's last handler printed them in its path span, on one of
    main's two WARNING lines. Main's lines are its own two formats, with the seen address as main
    logged it. Main's path span is its line after its head and, on the past-cap line, before
    ``seen_ip=`` and the seen text, as main logged it or as two handlers write it alone. Where
    neither tail is found whole, the span runs to the end of the line and the larger of the two
    tails' counts of the word is taken off, uncapped. The subtraction is strict: it guesses no
    boundary, so a word only main's tail printed is not credited to main, but a path word main
    printed can be taken off when its tail, written a third way, did not print it, a false red
    that ``_KNOWN_FALSE_RED`` pins. Not covered, at least: a path word a pass's placeholder or
    escape spells, which a tail rewritten more in the line than alone could add."""
    seen_text = _bounded_address_text(seen)
    repeat = _new_ip_path_field(path)
    over = _new_ip_path_field(path, seen_text)
    main_tail = _seen_tail(seen_text)
    pairs = (
        (_sink_lines(_REPEAT_HEAD + "%s", path), _sink_lines(_REPEAT_HEAD + "%s", repeat)),
        (
            _sink_lines(_OVER_HEAD + "path=%s%s", path, main_tail),
            _sink_lines(_OVER_HEAD + "seen_ip=%s path=%s", _address_log_field(seen), over),
        ),
    )
    # The control: every sink wrote the WARNING. Its opening words, since main's own line can lose
    # ``path=`` to a run of the path.
    opening = "a request from a new client address must re-verify; the address "
    assert all(line.startswith(opening) for pair in pairs for side in pair for line in side)
    words = set(re.findall(r"[A-Za-z0-9]{3,}", path))
    tails = (main_tail, _last_sink_line("%s", main_tail))
    shown = []
    for (main, ours), head, after in zip(
        pairs, (_REPEAT_HEAD, _OVER_HEAD + "path="), (("",), tails), strict=True
    ):
        span, taken_off = _main_span(main[-1], head, opening, after)
        fields = [_unescaped(_path_value(line)) for line in ours]
        for word in sorted(words):
            in_main_span = max(0, span.count(word) - taken_off(word))
            if any(field.count(word) > in_main_span for field in fields):
                shown.append(word)
    return shown


def _main_span(
    line: str, head: str, opening: str, tails: tuple[str, ...]
) -> tuple[str, Callable[[str], int]]:
    """Main's path span in ``line``, and how many of a word in it the caller takes off: the rest
    of ``head`` where a pass took part of it; and, where no tail of ``tails`` is found whole at the
    line's end, the larger of the tails' counts, uncapped: the strict rule
    ``_hides_no_less_than_main`` states."""
    line = line.rstrip("\n")
    extra = ""
    if line.startswith(head):
        line = line[len(head) :]
    else:
        line, extra = line[len(opening) :], head[len(opening) :]
    for tail in tails:
        if line.endswith(tail):
            return line[: len(line) - len(tail)], extra.count
    return line, lambda word: extra.count(word) + max(tail.count(word) for tail in tails)


def _path_value(line: str) -> str:
    """The value of a line's ``path`` field, read by ``_logged_fields``. Only that field is read:
    the seen address field of an unparsed address is a digest under a key drawn per process, and
    could hold a path word."""
    return dict(_logged_fields(line.rstrip("\n")))["path"]


#: Known false reds of the strict baseline (round-5aa03c4b): main wrote the past-cap tail a third
#: way, the encoded run raw and the date redacted, while the path's own date printed, so taking
#: off the raw tail's date takes off the path's. The field prints the date no more often than main.
_KNOWN_FALSE_RED = (
    "//codemrn/1980-01-01SECRET\t|",
    "/'.:\t1980-01-01Authorization: 123-45-6789",
)


@pytest.mark.parametrize("path", _KNOWN_FALSE_RED)
def test_the_strict_baseline_reports_a_known_false_red(path: str) -> None:
    """RED when: the baseline stops flagging a named false red, so its subtraction is no longer the
    strict one its docstring states, or the field prints the date more often than main's line did
    (BACKLOG #3770). Either change needs this vector re-read rather than dropped."""
    seen = "a%7Cb%7Cc 1980-01-01"
    seen_text = _bounded_address_text(seen)
    line = _last_sink_line(_OVER_HEAD + "path=%s%s", path, _seen_tail(seen_text))
    # The controls: main's tail is neither raw nor as written alone, main printed the path's date
    # once, and the field prints it once.
    assert line.endswith(" seen_ip=a%7Cb%7Cc [redacted]") and line.count("1980") == 1, ascii(line)
    assert _unescaped(_new_ip_path_field(path, seen_text)).count("1980") == 1
    assert _hides_no_less_than_main(path, seen) == ["1980"], ascii(path)


@pytest.mark.parametrize(("path", "seen"), _QUOTE_CLOSING_SEEN)
def test_a_seen_address_that_closes_a_quote_hides_the_path(path: str, seen: str) -> None:
    """RED when: the past-cap line's path field prints words of the path that main's past-cap line
    hid only because the seen text after the path closed a quote the path opened; or such a path
    stops logging the placeholder, a case ``redacted_log_field`` lists (BACKLOG #3770)."""
    assert _new_ip_path_field(path, _bounded_address_text(seen)) == _UNREADABLE_FIELD, (path, seen)
    assert not _hides_no_less_than_main(path, seen), (path, seen)


@pytest.mark.parametrize("path", _CONTROL_HL7_PATHS)
def test_a_control_character_does_not_unhide_an_encoded_hl7_name(path: str) -> None:
    """RED when: the path field prints a percent-encoded HL7 name that follows a control
    character, on any sink of either line (BACKLOG #3770)."""
    for line in _sink_lines("path=%s", _new_ip_path_field(path)):
        assert "DOE" not in _unescaped(line) and "JANE" not in _unescaped(line), ascii(line)
    assert not _hides_no_less_than_main(path)


@pytest.mark.parametrize("path", _MAIN_HID_PATHS)
def test_the_path_field_hides_no_less_than_main(path: str) -> None:
    """RED when: a word of the path that main's last shipped handler hid on main's repeat or
    past-cap line prints on a sink of this branch's matching line (BACKLOG #3770). Main logged the
    raw path in ``path=%s`` and ``path=%s seen_ip=%s``; this branch logs an escaped field the
    handlers cannot read into, so the field must already carry what they would have hidden."""
    for seen in _BASELINE_SEEN:
        assert not _hides_no_less_than_main(path, seen), (ascii(path), seen)


#: What the seeded corpora build paths from: labels, separators, encoded separators, controls,
#: words, a no-break space and a credential shape. The last two turn a pass off for a whole line.
_CORPUS_PIECES = (
    "password",
    "Bearer",
    "bearer ",
    "token",
    "session",
    "code",
    "MEFOR_X",
    "mrn",
    "MRN",
    '"name": ',
    "Authorization: ",
    "|",
    "^",
    "&",
    "~",
    "%7C",
    "%5E",
    "%26",
    "%2C",
    "%3B",
    "%20",
    "=",
    ":",
    " ",
    "\t",
    "\n",
    "\r",
    "\x01",
    "\x0b",
    "DOE",
    "JANE",
    "Jane Doe",
    "1980-01-01",
    "19800101",
    "123-45-6789",
    "abc",
    "SECRET",
    "hunter2",
    "/",
    "-",
    ".",
    "\xa0",
    "code=SECRETVALUE",
)


def _corpus_path(rng: random.Random) -> str:
    """One path of a seeded corpus: one to nine of ``_CORPUS_PIECES`` after a slash."""
    return "/" + "".join(rng.choice(_CORPUS_PIECES) for _ in range(rng.randrange(1, 10)))


def test_the_path_field_hides_no_less_than_main_over_a_seeded_corpus() -> None:
    """The same, over paths built from labels, separators, encoded separators, controls and
    words (BACKLOG #3770)."""
    rng = random.Random(3770)
    for n in range(300):
        path = _corpus_path(rng)
        seen = _BASELINE_SEEN[n % len(_BASELINE_SEEN)]
        assert not _hides_no_less_than_main(path, seen), (ascii(path), seen)


def test_an_unparsed_address_logs_a_keyed_digest() -> None:
    """RED when: the past-cap line logs a plain digest of an unparsed address, so a low-entropy
    name or password a client put in a forwarded header is recovered by hashing guesses (BACKLOG
    #3770)."""
    import hashlib

    for text in ("DOE JANE", "password=hunter2", "fe80::1%eth0"):
        field = _address_log_field(text)
        plain = hashlib.sha256(text.encode()).hexdigest()[:16]
        assert plain not in field, text
        assert re.fullmatch(r'"(?:unparsed|fe80::1-zone)-sha256-[0-9a-f]{16}"', field), field
        assert field == _address_log_field(text)


def test_redact_log_value_follows_the_shipped_filter_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED when: ``redact_log_value`` stops reading the filters ``_install_phi_filters`` installs,
    so a filter added there never reaches a new-address WARNING's path, whose escape hides its text
    from every handler filter (BACKLOG #3770)."""
    import messagefoundry.logging_setup as logging_setup

    assert redact_log_value("/x code=a password=b DOE JANE") == (
        "/x code=<redacted> password=<redacted> [redacted]"
    )

    class _Marker(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:
            record.msg, record.args = record.getMessage().replace("MARKER", "[gone]"), None
            return True

    installed = logging_setup._install_phi_filters

    def _with_marker(handler: logging.Handler) -> None:
        installed(handler)
        handler.addFilter(_Marker())

    monkeypatch.setattr(logging_setup, "_install_phi_filters", _with_marker)
    assert redact_log_value("/a/MARKER/b") == "/a/[gone]/b"


def test_a_rewritten_context_logs_a_placeholder() -> None:
    """RED when: a pass that rewrites the line's fixed context around the value leaves that context
    in the value; or a seen text a pass takes into the path is not caught; or a path ending in a
    credential label is unreadable on the repeat line, or ``/x/password:`` is readable on the
    past-cap line, where its label takes ``seen_ip=`` as its value; or the placeholder passes its
    bound (BACKLOG #3770).
    ``/x/password:`` before ``seen_ip=`` reads as a label whose value is the next field."""
    assert _UNREADABLE not in ("<redacted>", "[redacted]")
    assert redact_log_value("/x/password:", after=" seen_ip=0.0.0.0") is None
    after = " seen_ip=0.0.0.0"
    assert redacted_log_field("/x/password:", 64, after=after) == _UNREADABLE_FIELD
    assert redacted_log_field("/a", 64) == '"/a"'
    # The placeholder is bounded like any value.
    for limit in range(16, 24):
        assert len(redacted_log_field("/x/password:", limit, after=after)) <= limit + 2
    assert _new_ip_path_field("/x/password:", "10.0.0.1") == _UNREADABLE_FIELD
    assert _new_ip_path_field("/x/password:") == '"/x/password_u003A_"'
    assert _new_ip_path_field("/plain/path", "10.0.0.1") == '"/plain/path"'
    assert _new_ip_path_field("/api/auth/bearer") == '"/api/auth/bearer"'
    # The bearer label takes ``seen_ip=`` as its value in the past-cap line, a case
    # ``redacted_log_field`` lists.
    for seen in ("10.0.0.1", "DOE JANE hunter2"):
        assert _new_ip_path_field("/api/auth/bearer", seen) == _UNREADABLE_FIELD, seen


#: Seen texts the past-cap reading rewrites on their own: a date, a name, an MRN or an HL7 run a
#: shipped filter rewrites, or a tab, which the shipped filters keep and only that reading's tab
#: round writes as a space. Each must leave an ordinary path readable.
_REWRITTEN_SEEN = (*_HOSTILE_SEEN, "1980-01-01", "MRN 12345", "Smith John", "a^b^c")


@pytest.mark.parametrize("seen", _REWRITTEN_SEEN)
@pytest.mark.parametrize("path", ["/plain", "/users", "/a b", "/api/admin/users/42"])
def test_a_rewritten_seen_address_leaves_an_ordinary_path_readable(path: str, seen: str) -> None:
    """RED when: a seen text that the past-cap reading rewrites alike in the line and on its own
    (``_REWRITTEN_SEEN``) makes an ordinary path unreadable on that line, so a caller's forwarded
    header blanks the only log of which path it reached (BACKLOG #3770)."""
    seen_text = _bounded_address_text(seen)
    tail = _seen_tail(seen_text)
    # The control: a shipped handler rewrites this seen text read alone, or it holds a tab, which
    # only the reading's tab round rewrites; so the case is the one named.
    assert "\t" in tail or _last_sink_line("%s", tail) != tail, seen
    field = _new_ip_path_field(path, seen_text)
    assert field == _new_ip_path_field(path) != _UNREADABLE_FIELD, (path, seen, field)


#: A path that switches a pass off for its whole line, a no-break space or a credential shape,
#: with an encoded HL7 seen text: the past-cap line leaves that text raw, while the text read
#: alone is rewritten (round-46f84b99).
_RAW_IN_LINE_SEEN = (
    ("/api/connections/IB_ACME\xa0/stop", "a%7Cb%7Cc"),
    ("/x code=SECRETVALUE", "DOE%5EJANE%5EQ"),
)


@pytest.mark.parametrize(("path", "seen"), _RAW_IN_LINE_SEEN)
def test_a_seen_text_left_raw_in_the_line_leaves_the_path_readable(path: str, seen: str) -> None:
    """RED when: a seen text the past-cap line leaves raw, though a pass rewrites it alone, makes
    a path readable on the repeat line unreadable on the past-cap line (BACKLOG #3770)."""
    seen_text = _bounded_address_text(seen)
    tail = _seen_tail(seen_text)
    line = _last_sink_line(_OVER_HEAD + "path=%s%s", path, tail)
    # The controls: the line kept the tail raw, and the tail read alone is rewritten.
    assert line.endswith(tail), ascii(line)
    assert _last_sink_line("%s", tail) != tail, seen
    field = _new_ip_path_field(path, seen_text)
    assert field == _new_ip_path_field(path) != _UNREADABLE_FIELD, (ascii(path), seen, field)
    assert not _hides_no_less_than_main(path, seen), (ascii(path), seen)


@pytest.mark.parametrize("seen", ["code=SECRETVALUE", "10.0.0.1\xa0"])
def test_a_seen_text_that_turns_a_pass_off_blanks_a_path_that_pass_rewrote(seen: str) -> None:
    """RED when: the case ``redacted_log_field`` names, a seen text that turns a pass off for the
    whole line so the line hides less of the path than the repeat line did, stops logging the
    placeholder (BACKLOG #3770). It fails closed; a change that makes it readable must also change
    that docstring, and still pass the hides-no-less tests."""
    path = "/api/x a%7Cb%7Cc"
    assert _new_ip_path_field(path) == '"/api/x_u0020_[redacted]"'
    assert _new_ip_path_field(path, _bounded_address_text(seen)) == _UNREADABLE_FIELD


@pytest.mark.parametrize("seen", ["a%7Cb%7Cc\tx", "a%7Cb%7Cc 1980-01-01", "a%7Cb%7Cc DOE JANE"])
@pytest.mark.parametrize("path", [path for path, _ in _RAW_IN_LINE_SEEN])
def test_a_raw_run_beside_another_rewritten_shape_blanks_a_switch_off_path(
    path: str, seen: str
) -> None:
    """RED when: the case ``redacted_log_field`` lists, a path that turns
    a pass off for its whole line with a seen text holding a raw encoded run beside a tab, a date
    or a name, stops logging the placeholder (BACKLOG #3770). It fails closed; a change that makes
    it readable must also change that docstring, and still pass the hides-no-less tests."""
    assert _new_ip_path_field(path, _bounded_address_text(seen)) == _UNREADABLE_FIELD
    assert _new_ip_path_field(path) != _UNREADABLE_FIELD


def _unexplained_blanks(field: Callable[[str, str], str]) -> tuple[int, list[str]]:
    """Over the seeded corpus, how many paths ``field`` blanks on the past-cap line though the
    repeat line reads them, and those of them main's own past-cap line, written by two shipped
    handlers, printed readably: as the repeat value, or main's own repeat-line path span, followed
    by the seen text raw or as the passes write it alone."""
    rng = random.Random(46)
    head = _OVER_HEAD + "path="
    seens = (*_BASELINE_SEEN, *(seen for _, seen in _RAW_IN_LINE_SEEN))
    blanked, readable_in_main = 0, []
    for n in range(300):
        path = _corpus_path(rng)
        seen_text = _bounded_address_text(seens[n % len(seens)])
        if field(path, seen_text) != _UNREADABLE_FIELD:
            continue
        value = redact_log_value(path, before=_REPEAT_HEAD)
        if value is None:
            continue
        blanked += 1
        # Main's own repeat span keeps a tab the repeat value, read with the tab round, respells.
        repeat = _last_sink_line(_REPEAT_HEAD + "%s", path)
        spans = {value}
        if repeat.startswith(_REPEAT_HEAD):
            spans.add(repeat[len(_REPEAT_HEAD) :])
        tail = _seen_tail(seen_text)
        tails = (tail, _last_sink_line("%s", tail))
        line = _last_sink_line(head + "%s%s", path, tail)
        if any(line == head + span + end for span in spans for end in tails):
            readable_in_main.append(ascii(path))
    return blanked, readable_in_main


def test_the_past_cap_line_blanks_a_path_only_where_main_wrote_neither_tail_form() -> None:
    """RED when: over the seeded corpus, the past-cap line logs the placeholder for a path the
    repeat line reads, though main's own past-cap line, written by two shipped handlers, printed
    it readably: the repeat value or main's own repeat-line path span, followed by the seen text
    raw or as the passes write it alone (BACKLOG #3770). Main's line is read through the real
    handlers here, not the reading the field's check uses. It does not catch a blank where main
    printed the path with the tail written a third way."""
    blanked, unexplained = _unexplained_blanks(_new_ip_path_field)
    # The control: the corpus reaches the placeholder at all.
    assert blanked, "no corpus path was blanked, so this measured nothing"
    assert not unexplained, unexplained
    # The control: a field that blanks every path holding a tab is caught, which a comparison
    # with the repeat value alone, a tab respelled, could not catch.
    # Only the paths it blanks are read further, so any other spelling serves the rest.
    _, caught = _unexplained_blanks(
        lambda path, seen_text: _UNREADABLE_FIELD if "\t" in path else '"readable"'
    )
    assert any("\\t" in path for path in caught), caught


def test_a_cut_checksum_is_never_read_as_a_date() -> None:
    """RED when: the cut mark ends where a word boundary falls before the checksum, so a checksum
    of eight decimal digits starting 19 or 20 logs as ``[redacted]`` (BACKLOG #3770)."""
    streams, handlers = _two_shipped_handlers()
    logger = logging.getLogger("tests.cut_checksum")
    logger.propagate = False
    for handler in handlers:
        logger.addHandler(handler)
    try:
        hits = 0
        for n in range(20000):
            token = redacted_log_field(f"/users/{'a' * 300}{n}", _NEW_IP_LOG_FIELD_MAX)
            if not re.search(r"_%crc32x(?:19|20)[0-9]{6}\"", token):
                continue
            hits += 1
            logger.warning("path=%s", token)
            assert all(s.getvalue().splitlines()[-1] == f"path={token}" for s in streams)
        assert hits  # the control: such a checksum occurred in the range
    finally:
        for handler in handlers:
            logger.removeHandler(handler)
            handler.close()
        logger.propagate = True

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2388: an ``amr`` exemption from the OIDC start-to-callback floor.

An identity provider that re-authenticates with no human step (integrated Windows sign-in, a client
certificate) answers every step-up faster than the 1 s floor, so every step-up was refused, and the
only advice was to turn the floor off for everyone. ``[auth].oidc_callback_floor_exempt_amr`` names
the ``amr`` values that mark such a sign-in, and only a signature-verified ``amr`` naming one skips
the floor. Each arm comes with its control, and the default (empty) must change nothing.
"""

from __future__ import annotations

import ast
import inspect
import json
import textwrap
import time
import urllib.parse
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import replace
from functools import partial
from typing import Any
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import oidc
from messagefoundry.auth import service as service_module
from messagefoundry.auth.audit_visibility import (
    DIRECTORY_LOGIN_LOCKED_ACTION,
    HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE,
)
from messagefoundry.auth.ldap import LdapError
from messagefoundry.auth.service import (
    DIRECTORY_IDENTITY_CONFLICT,
    DIRECTORY_ROLE_MAP_UNSEALED,
    DIRECTORY_ROLES_DEMOTED,
    IDP_ANSWER_UNUSABLE,
    TOO_EARLY,
    AuthService,
)
from messagefoundry.config.settings import AuthSettings, _auth_limit_loosenings
from messagefoundry.store.store import MessageStore
from tests._ast_sites import parse_source
from tests.test_auth_oidc_service import (
    AUTH_CODE,
    DEFAULT_SUB,
    PRINCIPAL,
    _audit_rows,
    _oid,
    _oidc_login,
    _service,
    _settings,
)
from tests.test_oidc_step_up import _begin, _return_from_idp, _staged

ORIGIN = "https://ops.example"
FLOOR = AuthSettings().oidc_callback_min_elapsed_seconds
EXEMPT = "wia"  # a synthetic amr value standing for integrated Windows sign-in
MARKER = "callback_floor_exempt_amr"
DEFERRED = "callback_floor_deferred"
#: ``(elapsed, marked)``: inside the floor, where the exemption applies, then past it, the control.
EARLY_THEN_LATE = [(FLOOR - 0.001, True), (FLOOR + 0.001, False)]


@pytest.fixture(scope="module")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture(autouse=True)
def _no_failure_pad(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _no_sleep(deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", _no_sleep)


async def _floored(
    store: MessageStore, rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch, **over: Any
) -> tuple[AuthService, list[float]]:
    service = await _service(store, rsa_key, oidc_callback_min_elapsed_seconds=FLOOR, **over)
    clock = [time.monotonic()]
    assert service._oidc_flows is not None
    monkeypatch.setattr(service._oidc_flows, "_clock", lambda: clock[0])
    return service, clock


def _verified(amr: tuple[str, ...], auth_time: float) -> oidc.FederatedPrincipal:
    now = time.time()
    return oidc.FederatedPrincipal(
        username="jdoe",
        subject=DEFAULT_SUB,
        issuer="https://idp.example",
        amr=amr,
        acr=None,
        expires_at=now + 600,
        auth_time=auth_time,
    )


async def _sign_in_too_early(
    service: AuthService,
    clock: list[float],
    amr: tuple[str, ...],
    *,
    elapsed: float = FLOOR - 0.001,
    auth_time_offset: float = 0.5,
) -> Any:
    """A sign-in whose person signed in at the IdP during the flow, returning ``elapsed`` seconds
    after the start: inside the floor unless a test says otherwise."""
    flow_id, url = await service.begin_oidc_login(client="127.0.0.1", public_origin=ORIGIN)
    state = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))["state"]
    issued_at = _staged(service, flow_id).issued_at
    service._exchange_and_validate = lambda *_a, **_k: _verified(amr, issued_at + auth_time_offset)  # type: ignore[method-assign]
    clock[0] += elapsed
    return await service.complete_oidc_login(
        flow_id=flow_id, state=state, code=AUTH_CODE, client="127.0.0.1", public_origin=ORIGIN
    )


def _detail(row: Any) -> dict[str, Any]:
    detail: dict[str, Any] = json.loads(str(row["detail"]))
    return detail


def _evidence(row: Any) -> dict[str, Any]:
    return dict(_detail(row).get("evidence") or {})


# --- settings and the loosening registry -----------------------------------------------------------


def test_the_list_ships_empty_and_loses_blank_values() -> None:
    assert AuthSettings().oidc_callback_floor_exempt_amr == []
    auth = _settings(oidc_callback_floor_exempt_amr=["", " wia ", "  "])
    assert auth.oidc_callback_floor_exempt_amr == ["wia"]
    assert _settings(oidc_callback_floor_exempt_amr=" wia, ,sc").oidc_callback_floor_exempt_amr == [
        "wia",
        "sc",
    ]


def _named(auth: AuthSettings) -> list[str]:
    return [name for name, _risk in _auth_limit_loosenings(auth)]


def test_a_listed_value_is_a_named_loosening_that_quotes_none() -> None:
    auth = _settings(
        oidc_callback_min_elapsed_seconds=FLOOR, oidc_callback_floor_exempt_amr=[EXEMPT]
    )
    entries = dict(_auth_limit_loosenings(auth))
    risk = entries["oidc_callback_floor_exempt_amr"]
    assert "not that a person acted" in risk
    assert EXEMPT not in risk


@pytest.mark.parametrize(
    ("auth", "named"),
    [
        pytest.param(_settings(oidc_callback_min_elapsed_seconds=FLOOR), False, id="empty"),
        pytest.param(
            _settings(oidc_callback_min_elapsed_seconds=0, oidc_callback_floor_exempt_amr=[EXEMPT]),
            False,
            id="floor-off",  # the floor's own entry already says off
        ),
        pytest.param(AuthSettings(oidc_callback_floor_exempt_amr=[EXEMPT]), False, id="oidc-off"),
        pytest.param(
            _settings(
                oidc_callback_min_elapsed_seconds=FLOOR, oidc_callback_floor_exempt_amr=[EXEMPT]
            ),
            True,
            id="set",
        ),
    ],
)
def test_the_exemption_is_named_only_while_it_can_apply(auth: AuthSettings, named: bool) -> None:
    assert ("oidc_callback_floor_exempt_amr" in _named(auth)) is named


# --- the sign-in leg, which has the same floor defect ----------------------------------------------


async def test_a_too_early_sign_in_with_an_exempt_amr_is_served_and_recorded(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT, "sc"]
        )
        # The token's amr carries more than the configured value. Only configured values may reach
        # the audit field, so a token-chosen value never does.
        served = await _sign_in_too_early(service, clock, ("mfa", EXEMPT, "x-token-only"))
        assert served.ok and served.token is not None, served
        [row] = await _audit_rows(store, "auth.login_success")
        # BACKLOG #3728 item 7: at the top level, as on every other row that carries it, and not
        # under `evidence` too.
        assert _detail(row)[MARKER] == [EXEMPT]
        assert MARKER not in _evidence(row)
        assert _evidence(row)["amr"] == ["mfa", EXEMPT, "x-token-only"]  # evidence still recorded
    finally:
        await store.close()


async def test_a_too_early_sign_in_without_an_exempt_amr_is_still_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: the exemption is keyed on the amr, not on the setting being present."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        early = await _sign_in_too_early(service, clock, ("pwd", "mfa"))
        assert not early.ok and early.reason == TOO_EARLY
    finally:
        await store.close()


async def test_a_sign_in_past_the_floor_records_no_exemption(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The field is present only when the exemption let a too-early callback through."""
    store = await MessageStore.open(":memory:")
    try:
        service, _clock = await _floored(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        served = await _oidc_login(service, monkeypatch, rsa_key, amr=["mfa", EXEMPT])
        assert served.ok, served
        rows = await _audit_rows(store, "auth.login_success")
        assert len(rows) == 1
        assert MARKER not in _detail(rows[0])
        assert MARKER not in _evidence(rows[0])
    finally:
        await store.close()


# BACKLOG #3220: a refusal after the exemption applied carries the marker too, so the review the
# loosening entry asks for also sees exempted attempts that failed. Each refusal is driven twice:
# inside the floor with an exempt amr (marked), and past the floor with the same amr (the control:
# the floor never applied, so there is nothing to mark). BACKLOG #3726: the lock refusal is written
# under its own action, which readers without users:manage never read (owner ruling 2026-09-28), so
# the marker can ride it; it used to share auth.login_failed, hidden by exact text, and took none.
async def _refuse_sign_in(service: AuthService, store: MessageStore, refusal: str) -> None:
    if refusal == "disabled":  # refused in _complete_ad_login, through _refuse_directory_row
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        await store.set_user_disabled(user.id, disabled=True)
    elif refusal == "not_in_directory":  # refused in _authenticate_oidc itself
        service._ldap._principal = None  # type: ignore[union-attr]
    elif refusal == "locked":  # refused in _complete_ad_login, under its own action
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        await store.record_login_failure(user.id, failed_attempts=5, locked_until=time.time() + 600)


async def _refusal_detail(store: MessageStore, action: str, reason: str | None) -> dict[str, Any]:
    """The one ``action`` row refused with ``reason`` (None: the row with no reason)."""
    details = [_detail(r) for r in await _audit_rows(store, action)]
    [detail] = [d for d in details if d.get("reason") == reason]
    return detail


@pytest.mark.parametrize(
    "refusal", ["disabled", "not_in_directory", "federated_subject_not_bound", "locked"]
)
@pytest.mark.parametrize(("elapsed", "marked"), EARLY_THEN_LATE)
async def test_a_refused_sign_in_carries_the_marker_only_when_the_exemption_applied(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    refusal: str,
    elapsed: float,
    marked: bool,
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored(
            store,
            rsa_key,
            monkeypatch,
            oidc_callback_floor_exempt_amr=[EXEMPT, "sc"],
            bind=None if refusal == "federated_subject_not_bound" else DEFAULT_SUB,
        )
        await _refuse_sign_in(service, store, refusal)
        out = await _sign_in_too_early(
            service, clock, ("mfa", EXEMPT, "x-token-only"), elapsed=elapsed
        )
        assert not out.ok and out.reason == refusal, out
        action = DIRECTORY_LOGIN_LOCKED_ACTION if refusal == "locked" else "auth.login_failed"
        detail = await _refusal_detail(store, action, refusal)
        if marked:
            # Configured values only: the token's other amr values never reach the row.
            assert detail["callback_floor_exempt_amr"] == [EXEMPT]
        else:
            assert "callback_floor_exempt_amr" not in detail
        # No lock stand-in under the visible action: it would show the lock and feed the burst.
        failed = await _audit_rows(store, "auth.login_failed")
        assert all(_detail(r).get("reason") != "locked" for r in failed)
        if refusal == "locked":
            # BACKLOG #3728 item 6: read the trail through the store's own filtered read, the one
            # the audit routes use for a reader without users:manage, rather than comparing the
            # exclusion's row set. The marked lock row is gone from it and nothing else is.
            everything = [(r["action"], r["detail"]) for r in await store.list_audit(limit=1000)]
            filtered = [
                (r["action"], r["detail"])
                for r in await store.list_audit(
                    limit=1000, exclude=HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE
                )
            ]
            assert any(a == DIRECTORY_LOGIN_LOCKED_ACTION for a, _d in everything), everything
            assert filtered, "the filtered read returned nothing, so its absence proves nothing"
            assert filtered == [r for r in everything if r[0] != DIRECTORY_LOGIN_LOCKED_ACTION]
    finally:
        await store.close()


async def _directory_down(
    service: AuthService, store: MessageStore, mp: pytest.MonkeyPatch
) -> None:
    def resolve(*_a: Any, **_k: Any) -> Any:
        raise LdapError("directory unavailable")

    mp.setattr(service._ldap, "resolve_principal", resolve)


async def _binding_changed(
    service: AuthService, store: MessageStore, mp: pytest.MonkeyPatch
) -> None:
    async def issue(*_a: Any, **_k: Any) -> Any:
        raise service_module._BindingChangedMidLogin()

    mp.setattr(service, "_issue_session", issue)


async def _renamed_onto(
    service: AuthService,
    store: MessageStore,
    _mp: pytest.MonkeyPatch,
    *,
    provider: str,
    object_id: str | None,
) -> None:
    """The directory renamed jdoe's object to ``jsmith``, a name another row already holds."""
    service._ldap._principal = replace(PRINCIPAL, username="jsmith")  # type: ignore[union-attr]
    await store.create_user(
        user_id=uuid4().hex,
        username="jsmith",
        auth_provider=provider,
        directory_object_id=object_id,
        password_generated=False,
    )


async def _create_race(service: AuthService, store: MessageStore, mp: pytest.MonkeyPatch) -> None:
    async def upsert(*_a: Any, **_k: Any) -> Any:
        raise service_module._DirectoryAccountConflict(DIRECTORY_IDENTITY_CONFLICT)

    mp.setattr(service, "_upsert_ad_user", upsert)


#: BACKLOG #3728 item 5: the sign-in refusal arms the item named as untested. Each is
#: ``(setup, audit action, the row's reason, the outcome's reason)``; the login_error row has no
#: reason, and the inline local conflict returns none.
_ArmSetup = Callable[[AuthService, MessageStore, pytest.MonkeyPatch], Awaitable[None]]
_SIGN_IN_ARMS: dict[str, tuple[_ArmSetup, str, str | None, str | None]] = {
    "login_error": (_directory_down, "auth.login_error", None, "directory_unavailable"),
    "binding_changed": (
        _binding_changed,
        "auth.login_failed",
        "federated_subject_unbound",
        "federated_subject_unbound",
    ),
    "inline_local_conflict": (
        partial(_renamed_onto, provider="local", object_id=None),
        "auth.login_failed",
        "local_account_conflict",
        None,
    ),
    "inline_identity_conflict": (
        partial(_renamed_onto, provider="ad", object_id=_oid("jsmith")),
        "auth.login_failed",
        DIRECTORY_IDENTITY_CONFLICT,
        DIRECTORY_IDENTITY_CONFLICT,
    ),
    "create_race_conflict": (
        _create_race,
        "auth.login_failed",
        DIRECTORY_IDENTITY_CONFLICT,
        DIRECTORY_IDENTITY_CONFLICT,
    ),
}


@pytest.mark.parametrize("arm", sorted(_SIGN_IN_ARMS))
@pytest.mark.parametrize(("elapsed", "marked"), EARLY_THEN_LATE)
async def test_the_other_sign_in_refusal_arms_carry_the_marker_only_when_it_applied(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    arm: str,
    elapsed: float,
    marked: bool,
) -> None:
    setup, action, row_reason, outcome_reason = _SIGN_IN_ARMS[arm]
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        await setup(service, store, monkeypatch)
        out = await _sign_in_too_early(service, clock, ("mfa", EXEMPT), elapsed=elapsed)
        assert not out.ok and out.reason == outcome_reason, out
        detail = await _refusal_detail(store, action, row_reason)
        if marked:
            assert detail[MARKER] == [EXEMPT]
        else:
            assert MARKER not in detail
    finally:
        await store.close()


async def test_a_too_early_single_sign_on_callback_is_not_marked_when_refused(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the other condition: an IdP answering from a sign-on made before the flow
    is not floored, so a refusal of it carries no marker even with an exempt amr."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        await _refuse_sign_in(service, store, "disabled")
        out = await _sign_in_too_early(service, clock, ("mfa", EXEMPT), auth_time_offset=-60.0)
        assert not out.ok and out.reason == "disabled", out
        detail = await _refusal_detail(store, "auth.login_failed", "disabled")
        assert "callback_floor_exempt_amr" not in detail
    finally:
        await store.close()


# --- the step-up leg -------------------------------------------------------------------------------


async def _signed_in(
    store: MessageStore, rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch, **over: Any
) -> tuple[AuthService, list[float], str]:
    service, clock = await _floored(store, rsa_key, monkeypatch, **over)
    out = await _oidc_login(service, monkeypatch, rsa_key)
    assert out.ok and out.token is not None
    return service, clock, out.token


async def test_with_the_list_empty_a_too_early_step_up_spends_no_code(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default keeps the shipped order: refused before the code exchange."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock, token = await _signed_in(store, rsa_key, monkeypatch)
        flow_id, _url = await _begin(service, token)
        flow = _staged(service, flow_id)
        clock[0] += FLOOR - 0.001

        def tripwire(**_kwargs: Any) -> Any:
            raise AssertionError("the code was redeemed for a too-early step-up")

        monkeypatch.setattr(oidc, "exchange_code", tripwire)
        out = await service.complete_oidc_step_up(
            flow_id=flow_id,
            state=flow.state,
            code=AUTH_CODE,
            client="10.0.0.9",
            public_origin=ORIGIN,
        )
        assert not out.elevation.ok and out.reason == TOO_EARLY
        detail = await _refusal_detail(store, "auth.reauth", TOO_EARLY)
        assert DEFERRED not in detail and MARKER not in detail  # nothing was deferred
    finally:
        await store.close()


async def test_an_exempt_amr_lets_a_too_early_step_up_elevate_and_records_it(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service, clock, token = await _signed_in(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        flow_id, _url = await _begin(service, token)
        clock[0] += FLOOR - 0.001
        out = await _return_from_idp(
            service, monkeypatch, rsa_key, flow_id, amr=["mfa", EXEMPT, "x-token-only"]
        )
        assert out.elevation.ok and out.elevation.token is not None, out
        rows = [_detail(r) for r in await _audit_rows(store, "auth.reauth")]
        assert rows[-1]["ok"] is True
        assert rows[-1][MARKER] == [EXEMPT]
        assert rows[-1][DEFERRED] is True
    finally:
        await store.close()


async def test_an_opted_in_site_still_refuses_a_too_early_step_up_with_no_exempt_amr(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the arm above. With the list set the refusal waits for the exchange, since
    only the exchange yields the amr, and then refuses as before."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock, token = await _signed_in(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        flow_id, _url = await _begin(service, token)
        clock[0] += FLOOR - 0.001
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, amr=["pwd", "mfa"])
        assert not out.elevation.ok and out.reason == TOO_EARLY
        assert not out.elevation.session_lost
        assert not await service.has_recent_step_up(token)
        rows = [_detail(r) for r in await _audit_rows(store, "auth.reauth")]
        assert rows[-1]["reason"] == TOO_EARLY
        # The code was redeemed before this refusal, and the row says so (BACKLOG #3728).
        assert rows[-1][DEFERRED] is True and MARKER not in rows[-1]
    finally:
        await store.close()


async def test_a_step_up_past_the_floor_records_no_exemption(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = await MessageStore.open(":memory:")
    try:
        service, clock, token = await _signed_in(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        flow_id, _url = await _begin(service, token)
        clock[0] += FLOOR + 0.001
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, amr=["mfa", EXEMPT])
        assert out.elevation.ok, out
        rows = [_detail(r) for r in await _audit_rows(store, "auth.reauth")]
        assert rows[-1]["ok"] is True
        assert MARKER not in rows[-1] and DEFERRED not in rows[-1]
    finally:
        await store.close()


@pytest.mark.parametrize(
    "refusal",
    [
        "not_in_directory",
        "step_up_subject_mismatch",
        DIRECTORY_ROLES_DEMOTED,
        DIRECTORY_ROLE_MAP_UNSEALED,
        "session_gone",  # BACKLOG #3728 item 5
    ],
)
@pytest.mark.parametrize(("elapsed", "marked"), EARLY_THEN_LATE)
async def test_a_refused_step_up_carries_the_marker_only_when_the_exemption_applied(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    refusal: str,
    elapsed: float,
    marked: bool,
) -> None:
    """BACKLOG #3220, the step-up leg: a refusal after the exchange carries the marker when the
    exemption let the too-early callback past the floor, and only then. The two role arms ride the
    bound refuse partial that carries the marker since main's #3082 reason merged into it."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock, token = await _signed_in(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        claims: dict[str, Any] = {"amr": ["mfa", EXEMPT, "x-token-only"]}
        if refusal == "not_in_directory":
            service._ldap._principal = None  # type: ignore[union-attr]
        elif refusal == DIRECTORY_ROLES_DEMOTED:
            # The account signed in as operator; its groups now map to no role.
            ldap: Any = service._ldap
            ldap._principal = replace(ldap._principal, groups=frozenset())
        elif refusal == DIRECTORY_ROLE_MAP_UNSEALED:
            monkeypatch.setattr(service_module, "ad_map_seal_ok", lambda _sealer, _current: False)
        elif refusal == "step_up_subject_mismatch":
            claims["sub"] = "S-1-5-21-someone-else"
        flow_id, _url = await _begin(service, token)
        if refusal == "session_gone":
            # After the start leg staged the session, so the callback finds it gone.
            await store.revoke_user_sessions(_staged(service, flow_id).step_up_user_id or "")
        clock[0] += elapsed
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, **claims)
        assert not out.elevation.ok and out.reason == refusal, out
        detail = await _refusal_detail(store, "auth.reauth", refusal)
        if marked:
            assert detail[MARKER] == [EXEMPT]
            assert detail[DEFERRED] is True
        else:
            assert MARKER not in detail and DEFERRED not in detail
    finally:
        await store.close()


def test_a_blank_configured_value_matches_no_blank_amr() -> None:
    """Load drops a blank, and the helper ignores one from any other constructor."""
    service = AuthService.__new__(AuthService)
    service._settings = AuthSettings.model_construct(oidc_callback_floor_exempt_amr=["", " "])
    values = service._oidc_callback_floor_exempt_values()
    assert service._oidc_callback_floor_exemption(values, ("", " ")) == ()
    # A set that skipped the filter: the helper refuses its blanks itself.
    assert service._oidc_callback_floor_exemption(frozenset({"", " "}), ("", " ")) == ()
    service._settings = AuthSettings.model_construct(oidc_callback_floor_exempt_amr=[EXEMPT])
    values = service._oidc_callback_floor_exempt_values()
    assert service._oidc_callback_floor_exemption(values, ("pwd", EXEMPT)) == (EXEMPT,)


# --- an exempt value the MFA gate also accepts -----------------------------------------------------


def test_an_exempt_value_the_mfa_gate_accepts_is_refused_at_load() -> None:
    """Listing ``mfa`` (the default MFA amr) would exempt every token the gate admits by it, which is
    the floor turned off while the loosening entry says it is narrower than that."""
    with pytest.raises(ValueError, match="oidc_mfa_amr_values accepts as MFA") as caught:
        _settings(oidc_callback_floor_exempt_amr=[EXEMPT, "mfa"])
    assert "'mfa'" not in str(caught.value)  # the refusal quotes no configured value


def test_the_overlap_loads_while_the_claim_gate_is_off() -> None:
    """With the gate off nothing reads oidc_mfa_amr_values, so there is no overlap to refuse."""
    auth = _settings(oidc_require_mfa_claim=False, oidc_callback_floor_exempt_amr=["mfa"])
    assert auth.oidc_callback_floor_exempt_amr == ["mfa"]


async def test_an_opted_in_too_early_step_up_whose_proof_fails_reports_that_failure(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With the list set the floor waits for the exchange, so a failed proof is refused with the
    proof's own reason, as SECURITY.md says, and nothing is elevated."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock, token = await _signed_in(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        flow_id, _url = await _begin(service, token)
        clock[0] += FLOOR - 0.001
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, amr=["pwd"])
        assert not out.elevation.ok and out.reason == "mfa_claim_missing"
    finally:
        await store.close()


#: BACKLOG #3728 item 3: each way the code exchange can fail on the step-up leg, as the exception
#: it raises and the reason the refusal is filed under.
_EXCHANGE_FAILURES: dict[str, tuple[Callable[[], Exception], str]] = {
    "claims": (lambda: oidc.ClaimsError("mfa_claim_missing"), "mfa_claim_missing"),
    "token_refused": (lambda: oidc.TokenRefusedError("refused", status=400), "token_refused"),
    "transport": (lambda: TimeoutError("timed out"), "idp_unavailable"),
    "unusable": (lambda: ValueError("unreadable"), IDP_ANSWER_UNUSABLE),
}


@pytest.mark.parametrize("failure", sorted(_EXCHANGE_FAILURES))
@pytest.mark.parametrize(("elapsed", "deferred"), EARLY_THEN_LATE)
async def test_a_failed_exchange_on_a_deferred_step_up_is_tied_to_the_exemption(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
    elapsed: float,
    deferred: bool,
) -> None:
    """BACKLOG #3728 item 3. An opted-in site redeems a too-early step-up's code before it decides
    the floor, so a failed exchange is refused before any amr is known. Its row carries
    ``callback_floor_deferred``, and never the matched-values marker, which it cannot know. The
    control: the same failure past the floor deferred nothing, so its row carries neither. Whether
    the callback is refused, and under which reason, does not change."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock, token = await _signed_in(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        make, reason = _EXCHANGE_FAILURES[failure]
        flow_id, _url = await _begin(service, token)
        flow = _staged(service, flow_id)

        def fail(*_a: Any, **_k: Any) -> Any:
            raise make()

        monkeypatch.setattr(service, "_exchange_and_validate", fail)
        clock[0] += elapsed
        out = await service.complete_oidc_step_up(
            flow_id=flow_id,
            state=flow.state,
            code=AUTH_CODE,
            client="10.0.0.9",
            public_origin=ORIGIN,
        )
        assert not out.elevation.ok and out.reason == reason, out
        detail = await _refusal_detail(store, "auth.reauth", reason)
        assert MARKER not in detail
        if deferred:
            assert detail[DEFERRED] is True
        else:
            assert DEFERRED not in detail
        if failure == "token_refused":
            # The arm's own `extra` and the bound floor fields both land.
            assert detail["status"] == 400
    finally:
        await store.close()


# --- BACKLOG #3728 item 1: a guard derived from the code, so a NEW outcome writer is caught --------
#
# The marker is passed by hand to every outcome writer after the exemption is decided. A test that
# names today's arms cannot catch tomorrow's, so this one reads the three methods' syntax trees and
# checks every outcome write in the region the marker covers, descending into each AuthService
# method the region calls. An outcome row that does not pass the marker fails it, and so does an
# audit write whose action the guard cannot read.
#
# Other actions, the side-effect rows docs/SECURITY.md says carry no marker, are not listed, so a
# new one anywhere under these methods does not fail this test. The cost: a NEW outcome action
# written by a direct `_audit` call would pass unseen until it is added below.

#: Audit actions that record a sign-in or step-up attempt's OUTCOME. Each must carry the marker.
_OUTCOME_ACTIONS = frozenset(
    {
        "auth.login_failed",
        "auth.login_error",
        "auth.login_success",
        "auth.reauth",
        DIRECTORY_LOGIN_LOCKED_ACTION,
    }
)
#: Writers that take the marker through a keyword, and that keyword.
_KEYWORD_WRITERS = {
    "_directory_reject_audit": "extra",
    "_refuse_directory_row": "extra",
    "_complete_ad_login": "outcome_extra",
}


def _methods_of(cls: ast.ClassDef) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    return {n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


@pytest.fixture(scope="module")
def service_methods() -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = parse_source(inspect.getsource(service_module))
    [cls] = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "AuthService"]
    return _methods_of(cls)


def _names(node: ast.AST | None) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)} if node else set()


def _keyword(call: ast.Call, name: str) -> ast.expr | None:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _callee(call: ast.Call) -> str | None:
    """``x`` for ``self.x(...)`` or ``x(...)``; None for anything else. Narrower than
    ``_ast_sites.callee_name`` on purpose: a call on another receiver, such as
    ``self._ldap.resolve_principal``, is not an AuthService method to descend into."""
    func = call.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.attr if func.value.id == "self" else None
    return func.id if isinstance(func, ast.Name) else None


def _calls(fn: ast.AST, after: int = 0) -> Iterator[ast.Call]:
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and node.lineno > after:
            yield node


def _action(call: ast.Call) -> str | None:
    arg = call.args[0] if call.args else None
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name):
        value = getattr(service_module, arg.id, None)
        return value if isinstance(value, str) else None
    return None


def _built_from(fn: ast.AST, variable: str) -> set[str]:
    """Every name a local dict ``variable`` is built or updated from inside ``fn``."""
    names: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(isinstance(t, ast.Name) and t.id == variable for t in targets):
                names |= _names(node.value)
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "update"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == variable
        ):
            names |= _names(node)
    return names


def _carries(fn: ast.AST, expr: ast.expr | None, markers: set[str]) -> bool:
    if not markers:
        return False
    names = _names(expr)
    return bool(names & markers) or any(_built_from(fn, n) & markers for n in names)


def _unmarked(
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    fn: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    after: int,
    markers: set[str],
    seen: set[str],
) -> tuple[list[str], int]:
    """Every outcome write in ``fn`` past line ``after`` that does not pass one of ``markers``, and
    how many outcome writes were checked (the positive control's count)."""
    problems: list[str] = []
    checked = 0
    where = fn.name
    for call in _calls(fn, after):
        callee = _callee(call)
        if callee == "_audit":
            action = _action(call)
            if action is None:
                problems.append(f"{where}:{call.lineno} writes an action the guard cannot read")
                continue
            if action not in _OUTCOME_ACTIONS:
                continue
            checked += 1
            if not _carries(fn, _keyword(call, "detail"), markers):
                problems.append(f"{where}:{call.lineno} writes {action!r} without the marker")
        elif callee in _KEYWORD_WRITERS:
            checked += 1
            if not _carries(fn, _keyword(call, _KEYWORD_WRITERS[callee]), markers):
                problems.append(f"{where}:{call.lineno} calls {callee} without the marker")
        elif callee == "_step_up_refused":
            problems.append(f"{where}:{call.lineno} calls _step_up_refused past the bound refuse")
        elif callee == "refuse":
            checked += 1
            if _keyword(call, "floor") is not None:
                problems.append(f"{where}:{call.lineno} passes floor=, replacing the bound fields")
        elif callee in methods and callee not in seen:
            seen.add(callee)
            # A method the region calls is checked whole, and must write no outcome row at all:
            # the marker cannot reach it.
            inner, inner_checked = _unmarked(
                methods, methods[callee], after=0, markers=set(), seen=seen
            )
            problems += inner
            checked += inner_checked
    return problems, checked


def _region_start(fn: ast.AST, target: str, keyword: str | None = None) -> int:
    """The line of the first assignment to ``target`` (whose call passes ``keyword``, if given)."""
    for node in sorted(
        (n for n in ast.walk(fn) if isinstance(n, ast.Assign)), key=lambda n: n.lineno
    ):
        if not any(isinstance(t, ast.Name) and t.id == target for t in node.targets):
            continue
        if keyword is None or (
            isinstance(node.value, ast.Call) and _keyword(node.value, keyword) is not None
        ):
            return node.lineno
    raise AssertionError(f"no assignment to {target} in {getattr(fn, 'name', fn)}")


#: The three regions the marker covers: the method, where the region starts, and the names the
#: marker travels under there.
_REGIONS = [
    ("_authenticate_oidc", ("floor_marker",), {"floor_marker"}),
    ("_complete_ad_login", None, {"outcome_extra"}),
    ("complete_oidc_step_up", ("refuse", "floor"), {"floor_fields"}),
]


@pytest.mark.parametrize(("method", "start", "markers"), _REGIONS, ids=[r[0] for r in _REGIONS])
def test_every_outcome_writer_after_the_exemption_passes_the_marker(
    service_methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    method: str,
    start: tuple[str, ...] | None,
    markers: set[str],
) -> None:
    fn = service_methods[method]
    after = _region_start(fn, *start) if start else 0
    problems, checked = _unmarked(service_methods, fn, after=after, markers=markers, seen=set())
    assert problems == [], problems
    # The positive control: the walk found the region's writers, so an empty list is not the
    # vacuous answer of a region that matched nothing.
    assert checked >= 5, (method, checked)


def test_the_guard_fires_on_an_arm_that_drops_the_marker() -> None:
    """The negative control, on synthetic code shaped like the real legs: a new refusal written
    without the marker, a refuse that replaces the bound fields, an action the guard cannot read,
    and a helper that writes an outcome row the marker cannot reach. Each is reported, and the
    marked writer and the side-effect row are not."""
    source = textwrap.dedent(
        """
        class AuthService:
            async def leg(self, client, action):
                floor_marker = {}
                await self._directory_reject_audit("u", "oidc", "x", client=client, extra=floor_marker)
                await self._audit("auth.ad_roles_resynced", detail=_json({}))
                await self._directory_reject_audit("u", "oidc", "new_arm", client=client)
                await self._audit("auth.login_failed", detail=_json({"reason": "y"}))
                await self._audit(action, detail=_json({}))
                await refuse("z", floor={})
                await self._helper()

            async def _helper(self):
                await self._audit("auth.login_failed", detail=_json({"reason": "w"}))
        """
    )
    [cls] = ast.parse(source).body
    assert isinstance(cls, ast.ClassDef)
    methods = _methods_of(cls)
    fn = methods["leg"]
    problems, _checked = _unmarked(
        methods, fn, after=_region_start(fn, "floor_marker"), markers={"floor_marker"}, seen=set()
    )
    assert len(problems) == 5, problems
    assert sum("without the marker" in p for p in problems) == 3, problems
    assert any("cannot read" in p for p in problems), problems
    assert any("floor=" in p for p in problems), problems


# --- BACKLOG #3221: a verified token clears the IdP flag, and the step-up's generic text ----------

#: The step-up leg's generic refusal line, which `too_early` and `token_refused` both read as, so a
#: caller cannot tell from the text whether the callback floor fired.
GENERIC_STEP_UP_TEXT = "The identity provider could not confirm it's you."


async def test_a_too_early_sign_in_after_a_verified_exchange_clears_the_idp_flag(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The IdP answered with a verified token, so it is reachable, whatever the floor then says."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored(store, rsa_key, monkeypatch)
        service.mark_oidc_unavailable("TimeoutError")
        assert service.oidc_available is False
        early = await _sign_in_too_early(service, clock, ("pwd", "mfa"))
        assert not early.ok and early.reason == TOO_EARLY
        assert service.oidc_available is True
    finally:
        await store.close()


async def test_a_too_early_step_up_after_a_verified_exchange_clears_the_idp_flag(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The opted-in site redeems the code before the floor refuses, so the IdP has answered."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock, token = await _signed_in(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        flow_id, _url = await _begin(service, token)
        clock[0] += FLOOR - 0.001
        service.mark_oidc_unavailable("TimeoutError")
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, amr=["pwd", "mfa"])
        assert not out.elevation.ok and out.reason == TOO_EARLY
        assert out.error == GENERIC_STEP_UP_TEXT
        assert service.oidc_available is True
    finally:
        await store.close()


async def test_a_too_early_step_up_refused_before_the_exchange_leaves_the_idp_flag(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with the list empty the floor refuses before the code is redeemed, so no
    answer arrived and the flag stays as it was. The text is the generic line."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock, token = await _signed_in(store, rsa_key, monkeypatch)
        flow_id, _url = await _begin(service, token)
        flow = _staged(service, flow_id)
        clock[0] += FLOOR - 0.001
        service.mark_oidc_unavailable("TimeoutError")
        out = await service.complete_oidc_step_up(
            flow_id=flow_id,
            state=flow.state,
            code=AUTH_CODE,
            client="10.0.0.9",
            public_origin=ORIGIN,
        )
        assert out.reason == TOO_EARLY and out.error == GENERIC_STEP_UP_TEXT
        assert service.oidc_available is False
    finally:
        await store.close()

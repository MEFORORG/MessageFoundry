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

import json
import time
import urllib.parse
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import oidc
from messagefoundry.auth import service as service_module
from messagefoundry.auth.audit_visibility import (
    DIRECTORY_LOCKED_REFUSAL_DETAIL,
    HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE,
)
from messagefoundry.auth.service import (
    DIRECTORY_ROLE_MAP_UNSEALED,
    DIRECTORY_ROLES_DEMOTED,
    TOO_EARLY,
    AuthService,
)
from messagefoundry.config.settings import AuthSettings, _auth_limit_loosenings
from messagefoundry.store.store import MessageStore
from tests.test_auth_oidc_service import (
    AUTH_CODE,
    DEFAULT_SUB,
    _audit_rows,
    _oidc_login,
    _service,
    _settings,
)
from tests.test_oidc_step_up import _begin, _return_from_idp, _staged

ORIGIN = "https://ops.example"
FLOOR = AuthSettings().oidc_callback_min_elapsed_seconds
EXEMPT = "wia"  # a synthetic amr value standing for integrated Windows sign-in


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


def _evidence(row: Any) -> dict[str, Any]:
    detail: dict[str, Any] = json.loads(str(row["detail"]))
    return dict(detail.get("evidence") or {})


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
        assert _evidence(row)["callback_floor_exempt_amr"] == [EXEMPT]
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
        assert "callback_floor_exempt_amr" not in _evidence(rows[0])
    finally:
        await store.close()


# BACKLOG #3220: a refusal after the exemption applied carries the marker too, so the review the
# loosening entry asks for also sees exempted attempts that failed. Each refusal is driven twice:
# inside the floor with an exempt amr (marked), and past the floor with the same amr (the control:
# the floor never applied, so there is nothing to mark).
async def _refuse_sign_in(service: AuthService, store: MessageStore, refusal: str) -> None:
    if refusal == "disabled":  # refused in _complete_ad_login, through _refuse_directory_row
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        await store.set_user_disabled(user.id, disabled=True)
    elif refusal == "not_in_directory":  # refused in _authenticate_oidc itself
        service._ldap._principal = None  # type: ignore[union-attr]


async def _refusal_detail(store: MessageStore, action: str, reason: str) -> dict[str, Any]:
    """The one ``action`` row refused with ``reason``."""
    details = [json.loads(str(r["detail"])) for r in await _audit_rows(store, action)]
    [detail] = [d for d in details if d.get("reason") == reason]
    return detail


@pytest.mark.parametrize("refusal", ["disabled", "not_in_directory", "federated_subject_not_bound"])
@pytest.mark.parametrize(("elapsed", "marked"), [(FLOOR - 0.001, True), (FLOOR + 0.001, False)])
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
        detail = await _refusal_detail(store, "auth.login_failed", refusal)
        if marked:
            # Configured values only: the token's other amr values never reach the row.
            assert detail["callback_floor_exempt_amr"] == [EXEMPT]
        else:
            assert "callback_floor_exempt_amr" not in detail
    finally:
        await store.close()


async def test_a_refused_exempted_sign_in_against_a_locked_account_keeps_the_hidden_lock_text(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The lock refusal is hidden from readers without users:manage by its exact text, so it takes
    no marker: a marker would make the row visible and show them the lock (owner ruling
    2026-09-28). Checked against the exclusion's row set, not through a store read."""
    store = await MessageStore.open(":memory:")
    try:
        service, clock = await _floored(
            store, rsa_key, monkeypatch, oidc_callback_floor_exempt_amr=[EXEMPT]
        )
        user = await store.get_user_by_username("jdoe")
        assert user is not None
        await store.record_login_failure(user.id, failed_attempts=5, locked_until=time.time() + 600)
        out = await _sign_in_too_early(service, clock, ("mfa", EXEMPT))
        assert not out.ok and out.reason == "locked", out
        [row] = [
            r
            for r in await _audit_rows(store, "auth.login_failed")
            if json.loads(str(r["detail"])).get("reason") == "locked"
        ]
        assert row["detail"] == DIRECTORY_LOCKED_REFUSAL_DETAIL
        assert (
            "auth.login_failed",
            row["detail"],
        ) in HIDDEN_FROM_READERS_WITHOUT_USERS_MANAGE.rows
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
        rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
        assert rows[-1]["ok"] is True
        assert rows[-1]["callback_floor_exempt_amr"] == [EXEMPT]
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
        rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
        assert rows[-1]["reason"] == TOO_EARLY
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
        rows = [json.loads(str(r["detail"])) for r in await _audit_rows(store, "auth.reauth")]
        assert rows[-1]["ok"] is True
        assert "callback_floor_exempt_amr" not in rows[-1]
    finally:
        await store.close()


@pytest.mark.parametrize(
    "refusal",
    [
        "not_in_directory",
        "step_up_subject_mismatch",
        DIRECTORY_ROLES_DEMOTED,
        DIRECTORY_ROLE_MAP_UNSEALED,
    ],
)
@pytest.mark.parametrize(("elapsed", "marked"), [(FLOOR - 0.001, True), (FLOOR + 0.001, False)])
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
        else:
            claims["sub"] = "S-1-5-21-someone-else"
        flow_id, _url = await _begin(service, token)
        clock[0] += elapsed
        out = await _return_from_idp(service, monkeypatch, rsa_key, flow_id, **claims)
        assert not out.elevation.ok and out.reason == refusal, out
        detail = await _refusal_detail(store, "auth.reauth", refusal)
        if marked:
            assert detail["callback_floor_exempt_amr"] == [EXEMPT]
        else:
            assert "callback_floor_exempt_amr" not in detail
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

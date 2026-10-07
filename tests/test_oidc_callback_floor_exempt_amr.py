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
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from messagefoundry.auth import oidc
from messagefoundry.auth.service import TOO_EARLY, AuthService
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


async def _sign_in_too_early(service: AuthService, clock: list[float], amr: tuple[str, ...]) -> Any:
    """A sign-in whose person signed in at the IdP during the flow, returning inside the floor."""
    flow_id, url = await service.begin_oidc_login(client="127.0.0.1", public_origin=ORIGIN)
    state = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))["state"]
    issued_at = _staged(service, flow_id).issued_at
    service._exchange_and_validate = lambda *_a, **_k: _verified(amr, issued_at + 0.5)  # type: ignore[method-assign]
    clock[0] += FLOOR - 0.001
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


def test_a_blank_configured_value_matches_no_blank_amr() -> None:
    """Load drops a blank, and the helper ignores one from any other constructor."""
    service = AuthService.__new__(AuthService)
    service._settings = AuthSettings.model_construct(oidc_callback_floor_exempt_amr=["", " "])
    assert service._oidc_callback_floor_exemption(("", " ")) == ()
    service._settings = AuthSettings.model_construct(oidc_callback_floor_exempt_amr=[EXEMPT])
    assert service._oidc_callback_floor_exemption(("pwd", EXEMPT)) == (EXEMPT,)  # the control


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

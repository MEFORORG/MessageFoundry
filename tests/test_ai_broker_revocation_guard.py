# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The AI broker's endpoint hop runs a revocation guard with an ``[ai]`` attestation pair
(BACKLOG #2193 slice (e), owner ruling 2026-10-27, on the ADR 0173 section 12 pattern).

Every call sends ``[ai].api_key`` over https that verifies the endpoint's certificate, and stdlib
ssl checks no CRL and no OCSP. So an off-box endpoint is refused under an enforcing or unknown
posture unless ``[ai].endpoint_revocation_attested`` is set with its reason. No CRL lever is built
for this hop. All endpoints and keys here are synthetic.
"""

from __future__ import annotations

import json
import logging
import ssl
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config import tls_policy
from messagefoundry.config.ai_policy import AiMode
from messagefoundry.config.settings import (
    AiSettings,
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    BackupSettings,
    CertMonitorSettings,
    EgressSettings,
    SecretRotationSettings,
    SecretsSettings,
    SecurityEnforcement,
    SecuritySettings,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.config.tls_policy import TLS_REVOCATION_ATTESTED_ENV, HopPosture
from messagefoundry.pipeline import Engine
from messagefoundry.transports import ai_broker as ai_broker_mod
from messagefoundry.transports.ai_broker import AiBroker, AiBrokerError, ai_broker_from_settings
from messagefoundry.transports.rest import _NO_REDIRECT_OPENER, opener_tls_context

_ENDPOINT = "https://ai.internal/v1/messages"
_KEY = "synthetic-ai-key-value"
_REASON = "synthetic: the endpoint certificate lives 24 hours"
_PAIR = "[ai].endpoint_revocation_attested"
_ENFORCING = HopPosture(enforcing=True)
_WARN = HopPosture(enforcing=False)
_LOGGER = "messagefoundry.transports.ai_broker"


@pytest.fixture(autouse=True)
def _fresh_crossings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Each test starts with no crossing logged and no process-wide attestation set."""
    # raising=False only so this file fails on its assertions, not in setup, where the set is
    # absent; the once-per-process tests below go red if it is renamed.
    monkeypatch.setattr(ai_broker_mod, "_LOGGED_CROSSINGS", set(), raising=False)
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    yield


def _broker(
    *,
    endpoint: str = _ENDPOINT,
    allowed: tuple[str, ...] = ("ai.internal",),
    posture: HopPosture | None,
    attested: bool = False,
    reason: str | None = None,
) -> AiBroker:
    return AiBroker(
        endpoint=endpoint,
        api_key=_KEY,
        allowed_endpoints=list(allowed),
        posture=posture,
        revocation_attested=attested,
        revocation_attested_reason=reason,
    )


def _managed_ai(**over: object) -> AiSettings:
    kw: dict[str, object] = {
        "mode": AiMode.MANAGED_ENDPOINT,
        "environment": "prod",
        "endpoint": _ENDPOINT,
        "api_key": _KEY,
        "allowed_endpoints": ["ai.internal"],
    }
    kw.update(over)
    return AiSettings(**kw)  # type: ignore[arg-type]


def _crossing_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if r.name == _LOGGER]


# --- the guard -----------------------------------------------------------------------------------


@pytest.mark.parametrize("posture", [_ENFORCING, None], ids=["enforcing", "unknown"])
def test_an_off_box_endpoint_with_no_attestation_is_refused(posture: HopPosture | None) -> None:
    """Mutation: delete the ``_refuse_an_unrevoked_ai_hop`` call in ``AiBroker.__init__``. Red:
    DID NOT RAISE. The unknown arm reds alone if ``None`` is read as non-enforcing."""
    with pytest.raises(AiBrokerError) as info:
        _broker(posture=posture)
    message = str(info.value)
    assert "no revocation check" in message
    assert _PAIR in message and "endpoint_revocation_attested_reason" in message
    # It offers only a lever that reaches this hop: no CRL setting, no connection's pair.
    assert "No CRL can reach this hop" in message
    assert "[tls].crl_file" not in message
    assert "tls_revocation_attested=true" not in message
    assert _KEY not in message


def test_the_attestation_crosses_an_enforcing_posture_and_logs_once(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Mutation: drop ``attested=`` from the disposition call. Red: the refusal raises."""
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    broker = _broker(posture=_ENFORCING, attested=True, reason=_REASON)
    assert broker.endpoint_host == "ai.internal"
    lines = _crossing_lines(caplog)
    assert len(lines) == 1
    assert "on operator attestation" in lines[0]
    assert _PAIR in lines[0]
    assert _REASON in lines[0]
    assert "tls_revocation_attested;" not in lines[0]  # not a connection's declaration
    # The broker is built for every request; the line is written once per process for the host.
    _broker(posture=_ENFORCING, attested=True, reason=_REASON)
    assert len(_crossing_lines(caplog)) == 1


def test_an_unknown_posture_is_crossed_by_the_attestation_too() -> None:
    broker = _broker(posture=None, attested=True, reason=_REASON)
    assert broker.endpoint_host == "ai.internal"


def test_a_warn_instance_crosses_with_one_warning_that_names_the_pair(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    _broker(posture=_WARN)
    _broker(posture=_WARN)
    lines = _crossing_lines(caplog)
    assert len(lines) == 1
    assert "insecure transport hop permitted" in lines[0]
    assert _PAIR in lines[0]
    assert _KEY not in lines[0]


def test_a_loopback_endpoint_is_on_the_box_and_logs_nothing(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    broker = _broker(
        endpoint="https://127.0.0.1:8443/v1/messages", allowed=("127.0.0.1",), posture=_ENFORCING
    )
    assert broker.endpoint_host == "127.0.0.1"
    assert _crossing_lines(caplog) == []


def test_the_process_wide_attestation_does_not_cross_an_enforcing_posture(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #299's clamp holds here: the blanket variable names no hop."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(AiBrokerError, match="no revocation check"):
        _broker(posture=_ENFORCING)
    with pytest.raises(AiBrokerError, match="no revocation check"):
        _broker(posture=None)
    # On a warn instance it crosses, silently, as the authority ranks it.
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    _broker(posture=_WARN)
    assert _crossing_lines(caplog) == []


def test_the_decision_reads_the_context_the_broker_dials_with(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``crl_checked`` is read off the shared opener's own context, never a setting. That opener
    loads no CRL today; a context that checks one would cross, so a later CRL lever can start
    there."""
    seen: list[ssl.SSLContext | None] = []

    def checks(ctx: ssl.SSLContext | None) -> bool:
        seen.append(ctx)
        return True

    monkeypatch.setattr(tls_policy, "context_checks_revocation", checks)
    broker = _broker(posture=_ENFORCING)
    expected = opener_tls_context(_NO_REDIRECT_OPENER, connector="AI endpoint")
    assert seen == [expected]
    # The context judged is the one this broker dials through.
    assert seen[0] is opener_tls_context(broker._opener, connector="AI endpoint")
    assert expected is not None
    assert not expected.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_earlier_refusals_still_win_over_the_revocation_refusal() -> None:
    """The guard runs last: an endpoint refused for another reason is never sent to attest."""
    with pytest.raises(AiBrokerError, match="cleartext http"):
        _broker(endpoint="http://ai.internal/v1/messages", posture=_ENFORCING)
    with pytest.raises(AiBrokerError, match="allowed_endpoints"):
        _broker(allowed=("other.internal",), posture=_ENFORCING)


@pytest.mark.parametrize("reason", [None, "", "   "], ids=["none", "empty", "blank"])
def test_a_broker_built_directly_cannot_attest_without_a_reason(reason: str | None) -> None:
    """The settings load refuses this pair; the constructor is a second way in, so it refuses it
    too. Mutation: delete the reason check in ``_refuse_an_unrevoked_ai_hop``. Red: DID NOT RAISE."""
    with pytest.raises(AiBrokerError, match="endpoint_revocation_attested=true requires"):
        _broker(posture=_ENFORCING, attested=True, reason=reason)


def test_a_truthy_non_bool_attestation_does_not_cross() -> None:
    with pytest.raises(AiBrokerError, match="no revocation check"):
        AiBroker(
            endpoint=_ENDPOINT,
            api_key=_KEY,
            allowed_endpoints=["ai.internal"],
            posture=_ENFORCING,
            revocation_attested="yes",  # type: ignore[arg-type]
            revocation_attested_reason=_REASON,
        )


# --- the settings pair and the factory -----------------------------------------------------------


def test_the_factory_threads_the_posture_and_the_pair() -> None:
    with pytest.raises(AiBrokerError, match="no revocation check"):
        ai_broker_from_settings(_managed_ai(), posture=_ENFORCING)
    with pytest.raises(AiBrokerError, match="no revocation check"):
        ai_broker_from_settings(_managed_ai(), posture=None)
    attested = _managed_ai(
        endpoint_revocation_attested=True, endpoint_revocation_attested_reason=_REASON
    )
    assert ai_broker_from_settings(attested, posture=_ENFORCING).endpoint_host == "ai.internal"
    assert ai_broker_from_settings(_managed_ai(), posture=_WARN).endpoint_host == "ai.internal"


@pytest.mark.parametrize(
    ("flag", "reason", "fragment"),
    [
        # Each phrase belongs to one rule only, so a rule answered with another's text reds.
        (True, None, r"endpoint_revocation_attested=true requires"),
        (True, "   ", r"endpoint_revocation_attested_reason must be non-empty"),
        (False, _REASON, r"endpoint_revocation_attested_reason is set without"),
        (True, "line one\nforged line", "must not contain control characters"),
    ],
    ids=["flag-no-reason", "blank-reason", "reason-no-flag", "control-char"],
)
def test_the_pair_is_refused_at_load_unless_it_travels_together(
    flag: bool, reason: str | None, fragment: str
) -> None:
    with pytest.raises(ValueError, match=fragment):
        AiSettings(endpoint_revocation_attested=flag, endpoint_revocation_attested_reason=reason)


def test_the_pair_loads_and_is_off_by_default() -> None:
    assert AiSettings().endpoint_revocation_attested is False
    held = AiSettings(
        endpoint_revocation_attested=True, endpoint_revocation_attested_reason=_REASON
    )
    assert held.endpoint_revocation_attested_reason == _REASON


def _loosenings(ai: AiSettings) -> dict[str, str]:
    return dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            path_form_fhir_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            backup=BackupSettings(),
            secrets=SecretsSettings(),
            ai=ai,
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
            service_env=None,
        )
    )


def test_the_attestation_is_a_named_loosening_that_carries_its_reason() -> None:
    """Mutation: delete the ``[ai]`` entry in ``security_loosenings``. Red: the name is absent."""
    switch = "ai.endpoint_revocation_attested"
    assert switch not in _loosenings(AiSettings())
    named = _loosenings(
        AiSettings(endpoint_revocation_attested=True, endpoint_revocation_attested_reason=_REASON)
    )
    assert switch in named
    assert _REASON in named[switch]
    assert "No CRL lever is built for this hop" in named[switch]


# --- the route -----------------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "ai_broker_revocation.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


def _client(app: object) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def test_the_route_answers_503_for_a_refused_hop_and_200_once_attested(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refusal is an ``AiBrokerError``, so the route maps it to 503, never a 500, and nothing is
    sent. The route hands the broker the instance posture, enforcing by default."""
    sent: list[str] = []

    def fake_chat(self: AiBroker, prompt: str) -> str:
        sent.append(prompt)
        return "synthetic reply"

    monkeypatch.setattr(ai_broker_mod.AiBroker, "chat", fake_chat)
    refused = create_app(engine, ai_settings=_managed_ai(), allow_no_auth=True)
    async with _client(refused) as c:
        r = await c.post("/ai/chat", json={"prompt": "synthetic prompt"})
    assert r.status_code == 503
    assert sent == []
    warned = create_app(
        engine,
        ai_settings=_managed_ai(),
        security_settings=SecuritySettings(enforcement=SecurityEnforcement.WARN),
        allow_no_auth=True,
    )
    async with _client(warned) as c:
        assert (await c.post("/ai/chat", json={"prompt": "warned"})).status_code == 200
    attested = create_app(
        engine,
        ai_settings=_managed_ai(
            endpoint_revocation_attested=True, endpoint_revocation_attested_reason=_REASON
        ),
        allow_no_auth=True,
    )
    async with _client(attested) as c:
        assert (await c.post("/ai/chat", json={"prompt": "attested"})).status_code == 200
    assert sent == ["warned", "attested"]


# --- the reporting surfaces ----------------------------------------------------------------------

_SWITCH = "ai.endpoint_revocation_attested"


async def test_the_posture_route_names_the_pair(engine: Engine) -> None:
    """``GET /security/posture`` reads the ``[ai]`` section ``create_app`` stashed. Mutation:
    pass ``ai=AiSettings()`` in ``_posture_loosenings``. Red: the switch is absent."""

    async def switches(ai: AiSettings) -> list[str]:
        app = create_app(engine, ai_settings=ai, allow_no_auth=True)
        async with _client(app) as c:
            resp = await c.get("/security/posture")
        assert resp.status_code == 200
        return [e["switch"] for e in resp.json()["loosenings"]]

    held = _managed_ai(
        endpoint_revocation_attested=True, endpoint_revocation_attested_reason=_REASON
    )
    assert _SWITCH in await switches(held)
    assert _SWITCH not in await switches(_managed_ai())


def test_security_show_names_the_pair_from_the_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``security show`` resolves ``[ai]`` from the whole file. Mutation: drop ``_ai = _full.ai``.
    Red: the switch is absent."""
    from messagefoundry.__main__ import main

    toml = tmp_path / "mf.toml"
    toml.write_text(
        "[ai]\nendpoint_revocation_attested = true\n"
        f'endpoint_revocation_attested_reason = "{_REASON}"\n',
        encoding="utf-8",
    )
    assert main(["security", "show", "--service-config", str(toml), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["loosenings_partial"] is False
    entries = {e["switch"]: e["risk"] for e in data["loosenings"]}
    assert _SWITCH in entries
    assert _REASON in entries[_SWITCH]

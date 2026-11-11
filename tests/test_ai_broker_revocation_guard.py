# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The AI broker's endpoint hop runs a revocation guard with an ``[ai]`` attestation pair
(BACKLOG #2193 slice (e), owner ruling 2026-10-27, on the ADR 0173 section 12 pattern).

Every call sends ``[ai].api_key`` over https that verifies the endpoint's certificate, and stdlib
ssl checks no OCSP. So an off-box endpoint is refused under an enforcing or unknown posture unless
``[tls].crl_file`` reaches the hop or ``[ai].endpoint_revocation_attested`` is set with its
reason. Since BACKLOG #5527 the broker resolves the instance ``[tls]`` policy, so
``[tls].internal_ca_file`` and ``[tls].crl_file`` reach its opener; the last section pins that.
All endpoints, keys, certificates and CRLs here are synthetic.
"""

from __future__ import annotations

import datetime
import inspect
import json
import ssl
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import NamedTuple

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.api import create_app
from messagefoundry.config import loaded_crls, tls_policy
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
    TlsSettings,
    security_loosenings,
)
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    TrustAnchorPolicy,
)
from messagefoundry.pipeline import Engine
from messagefoundry.transports import ai_broker as ai_broker_mod
from messagefoundry.transports import rest
from messagefoundry.transports.ai_broker import AiBroker, AiBrokerError, ai_broker_from_settings
from messagefoundry.transports.rest import _shared_no_redirect_opener, opener_tls_context
from tests.test_revocation_guard_remaining_hops import _guard_log

_ENDPOINT = "https://ai.internal/v1/messages"
_KEY = "synthetic-ai-key-value"
_REASON = "synthetic: the endpoint certificate lives 24 hours"
_PAIR = "[ai].endpoint_revocation_attested"
_ENFORCING = HopPosture(enforcing=True)
_WARN = HopPosture(enforcing=False)
_LOGGER = "messagefoundry.transports.ai_broker"


@pytest.fixture(autouse=True)
def _fresh_crossings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Each test starts with no crossing logged, no anchored opener held and no process-wide
    attestation set."""
    # raising=False only so this file fails on its assertions, not in setup, where the set is
    # absent; the once-per-process tests below go red if it is renamed.
    monkeypatch.setattr(ai_broker_mod, "_LOGGED_CROSSINGS", set(), raising=False)
    # raising=True: a renamed slot must fail here, or held openers would leak across tests.
    monkeypatch.setattr(ai_broker_mod, "_anchored_opener", None, raising=True)
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    yield


def _broker(
    *,
    endpoint: str = _ENDPOINT,
    allowed: tuple[str, ...] = ("ai.internal",),
    posture: HopPosture | None,
    attested: bool = False,
    reason: str | None = None,
    policy: TrustAnchorPolicy | None = None,
) -> AiBroker:
    return AiBroker(
        endpoint=endpoint,
        api_key=_KEY,
        allowed_endpoints=list(allowed),
        posture=posture,
        revocation_attested=attested,
        revocation_attested_reason=reason,
        trust_anchor_policy=policy,
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


@pytest.fixture
def ai_log() -> Iterator[list[str]]:
    """The WARNING-and-above messages the broker's own logger emits during the test.

    Not the root-level capture fixture, which depends on every logger between the emitter and the
    root staying as this test found it; a test elsewhere on the same xdist worker can change that,
    and an arm that asserts no line would then pass with its records lost. The suite's shared
    capture on the emitting logger, which says what it sets and puts back."""
    with _guard_log(_LOGGER) as log:
        yield log.messages


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
    # It offers only levers that reach this hop. With no [tls] policy handed in, no CRL can
    # reach it, so [tls].crl_file is not offered (BACKLOG #5527); nor is a connection's pair.
    assert "[tls].crl_file" not in message
    assert "tls_revocation_attested=true" not in message
    assert _KEY not in message


def test_the_attestation_crosses_an_enforcing_posture_and_logs_once(
    ai_log: list[str],
) -> None:
    """Mutation: drop ``attested=`` from the disposition call. Red: the refusal raises."""
    broker = _broker(posture=_ENFORCING, attested=True, reason=_REASON)
    assert broker.endpoint_host == "ai.internal"
    lines = ai_log
    assert len(lines) == 1
    assert "on operator attestation" in lines[0]
    assert _PAIR in lines[0]
    assert _REASON in lines[0]
    assert "tls_revocation_attested;" not in lines[0]  # not a connection's declaration
    # The broker is built for every request; the line is written once per process for the host.
    _broker(posture=_ENFORCING, attested=True, reason=_REASON)
    assert len(ai_log) == 1


def test_an_unknown_posture_is_crossed_by_the_attestation_too() -> None:
    broker = _broker(posture=None, attested=True, reason=_REASON)
    assert broker.endpoint_host == "ai.internal"


def test_a_warn_instance_crosses_with_one_warning_that_names_the_pair(
    ai_log: list[str],
) -> None:
    _broker(posture=_WARN)
    _broker(posture=_WARN)
    lines = ai_log
    assert len(lines) == 1
    assert "insecure transport hop permitted" in lines[0]
    assert _PAIR in lines[0]
    assert _KEY not in lines[0]


def test_a_loopback_endpoint_is_on_the_box_and_logs_nothing(
    ai_log: list[str],
) -> None:
    broker = _broker(
        endpoint="https://127.0.0.1:8443/v1/messages", allowed=("127.0.0.1",), posture=_ENFORCING
    )
    assert broker.endpoint_host == "127.0.0.1"
    assert ai_log == []


def test_the_process_wide_attestation_does_not_cross_an_enforcing_posture(
    monkeypatch: pytest.MonkeyPatch, ai_log: list[str]
) -> None:
    """BACKLOG #299's clamp holds here: the blanket variable names no hop."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(AiBrokerError, match="no revocation check"):
        _broker(posture=_ENFORCING)
    with pytest.raises(AiBrokerError, match="no revocation check"):
        _broker(posture=None)
    # On a warn instance it crosses, silently, as the authority ranks it.
    _broker(posture=_WARN)
    assert ai_log == []


def test_the_decision_reads_the_context_the_broker_dials_with(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``crl_checked`` is read off the context of the opener the broker dials, never a setting.
    With no ``[tls]`` policy that is the shared opener, which loads no CRL; the last section pins
    the opener a CRL reaches."""
    seen: list[ssl.SSLContext | None] = []

    def checks(ctx: ssl.SSLContext | None) -> bool:
        seen.append(ctx)
        return True

    monkeypatch.setattr(tls_policy, "context_checks_revocation", checks)
    broker = _broker(posture=_ENFORCING)
    expected = opener_tls_context(_shared_no_redirect_opener(), connector="AI endpoint")
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


def test_a_broker_built_directly_refuses_a_reason_that_could_forge_a_log_line() -> None:
    with pytest.raises(AiBrokerError, match="must not contain control characters"):
        _broker(posture=_ENFORCING, attested=True, reason="ok\nFORGED: synthetic line")


def test_an_attested_hop_whose_context_checks_a_crl_logs_no_attested_crossing(
    monkeypatch: pytest.MonkeyPatch, ai_log: list[str]
) -> None:
    """That hop crossed on a real check, so a line saying it crossed without one would be false."""
    monkeypatch.setattr(tls_policy, "context_checks_revocation", lambda ctx: True)
    _broker(posture=_ENFORCING, attested=True, reason=_REASON)
    assert ai_log == []


def test_an_attested_hop_whose_context_skips_time_validity_keeps_the_crossing_line(
    monkeypatch: pytest.MonkeyPatch, ai_log: list[str]
) -> None:
    """Such a context accepts a lapsed CRL, so its CRL does not silence the line, as at
    ``RevocationHopGuard.enforce_construction``. The engine never builds this hop's context to skip
    time validity, so the context's two answers are stood in for; the test above is the control."""
    monkeypatch.setattr(tls_policy, "context_checks_revocation", lambda ctx: True)
    monkeypatch.setattr(tls_policy, "skips_validity_period", lambda ctx: True)
    _broker(posture=_ENFORCING, attested=True, reason=_REASON)
    assert len(ai_log) == 1


def test_an_unattested_hop_whose_context_skips_time_validity_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Such a CRL is no check, so it cannot cross an enforcing hop on its own: the broker reads the
    one ``crl_checked`` field the disposition reads (vault BACKLOG #5086). Before that row the
    disposition read the bare CRL flag and this broker constructed. Stood in for as above."""
    monkeypatch.setattr(tls_policy, "context_checks_revocation", lambda ctx: True)
    monkeypatch.setattr(tls_policy, "skips_validity_period", lambda ctx: True)
    with pytest.raises(AiBrokerError, match="no revocation check"):
        _broker(posture=_ENFORCING)


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
            ech_cleartext_sidecar_hops=(),
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
    # BACKLOG #5527: a CRL reaches this hop on some paths now, so the entry says which.
    assert "only where the engine's [tls] policy reaches the hop" in named[switch]
    assert "No CRL lever is built" not in named[switch]


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


# --- the [tls] policy reaches the broker's opener (BACKLOG #5527) -------------------------------


class _Pki(NamedTuple):
    """A synthetic internal CA and a CRL it signed, each as a PEM path."""

    ca_file: str
    crl_file: str


_PKI_CN = "mefor-5527-synthetic-internal-ca"


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> _Pki:
    now = datetime.datetime.now(datetime.UTC)
    day = datetime.timedelta(days=1)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _PKI_CN)])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - day)
        .not_valid_after(now + 30 * day)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(name)
        .last_update(now - day)
        .next_update(now + 30 * day)
        .sign(key, hashes.SHA256())
    )
    folder = tmp_path_factory.mktemp("pki5527")
    ca_path = folder / "internal_ca.pem"
    crl_path = folder / "internal_crl.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    crl_path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return _Pki(ca_file=str(ca_path), crl_file=str(crl_path))


def _context(broker: AiBroker) -> ssl.SSLContext:
    ctx = opener_tls_context(broker._opener, connector="AI endpoint")
    assert ctx is not None
    return ctx


def _anchor_cns(ctx: ssl.SSLContext) -> list[str]:
    """The common name of each root the context trusts, read off the context itself."""
    names: list[str] = []
    for cert in ctx.get_ca_certs():
        for rdn in cert.get("subject", ()):
            names.extend(str(pair[1]) for pair in rdn if pair[0] == "commonName")
    return names


def test_a_tls_crl_reaches_the_broker_and_crosses_an_enforcing_posture(
    pki: _Pki, ai_log: list[str]
) -> None:
    """The row's own failing case. With ``[tls].crl_file`` set, the broker dials an opener of its
    own whose context checks that CRL, so an off-box endpoint crosses enforce with no attestation
    and logs no crossing line. Red on the parent commit: the shared opener carried no CRL, so the
    broker refused the hop."""
    broker = _broker(posture=_ENFORCING, policy=TrustAnchorPolicy(crl_file=pki.crl_file))
    assert broker._opener is not _shared_no_redirect_opener()
    assert _context(broker).verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    assert ai_log == []


def test_a_pinned_internal_ca_is_the_only_root_the_broker_trusts(pki: _Pki) -> None:
    """``pinned`` trusts the internal CA alone, so the opener is the broker's own and its context
    holds no system root. Red on the parent commit: the broker dialled the shared opener on the
    OS trust store whatever ``[tls].internal_ca_file`` named."""
    policy = TrustAnchorPolicy(internal_ca_file=pki.ca_file, mode="pinned")
    broker = _broker(posture=_WARN, policy=policy)
    assert broker._opener is not _shared_no_redirect_opener()
    ctx = _context(broker)
    assert _anchor_cns(ctx) == [_PKI_CN]
    # No CRL rode along, so the hop still checks none: an internal CA alone is not a revocation
    # lever, and the enforcing refusal still applies.
    assert not ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    with pytest.raises(AiBrokerError, match="no revocation check"):
        _broker(posture=_ENFORCING, policy=policy)


def test_an_augmenting_internal_ca_is_added_to_the_broker_roots(pki: _Pki) -> None:
    policy = TrustAnchorPolicy(internal_ca_file=pki.ca_file, mode="augment")
    broker = _broker(posture=_WARN, policy=policy)
    assert broker._opener is not _shared_no_redirect_opener()
    assert _PKI_CN in _anchor_cns(_context(broker))


def test_the_internal_ca_and_its_crl_ride_together(pki: _Pki) -> None:
    policy = TrustAnchorPolicy(internal_ca_file=pki.ca_file, mode="pinned", crl_file=pki.crl_file)
    ctx = _context(_broker(posture=_ENFORCING, policy=policy))
    assert _anchor_cns(ctx) == [_PKI_CN]
    assert ctx.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


@pytest.mark.parametrize(
    "policy",
    [
        None,
        TrustAnchorPolicy(),
        # system mode ignores the internal CA, so nothing narrows and the file is never read.
        TrustAnchorPolicy(internal_ca_file="unused-in-system-mode.pem", mode="system"),
    ],
    ids=["none", "empty", "system-mode-ca"],
)
def test_a_policy_that_narrows_nothing_keeps_the_shared_opener(
    policy: TrustAnchorPolicy | None,
) -> None:
    """The shared opener is reused, never copied or mutated: callers compare it by identity."""
    broker = _broker(posture=_WARN, policy=policy)
    assert broker._opener is _shared_no_redirect_opener()


def test_a_loopback_endpoint_takes_neither_the_internal_ca_nor_the_crl(pki: _Pki) -> None:
    """``resolve_trust_anchor`` exempts a loopback host from both, matching the guard's on-box
    arm, so an on-box gateway under a different local PKI is not broken by the org's CA or CRL."""
    policy = TrustAnchorPolicy(internal_ca_file=pki.ca_file, mode="pinned", crl_file=pki.crl_file)
    broker = _broker(
        endpoint="https://127.0.0.1:8443/v1/messages",
        allowed=("127.0.0.1",),
        posture=_ENFORCING,
        policy=policy,
    )
    assert broker._opener is _shared_no_redirect_opener()


def test_a_broker_handed_a_tls_policy_offers_the_crl_lever(ai_log: list[str]) -> None:
    """Where a ``[tls]`` policy reaches the broker, ``[tls].crl_file`` is a way across, so the
    refusal and the warn line both offer it beside the pair. The control is the first test in this
    file, which hands no policy and is offered no CRL."""
    with pytest.raises(AiBrokerError) as info:
        _broker(posture=_ENFORCING, policy=TrustAnchorPolicy())
    message = str(info.value)
    assert "Set [tls].crl_file" in message
    assert "instance-wide" in message  # the CRL reaches every other hop too
    assert _PAIR in message
    _broker(posture=_WARN, policy=TrustAnchorPolicy())
    assert len(ai_log) == 1
    assert "[tls].crl_file" in ai_log[0]
    assert _PAIR in ai_log[0]


def test_the_anchored_opener_is_held_across_requests(pki: _Pki) -> None:
    """The broker is built per request, but its anchored opener is built once for an anchor, so
    ``crl_reload`` can bring its CRL current and the expiry monitor sees one live copy. A changed
    policy builds a new one."""
    crl = TrustAnchorPolicy(crl_file=pki.crl_file)
    first = _broker(posture=_ENFORCING, policy=crl)
    second = _broker(posture=_ENFORCING, policy=crl)
    assert second._opener is first._opener
    # Held, the context is recorded as a live copy of the CRL, which is what the expiry monitor
    # judges and crl_reload brings current.
    held = _context(first)
    assert any(ctx is held for ctx, _ in loaded_crls.held_contexts())
    # ADR 0135 AC-7: the anchored opener refuses redirects as the shared one does.
    # `handlers` is set in OpenerDirector.__init__ but absent from typeshed's stub.
    handlers = vars(first._opener)["handlers"]
    assert any(isinstance(h, rest._NoRedirectHandler) for h in handlers)
    pinned = TrustAnchorPolicy(internal_ca_file=pki.ca_file, mode="pinned", crl_file=pki.crl_file)
    third = _broker(posture=_ENFORCING, policy=pinned)
    assert third._opener is not first._opener
    assert _broker(posture=_ENFORCING, policy=pinned)._opener is third._opener


def test_a_tls_file_that_cannot_be_loaded_is_the_brokers_own_error(tmp_path: Path) -> None:
    """Either file failing to load is an ``AiBrokerError``, which the route answers 503, never an
    unhandled 500."""
    missing = str(tmp_path / "gone.pem")
    with pytest.raises(AiBrokerError, match="endpoint opener refused"):
        _broker(posture=_ENFORCING, policy=TrustAnchorPolicy(crl_file=missing))
    with pytest.raises(AiBrokerError, match=r"endpoint opener refused: \[tls\]\.internal_ca_file"):
        _broker(posture=_WARN, policy=TrustAnchorPolicy(internal_ca_file=missing, mode="pinned"))


async def test_the_route_hands_the_broker_the_instance_tls_policy(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, pki: _Pki
) -> None:
    """``POST /ai/chat`` reads the ``[tls]`` section the managed app stashes, as the alerts test
    send does. With its CRL the unattested hop answers 200 under enforce; the route test above is
    the control that answers 503 without it. Red on the parent commit: 503."""
    seen: list[ssl.SSLContext] = []

    def fake_chat(self: AiBroker, prompt: str) -> str:
        seen.append(_context(self))
        return "synthetic reply"

    monkeypatch.setattr(ai_broker_mod.AiBroker, "chat", fake_chat)
    app = create_app(engine, ai_settings=_managed_ai(), allow_no_auth=True)
    app.state.tls_settings = TlsSettings(crl_file=pki.crl_file)
    async with _client(app) as c:
        r = await c.post("/ai/chat", json={"prompt": "synthetic prompt"})
    assert r.status_code == 200
    assert len(seen) == 1
    assert seen[0].verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


# --- the posture entry claims no CRL check where [tls].crl_file does not reach (#5527) ---------


@pytest.mark.parametrize(
    ("path", "names_the_path"),
    [
        ("direct-create-app", "a direct create_app (the embedded path)"),
        ("loopback", "A loopback endpoint"),
    ],
    ids=["direct-create-app", "loopback"],
)
async def test_the_posture_entry_claims_no_crl_check_where_crl_file_does_not_reach(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, pki: _Pki, path: str, names_the_path: str
) -> None:
    """With ``[tls].crl_file`` set, the ``GET /security/posture`` entry must not say a CRL is
    checked on a path where none is. Two such paths: a direct ``create_app``, which takes no
    ``[tls]`` section, so the instance's ``crl_file`` cannot reach its route; and a loopback
    endpoint on an app that holds the ``[tls]`` section, as ``serve`` stashes it, which
    ``resolve_trust_anchor`` exempts from the CRL. Each arm first proves, on the context the route
    really dials with, that no CRL is checked, then reads the entry. Red on 547561b4da: the entry
    said "no CRL unless [tls].crl_file is set", a CRL check on both paths."""
    seen: list[ssl.SSLContext] = []

    def fake_chat(self: AiBroker, prompt: str) -> str:
        seen.append(_context(self))
        return "synthetic reply"

    monkeypatch.setattr(ai_broker_mod.AiBroker, "chat", fake_chat)
    if path == "direct-create-app":
        # The fact the entry's clause rests on: create_app has no [tls] parameter, so whatever
        # crl_file the instance's [tls] names has no way into this app.
        assert "tls_settings" not in inspect.signature(create_app).parameters
        ai = _managed_ai(
            endpoint_revocation_attested=True, endpoint_revocation_attested_reason=_REASON
        )
        app = create_app(engine, ai_settings=ai, allow_no_auth=True)
        assert getattr(app.state, "tls_settings", None) is None
    else:
        ai = _managed_ai(
            endpoint="https://127.0.0.1:8443/v1/messages",
            allowed_endpoints=["127.0.0.1"],
            endpoint_revocation_attested=True,
            endpoint_revocation_attested_reason=_REASON,
        )
        app = create_app(engine, ai_settings=ai, allow_no_auth=True)
        app.state.tls_settings = TlsSettings(crl_file=pki.crl_file)
    async with _client(app) as c:
        chat = await c.post("/ai/chat", json={"prompt": "synthetic prompt"})
        posture = await c.get("/security/posture")
    assert chat.status_code == 200
    assert len(seen) == 1
    assert not seen[0].verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    assert posture.status_code == 200
    risk = {e["switch"]: e["risk"] for e in posture.json()["loosenings"]}[_SWITCH]
    assert "unless [tls].crl_file is set" not in risk
    assert "check no CRL whatever [tls].crl_file says" in risk
    assert names_the_path in risk

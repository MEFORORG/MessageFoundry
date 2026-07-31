# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Inbound HTTP intake authentication (ADR 0154 increment A) — the per-inbound peer control.

Deliberately NOT ``tests/test_http_auth.py`` (the existing *outbound* OAuth2/Digest suite) and NOT
``tests/test_inbound_http_source.py`` (which pins the shipped 202 slice).

This module starts with the offline half: every refusal here is raised by the ``Http()`` factory, so it
fires with **no store and no posture** — in ``messagefoundry check``, in dry-run, and identically
through the ``connections.toml`` desugar, which routes through the very same factory. Each case is a
configuration whose failure mode would otherwise be silent or total.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import Http, WiringError, env
from messagefoundry.pipeline.wiring_runner import _IntakeRateLimiter
from messagefoundry.transports.http_listener import HttpRequestError, HttpSource

KEY = "acme-intake-key"
NEXT_KEY = "acme-intake-key-rotated"


def test_valid_configurations_build() -> None:
    Http(port=8080)  # the default: intake_auth="none", byte-identical to every shipped config
    Http(port=8080, intake_auth="api_key", intake_api_key=env("acme_intake_key"))
    Http(port=8080, intake_auth="bearer", intake_api_key=env("acme_intake_key"))
    Http(
        port=8080,
        intake_auth="api_key",
        intake_api_key=env("acme_intake_key"),
        intake_api_key_next=env("acme_intake_key_next"),  # mid-rotation: both live
    )
    Http(
        port=8443,
        tls=True,
        tls_cert_file="/tmp/server.pem",
        tls_key_file="/tmp/server.key",
        tls_ca_file="/tmp/ca.pem",
        intake_auth="mtls_subject",
        intake_client_subjects=["CN:partner.example", "SAN:DNS:partner.example"],
    )


def test_intake_auth_offline_validation_refuses() -> None:
    """AC-7 (intake arm): every unworkable intake-auth shape is refused with no store."""
    # A key mode with no credential would refuse 100 % of traffic. An unset value is not an
    # env-resolution failure, so resolve_env_settings does not catch it — nothing else would.
    for mode in ("api_key", "bearer"):
        with pytest.raises(WiringError, match="needs intake_api_key"):
            Http(port=8080, intake_auth=mode)

    # mtls_subject without tls / without a CA: the SSLContext never REQUESTS a client certificate, so
    # getpeercert() is empty and deny-by-default 403s everything, with no start-time error.
    with pytest.raises(WiringError, match="needs tls=True and tls_ca_file"):
        Http(port=8443, intake_auth="mtls_subject", intake_client_subjects=["CN:p.example"])
    with pytest.raises(WiringError, match="needs tls=True and tls_ca_file"):
        Http(
            port=8443,
            tls=True,
            tls_cert_file="/tmp/server.pem",
            intake_auth="mtls_subject",
            intake_client_subjects=["CN:p.example"],
        )

    # A CA with no subject list is "any certificate this CA ever signed" — no subject binding at all.
    with pytest.raises(WiringError, match="needs a non-empty intake_client_subjects"):
        Http(
            port=8443,
            tls=True,
            tls_cert_file="/tmp/server.pem",
            tls_ca_file="/tmp/ca.pem",
            intake_auth="mtls_subject",
        )

    # An unqualified subject matches nothing, so it would 403 the very partner it names.
    with pytest.raises(WiringError, match="must be qualified"):
        Http(
            port=8443,
            tls=True,
            tls_cert_file="/tmp/server.pem",
            tls_ca_file="/tmp/ca.pem",
            intake_auth="mtls_subject",
            intake_client_subjects=["partner.example"],
        )

    with pytest.raises(WiringError, match="must be one of"):
        Http(port=8080, intake_auth="basic")  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="intake_auth_health"):
        Http(port=8080, intake_auth_health="skip")  # type: ignore[arg-type]


def test_intake_credential_must_be_an_env_reference() -> None:
    # Mirrors File(credential_password=...) (ADR 0132): a secret is never inline, and a fallback
    # credential is a silent credential.
    with pytest.raises(WiringError, match="must be an env\\(\\) reference"):
        Http(port=8080, intake_auth="api_key", intake_api_key="literal-key")  # type: ignore[arg-type]
    with pytest.raises(WiringError, match="must not carry a default="):
        Http(port=8080, intake_auth="api_key", intake_api_key=env("k", default="fallback"))
    with pytest.raises(WiringError, match="must not carry a cast="):
        Http(port=8080, intake_auth="api_key", intake_api_key=env("k", cast=str))
    # The rotation slot is held to the same rule — it is the same credential class.
    with pytest.raises(WiringError, match="must be an env\\(\\) reference"):
        Http(
            port=8080,
            intake_auth="api_key",
            intake_api_key=env("k"),
            intake_api_key_next="literal-next",  # type: ignore[arg-type]
        )


def test_credential_configured_without_a_mode_is_refused() -> None:
    # Not in the ADR's enumerated list, but the same defect class the gate exists for: a control that
    # is configured but never consulted reads as protection that does not exist. An operator who sets
    # a key and forgets the mode has an unauthenticated listener and a config that says otherwise.
    with pytest.raises(WiringError, match="intake_auth='none'"):
        Http(port=8080, intake_api_key=env("acme_intake_key"))
    with pytest.raises(WiringError, match="intake_auth='none'"):
        Http(port=8080, intake_client_subjects=["CN:partner.example"])


def test_settings_are_carried_onto_the_spec() -> None:
    spec = Http(
        port=8080,
        intake_auth="api_key",
        intake_api_key=env("acme_intake_key"),
        intake_api_key_header="x-acme-key",
        intake_auth_rate_limit=25,
    )
    assert spec.settings["intake_auth"] == "api_key"
    assert spec.settings["intake_api_key_header"] == "x-acme-key"
    assert spec.settings["intake_auth_rate_limit"] == 25
    assert spec.settings["intake_auth_rate_limit_global"] == 60  # default
    assert spec.settings["intake_auth_health"] == "require"  # probes are inside the gate by default
    assert spec.settings["intake_api_key_next"] is None  # rotation is opt-in


def test_intake_credentials_are_redacted_and_rotatable() -> None:
    # The secrets must reach /metadata redaction AND the ASVS 13.3.4 rotation fingerprinter. Being in
    # _SECRET_SETTING_KEYS and NOT in _NON_ROTATABLE_SECRET_SETTING_KEYS is what does both; the header
    # NAME is neither a secret nor rotatable.
    from messagefoundry.config.wiring import (
        _NON_ROTATABLE_SECRET_SETTING_KEYS,
        _SECRET_SETTING_KEYS,
    )

    assert "intake_api_key" in _SECRET_SETTING_KEYS
    assert "intake_api_key_next" in _SECRET_SETTING_KEYS
    assert "intake_api_key_header" not in _SECRET_SETTING_KEYS
    assert not {"intake_api_key", "intake_api_key_next"} & _NON_ROTATABLE_SECRET_SETTING_KEYS


# --- the enforcement half (ADR 0154 D6) ---------------------------------------------------------
#
# These drive a real listener over loopback with a trivial handler, so no store is involved. That is
# not a shortcut: every refusal below runs BEFORE the pipeline handler by construction, so "nothing
# was committed" is a property of where the code sits, not of how the test is wired.


class _Audit:
    """Captures what crossed the audit seam, so a test can assert on what was NOT written."""

    def __init__(self) -> None:
        self.rows: list[tuple[str, str | None, str | None]] = []

    async def __call__(self, action: str, client: str | None, detail: str | None) -> None:
        self.rows.append((action, client, detail))


class _CountingLimiter:
    """Records every consult and charge, so a test can prove a SUCCESS never charged the budget."""

    def __init__(self, *, allow: bool = True) -> None:
        self.allow = allow
        self.checks: list[str] = []
        self.charges: list[str] = []
        self.successes: list[str] = []

    def check(self, peer: str) -> bool:
        self.checks.append(peer)
        return self.allow

    def charge_failure(self, peer: str) -> None:
        self.charges.append(peer)

    def note_success(self, peer: str) -> None:
        self.successes.append(peer)


async def _start(**settings: Any) -> HttpSource:
    base: dict[str, Any] = {"host": "127.0.0.1", "port": 0, "intake_api_key_header": "x-api-key"}
    base.update(settings)
    source = HttpSource(Source(type=ConnectorType.HTTP, settings=base))

    async def handler(raw: bytes) -> str | None:
        return "msg-1"  # stands in for the committed ingress message_id

    await source.start(handler)
    return source


class _Resp:
    __slots__ = ("status", "headers", "body")

    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status, self.headers, self.body = status, headers, body


async def _request(
    port: int, *, method: str = "POST", body: bytes = b"{}", headers: dict[str, str] | None = None
) -> _Resp:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        head = [f"{method} /ingest HTTP/1.1", "Host: localhost"]
        if method in ("POST", "PUT", "PATCH"):
            head.append(f"Content-Length: {len(body)}")
        head.extend(f"{k}: {v}" for k, v in (headers or {}).items())
        head.extend(["", ""])
        writer.write("\r\n".join(head).encode("ascii") + body)
        await writer.drain()
        try:
            data = await asyncio.wait_for(reader.read(-1), 5.0)
        except (ConnectionResetError, OSError):
            data = b""
    finally:
        writer.close()
        try:  # noqa: SIM105
            await writer.wait_closed()
        except OSError:
            pass
    head_bytes, _, payload = data.partition(b"\r\n\r\n")
    if not head_bytes:
        # The Windows Proactor loop may reset a refused connection before its 4xx flushes; the
        # refusal is then asserted via the audit side-channel, as this suite's siblings do.
        return _Resp(0, {}, b"")
    lines = head_bytes.decode("iso-8859-1").split("\r\n")
    parsed: dict[str, str] = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if sep:
            parsed[name.strip().lower()] = value.strip()
    return _Resp(int(lines[0].split(" ", 2)[1]), parsed, payload)


async def test_missing_wrong_and_empty_credentials_are_indistinguishable_401() -> None:
    """AC-11: one status, one body — no oracle, and nothing committed."""
    audit = _Audit()
    src = await _start(intake_auth="api_key", intake_api_key=KEY)
    src.on_intake_audit = audit
    try:
        responses = [
            await _request(src.sockport),  # no credential at all
            await _request(src.sockport, headers={"x-api-key": "wrong"}),  # wrong value
            await _request(src.sockport, headers={"x-api-key": ""}),  # present but empty
        ]
    finally:
        await src.stop()

    for resp in responses:
        assert resp.status in (401, 0), resp.status
    bodies = {r.body for r in responses if r.status}
    assert len(bodies) <= 1, f"the refusals are distinguishable by body: {bodies}"
    # Deterministic regardless of the Proactor flush race: three refusals, all the same kind.
    assert [row[0] for row in audit.rows] == ["intake.auth_failed"] * 3


async def test_absent_credential_401_and_dual_key_rotation_accepts_both() -> None:
    """AC-12: the sha256(b"") hazard, and the no-outage rotation it must not break."""
    src = await _start(intake_auth="api_key", intake_api_key=KEY)  # intake_api_key_next UNSET
    try:
        # Presenting nothing must NOT match the unconfigured rotation slot.
        assert (await _request(src.sockport)).status in (401, 0)
        assert (await _request(src.sockport, headers={"x-api-key": KEY})).status == 202
    finally:
        await src.stop()

    src = await _start(intake_auth="api_key", intake_api_key=KEY, intake_api_key_next=NEXT_KEY)
    try:
        assert (await _request(src.sockport, headers={"x-api-key": KEY})).status == 202
        assert (await _request(src.sockport, headers={"x-api-key": NEXT_KEY})).status == 202
        assert (await _request(src.sockport)).status in (401, 0)  # still not the empty credential
    finally:
        await src.stop()


async def test_bearer_mode_reads_authorization_and_challenges() -> None:
    src = await _start(intake_auth="bearer", intake_api_key=KEY)
    try:
        assert (
            await _request(src.sockport, headers={"Authorization": f"Bearer {KEY}"})
        ).status == (202)
        # The scheme is case-insensitive; the credential is not.
        assert (
            await _request(src.sockport, headers={"Authorization": f"bearer {KEY}"})
        ).status == (202)
        refused = await _request(src.sockport, headers={"Authorization": "Bearer nope"})
        assert refused.status in (401, 0)
        if refused.status:
            assert refused.headers.get("www-authenticate") == "Bearer"
        # A non-Bearer scheme presents no credential at all.
        assert (await _request(src.sockport, headers={"Authorization": f"Basic {KEY}"})).status in (
            401,
            0,
        )
    finally:
        await src.stop()


async def test_successful_auth_never_consumes_rate_budget() -> None:
    """AC-13: the budget bounds guessing; it must not become a throughput cap."""
    limiter = _CountingLimiter()
    src = await _start(intake_auth="api_key", intake_api_key=KEY)
    src.intake_rate_limiter = limiter
    try:
        for _ in range(25):  # far more than the default limit of 10
            assert (await _request(src.sockport, headers={"x-api-key": KEY})).status == 202
    finally:
        await src.stop()
    assert len(limiter.checks) == 25  # consulted every time...
    assert limiter.charges == []  # ... but never charged for a success
    assert len(limiter.successes) == 25


async def test_rate_limited_peer_is_429_before_any_comparison() -> None:
    limiter = _CountingLimiter(allow=False)  # budget already spent
    audit = _Audit()
    src = await _start(intake_auth="api_key", intake_api_key=KEY)
    src.intake_rate_limiter = limiter
    src.on_intake_audit = audit
    try:
        # Even the CORRECT credential is refused once the budget is gone — the limiter is consulted
        # before any comparison, so a spent budget short-circuits regardless of what was presented.
        resp = await _request(src.sockport, headers={"x-api-key": KEY})
    finally:
        await src.stop()
    assert resp.status in (429, 0)
    if resp.status:
        assert resp.headers.get("retry-after") == "60"
    assert [row[0] for row in audit.rows] == ["intake.auth_rate_limited"]
    assert limiter.charges == []  # a rate-limit refusal is not itself a failed attempt


async def test_auth_failure_audited_without_credential_material() -> None:
    """AC-15: the peer and the mode, never the credential — not a prefix, not a length."""
    audit = _Audit()
    src = await _start(intake_auth="api_key", intake_api_key=KEY)
    src.on_intake_audit = audit
    try:
        await _request(src.sockport, headers={"x-api-key": "super-secret-guess"})
    finally:
        await src.stop()

    assert len(audit.rows) == 1
    action, client, detail = audit.rows[0]
    assert action == "intake.auth_failed"
    assert (
        client
    )  # the peer IS in scope here — the first engine-internal writer of client= (ADR 0150)
    assert detail == "mode=api_key"
    blob = json.dumps(audit.rows)
    for leak in ("super-secret-guess", "super", "guess", KEY):
        assert leak not in blob, f"credential material {leak!r} reached the audit row"
    assert "18" not in blob  # nor its length


async def test_health_probes_are_inside_the_gate_by_default() -> None:
    src = await _start(intake_auth="api_key", intake_api_key=KEY)
    try:
        assert (await _request(src.sockport, method="GET")).status in (401, 0)
    finally:
        await src.stop()

    # ... and the explicit opt-out lets a load-balancer check through.
    src = await _start(intake_auth="api_key", intake_api_key=KEY, intake_auth_health="allow")
    try:
        assert (await _request(src.sockport, method="GET")).status == 200
        assert (await _request(src.sockport)).status in (401, 0)  # POST still needs the credential
    finally:
        await src.stop()


async def test_intake_auth_none_is_byte_identical() -> None:
    src = await _start()  # the shipped default
    try:
        assert (await _request(src.sockport)).status == 202
        assert (await _request(src.sockport, method="GET")).status == 200
    finally:
        await src.stop()


class _FakeWriter:
    """Stands in for an accepted TLS socket, so the subject binding is testable without a handshake."""

    def __init__(self, peercert: object) -> None:
        self._peercert = peercert

    def get_extra_info(self, name: str) -> Any:
        if name != "ssl_object":
            return None
        cert = self._peercert

        class _Ssl:
            def getpeercert(self) -> object:
                return cert

        return _Ssl()


def _peercert(common_name: str) -> dict[str, object]:
    return {"subject": ((("commonName", common_name),),)}


def test_valid_chain_unlisted_subject_is_403() -> None:
    """AC-14: authorization, not authentication — deliberately distinct from the 401.

    Exercises the subject binding directly rather than through a real handshake: by the time
    ``_authorize_peer_cert`` runs, TLS has already verified the chain against ``tls_ca_file``, and
    what is left to test is the part the CA does **not** give you. Constructing the source without
    ``tls`` keeps this a unit test of that logic — the factory refuses that combination, which
    ``test_intake_auth_offline_validation_refuses`` covers.
    """
    src = HttpSource(
        Source(
            type=ConnectorType.HTTP,
            settings={
                "host": "127.0.0.1",
                "port": 0,
                "intake_auth": "mtls_subject",
                "intake_client_subjects": ["CN:partner.example"],
            },
        )
    )

    # A chain the CA signed, carrying an allow-listed subject: accepted.
    assert src._authorize_peer_cert(_FakeWriter(_peercert("partner.example")), "10.0.0.1") is None

    # The same CA, a subject nobody listed: 403, NOT 401. A bare tls+tls_ca_file would have accepted
    # this — it means "any certificate this CA ever signed".
    denied = src._authorize_peer_cert(_FakeWriter(_peercert("attacker.example")), "10.0.0.1")
    assert isinstance(denied, HttpRequestError)
    assert denied.status == 403
    assert denied.kind == "auth_subject_denied"

    # No certificate presented at all is an AUTHENTICATION failure instead.
    missing = src._authorize_peer_cert(_FakeWriter(None), "10.0.0.1")
    assert isinstance(missing, HttpRequestError)
    assert missing.status == 401
    assert missing.kind == "intake_auth_failed"

    # A spoofed commonName cannot collide with a pinned SAN — the namespaces are disjoint.
    src._intake_subjects = {"SAN:DNS:partner.example": "SAN:DNS:partner.example"}
    spoofed = src._authorize_peer_cert(_FakeWriter(_peercert("partner.example")), "10.0.0.1")
    assert isinstance(spoofed, HttpRequestError)
    assert spoofed.status == 403


def test_global_limit_trip_does_not_deny_authenticated_peer() -> None:
    """AC-19: one attacker must not be able to 429 a partner that is authenticating correctly."""
    limiter = _IntakeRateLimiter(per_peer=100, glob=2)

    # A partner authenticates, so it is on record as good for this window.
    assert limiter.check("partner")
    limiter.note_success("partner")

    # An attacker burns the whole GLOBAL budget from another address.
    for _ in range(5):
        limiter.charge_failure("attacker")
    assert not limiter.check("attacker")

    # The partner still gets through: the global arm is consulted only for peers with no successful
    # authentication in the window. Without this its next message would be refused 429 PRE-INGRESS
    # and therefore never counted — silent loss, which is the defect this design exists to avoid.
    assert limiter.check("partner")

    # An unknown third peer is correctly subject to the exhausted global arm.
    assert not limiter.check("stranger")


def test_per_peer_arm_still_bounds_an_authenticated_peer() -> None:
    # note_success exempts a peer from the GLOBAL arm only — its own budget still applies, so a
    # credential that leaks cannot then be used for unbounded guessing from that address.
    limiter = _IntakeRateLimiter(per_peer=2, glob=0)
    limiter.note_success("partner")
    limiter.charge_failure("partner")
    limiter.charge_failure("partner")
    assert not limiter.check("partner")

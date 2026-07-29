# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""REST destination connector (ADR 0003): delivery, error→retry/dead-letter mapping, egress, TLS.

The opener is faked so nothing hits the network — we assert the Request that would be sent and the
exception classification (transient DeliveryError vs permanent NegativeAckError).
"""

from __future__ import annotations

import email.message
import urllib.error
import urllib.request

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import Rest, WiringError
from messagefoundry.pipeline.wiring_runner import check_egress_allowed
from messagefoundry.transports import build_destination
from messagefoundry.transports import rest as rest_mod
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.rest import RestDestination

URL = "https://api.example.com/ingest"


def _dest(**over: object) -> RestDestination:
    """Build a RestDestination from Rest(...) settings (env() refs already 'resolved' = literals)."""
    settings = Rest(url=URL, **over).settings  # type: ignore[arg-type]
    d = build_destination(Destination(name="OB_REST", type=ConnectorType.REST, settings=settings))
    assert isinstance(d, RestDestination)
    return d


def _http_error(code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(URL, code, "err", email.message.Message(), None)


class _FakeResp:
    def read(self) -> bytes:
        return b""

    def __enter__(self) -> _FakeResp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _FakeOpener:
    """Stands in for the urllib opener: records the Request, returns 2xx or raises a chosen error."""

    def __init__(self, exc: Exception | None = None) -> None:
        self.exc = exc
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _FakeResp:
        self.requests.append(req)
        if self.exc is not None:
            raise self.exc
        return _FakeResp()


async def test_rest_posts_payload_and_succeeds_on_2xx() -> None:
    dest = _dest(bearer_token="tok", headers={"X-Source": "mf"})
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send('{"a": 1}')
    assert len(opener.requests) == 1
    req = opener.requests[0]
    assert req.full_url == URL
    assert req.method == "POST"
    assert req.data == b'{"a": 1}'
    # Header content checked on the built map (original case; urllib title-cases its own copy).
    assert dest._headers["Content-Type"] == "application/json"
    assert dest._headers["Authorization"] == "Bearer tok"
    assert dest._headers["X-Source"] == "mf"


async def test_rest_5xx_is_transient_delivery_error() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(_http_error(503))  # type: ignore[assignment]
    with pytest.raises(DeliveryError):
        await dest.send("x")


async def test_rest_4xx_is_permanent_negative_ack() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(_http_error(400))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("x")
    assert ei.value.permanent is True
    assert ei.value.code == "400"


@pytest.mark.parametrize("code", [408, 429])
async def test_rest_busy_4xx_retries_not_dead_letters(code: int) -> None:
    dest = _dest()
    dest._opener = _FakeOpener(_http_error(code))  # type: ignore[assignment]
    with pytest.raises(DeliveryError) as ei:
        await dest.send("x")
    assert not isinstance(
        ei.value, NegativeAckError
    )  # transient, so it retries rather than fails fast


async def test_rest_connection_error_is_transient() -> None:
    dest = _dest()
    dest._opener = _FakeOpener(urllib.error.URLError("connection refused"))  # type: ignore[assignment]
    with pytest.raises(DeliveryError):
        await dest.send("x")


def test_rest_rejects_non_http_scheme() -> None:
    with pytest.raises(ValueError):
        build_destination(
            Destination(name="OB", type=ConnectorType.REST, settings=Rest(url="ftp://x/y").settings)
        )


def test_rest_basic_auth_header() -> None:
    dest = _dest(basic_user="u", basic_password="p")
    assert dest._headers["Authorization"] == "Basic dTpw"  # base64("u:p")


def test_rest_rejects_over_length_url() -> None:
    # WP-L3-09 (ASVS 4.2.5): an over-length URL is rejected at construction with a clear config error.
    long_url = URL + "a" * 9000
    with pytest.raises(ValueError, match="over the 8192-char limit"):
        build_destination(
            Destination(name="OB", type=ConnectorType.REST, settings=Rest(url=long_url).settings)
        )


def test_rest_rejects_over_length_header_value() -> None:
    # WP-L3-09: an over-length built header value (here a runaway bearer credential) is rejected, and
    # the message names the header — never its value (it may be a secret).
    with pytest.raises(ValueError, match="outbound header 'Authorization'"):
        _dest(bearer_token="x" * 9000)


# --- ASVS 4.2.5: the SEND-TIME half of the length bound -------------------------------------------
#
# The construction gate above sees only statically configured values. Three classes are added AFTER
# it — per-message headers, the server-minted SMART bearer, and the detached-JWS headers — and were
# unbounded until the send-time gate. Each test below names the mutation that reds it.


async def test_rest_over_length_message_header_is_a_permanent_nak() -> None:
    """Mutation: delete the `enforce_send_time_length_limits` call in `_post`. Red: DID NOT RAISE —
    the send completes and ships a 9000-char header. Permanent, not transient: the same message
    overflows on every retry, so retrying is a guaranteed-futile loop that also holds the lane."""
    dest = _dest()
    dest._opener = _FakeOpener()  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send("x", metadata={"http.header.X-Case-Ref": "v" * 9000})
    assert exc.value.permanent is True
    assert exc.value.credential_fault is False
    assert "over the 8192-char limit" in str(exc.value)


async def test_the_message_header_arm_never_names_the_header() -> None:
    """PHI egress. At construction a header name is operator-static, so naming it is safe. At send
    time `outbound_headers_from_metadata` derives it from a message-metadata key suffix, and this
    string reaches `last_error`, `message_events.detail` and — on the DeliveryError arm — the webhook
    AlertSink, i.e. OFF-BOX. Only the class and the length may leave.

    Mutation: put `violation.name` back in the message-derived branch. Red: the `not in` below."""
    dest = _dest()
    dest._opener = _FakeOpener()  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send("x", metadata={"http.header.X-Patient-MRN-12345": "v" * 9000})
    text = str(exc.value)
    assert "X-Patient-MRN-12345" not in text
    assert "MRN" not in text
    assert "per-message request-header value of 9000 chars" in text


async def test_rest_send_time_gate_does_not_disturb_the_ordinary_path() -> None:
    """Byte-identity control. Mutation: drop MAX_OUTBOUND_HEADER_VALUE_LEN to 64 — the 100-char
    header below reds, proving the gate is on the ordinary path and not dead code."""
    dest = _dest(headers={"X-Idempotency-Key": "k" * 100})
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send("x", metadata={"http.header.X-Case-Ref": "ok"})
    assert len(opener.requests) == 1
    assert opener.requests[0].full_url == URL


async def test_the_first_violation_found_is_the_dynamic_one_not_content_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Positive control, and it is fiddly for a reason. `_build_headers` seeds `Content-Type:
    application/json` FIRST and `_post` does `dict(self._headers)` then `.update(dynamic)`, so with
    the limit patched below Content-Type's own length the FIRST violation found is Content-Type — a
    connection-static value, which raises the *base* DeliveryError and would make this test assert
    the wrong arm entirely. `application/json` is 16 chars, so the limit is patched to 18 and the
    dynamic value made 20. Construct FIRST, patch SECOND: patching before construction would trip the
    construction gate instead."""
    dest = _dest()
    dest._opener = _FakeOpener()  # type: ignore[assignment]
    monkeypatch.setattr(rest_mod, "MAX_OUTBOUND_HEADER_VALUE_LEN", 18)
    with pytest.raises(NegativeAckError) as exc:
        await dest.send("x", metadata={"http.header.X-Case-Ref": "v" * 20})
    assert "20 chars" in str(exc.value)
    assert "Content-Type" not in str(exc.value)


async def test_rest_over_length_minted_bearer_is_a_credential_fault_and_is_invalidated() -> None:
    """The only test that proves PLACEMENT. Mutation: move the guard from `_post` back into `send`
    (the naive fix). Red: DID NOT RAISE — `send` cannot see a bearer the provider mints inside
    `_post`.

    `credential_fault=True`, not a plain transient: the provider CACHES, so without `invalidate()`
    every retry re-sends the byte-identical over-length token forever; and with `invalidate()` but no
    `credential_fault`, every retry re-signs a client assertion and POSTs the IdP forever. The
    delivery worker's `credential_fault_policy` exists to stop exactly that re-auth storm."""

    class _Provider:
        def __init__(self) -> None:
            self.token: str | None = "T" * 9000
            self.invalidated = False

        def access_token(self) -> str:
            return self.token or ""

        def invalidate(self) -> None:
            self.invalidated = True
            self.token = None

    dest = _dest()
    provider = _Provider()
    dest._token_provider = provider  # type: ignore[assignment]
    dest._opener = _FakeOpener()  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as exc:
        await dest.send("x")
    assert exc.value.permanent is True
    assert exc.value.credential_fault is True
    assert provider.invalidated is True
    assert "T" * 20 not in str(exc.value)  # never echo the credential


def _signing_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        .private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        .decode("ascii")
    )


def _signing_dest(pem: str, key_id: str) -> RestDestination:
    """Built from FLAT ``sign_*`` settings — the `Rest()` spec has no signing arm, and
    ``signer_from_destination`` falls back to these for a directly-built Destination."""
    d = build_destination(
        Destination(
            name="OB_REST_SIGNED",
            type=ConnectorType.REST,
            settings={"url": URL, "sign_private_key": pem, "sign_key_id": key_id},
        )
    )
    assert isinstance(d, RestDestination)
    return d


def test_over_length_sign_key_id_is_refused_at_construction() -> None:
    """An absurd `sign_key_id` is the reachable cause of an over-length signature header, and it is a
    CONFIG fault — caught before the connector is ever handed a message.

    Mutation: delete the `enforce_signature_header_limits` call in `RestDestination.__init__`. Red:
    DID NOT RAISE."""
    with pytest.raises(ValueError, match="over the 8192-char limit"):
        _signing_dest(_signing_pem(), "k" * 9000)


def test_signature_header_length_is_message_independent() -> None:
    """This is what legitimises bounding the signature at CONSTRUCTION rather than per send: the JWS
    is detached, so the body contributes only its fixed-width hash.

    Mutation: make the JWS attached (sign over the body instead of its digest). Red: the set below
    grows and `assert len(...) == 1` fails."""
    signer = _signing_dest(_signing_pem(), "k1")._signer
    assert signer is not None
    lengths = {
        len(next(iter(signer.signature_headers(body).values())))
        for body in (b"", b"x" * 10, b"y" * 100_000)
    }
    assert len(lengths) == 1, f"signature header length varies with the body: {lengths}"


def test_rest_verify_tls_false_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError):
        _dest(verify_tls=False)


def test_rest_verify_tls_false_allowed_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    # #200 (ADR 0092): the global escape now only DOWNGRADES REFUSE→WARN on a NON-production instance
    # (decision 2). Under a non-prod PHI posture it warns-and-builds; on production it would refuse.
    with active_hop_posture(HopPosture(is_phi=True, enforcing=False)):
        dest = _dest(verify_tls=False)  # builds a no-verify opener; no exception
    assert dest._opener is not None


def test_rest_credentials_over_cleartext_http_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # Basic/bearer over plain http leaks the credential — refused unless the explicit escape is set.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="cleartext http"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.REST,
                settings=Rest(url="http://api.example.com/x", bearer_token="tok").settings,
            )
        )


def test_rest_credentials_over_cleartext_http_allowed_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    # #200: the escape downgrades REFUSE→WARN only on a NON-production instance (decision 2).
    with active_hop_posture(HopPosture(is_phi=True, enforcing=False)):
        dest = build_destination(
            Destination(
                name="OB",
                type=ConnectorType.REST,
                settings=Rest(url="http://api.example.com/x", bearer_token="tok").settings,
            )
        )
    assert isinstance(dest, RestDestination)  # built (warns), not refused


def test_rest_cleartext_http_without_credentials_is_allowed() -> None:
    # No Authorization header → nothing to leak → plain http is fine (e.g. a loopback sink).
    dest = build_destination(
        Destination(
            name="OB", type=ConnectorType.REST, settings=Rest(url="http://localhost/x").settings
        )
    )
    assert isinstance(dest, RestDestination)


def test_rest_cleartext_http_loopback_ip_without_credentials_is_allowed() -> None:
    # ASVS 12.2.1: on-box loopback (127.0.0.1) cleartext egress is NOT a network exposure → allowed,
    # so the default loopback posture and existing loopback sinks stay byte-identical.
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.REST,
            settings=Rest(url="http://127.0.0.1:8000/x").settings,
        )
    )
    assert isinstance(dest, RestDestination)


def test_rest_cleartext_http_nonloopback_refused_without_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # ASVS 12.2.1: even with NO Authorization header the request body is PHI, so a cleartext http
    # egress to a non-loopback host is refused unless the explicit escape is set.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError, match="cleartext http to a non-loopback host"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.REST,
                settings=Rest(url="http://api.example.com/x").settings,
            )
        )


def test_rest_cleartext_http_nonloopback_allowed_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    # #200: the escape downgrades REFUSE→WARN only on a NON-production instance (decision 2).
    with active_hop_posture(HopPosture(is_phi=True, enforcing=False)):
        dest = build_destination(
            Destination(
                name="OB",
                type=ConnectorType.REST,
                settings=Rest(url="http://api.example.com/x").settings,
            )
        )
    assert isinstance(dest, RestDestination)  # built (warns loudly), not refused


def test_rest_egress_allowlist_blocks_unlisted_host() -> None:
    dest = Destination(
        name="OB", type=ConnectorType.REST, settings=Rest(url="https://evil.example.net/x").settings
    )
    with pytest.raises(WiringError):
        check_egress_allowed(dest, EgressSettings(allowed_http=["api.example.com"]))


def test_rest_egress_allowlist_permits_listed_host() -> None:
    dest = Destination(name="OB", type=ConnectorType.REST, settings=Rest(url=URL).settings)
    check_egress_allowed(dest, EgressSettings(allowed_http=["api.example.com"]))  # no raise


def test_rest_egress_unrestricted_when_empty() -> None:
    dest = Destination(
        name="OB", type=ConnectorType.REST, settings=Rest(url="https://anywhere.example/x").settings
    )
    check_egress_allowed(dest, EgressSettings())  # empty allowlist = unrestricted


# --- per-message dynamic HTTP headers (BACKLOG #68) -------------------------------------------------


def test_rest_dynamic_headers_flag_opt_in() -> None:
    # consumes_metadata (the delivery worker's read gate) is off by default and on only when opted in.
    assert _dest().consumes_metadata is False
    assert _dest(dynamic_headers=True).consumes_metadata is True


async def test_rest_per_message_header_from_metadata_appears_on_request() -> None:
    dest = _dest()
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(
        '{"a": 1}',
        metadata={"http.header.X-Idempotency-Key": "abc123", "note": "not-a-header"},
    )
    req = opener.requests[0]
    assert req.get_header("X-idempotency-key") == "abc123"
    # A non-http.header.* metadata key is display-only — it never rides the request.
    assert not req.has_header("Note")


async def test_rest_per_message_header_overrides_static_and_keeps_others() -> None:
    dest = _dest(headers={"X-Trace": "static", "X-Keep": "kept"})
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send("x", metadata={"http.header.X-Trace": "dynamic"})
    req = opener.requests[0]
    assert req.get_header("X-trace") == "dynamic"  # per-message value wins over the static one
    assert req.get_header("X-keep") == "kept"  # an unrelated static header is untouched


async def test_rest_no_metadata_is_byte_identical() -> None:
    # Default (no metadata) sends exactly the static headers — no dynamic-header machinery on the wire.
    dest = _dest(headers={"X-Source": "mf"})
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send("x")
    req = opener.requests[0]
    assert req.get_header("X-source") == "mf"


async def test_rest_crlf_in_header_value_is_neutralized_no_injection() -> None:
    # A message-derived value carrying CR/LF must not split the request into a second header line.
    dest = _dest()
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send("x", metadata={"http.header.X-Evil": "ok\r\nX-Injected: pwned"})
    req = opener.requests[0]
    assert req.get_header("X-evil") == "okX-Injected: pwned"  # control chars stripped in place
    assert not req.has_header("X-injected")  # no smuggled second header


async def test_rest_invalid_header_name_is_dropped() -> None:
    dest = _dest()
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send(
        "x",
        metadata={"http.header.Bad Name": "v", "http.header.X-Ok": "v"},
    )
    req = opener.requests[0]
    assert req.get_header("X-ok") == "v"
    assert not req.has_header("Bad name")  # a name that isn't a valid token can't be emitted


async def test_rest_dynamic_headers_dont_clobber_authorization() -> None:
    # A message-derived value must not overwrite the security-critical Authorization header.
    dest = _dest(bearer_token="tok")
    opener = _FakeOpener()
    dest._opener = opener  # type: ignore[assignment]
    await dest.send("x", metadata={"http.header.Authorization": "Bearer attacker"})
    req = opener.requests[0]
    assert req.get_header("Authorization") == "Bearer tok"


# --- ASVS 15.3.2: HTTP redirects are refused, never followed (HTTPFHIR-28) -------------------------


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
async def test_rest_3xx_redirect_is_refused_permanent_never_followed(code: int) -> None:
    # A 3xx could divert a PHI-bearing POST to an unintended host. _NoRedirectHandler makes urllib
    # raise the redirect as an HTTPError; send() must classify it PERMANENT (dead-lettered), never
    # follow it and never retry it (a retry would keep re-offering the PHI body to the divert target).
    dest = _dest()
    dest._opener = _FakeOpener(_http_error(code))  # type: ignore[assignment]
    with pytest.raises(NegativeAckError) as ei:
        await dest.send("x")
    assert ei.value.permanent is True  # dead-lettered, not retried
    assert ei.value.code == str(code)  # classified as this exact redirect status
    # It is NOT a transient DeliveryError (which the retry loop would re-attempt).
    assert isinstance(ei.value, NegativeAckError)


def test_no_redirect_handler_refuses_redirect_and_is_wired_into_default_opener() -> None:
    from messagefoundry.transports import rest

    # The handler itself returns None (→ urllib raises the 3xx instead of following it to `newurl`,
    # here a hostile off-host target that would receive the PHI POST).
    handler = rest._NoRedirectHandler()
    result = handler.redirect_request(
        urllib.request.Request("https://api.example.com/x"),
        None,
        302,
        "Found",
        email.message.Message(),
        "https://evil.example/y",
    )
    assert result is None  # refuses to build a follow-up request → no redirect

    # And the refusal is wired into the shared verifying opener, so every REST delivery inherits it.
    assert any(isinstance(h, rest._NoRedirectHandler) for h in rest._NO_REDIRECT_OPENER.handlers)


def test_outbound_headers_from_metadata_is_pure_and_sanitizing() -> None:
    from messagefoundry.transports.rest import outbound_headers_from_metadata

    bag = {
        "http.header.X-Trace-Id": "t-1",
        "http.header.X-Bad": "line1\r\nline2\x00",
        "http.header.Illegal Name": "v",
        "plain": "ignored",
    }
    first = outbound_headers_from_metadata(bag)
    second = outbound_headers_from_metadata(bag)
    assert first == second  # deterministic — a re-run yields identical headers (pure)
    assert first == {"X-Trace-Id": "t-1", "X-Bad": "line1line2"}
    assert outbound_headers_from_metadata(None) == {}
    assert outbound_headers_from_metadata({}) == {}

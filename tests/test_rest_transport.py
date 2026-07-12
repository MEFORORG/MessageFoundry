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


def test_rest_verify_tls_false_refused_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(ValueError):
        _dest(verify_tls=False)


def test_rest_verify_tls_false_allowed_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    # #200 (ADR 0092): the global escape now only DOWNGRADES REFUSE→WARN on a NON-production instance
    # (decision 2). Under a non-prod PHI posture it warns-and-builds; on production it would refuse.
    with active_hop_posture(HopPosture(is_phi=True, production=False)):
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
    with active_hop_posture(HopPosture(is_phi=True, production=False)):
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
    with active_hop_posture(HopPosture(is_phi=True, production=False)):
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

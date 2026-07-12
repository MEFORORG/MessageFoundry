# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0015 — WS-* SOAP outbound (mutual-TLS client cert + WS-Security / WS-Addressing).

Covers: the client-cert opener + opener-selection precedence, header-stamping purity (the
non-deterministic MessageID/Timestamp/Nonce are minted in send(), never the transform), PasswordText
vs PasswordDigest, envelope assembly (string templating, escaping, no XML parser), the hardened
fragment well-formedness gate (XXE-negative), the purity-leak lint, WS-Security fault classification,
capture, and the wiring-time factory validation.
"""

from __future__ import annotations

import base64
import hashlib
import urllib.request
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import Soap, WiringError, build_outbound_connection
from messagefoundry.transports import build_destination
from messagefoundry.transports import soap as soap_mod
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.soap import (
    SoapDestination,
    _assert_well_formed_fragment,
    _classify_soap,
    _client_cert_opener,
    _reject_ws_leak,
)

URL = "https://api.example.com/svc"


def _dest(**over: object) -> SoapDestination:
    settings = Soap(url=URL, **over).settings  # type: ignore[arg-type]
    d = build_destination(Destination(name="OB_SOAP", type=ConnectorType.SOAP, settings=settings))
    assert isinstance(d, SoapDestination)
    return d


class _Resp:
    def __init__(self, status: int = 200, body: bytes = b"") -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _Opener:
    def __init__(self, resp: _Resp | None = None) -> None:
        self._resp = resp or _Resp(200, b"")
        self.requests: list[urllib.request.Request] = []

    def open(self, req: urllib.request.Request, timeout: float | None = None) -> _Resp:
        self.requests.append(req)
        return self._resp


# --- mutual-TLS opener -------------------------------------------------------


class _FakeCtx:
    def __init__(self) -> None:
        self.minimum_version: object = None
        self.cert_args: tuple[object, ...] | None = None

    def load_cert_chain(
        self, certfile: object, keyfile: object = None, password: object = None
    ) -> None:
        self.cert_args = (certfile, keyfile, password)


def test_client_cert_opener_loads_chain_and_floors_tls(monkeypatch: pytest.MonkeyPatch) -> None:
    import ssl

    fake = _FakeCtx()
    monkeypatch.setattr(soap_mod.ssl, "create_default_context", lambda: fake)
    opener = _client_cert_opener("client.pem", "key.pem", "pw")
    assert fake.cert_args == ("client.pem", "key.pem", "pw")
    assert fake.minimum_version == ssl.TLSVersion.TLSv1_2  # ADR 0002 floor
    # PHI no-redirect defense retained.
    assert any(isinstance(h, soap_mod._NoRedirectHandler) for h in opener.handlers)


def test_opener_selection_prefers_client_cert(monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = object()
    monkeypatch.setattr(soap_mod, "_client_cert_opener", lambda *a, **k: sentinel)
    dest = _dest(
        client_cert_file="client.pem", client_key_file="key.pem"
    )  # verify_tls default True
    assert dest._opener is sentinel


def test_no_client_cert_uses_shared_opener_unchanged() -> None:
    before = soap_mod._NO_REDIRECT_OPENER
    dest = _dest()
    assert dest._opener is soap_mod._NO_REDIRECT_OPENER
    assert soap_mod._NO_REDIRECT_OPENER is before  # REST's shared singleton never mutated


def test_client_cert_without_key_rejected() -> None:
    with pytest.raises(ValueError, match="client_key_file"):
        _dest(client_cert_file="client.pem")


def test_client_cert_with_verify_tls_false_rejected() -> None:
    with pytest.raises(ValueError, match="verify_tls"):
        _dest(client_cert_file="client.pem", client_key_file="key.pem", verify_tls=False)


def test_client_cert_requires_https() -> None:
    with pytest.raises(ValueError, match="https"):
        build_destination(
            Destination(
                name="OB",
                type=ConnectorType.SOAP,
                settings=Soap(
                    url="http://api.example.com/svc",
                    client_cert_file="c.pem",
                    client_key_file="k.pem",
                ).settings,
            )
        )


# --- header-stamping purity (non-determinism lives in send()) ----------------


async def _send_capture(dest: SoapDestination, payload: str) -> str:
    op = _Opener(_Resp(200, b"<ok/>"))
    dest._opener = op  # type: ignore[assignment]
    await dest.send(payload)
    return op.requests[0].data.decode()  # type: ignore[union-attr]


async def test_ws_headers_stamped_in_send(monkeypatch: pytest.MonkeyPatch) -> None:
    dest = _dest(soap_version="1.2", ws_addressing=True, ws_security=True, soap_action="urn:Submit")
    monkeypatch.setattr(dest, "_now_fn", lambda: 1_700_000_000.0)
    monkeypatch.setattr(dest, "_uuid_fn", lambda: "urn:uuid:FIXED")
    env = await _send_capture(dest, "<sub:Submit>HL7</sub:Submit>")
    assert "<wsa:MessageID>urn:uuid:FIXED</wsa:MessageID>" in env
    assert "<wsa:Action>urn:Submit</wsa:Action>" in env
    assert "<wsa:To>https://api.example.com/svc</wsa:To>" in env
    assert "<wsu:Created>" in env and "<wsu:Expires>" in env
    # The Handler's <Body> fragment is concatenated verbatim into the transport envelope.
    assert "<soap:Body><sub:Submit>HL7</sub:Submit></soap:Body>" in env


async def test_message_id_differs_per_send_body_identical() -> None:
    dest = _dest(soap_version="1.2", ws_addressing=True)
    op = _Opener(_Resp(200, b""))
    dest._opener = op  # type: ignore[assignment]
    await dest.send("<b/>")
    await dest.send("<b/>")
    e1, e2 = op.requests[0].data.decode(), op.requests[1].data.decode()  # type: ignore[union-attr]

    def mid(env: str) -> str:
        return env.split("<wsa:MessageID>")[1].split("</wsa:MessageID>")[0]

    assert mid(e1) != mid(e2)  # non-determinism is in the transport, per call
    assert "<soap:Body><b/></soap:Body>" in e1 and "<soap:Body><b/></soap:Body>" in e2


async def test_password_text_default(monkeypatch: pytest.MonkeyPatch) -> None:
    dest = _dest(soap_version="1.2", ws_security=True, ws_username="u", ws_password="p")
    monkeypatch.setattr(dest, "_now_fn", lambda: 1_700_000_000.0)
    env = await _send_capture(dest, "<op/>")
    assert "#PasswordText" in env and ">p<" in env
    assert "wsse:Nonce" not in env  # PasswordText carries no Nonce/Created in the token


async def test_password_digest_computed_in_send(monkeypatch: pytest.MonkeyPatch) -> None:
    dest = _dest(
        soap_version="1.2",
        ws_security=True,
        ws_username="u",
        ws_password="secret",
        ws_password_type="digest",
    )
    monkeypatch.setattr(dest, "_now_fn", lambda: 1_700_000_000.0)
    monkeypatch.setattr(dest, "_nonce_fn", lambda: b"\x01" * 16)
    env = await _send_capture(dest, "<op/>")
    created = soap_mod._iso(1_700_000_000.0)
    expected = base64.b64encode(
        hashlib.sha1(b"\x01" * 16 + created.encode() + b"secret").digest()  # noqa: S324
    ).decode("ascii")
    assert "#PasswordDigest" in env
    assert expected in env
    assert base64.b64encode(b"\x01" * 16).decode("ascii") in env  # the Nonce


async def test_stamped_values_are_xml_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    dest = _dest(soap_version="1.2", ws_addressing=True, soap_action="urn:a&b")
    monkeypatch.setattr(dest, "_uuid_fn", lambda: "urn:uuid:x")
    env = await _send_capture(dest, "<op/>")
    assert "<wsa:Action>urn:a&amp;b</wsa:Action>" in env


def test_plain_mode_is_byte_identical() -> None:
    # No ws_addressing/ws_security → the Handler's full envelope is posted unchanged (status quo).
    dest = _dest()
    assert dest._ws_mode is False


# --- envelope assembly / no XML parser on assembly+response ------------------


def test_no_dom_xml_parser_imported() -> None:
    # ADR 0015 §2a: assembly is string templating, response classification is regex; the ONE allowed
    # parse is the hardened xml.sax well-formedness gate. No DOM/tree parser (XXE surface) is imported.
    src = Path(soap_mod.__file__).read_text(encoding="utf-8")
    for banned in ("xml.etree", "lxml", "defusedxml", "minidom", "ElementTree"):
        assert banned not in src, f"unexpected XML parser import: {banned}"


# --- fragment well-formedness gate (XXE-negative) ----------------------------


@pytest.mark.parametrize(
    "fragment",
    [
        "<a>unbalanced",
        "</soap:Body><soap:Header>",  # a smuggled close + reopen
        "<a>tom & jerry</a>",  # unescaped &
        "<!DOCTYPE x><a/>",  # a stray DOCTYPE
    ],
)
def test_malformed_fragment_rejected(fragment: str) -> None:
    with pytest.raises(ValueError):
        _assert_well_formed_fragment(fragment)


def test_doctype_with_external_entity_rejected_before_parse(tmp_path: Path) -> None:
    # XXE-negative: a DOCTYPE referencing an external entity is rejected by the string guard BEFORE the
    # parser runs, so no file is ever read (and external entity resolution is off regardless).
    secret = tmp_path / "secret.txt"
    secret.write_text("TOPSECRET", encoding="utf-8")
    fragment = f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{secret}">]><a>&xxe;</a>'
    with pytest.raises(ValueError, match="DOCTYPE"):
        _assert_well_formed_fragment(fragment)


def test_well_formed_fragment_accepted() -> None:
    _assert_well_formed_fragment("<sub:Submit>HL7</sub:Submit>")  # no raise


# --- purity-leak lint (best-effort) ------------------------------------------


def test_leak_lint_rejects_ws_namespace_by_uri() -> None:
    frag = '<o:Security xmlns:o="http://docs.oasis-open.org/wss/2004/01/'
    frag += 'oasis-200401-wss-wssecurity-secext-1.0.xsd"/>'
    with pytest.raises(ValueError, match="WS-"):
        _reject_ws_leak(frag)


def test_leak_lint_rejects_header_element() -> None:
    with pytest.raises(ValueError, match="Header"):
        _reject_ws_leak("<soap:Header/>")


def test_leak_lint_allows_plain_body_fragment() -> None:
    _reject_ws_leak("<sub:Submit><MSH>...</MSH></sub:Submit>")  # no raise


# --- WS-Security fault classification ----------------------------------------


@pytest.mark.parametrize(
    "code",
    ["wsse:FailedAuthentication", "wsse:InvalidSecurityToken", "wsse:MessageExpired"],
)
def test_wssecurity_fault_is_permanent(code: str) -> None:
    body = f"<soap:Fault><faultcode>{code}</faultcode></soap:Fault>"
    failure = _classify_soap(500, body)
    assert isinstance(failure, NegativeAckError)
    assert failure.permanent is True
    assert failure.code == "wssecurity"


# --- capture (ADR 0013, reused) ----------------------------------------------


async def test_ws_capture_accepted_and_no_reply() -> None:
    dest = _dest(soap_version="1.2", ws_addressing=True, capture_response=True)
    op = _Opener(_Resp(200, b"<resp/>"))
    dest._opener = op  # type: ignore[assignment]
    r = await dest.send("<op/>")
    assert r is not None and r.outcome == "accepted"

    dest2 = _dest(soap_version="1.2", ws_addressing=True, capture_response=True)
    dest2._opener = _Opener(_Resp(200, b""))  # type: ignore[assignment]
    r2 = await dest2.send("<op/>")
    assert r2 is not None and r2.outcome == "no_reply"


# --- wiring-time factory validation (check / dry-run, no store) ---------------


def test_factory_ws_requires_soap_12() -> None:
    for kw in ({"ws_security": True}, {"ws_addressing": True}):
        with pytest.raises(WiringError, match="1.2"):
            build_outbound_connection("OB", Soap(url=URL, **kw))  # type: ignore[arg-type]


def test_factory_client_cert_pairing() -> None:
    with pytest.raises(WiringError, match="together"):
        build_outbound_connection("OB", Soap(url=URL, client_cert_file="c.pem"))


def test_factory_client_cert_verify_tls_false() -> None:
    with pytest.raises(WiringError, match="verify_tls"):
        build_outbound_connection(
            "OB", Soap(url=URL, client_cert_file="c.pem", client_key_file="k.pem", verify_tls=False)
        )


def test_factory_bad_password_type() -> None:
    with pytest.raises(WiringError, match="ws_password_type"):
        build_outbound_connection("OB", Soap(url=URL, soap_version="1.2", ws_password_type="md5"))

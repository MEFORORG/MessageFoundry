# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Refusals that withhold content keep it off the exception chain too (BACKLOG #1796).

``tests/test_from_none_is_not_redaction.py`` held three sites as UNSAFE. Each raised its refusal
inside the handler, so the caught error stayed on ``__context__`` (``from None``) or ``__cause__``
(``from exc``), and anything that walks the chain would have read what the message withheld. Each
would have leaked on first deployment:

* the operator resend's 4xx (``api/app.py`` ``_guard_resubmission``) over an ``IngressGuardError``
  whose own cause, from ``pipeline/ingress_guards.py``, was a Unicode error holding the WHOLE body;
* ``transports/database.py`` ``_lookup_max_rows``, where ``int()``'s ``ValueError`` quotes the
  env()-resolved value the message says it withholds;
* ``transports/rest.py`` ``refuse_url_credentials``, where ``urlsplit().port``'s ``ValueError``
  quotes the port field, which is the password in ``https://svc:PW/path``.

Every refusal test here fails against the pre-fix code; the controls pass on both (measured
2026-09-26: 9 failed, 5 passed with the four engine files at their parent-commit state). Each refusal
test asserts the planted value is reachable from
NEITHER the message NOR anything on ``__cause__``/``__context__``, walking both links at every step.
The walker is controlled first, and each refusal has a control beside it that still admits.
Synthetic values only.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import struct
import tarfile
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException
from pydantic import ValidationError
from starlette.requests import Request

import messagefoundry.parsing._builtin_hl7 as _builtin_hl7
from messagefoundry.api import app as api_app
from messagefoundry.api.models import ChannelInfo
from messagefoundry.apiclient.client import ApiError, _decode
from messagefoundry.auth.oidc.jwks import JwksError, parse_jwks
from messagefoundry.auth.webauthn import WebAuthnVerificationError, credential_id_from_response
from messagefoundry.cli_common import _load_operator_json, _OperatorJsonError
from messagefoundry.config.code_sets import CodeSetError, load_code_set
from messagefoundry.config.connections_file import load_connections_file
from messagefoundry.config.models import ContentType
from messagefoundry.config.settings import EgressSettings, StoreSettings
from messagefoundry.config.wiring import InboundConnection, Registry, WiringError
from messagefoundry.corepoint_import import (
    CorepointImportError,
    _assert_encodable,
    import_corepoint,
    parse_export,
)
from messagefoundry.lens import LensParseError, parse_module, rewrite_module
from messagefoundry.parsing.message import RawMessage
from messagefoundry.parsing.peek import HL7PeekError, Peek
from messagefoundry.pipeline import ingress_guards
from messagefoundry.pipeline._sandbox_codec import SandboxCodecError, decode_frame
from messagefoundry.pipeline.dr_backup import _read_manifest_from_tar
from messagefoundry.pipeline.ingress_guards import (
    IngressGuardError,
    admit_resubmitted_body,
    decode_ingress,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.backup_codec import MAGIC, BackupCodecError, read_header
from messagefoundry.store.crypto import CipherError, StoreKeylessError, decrypt_json_cell
from messagefoundry.store.crypto_transit import build_transit_cipher
from messagefoundry.transports.ai_broker import AiBrokerError, ai_broker_from_settings
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.database import _bind_params, _lookup_max_rows
from messagefoundry.transports.http_auth import HttpAuthError
from messagefoundry.transports.http_listener import HttpRequestError, _read_exactly, _read_head
from messagefoundry.transports.rest import refuse_url_credentials
from messagefoundry.transports.signing import (
    SigningError,
    b64u_encode,
    unverified_jws_header,
    verify_compact_jws,
)
from tests.test_ai_broker import _managed_ai
from tests.test_builtin_hl7_hardening import _hl7_registry
from tests.test_crypto_transit import _FakeTransit, _use_fake
from tests.test_ingress_guard_parity import _inbound
from tests.test_mllp_persistent import _dest as _mllp_dest

#: Stands in for a body, a resolved setting or a password. Letters only, so every site accepts it.
_PLANTED = "SYNTHETICPLANTED"
_ADT = "MSH|^~\\&|A|B|C|D|20260926||ADT^A01|1|P|2.5\rPID|1||" + _PLANTED


def _chain(exc: BaseException) -> list[BaseException]:
    """Every exception reachable from ``exc`` by ``__cause__`` or ``__context__``, ``exc`` first.

    Both links at every step: following ``__cause__ or __context__`` skips a context whenever a
    cause is set, which is exactly the shape a ``from exc`` inside a handler produces."""
    seen: list[BaseException] = []
    stack: list[BaseException | None] = [exc]
    while stack:
        cur = stack.pop()
        if cur is None or any(cur is s for s in seen):
            continue
        seen.append(cur)
        stack += [cur.__cause__, cur.__context__]
    return seen


def _holders(exc: BaseException) -> list[str]:
    """The type names of every exception on ``exc``'s chain whose text, args or attributes hold the
    planted value. ``.object`` is read by name, since a Unicode error keeps it off ``__dict__``."""
    hits = []
    for e in _chain(exc):
        fields = (str(e), repr(e.args), repr(getattr(e, "object", None)), repr(vars(e)))
        if any(_PLANTED in f for f in fields):
            hits.append(type(e).__name__)
    return hits


def _assert_bare(exc: BaseException) -> None:
    assert _chain(exc) == [exc], [type(e).__name__ for e in _chain(exc)]
    assert _holders(exc) == []


def test_the_walker_finds_what_from_none_leaves_behind() -> None:
    """Control: the pre-fix shape is found, so a clean reading below means clean."""
    with pytest.raises(ValueError) as caught:
        try:
            (_PLANTED + chr(0xE9)).encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("refused at position N") from None
    assert _holders(caught.value) == ["UnicodeEncodeError"]
    with pytest.raises(AssertionError):
        _assert_bare(caught.value)


# ---- pipeline/ingress_guards.py: no refusal chains the error it replaces -----------------------


def test_a_resubmission_the_charset_cannot_hold_keeps_no_body_on_the_chain() -> None:
    with pytest.raises(IngressGuardError) as caught:
        admit_resubmitted_body(_ADT + chr(0xE9), _inbound(encoding="ascii"))
    assert caught.value.phase == "decode"
    assert caught.value.reason.startswith("encode error (ascii): ")
    _assert_bare(caught.value)


def test_an_undecodable_body_keeps_no_body_on_the_chain() -> None:
    body = (_PLANTED + chr(0xE9)).encode("latin-1")
    with pytest.raises(IngressGuardError) as caught:
        decode_ingress(body, _inbound(content_type=ContentType.JSON))
    assert caught.value.phase == "decode"
    _assert_bare(caught.value)


def test_a_parse_refusal_keeps_what_the_parser_quoted_off_the_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A parser's own error can sit under ``HL7PeekError`` and quote the body it failed on."""

    class _Refusing:
        @staticmethod
        def parse(text: str, *, max_bytes: int | None) -> None:
            try:
                raise ValueError(text)
            except ValueError as exc:
                raise HL7PeekError("could not parse HL7 message") from exc

    monkeypatch.setattr(ingress_guards, "Peek", _Refusing)
    with pytest.raises(IngressGuardError) as caught:
        admit_resubmitted_body(_ADT, _inbound())
    assert caught.value.phase == "parse"
    assert caught.value.reason == "parse error: HL7PeekError: could not parse HL7 message"
    _assert_bare(caught.value)


def test_an_admitted_resubmission_is_unchanged() -> None:
    """Control: a body the guards accept still comes back in the form the listener commits."""
    assert admit_resubmitted_body(_ADT, _inbound()) == _ADT


# ---- api/app.py _guard_resubmission: the 4xx carries no chain -----------------------------------


class _AuditSink:
    def __init__(self) -> None:
        self.rows: list[tuple[str, dict[str, object]]] = []

    async def record_audit(self, action: str, **kwargs: object) -> None:
        self.rows.append((action, kwargs))


async def _guard(raw: str, inbound: InboundConnection | None, sink: _AuditSink) -> str:
    engine: Any = SimpleNamespace(store=sink)
    identity: Any = SimpleNamespace(username="operator")
    request = Request({"type": "http", "client": ("127.0.0.1", 50000), "headers": []})
    return await api_app._guard_resubmission(
        engine,
        identity,
        request,
        raw=raw,
        inbound=inbound,
        action="resend.refused",
        channel_id="in",
        detail={"id": "m1"},
    )


async def test_the_resubmission_4xx_carries_no_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """The API half alone: a guard error that DOES carry content must not ride under the 4xx."""

    async def _refuse(raw: str, inbound: InboundConnection | None) -> str:
        try:
            raise ValueError(raw)
        except ValueError as exc:
            raise IngressGuardError("parse error: withheld", phase="parse") from exc

    monkeypatch.setattr(api_app, "admit_resubmission", _refuse)
    sink = _AuditSink()
    with pytest.raises(HTTPException) as caught:
        await _guard(_ADT, None, sink)
    assert caught.value.status_code == 422
    assert caught.value.detail == "parse error: withheld"
    _assert_bare(caught.value)
    [(action, row)] = sink.rows
    assert action == "resend.refused"
    assert json.loads(str(row["detail"])) == {
        "id": "m1",
        "phase": "parse",
        "reason": "parse error: withheld",
    }


async def test_the_resubmission_4xx_end_to_end_carries_no_body() -> None:
    with pytest.raises(HTTPException) as caught:
        await _guard(_ADT + chr(0xE9), _inbound(encoding="ascii"), _AuditSink())
    assert caught.value.status_code == 422
    _assert_bare(caught.value)


async def test_an_admitted_resubmission_passes_the_api_guard() -> None:
    """Control: the hoisted raise is reached only on a refusal."""
    sink = _AuditSink()
    assert await _guard(_ADT, _inbound(), sink) == _ADT
    assert sink.rows == []


# ---- transports/database.py _lookup_max_rows ------------------------------------------------------


@pytest.mark.parametrize("value", [_PLANTED, f"1{_PLANTED}", f" 1 {_PLANTED}"])
def test_a_refused_max_rows_keeps_the_value_off_the_chain(value: str) -> None:
    with pytest.raises(ValueError) as caught:
        _lookup_max_rows(value, "LK_1796")
    assert "value withheld" in str(caught.value)
    _assert_bare(caught.value)


def test_a_numeric_max_rows_is_still_read() -> None:
    """Control: the refusal fires on the value, not on every string."""
    assert _lookup_max_rows("25", "LK_1796") == 25
    assert _lookup_max_rows(0, "LK_1796") is None


# ---- transports/rest.py refuse_url_credentials ----------------------------------------------------


def test_a_password_read_as_a_port_stays_off_the_chain() -> None:
    with pytest.raises(HttpAuthError) as caught:
        refuse_url_credentials(f"https://svc:{_PLANTED}/path", "url", error=HttpAuthError)
    assert "not a number from 0 to 65535" in str(caught.value)
    _assert_bare(caught.value)


def test_a_numeric_port_is_still_admitted() -> None:
    """Control: the refusal fires on a non-numeric port, not on every explicit one."""
    refuse_url_credentials("https://svc.example.invalid:8443/path", "url")


# ==== BACKLOG #2085: raises inside a handler that caught a body-holding error ======================
#
# tests/test_from_none_is_not_redaction.py's second gate found these by the CAUGHT type. Each test
# plants the synthetic value in the input a refusal withholds and walks both chain links. Each failed
# against the pre-#2085 code, where the refusal was raised inside the handler with ``from exc``.


def _raise_recursion(*_args: object, **_kwargs: object) -> object:
    raise RecursionError("simulated deep nesting")


@pytest.mark.parametrize(
    "body",
    [b'{"keys": [' + _PLANTED.encode(), _PLANTED.encode() + b"\xff"],
    ids=["bad-json", "bad-utf8"],
)
def test_a_refused_jwks_keeps_the_body_off_the_chain(body: bytes) -> None:
    with pytest.raises(JwksError) as caught:
        parse_jwks(body)
    assert str(caught.value) == "JWKS body is not valid JSON"
    _assert_bare(caught.value)


def test_a_jwks_nested_past_the_decoder_is_a_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    """json's depth limit raises RecursionError, which the old ValueError arm did not reach.

    Manufactured, never real nesting: see tests/test_sandbox_codec.py
    ``test_recursion_error_is_not_a_value_error`` (BACKLOG #1222)."""
    monkeypatch.setattr(json, "loads", _raise_recursion)
    with pytest.raises(JwksError):
        parse_jwks(b"[]")


def test_an_unreadable_jws_header_keeps_it_off_the_chain() -> None:
    with pytest.raises(SigningError) as caught:
        unverified_jws_header(f"{b64u_encode(b'{' + _PLANTED.encode())}.e30.c2ln")
    assert str(caught.value) == "compact JWS protected header is not valid base64url JSON"
    _assert_bare(caught.value)


def test_an_unreadable_jws_payload_keeps_the_claims_off_the_chain() -> None:
    """The payload is decoded only after the signature verifies, so the token is signed for real."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    header = b64u_encode(json.dumps({"alg": "RS256"}).encode())
    payload = b64u_encode(b'{"sub": "' + _PLANTED.encode() + b"\xff")
    signature = key.sign(f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256())
    jws = f"{header}.{payload}.{b64u_encode(signature)}"
    with pytest.raises(SigningError) as caught:
        verify_compact_jws(jws, key.public_key(), allowed_algorithms=["RS256"])
    assert str(caught.value) == "compact JWS payload is not valid base64url JSON"
    _assert_bare(caught.value)


def test_a_malformed_ceremony_response_keeps_it_off_the_chain() -> None:
    pytest.importorskip("webauthn")
    with pytest.raises(WebAuthnVerificationError) as caught:
        credential_id_from_response('{"rawId": "' + _PLANTED)
    assert str(caught.value) == "malformed ceremony response"
    _assert_bare(caught.value)


@pytest.mark.parametrize(
    ("response", "reason"),
    [
        ("{}", "malformed ceremony response"),
        ("[]", "ceremony response has no rawId"),
        ('{"rawId": ""}', "ceremony response has no rawId"),
        ('{"rawId": "\\u00e9"}', "malformed ceremony response"),  # not ASCII, so not base64url
    ],
)
def test_ceremony_refusal_texts_are_unchanged(response: str, reason: str) -> None:
    """Control: moving the raises out of the handler kept each refusal's text, and a good id reads."""
    pytest.importorskip("webauthn")
    with pytest.raises(WebAuthnVerificationError, match=f"^{reason}$"):
        credential_id_from_response(response)
    assert credential_id_from_response('{"rawId": "AAEC"}') == b"\x00\x01\x02"


def test_an_unparseable_ai_reply_keeps_it_off_the_chain() -> None:
    broker = ai_broker_from_settings(_managed_ai())
    with pytest.raises(AiBrokerError) as caught:
        broker._extract_text("{" + _PLANTED)
    assert "returned an unparseable response" in str(caught.value)
    _assert_bare(caught.value)


def test_an_unparseable_database_payload_keeps_it_off_the_chain() -> None:
    with pytest.raises(NegativeAckError) as caught:
        _bind_params('{"a": ' + _PLANTED, ["a"])
    assert str(caught.value).startswith("DATABASE payload is not valid JSON: Expecting")
    assert caught.value.permanent
    _assert_bare(caught.value)


def test_a_database_payload_nested_past_the_decoder_is_permanent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(json, "loads", _raise_recursion)
    with pytest.raises(NegativeAckError) as caught:
        _bind_params("{}", [])
    assert caught.value.permanent


def _reader(data: bytes, *, limit: int = 2**16) -> asyncio.StreamReader:
    reader = asyncio.StreamReader(limit=limit)
    reader.feed_data(data)
    reader.feed_eof()
    return reader


async def test_a_truncated_http_body_keeps_it_off_the_chain() -> None:
    with pytest.raises(HttpRequestError) as caught:
        await _read_exactly(_reader(_PLANTED.encode()), 1000)
    assert caught.value.status == 400
    _assert_bare(caught.value)


async def test_a_truncated_http_head_keeps_its_headers_off_the_chain() -> None:
    head = f"POST / HTTP/1.1\r\nAuthorization: Bearer {_PLANTED}\r\n".encode()
    with pytest.raises(HttpRequestError) as caught:
        await _read_head(_reader(head), max_header_bytes=8192)
    assert caught.value.status == 400
    _assert_bare(caught.value)


async def test_an_oversize_http_head_still_refuses_413() -> None:
    """Control for the LimitOverrunError arm, which moved out of its handler with its sibling."""
    head = b"GET / HTTP/1.1\r\nHost: a-very-long-host-name.example.invalid\r\n\r\n"
    with pytest.raises(HttpRequestError) as caught:
        await _read_head(_reader(head, limit=16), max_header_bytes=8192)
    assert caught.value.status == 413
    _assert_bare(caught.value)


class _MalformedPlaintextTransit(_FakeTransit):
    """Transit answers a decrypt with plaintext that is not UTF-8: the planted value, then 0xFF."""

    def decrypt_data(self, **_: Any) -> dict[str, Any]:
        raw = _PLANTED.encode() + b"\xff"
        return {"data": {"plaintext": base64.b64encode(raw).decode("ascii")}}


def test_malformed_transit_plaintext_stays_off_the_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    """The decode error's ``.object`` IS the decrypted plaintext, the PHI the cipher protects."""
    _use_fake(monkeypatch, _MalformedPlaintextTransit())
    cipher = build_transit_cipher(StoreSettings())
    with pytest.raises(CipherError) as caught:
        cipher.decrypt("mfenc:v3:vault:v1:AAAA", aad=None)
    assert "Transit returned malformed plaintext" in str(caught.value)
    _assert_bare(caught.value)


class _StubCipher:
    """Decrypts every cell to the planted text, which is not JSON; ``encrypted`` sets the marker test."""

    def __init__(self, *, encrypted: bool) -> None:
        self.encrypted = encrypted

    def decrypt(self, stored: str, *, aad: bytes | None) -> str:
        return "{" + _PLANTED

    def is_encrypted(self, stored: str) -> bool:
        return self.encrypted


def test_a_keyless_json_cell_keeps_the_cell_off_the_chain() -> None:
    cipher: Any = _StubCipher(encrypted=True)
    with pytest.raises(StoreKeylessError) as caught:
        decrypt_json_cell(cipher, "mfenc:v1:x", aad=None, table="state")
    assert "carries encrypted rows" in str(caught.value)
    _assert_bare(caught.value)


def test_a_malformed_plaintext_cell_still_surfaces_its_decode_error() -> None:
    """Control: the documented contract, a legacy plaintext row's JSONDecodeError, is unchanged."""
    cipher: Any = _StubCipher(encrypted=False)
    with pytest.raises(json.JSONDecodeError):
        decrypt_json_cell(cipher, "{", aad=None, table="state")


@pytest.mark.parametrize(
    "header", [b'{"alg": "' + _PLANTED.encode(), _PLANTED.encode() + b"\xff"], ids=["json", "utf8"]
)
def test_a_malformed_backup_header_keeps_it_off_the_chain(header: bytes) -> None:
    """The not-UTF-8 case escaped as a raw UnicodeDecodeError before #2085, not a refusal."""
    archive = MAGIC + bytes([1]) + struct.pack("<I", len(header)) + header
    with pytest.raises(BackupCodecError) as caught:
        read_header(io.BytesIO(archive))
    assert str(caught.value) == "malformed .mfbak header (bad JSON)"
    _assert_bare(caught.value)


def test_a_malformed_backup_manifest_keeps_it_off_the_chain(tmp_path: Path) -> None:
    manifest = b'{"files": "' + _PLANTED.encode()
    tar_path = tmp_path / "backup.tar"
    with tarfile.open(tar_path, "w:") as tar:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(manifest)
        tar.addfile(info, io.BytesIO(manifest))
    with pytest.raises(tarfile.TarError) as caught:
        _read_manifest_from_tar(tar_path)
    assert "could not be parsed: JSONDecodeError at line 1" in str(caught.value)
    _assert_bare(caught.value)


def test_a_malformed_sandbox_frame_keeps_the_body_off_the_chain() -> None:
    header = b'{"body": "' + _PLANTED.encode()
    with pytest.raises(SandboxCodecError) as caught:
        decode_frame(struct.pack(">I", len(header)) + header)
    assert str(caught.value).startswith("malformed sandbox frame: JSONDecodeError: ")
    _assert_bare(caught.value)


def test_malformed_operator_json_keeps_it_off_the_chain() -> None:
    with pytest.raises(_OperatorJsonError) as caught:
        _load_operator_json('{"password": "' + _PLANTED, "connection JSON")
    assert str(caught.value).startswith(
        "invalid connection JSON: Unterminated string starting at: line 1"
    )
    _assert_bare(caught.value)


def test_a_malformed_corepoint_export_keeps_it_off_the_chain() -> None:
    with pytest.raises(CorepointImportError) as caught:
        parse_export('{"channels": "' + _PLANTED)
    assert str(caught.value).startswith(
        "export is not valid JSON: Unterminated string starting at: line 1"
    )
    _assert_bare(caught.value)


def test_a_non_utf8_corepoint_export_keeps_it_off_the_chain(tmp_path: Path) -> None:
    export = tmp_path / "export.json"
    export.write_bytes(_PLANTED.encode() + b"\xff")
    with pytest.raises(CorepointImportError) as caught:
        import_corepoint(export, tmp_path / "out")
    assert "cannot read export" in str(caught.value)
    _assert_bare(caught.value)


def test_an_unencodable_corepoint_value_keeps_it_off_the_chain() -> None:
    with pytest.raises(CorepointImportError) as caught:
        _assert_encodable(_PLANTED + "\ud800", "[x]")
    assert "unpaired surrogate" in str(caught.value)
    _assert_bare(caught.value)


def test_a_non_utf8_lens_module_keeps_it_off_the_chain(tmp_path: Path) -> None:
    module = tmp_path / "mod.py"
    module.write_bytes(_PLANTED.encode() + b"\xff")
    with pytest.raises(LensParseError) as caught:
        parse_module(module)
    assert "cannot read" in str(caught.value)
    _assert_bare(caught.value)


def test_an_invalid_engine_reply_keeps_the_body_off_the_client_chain() -> None:
    response = httpx.Response(200, content=b'{"x": "' + _PLANTED.encode())
    with pytest.raises(ApiError) as caught:
        _decode(response, ChannelInfo)
    assert str(caught.value).startswith("invalid response from engine: ")
    _assert_bare(caught.value)


def test_a_reply_failing_its_model_keeps_the_value_out_of_the_message() -> None:
    """pydantic's own text quotes each failing ``input_value``; the ApiError names locations only."""
    reply = {"id": _PLANTED, "name": 5, "enabled": True, "running": True, "source_type": _PLANTED}
    with pytest.raises(ValidationError) as raw:  # control: pydantic's own text quotes the input
        ChannelInfo.model_validate({**reply, "destinations": _PLANTED})
    assert _PLANTED in str(raw.value)
    with pytest.raises(ApiError) as caught:
        _decode(httpx.Response(200, json={**reply, "destinations": _PLANTED}), ChannelInfo)
    assert "validation error(s) for ChannelInfo" in str(caught.value)
    assert "name: " in str(caught.value) and "destinations: " in str(caught.value)
    assert _PLANTED not in str(caught.value)
    _assert_bare(caught.value)


def test_a_non_utf8_module_is_a_lens_refusal_on_rewrite_too(tmp_path: Path) -> None:
    module = tmp_path / "mod.py"
    module.write_bytes(_PLANTED.encode() + b"\xff")
    with pytest.raises(LensParseError) as caught:
        rewrite_module(module, {})
    assert "cannot read" in str(caught.value)
    _assert_bare(caught.value)


def test_a_malformed_code_set_keeps_the_file_off_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "codes.toml"
    path.write_text(f'secret = "{_PLANTED}"\nx = = 1\n', encoding="utf-8")
    with pytest.raises(CodeSetError) as caught:
        load_code_set(path)
    assert "invalid TOML" in str(caught.value)
    _assert_bare(caught.value)


def test_a_non_utf8_toml_file_is_a_refusal_not_an_escape(tmp_path: Path) -> None:
    """tomllib decodes the bytes itself, so a non-UTF-8 file raised a raw UnicodeDecodeError."""
    path = tmp_path / "connections.toml"
    path.write_bytes(f'password = "{_PLANTED}"\n'.encode() + b"\xff")
    with pytest.raises(WiringError) as caught:
        load_connections_file(path, Registry())
    _assert_bare(caught.value)
    codes = tmp_path / "codes.toml"
    codes.write_bytes(f'secret = "{_PLANTED}"\n'.encode() + b"\xff")
    with pytest.raises(CodeSetError) as code_caught:
        load_code_set(codes)
    _assert_bare(code_caught.value)


def test_a_non_utf8_engine_reply_is_an_api_error() -> None:
    response = httpx.Response(200, content=b'{"x": "' + _PLANTED.encode() + b'\xff"}')
    with pytest.raises(ApiError) as caught:
        _decode(response, ChannelInfo)
    _assert_bare(caught.value)


def test_a_non_ascii_compact_jws_is_a_signing_error() -> None:
    """``.encode("ascii")`` raised UnicodeEncodeError, which the sign-in callback reads as an outage."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    header = b64u_encode(json.dumps({"alg": "RS256"}).encode())
    with pytest.raises(SigningError) as caught:
        verify_compact_jws(
            f"{header}.{_PLANTED}é.c2ln", key.public_key(), allowed_algorithms=["RS256"]
        )
    assert str(caught.value) == "compact JWS must be ASCII (base64url segments)"
    _assert_bare(caught.value)


class _NonStringPlaintextTransit(_FakeTransit):
    def decrypt_data(self, **_: Any) -> dict[str, Any]:
        return {"data": {"plaintext": None}}


def test_a_non_string_transit_plaintext_is_a_cipher_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _use_fake(monkeypatch, _NonStringPlaintextTransit())
    with pytest.raises(CipherError) as caught:
        build_transit_cipher(StoreSettings()).decrypt("mfenc:v3:vault:v1:AAAA", aad=None)
    _assert_bare(caught.value)


def test_a_malformed_connections_file_keeps_the_file_off_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "connections.toml"
    path.write_text(f'password = "{_PLANTED}"\nx = = 1\n', encoding="utf-8")
    with pytest.raises(WiringError) as caught:
        load_connections_file(path, Registry())
    assert str(caught.value).startswith("cannot read connections.toml: ")
    _assert_bare(caught.value)


def test_raw_message_json_error_keeps_the_body_off_itself() -> None:
    """``RawMessage.json`` let json's own error out, and its ``.doc`` IS the body."""
    body = '{"mrn": "' + _PLANTED
    with pytest.raises(json.JSONDecodeError) as original:
        json.loads(body)
    with pytest.raises(json.JSONDecodeError) as caught:
        RawMessage(body, "json").json()
    err, was = caught.value, original.value
    assert err.doc == "" and was.doc == body  # the control: json's own error holds the body
    assert (str(err), err.msg, err.pos, err.lineno, err.colno) == (
        str(was),
        was.msg,
        was.pos,
        was.lineno,
        was.colno,
    )
    _assert_bare(err)


def test_raw_message_json_still_parses() -> None:
    """Control: a well-formed body parses as before."""
    assert RawMessage('{"a": 1}', "json").json() == {"a": 1}


# ---- the HL7 parse refusal: its text reaches MSA-3 and the stored reason on every listener -------
#
# One rule (BACKLOG #2085): an HL7PeekError's text is content-free by construction, and every listener
# renders it through the same redaction for the stored reason and the AR text. Peek.parse used to
# interpolate python-hl7's error, whose text is not vetted. python-hl7 is retired; the refusal that
# replaced its fallback is a fault inside the built-in parse, whose text is not vetted either. The
# stand-in below is a SYNTHETIC fault that quotes the planted segment, the worst case for a refusal.

_SEGMENT = f"PID|1||{_PLANTED}^^^MRN||DOE^JANE"


def _parser_fault_quoting_the_body(text: str) -> object:
    raise RuntimeError(f"Segment received before message header {_SEGMENT}")


@pytest.fixture
def parser_faults(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the built-in parse fault while quoting the body."""
    monkeypatch.setattr(_builtin_hl7, "parse", _parser_fault_quoting_the_body)


def test_the_stand_in_quotes_the_body() -> None:
    """Control: the stand-in's own text does hold the planted value, so a clean reading is clean."""
    with pytest.raises(RuntimeError) as caught:
        _parser_fault_quoting_the_body(_ADT)
    assert _PLANTED in str(caught.value)


@pytest.mark.usefixtures("parser_faults")
def test_a_parser_fault_refusal_names_only_the_error_class() -> None:
    with pytest.raises(HL7PeekError) as caught:
        Peek.parse(_ADT)
    assert str(caught.value) == "could not parse HL7 message (RuntimeError)"
    _assert_bare(caught.value)


@pytest.mark.usefixtures("parser_faults")
async def test_the_mllp_ar_ack_and_reason_carry_no_body(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "engine.db")
    try:
        reg = _hl7_registry()
        ack = await RegistryRunner(
            reg, store, egress=EgressSettings(deny_by_default=False)
        )._handle_inbound(reg.inbound["IB_HL7"], _ADT.encode())
        cur = await store._db.execute("SELECT status, error FROM messages")
        rows = [dict(r) for r in await cur.fetchall()]
    finally:
        await store.close()
    assert ack is not None and "MSA|AR" in ack
    assert "MSA|AR||could not parse HL7 message (RuntimeError)" in ack  # no class prefix
    [row] = rows
    assert row["status"] == MessageStatus.ERROR.value
    assert row["error"] == "parse error: HL7PeekError: could not parse HL7 message (RuntimeError)"
    # The ACK echoes the sender's own MSH, never the PID the refusal is about.
    assert _PLANTED not in ack and _PLANTED not in row["error"]


@pytest.mark.usefixtures("parser_faults")
def test_the_resubmission_reason_carries_no_body() -> None:
    with pytest.raises(IngressGuardError) as caught:
        admit_resubmitted_body(_ADT, _inbound())
    assert caught.value.reason == (
        "parse error: HL7PeekError: could not parse HL7 message (RuntimeError)"
    )
    _assert_bare(caught.value)


def test_an_unparseable_ack_keeps_the_parse_error_off_the_chain() -> None:
    with pytest.raises(DeliveryError) as caught:
        _mllp_dest(1)._check_ack(b"not an ack " + _PLANTED.encode())
    assert str(caught.value).startswith("unparseable ACK: HL7PeekError: ")
    _assert_bare(caught.value)

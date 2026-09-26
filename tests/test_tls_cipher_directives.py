# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2106 -- an operator ``tls_ciphers`` string may not carry an OpenSSL ``@`` directive.

``@SECLEVEL=0:ECDHE-ECDSA-AES256-GCM-SHA384`` names only approved suites, so every suite check in
``validate_tls_ciphers`` passed it. Applied, it moved the context's security level from 2 to 0, and a
client then accepted a server certificate with an RSA-1024 key. The level-2 floor is what refuses that
key, so the directive undid it with every gate saying yes.

Two guards now hold, and each is tested with a control that shows the test can pass:

* ``validate_tls_ciphers`` refuses any ``@`` token, on the operator knob and the proxy declaration;
* ``refuse_lowered_security_level`` refuses a context below the stock level, after the string is
  applied, on the API listener and the four MLLP/DICOM seams.

The handshake tests at the end are the harm itself, measured on a real TLS exchange in memory.
"""

from __future__ import annotations

import datetime
import ssl
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.config import tls_policy
from messagefoundry.config.settings import ApiSettings
from messagefoundry.config.tls_policy import (
    apply_connection_tls_ciphers,
    validate_proxy_tls_posture,
    validate_tls_ciphers,
)

#: One approved suite per key type. The directive forms below are these plus a directive, so each
#: refusal has a control that differs from it by the directive alone.
ECDSA_SUITE = "ECDHE-ECDSA-AES256-GCM-SHA384"
RSA_SUITE = "ECDHE-RSA-AES256-GCM-SHA384"

#: Every form measured to parse on CPython 3.14.6 / OpenSSL 3.5.7, so the refusal is ours and not a
#: parse error. OpenSSL takes ``:``, ``,``, ``;`` and a space as separators. ``@SECLEVEL=2`` is
#: refused too: a directive is refused for being one, not for the level it names.
DIRECTIVE_FORMS = [
    f"@SECLEVEL=0:{ECDSA_SUITE}",
    f"@SECLEVEL=1:{ECDSA_SUITE}",
    f"@SECLEVEL=2:{ECDSA_SUITE}",
    f"{ECDSA_SUITE}:@SECLEVEL=0",
    f"@STRENGTH:{ECDSA_SUITE}",
    f"{ECDSA_SUITE}:@STRENGTH",
    f"{ECDSA_SUITE} @SECLEVEL=0",
    f"{ECDSA_SUITE},@SECLEVEL=0",
    f"{ECDSA_SUITE};@SECLEVEL=0",
]


def _stock_level(protocol: ssl._SSLMethod) -> int:
    return ssl.SSLContext(protocol).security_level


# --- the validator: every '@' token is refused, on both call shapes -------------------------------


def test_the_build_default_is_level_two() -> None:
    """The premise every test below leans on. If a build ships a different default, the harm
    measured here changes shape, and this says so first."""
    assert _stock_level(ssl.PROTOCOL_TLS_SERVER) == 2
    assert _stock_level(ssl.PROTOCOL_TLS_CLIENT) == 2


@pytest.mark.parametrize("value", DIRECTIVE_FORMS)
def test_every_directive_form_parses_on_this_build(value: str) -> None:
    """Control for the refusals below: OpenSSL accepts each form, so the refusal is not a parse
    error in disguise."""
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).set_ciphers(value)


@pytest.mark.parametrize("require_approved", [True, False])
@pytest.mark.parametrize("value", DIRECTIVE_FORMS)
def test_validate_tls_ciphers_refuses_every_directive(value: str, require_approved: bool) -> None:
    """Both call shapes. ``False`` is the ``[api].proxy_tls_ciphers`` declaration, where the
    allow-list does not run, so the directive check must sit outside it."""
    with pytest.raises(ValueError, match="directive") as excinfo:
        validate_tls_ciphers(value, require_approved_suites=require_approved)
    assert "@" in str(excinfo.value), "the refusal does not name the directive it found"


@pytest.mark.parametrize("require_approved", [True, False])
@pytest.mark.parametrize("suite", [ECDSA_SUITE, RSA_SUITE, f"{ECDSA_SUITE}:{RSA_SUITE}"])
def test_the_same_string_without_the_directive_is_accepted(
    suite: str, require_approved: bool
) -> None:
    """Planted control: the directive forms minus the directive pass, so the refusals above are
    about the directive and nothing else in the string."""
    assert validate_tls_ciphers(suite, require_approved_suites=require_approved) == suite


def test_the_refusal_tells_the_operator_what_to_do() -> None:
    with pytest.raises(ValueError) as excinfo:
        validate_tls_ciphers(f"@SECLEVEL=0:{ECDSA_SUITE}")
    message = str(excinfo.value)
    assert "@SECLEVEL=0" in message, "names the directive"
    assert "RSA-1024" in message, "says why it is refused"
    assert "Remove" in message, "says what to do instead"


def test_the_proxy_declaration_refuses_a_directive() -> None:
    with pytest.raises(ValueError, match=r"proxy_tls_ciphers.*directive"):
        validate_proxy_tls_posture("1.2", f"@SECLEVEL=0:{ECDSA_SUITE}")
    validate_proxy_tls_posture("1.2", ECDSA_SUITE)  # control


def test_the_api_setting_refuses_a_directive_at_load() -> None:
    with pytest.raises(ValidationError, match="directive"):
        ApiSettings(tls_ciphers=f"@SECLEVEL=0:{ECDSA_SUITE}")
    assert ApiSettings(tls_ciphers=ECDSA_SUITE).tls_ciphers == ECDSA_SUITE  # control


# --- the connection path: refused, and an allowed string keeps level 2 ----------------------------


@pytest.mark.parametrize("protocol", [ssl.PROTOCOL_TLS_SERVER, ssl.PROTOCOL_TLS_CLIENT])
def test_a_connection_refuses_a_directive_and_keeps_level_two(protocol: ssl._SSLMethod) -> None:
    ctx = ssl.SSLContext(protocol)
    with pytest.raises(ValueError, match=r"MLLP listener: tls_ciphers rejected.*directive"):
        apply_connection_tls_ciphers(
            ctx, {"tls_ciphers": f"@SECLEVEL=0:{ECDSA_SUITE}"}, connector="MLLP listener"
        )
    assert ctx.security_level == 2, "the refused string still reached the context"


@pytest.mark.parametrize("protocol", [ssl.PROTOCOL_TLS_SERVER, ssl.PROTOCOL_TLS_CLIENT])
@pytest.mark.parametrize("ciphers", [ECDSA_SUITE, f"{ECDSA_SUITE}:{RSA_SUITE}", None])
def test_an_allowed_operator_string_keeps_level_two(
    protocol: ssl._SSLMethod, ciphers: str | None
) -> None:
    """``None`` is the unset default, which narrows by name and writes the level back."""
    ctx = ssl.SSLContext(protocol)
    settings = {} if ciphers is None else {"tls_ciphers": ciphers}
    apply_connection_tls_ciphers(ctx, settings, connector="MLLP destination")
    assert ctx.security_level == 2


# --- defence in depth: the context itself is checked after the string is applied ------------------


def test_refuse_lowered_security_level_refuses_level_zero() -> None:
    refuse = tls_policy.refuse_lowered_security_level
    lowered = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    lowered.set_ciphers(f"@SECLEVEL=0:{RSA_SUITE}")
    assert lowered.security_level == 0, "control: the directive did not take"
    with pytest.raises(ValueError, match=r"test hop: .*security level 0"):
        refuse(lowered, connector="test hop")
    refuse(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), connector="test hop")  # control: stock passes


def test_a_connection_whose_validator_is_bypassed_still_refuses_a_lowered_level(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The second guard, reached without the first. With the validator stubbed out, only the
    level check stands between the directive and the context."""
    monkeypatch.setattr(tls_policy, "validate_tls_ciphers", lambda value, **_: value)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    with pytest.raises(ValueError, match=r"DICOM destination: .*security level 0"):
        apply_connection_tls_ciphers(
            ctx, {"tls_ciphers": f"@SECLEVEL=0:{RSA_SUITE}"}, connector="DICOM destination"
        )


def _ec_pair(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_the_api_listener_keeps_level_two_with_an_allowed_string(tmp_path: Path) -> None:
    cert, key = _ec_pair(tmp_path)
    api = ApiSettings(tls_cert_file=str(cert), tls_key_file=str(key), tls_ciphers=ECDSA_SUITE)
    assert build_api_ssl_context(api).security_level == 2


def test_the_api_listener_refuses_a_lowered_level_that_skipped_the_settings_validator(
    tmp_path: Path,
) -> None:
    """``model_construct`` skips pydantic validation, which is the one path that could hand the
    builder an unvalidated string. The control builds the same settings without the directive."""
    cert, key = _ec_pair(tmp_path)

    def construct(ciphers: str) -> ApiSettings:
        return ApiSettings.model_construct(
            tls_cert_file=str(cert), tls_key_file=str(key), tls_ciphers=ciphers
        )

    with pytest.raises(ValueError, match=r"API/UI listener: .*security level 0"):
        build_api_ssl_context(construct(f"@SECLEVEL=0:{ECDSA_SUITE}"))
    assert build_api_ssl_context(construct(ECDSA_SUITE)).security_level == 2


# --- the harm: an RSA-1024 server certificate, on a real handshake --------------------------------


def _rsa_1024_server(tmp_path: Path) -> tuple[ssl.SSLContext, bytes]:
    """A server presenting a self-signed RSA-1024 certificate for ``localhost``, and its PEM.

    The server context runs at level 0 on purpose: at 2, ``load_cert_chain`` refuses the key before
    any client is asked. The question is what the CLIENT does."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path, key_path = tmp_path / "rsa1024.pem", tmp_path / "rsa1024.key"
    cert_path.write_bytes(pem)
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.set_ciphers("ALL:@SECLEVEL=0")
    server.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return server, pem


def _client_trusting(pem: bytes) -> ssl.SSLContext:
    client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client.load_verify_locations(cadata=pem.decode("ascii"))
    return client


def _handshake(client_ctx: ssl.SSLContext, server_ctx: ssl.SSLContext) -> None:
    """Run a full TLS handshake over memory BIOs. Raises the client's or server's ``SSLError``."""
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname="localhost")
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    client_done = server_done = False
    for _ in range(20):
        if not client_done:
            try:
                client.do_handshake()
                client_done = True
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read())
        if not server_done:
            try:
                server.do_handshake()
                server_done = True
            except ssl.SSLWantReadError:
                pass
        c_in.write(s_out.read())
        if client_done and server_done:
            return
    raise AssertionError("the in-memory handshake did not finish")


def test_control_a_stock_client_at_level_zero_accepts_an_rsa_1024_server(tmp_path: Path) -> None:
    """The harm, shown to exist on this build. Without this, the refusals below could be passing
    because the handshake fails for some other reason."""
    server, pem = _rsa_1024_server(tmp_path)
    client = _client_trusting(pem)
    client.set_ciphers(f"@SECLEVEL=0:{RSA_SUITE}")
    _handshake(client, server)


def test_a_client_built_from_operator_input_refuses_an_rsa_1024_server(tmp_path: Path) -> None:
    server, pem = _rsa_1024_server(tmp_path)
    client = _client_trusting(pem)
    apply_connection_tls_ciphers(client, {"tls_ciphers": RSA_SUITE}, connector="MLLP destination")
    with pytest.raises(ssl.SSLError, match="key too weak"):
        _handshake(client, server)


def test_operator_input_cannot_build_the_level_zero_client(tmp_path: Path) -> None:
    """The row's reproduction, closed: the string that lowered the level is refused before it
    reaches a context, so no handshake happens with it."""
    server, pem = _rsa_1024_server(tmp_path)
    client = _client_trusting(pem)
    with pytest.raises(ValueError, match="directive"):
        apply_connection_tls_ciphers(
            client, {"tls_ciphers": f"@SECLEVEL=0:{RSA_SUITE}"}, connector="MLLP destination"
        )
    with pytest.raises(ssl.SSLError, match="key too weak"):
        _handshake(client, server)

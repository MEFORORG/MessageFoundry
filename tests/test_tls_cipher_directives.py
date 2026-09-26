# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2106 -- an operator ``tls_ciphers`` string may not carry an OpenSSL ``@`` directive.

``@SECLEVEL=0:ECDHE-ECDSA-AES256-GCM-SHA384`` names only approved suites, so every suite check in
``validate_tls_ciphers`` passed it. Applied, it moved the context's security level from 2 to 0, and a
client then accepted a server certificate with an RSA-1024 key. The level-2 floor is what refuses that
key, so the directive undid it with every gate saying yes.

Two guards now hold, and each is tested with a control that shows the test can pass:

* ``validate_tls_ciphers`` refuses any ``@`` token, on the operator knob and the proxy declaration;
* ``harden_cipher_suites`` refuses a finished context below the stock level, through
  ``refuse_lowered_security_level``. Every seam calls it after applying an operator string.

``tests/test_connection_tls_ciphers.py`` runs both guards over the four MLLP and DICOM seams. The
handshake tests at the end are the harm itself, measured on a real TLS exchange in memory.
"""

from __future__ import annotations

import datetime
import ssl
import warnings
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import ValidationError

from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.config import tls_policy
from messagefoundry.config.settings import ApiSettings
from messagefoundry.config.tls_policy import (
    apply_connection_tls_ciphers,
    harden_cipher_suites,
    validate_proxy_tls_posture,
    validate_tls_ciphers,
)
from messagefoundry.pki import make_self_signed

#: One approved suite per key type. The directive forms below are these plus a directive, so each
#: refusal has a control that differs from it by the directive alone.
ECDSA_SUITE = "ECDHE-ECDSA-AES256-GCM-SHA384"
RSA_SUITE = "ECDHE-RSA-AES256-GCM-SHA384"

#: Every form measured to parse on CPython 3.14.6 / OpenSSL 3.5.7, so the refusal is ours and not a
#: parse error. OpenSSL takes ``:``, ``,``, ``;`` and a space as separators, and it also starts a
#: directive at an ``@`` with NO separator, the last form. ``@SECLEVEL=2`` and ``@SECLEVEL=3`` are
#: refused too: a directive is refused for being one, not for the level it names.
DIRECTIVE_FORMS = [
    f"@SECLEVEL=0:{ECDSA_SUITE}",
    f"@SECLEVEL=1:{ECDSA_SUITE}",
    f"@SECLEVEL=2:{ECDSA_SUITE}",
    f"@SECLEVEL=3:{ECDSA_SUITE}",
    f"{ECDSA_SUITE}:@SECLEVEL=0",
    f"@STRENGTH:{ECDSA_SUITE}",
    f"{ECDSA_SUITE}:@STRENGTH",
    f"{ECDSA_SUITE} @SECLEVEL=0",
    f"{ECDSA_SUITE},@SECLEVEL=0",
    f"{ECDSA_SUITE};@SECLEVEL=0",
    f"{ECDSA_SUITE}@SECLEVEL=0",
]

SIDES = [ssl.PROTOCOL_TLS_SERVER, ssl.PROTOCOL_TLS_CLIENT]


def _stock_level(protocol: ssl._SSLMethod) -> int:
    return ssl.SSLContext(protocol).security_level


# --- the validator: every '@' token is refused, on both call shapes -------------------------------


def test_the_build_default_is_level_two() -> None:
    """The premise the handshake tests lean on: level 2 refuses an RSA-1024 key and level 1 would
    not. The other tests compare against the stock level, so they hold on any build."""
    assert _stock_level(ssl.PROTOCOL_TLS_SERVER) == 2
    assert _stock_level(ssl.PROTOCOL_TLS_CLIENT) == 2


@pytest.mark.parametrize("value", DIRECTIVE_FORMS)
def test_every_directive_form_parses_on_this_build(value: str) -> None:
    """Control for the refusals below: OpenSSL accepts each form, so the refusal is not a parse
    error in disguise."""
    ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).set_ciphers(value)


def test_a_directive_with_no_separator_still_lowers_the_level() -> None:
    """Why the check looks for ``@`` anywhere in a token, not only at its start."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers(f"{ECDSA_SUITE}@SECLEVEL=0")
    assert ctx.security_level == 0


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


# --- the connection path: refused, and an allowed string keeps the stock level --------------------


@pytest.mark.parametrize("protocol", SIDES)
def test_a_connection_refuses_a_directive_and_keeps_the_stock_level(
    protocol: ssl._SSLMethod,
) -> None:
    ctx = ssl.SSLContext(protocol)
    with pytest.raises(ValueError, match=r"MLLP listener: tls_ciphers rejected.*directive"):
        apply_connection_tls_ciphers(
            ctx, {"tls_ciphers": f"@SECLEVEL=0:{ECDSA_SUITE}"}, connector="MLLP listener"
        )
    assert ctx.security_level == _stock_level(protocol), "the refused string reached the context"


@pytest.mark.parametrize("protocol", SIDES)
@pytest.mark.parametrize("ciphers", [ECDSA_SUITE, f"{ECDSA_SUITE}:{RSA_SUITE}", None])
def test_an_allowed_operator_string_keeps_the_stock_level(
    protocol: ssl._SSLMethod, ciphers: str | None
) -> None:
    """``None`` is the unset default, which narrows by name and writes the level back."""
    ctx = ssl.SSLContext(protocol)
    settings = {} if ciphers is None else {"tls_ciphers": ciphers}
    apply_connection_tls_ciphers(ctx, settings, connector="MLLP destination")
    harden_cipher_suites(ctx, connector="MLLP destination")
    assert ctx.security_level == _stock_level(protocol)


# --- defence in depth: the finished context is checked, whatever reached it ------------------------


@pytest.mark.parametrize("protocol", SIDES)
def test_refuse_lowered_security_level_refuses_level_zero(protocol: ssl._SSLMethod) -> None:
    refuse = tls_policy.refuse_lowered_security_level
    lowered = ssl.SSLContext(protocol)
    lowered.set_ciphers(f"@SECLEVEL=0:{RSA_SUITE}")
    assert lowered.security_level == 0, "control: the directive did not take"
    with pytest.raises(ValueError, match=r"test hop: .*security level 0"):
        refuse(lowered, connector="test hop")
    refuse(ssl.SSLContext(protocol), connector="test hop")  # control: stock passes


def test_harden_cipher_suites_refuses_a_lowered_level() -> None:
    """The seam's own assertion carries the check, so the call-site guard that holds every seam to
    ``harden_cipher_suites`` by name holds it to this too. Level 0 with approved suites fails no
    suite check, so the level is the only thing that can raise here."""
    lowered = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    lowered.set_ciphers(f"@SECLEVEL=0:{RSA_SUITE}")
    with pytest.raises(ValueError, match=r"MLLP destination: .*security level 0"):
        harden_cipher_suites(lowered, connector="MLLP destination")
    stock = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    stock.set_ciphers(RSA_SUITE)
    harden_cipher_suites(stock, connector="MLLP destination")  # control


def test_the_stock_level_lookup_never_builds_a_deprecated_context() -> None:
    """A bare ``ssl.SSLContext()`` is ``PROTOCOL_TLS``, which warns on construction. The check
    compares it against a client context rather than building another one of its kind."""
    with pytest.warns(DeprecationWarning):
        legacy = ssl.SSLContext(ssl.PROTOCOL_TLS)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        tls_policy.refuse_lowered_security_level(legacy, connector="legacy")


def _ec_pair(tmp_path: Path) -> tuple[Path, Path]:
    cert_pem, key_pem = make_self_signed("localhost", [], 30)
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    return cert_path, key_path


def test_the_api_listener_keeps_the_stock_level_with_an_allowed_string(tmp_path: Path) -> None:
    cert, key = _ec_pair(tmp_path)
    api = ApiSettings(tls_cert_file=str(cert), tls_key_file=str(key), tls_ciphers=ECDSA_SUITE)
    assert build_api_ssl_context(api).security_level == _stock_level(ssl.PROTOCOL_TLS_SERVER)


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
    control = build_api_ssl_context(construct(ECDSA_SUITE))
    assert control.security_level == _stock_level(ssl.PROTOCOL_TLS_SERVER)


# --- the harm: an RSA-1024 server certificate, on a real handshake --------------------------------


def _rsa_1024_server(tmp_path: Path) -> tuple[ssl.SSLContext, bytes]:
    """A server presenting a self-signed RSA-1024 certificate for ``localhost``, and its PEM.

    The server context runs at level 0 on purpose: at 2, ``load_cert_chain`` refuses the key before
    any client is asked. The question is what the CLIENT does. ``make_self_signed`` mints EC only,
    so the RSA key is built here."""
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
    harden_cipher_suites(client, connector="MLLP destination")
    with pytest.raises(ssl.SSLError, match="key too weak"):
        _handshake(client, server)


def test_operator_input_cannot_build_the_level_zero_client(tmp_path: Path) -> None:
    """The row's reproduction, closed: the string that lowered the level is refused before it
    reaches a context, so the client keeps refusing the key."""
    server, pem = _rsa_1024_server(tmp_path)
    client = _client_trusting(pem)
    with pytest.raises(ValueError, match="directive"):
        apply_connection_tls_ciphers(
            client, {"tls_ciphers": f"@SECLEVEL=0:{RSA_SUITE}"}, connector="MLLP destination"
        )
    with pytest.raises(ssl.SSLError, match="key too weak"):
        _handshake(client, server)

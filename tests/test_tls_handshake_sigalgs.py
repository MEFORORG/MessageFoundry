# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""TLS 1.2 handshake signature algorithms on every engine-built context (BACKLOG #1168, ASVS 11.3.1).

WHAT THIS IS. A MEASUREMENT with a tripwire, not a fix. The 2026-09-22 owner ruling on 11.3.1
commissioned "the TLS 1.2 handshake signature padding measurement" before the DIRECT connector's
fate returns to the owner. That surface was named by the 2026-08-21 decision packet's critic: an
engine-shaped client, with the shipped hardening assertion passing, completed a handshake whose peer
signature was PKCS#1 v1.5. This module records, per engine-built context, which signature schemes
the context OFFERS (client side) and which one it CHOOSES (server side), and it fails the day that
changes in either direction. It narrows no signature algorithm and raises no protocol floor; both
are interop-priced owner calls.

WHY BYTE-LEVEL ON BOTH SIDES. CPython 3.14 exposes no signature-algorithm seam on ``SSLContext``:
no setter, and no way to read which scheme a handshake used (``set_client_sigalgs``,
``set_server_sigalgs`` and ``SSLSocket.client_sigalg``/``server_sigalg`` arrive in 3.15, the same
family as the ``set_groups`` that ``harden_kex_groups`` waits for). So the client half reads the
``signature_algorithms`` extension (0x000d) out of the ClientHello the context really emits, and the
server half feeds a hand-built TLS 1.2 ClientHello into the context and reads the
SignatureAndHashAlgorithm out of the ServerKeyExchange it really emits. Both run through
``ssl.MemoryBIO``: no socket, no network, no ``openssl`` binary, so there is no skip arm that could
turn this into a guard that cannot fail on a runner lacking a tool. (The 2026-08-21 packet's own
instrument fault was reading cipher suites, which cannot tell a PKCS#1-only server from a PSS-only
one. Nothing below reads a suite to answer a signature question.)

A PROCESS-WIDE ROUTE DOES EXIST, AND IT IS WHAT THE RED RUN USED. An ``OPENSSL_CONF`` file whose
``system_default`` section sets ``SignatureAlgorithms`` to a list without the rsa_pkcs1 schemes was
measured (CPython 3.14.6, OpenSSL 3.5.7) to turn every tripwire below red: no client context offers
rsa_pkcs1, and every listener refuses a PKCS#1-only peer. It is environment, not engine code, and
it reaches every context in the process at once. So a red here can mean the runner's OpenSSL
configuration changed, not only the engine.

WHICH CONTEXTS. Derived, not hand-counted: every call to ``harden_cipher_suites`` under
``messagefoundry/`` marks a context the engine builds and asserts, which is the "shipped hardening
gate" the critic's client passed. Each call site is keyed by file, enclosing function and the
``connector=`` expression it passes, and :data:`_SITES` must name exactly that set. A new builder
fails :func:`test_the_measured_population_is_the_derived_population` until someone says how to
build it here. That is an "at least" over one predicate: contexts built without that gate (the
tray and ``apiclient`` copies, the deliberately unhardened ``tls_probe`` offer) are outside it.

WHAT THE ASSERTIONS PIN, AND WHAT THEY DO NOT. The ``rsa_pkcs1_*`` SHA-2 codepoints 0x0401, 0x0501
and 0x0601 are asserted PRESENT where they are present today, not the whole ordered list, because a
Linux runner's OpenSSL build may order or extend the list differently. The day a pin removes them,
this module goes red on purpose, and the fix is to update it together with the 11.3.1 record, not to
delete the arm. ``rsa_pkcs1_sha224`` (0x0301) is offered on the development runtime too, but is not
asserted, for the same portability reason.
"""

from __future__ import annotations

import ast
import datetime
import os
import ssl
import struct
import sys
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import messagefoundry
from messagefoundry import logging_setup
from messagefoundry.api import tls as api_tls
from messagefoundry.auth import oidc_http
from messagefoundry.config import settings as settings_module
from messagefoundry.config import tls_policy
from messagefoundry.config.settings import ApiSettings, StoreSettings
from messagefoundry.store import postgres
from messagefoundry.transports import dicom, mllp, remotefile, rest, soap
from messagefoundry.verify import smoke

# --- TLS codepoints (RFC 8446 section 4.2.3; RFC 5246 section 7.4.1.4.1) ----------------------------

RSA_PKCS1_SHA256 = 0x0401
RSA_PKCS1_SHA384 = 0x0501
RSA_PKCS1_SHA512 = 0x0601
RSA_PKCS1_SHA1 = 0x0201
RSA_PSS_RSAE_SHA256 = 0x0804
ECDSA_SECP256R1_SHA256 = 0x0403
ECDSA_SECP384R1_SHA384 = 0x0503

#: The rsa_pkcs1 codepoints this tripwire pins as offered. Every one is PKCS#1 v1.5, the padding
#: scheme ASVS 11.3.1 names.
PINNED_RSA_PKCS1 = frozenset({RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512})

#: Every rsa_pkcs1 codepoint TLS defines, for the "is any PKCS#1 v1.5 scheme offered" reading.
ALL_RSA_PKCS1 = frozenset({0x0201, 0x0301, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512})

_TLS12 = 0x0303
_HANDSHAKE = 22
_CLIENT_HELLO = 1
_SERVER_HELLO = 2
_SERVER_KEY_EXCHANGE = 12
_EXT_SUPPORTED_GROUPS = 0x000A
_EXT_EC_POINT_FORMATS = 0x000B
_EXT_SIGNATURE_ALGORITHMS = 0x000D
_EXT_SUPPORTED_VERSIONS = 0x002B
_EXT_RENEGOTIATION_INFO = 0xFF01
_NAMED_CURVE = 3

#: ECDHE-RSA AEAD suites only. The engine's listeners are narrowed to ECDHE/DHE AEAD suites, so a
#: ClientHello without one would fail on suite selection and read as a signature refusal.
_ECDHE_RSA_AEAD = (0xC02F, 0xC030, 0xCCA8)
#: x25519, secp256r1, secp384r1. ECDHE needs a shared group, or it fails for the wrong reason.
_GROUPS = (0x001D, 0x0017, 0x0018)


# --- wire parsing ------------------------------------------------------------------------------------


def _u16(buf: bytes, at: int) -> int:
    value: int = struct.unpack(">H", buf[at : at + 2])[0]
    return value


def _u16_list(body: bytes) -> list[int]:
    """A TLS ``uint16 <..>`` vector: a two-byte length, then that many bytes of uint16 values."""
    length = _u16(body, 0)
    return [_u16(body, 2 + k) for k in range(0, length, 2)]


def _handshake_messages(wire: bytes) -> list[tuple[int, bytes]]:
    """Every handshake message in a run of plaintext TLS records, as ``(type, body)``.

    Handshake messages may span records, so the record payloads are joined before splitting."""
    payload = bytearray()
    at = 0
    while at + 5 <= len(wire):
        content_type, length = wire[at], _u16(wire, at + 3)
        if content_type == _HANDSHAKE:
            payload += wire[at + 5 : at + 5 + length]
        at += 5 + length
    messages: list[tuple[int, bytes]] = []
    at = 0
    while at + 4 <= len(payload):
        kind, length = payload[at], int.from_bytes(payload[at + 1 : at + 4], "big")
        messages.append((kind, bytes(payload[at + 4 : at + 4 + length])))
        at += 4 + length
    return messages


def _client_hello_extensions(body: bytes) -> dict[int, bytes]:
    at = 2 + 32  # client_version, random
    at += 1 + body[at]  # session_id
    at += 2 + _u16(body, at)  # cipher_suites
    at += 1 + body[at]  # compression_methods
    end = at + 2 + _u16(body, at)
    at += 2
    extensions: dict[int, bytes] = {}
    while at < end:
        kind, length = _u16(body, at), _u16(body, at + 2)
        extensions[kind] = body[at + 4 : at + 4 + length]
        at += 4 + length
    return extensions


def _build_client_hello(sigalgs: list[int]) -> bytes:
    """A TLS 1.2 ClientHello record offering ECDHE-RSA AEAD suites and exactly ``sigalgs``.

    No ``supported_versions`` extension, so a server that accepts it negotiates TLS 1.2, where the
    handshake signature travels in the clear in ServerKeyExchange."""

    def ext(kind: int, data: bytes) -> bytes:
        return struct.pack(">HH", kind, len(data)) + data

    def u16_vector(values: tuple[int, ...] | list[int]) -> bytes:
        return struct.pack(">H", 2 * len(values)) + b"".join(struct.pack(">H", v) for v in values)

    extensions = (
        ext(_EXT_SUPPORTED_GROUPS, u16_vector(_GROUPS))
        + ext(_EXT_EC_POINT_FORMATS, b"\x01\x00")
        + ext(_EXT_SIGNATURE_ALGORITHMS, u16_vector(sigalgs))
        + ext(_EXT_RENEGOTIATION_INFO, b"\x00")
    )
    body = (
        struct.pack(">H", _TLS12)
        + os.urandom(32)
        + b"\x00"
        + u16_vector(_ECDHE_RSA_AEAD)
        + b"\x01\x00"
        + struct.pack(">H", len(extensions))
        + extensions
    )
    message = bytes([_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(message)) + message


@dataclass(frozen=True)
class ServerReading:
    """What a server context did with one crafted ClientHello."""

    version: int | None  #: the ServerHello version, or None when the handshake failed
    chosen: int | None  #: the ServerKeyExchange SignatureAndHashAlgorithm
    refusal: str | None  #: the OpenSSL reason when the handshake failed


def server_choice(ctx: ssl.SSLContext, sigalgs: list[int]) -> ServerReading:
    """Feed ``ctx`` a TLS 1.2 ClientHello offering ``sigalgs`` and read the scheme it signs with."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_side=True)
    incoming.write(_build_client_hello(sigalgs))
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass  # the server flight is written and it now waits for ClientKeyExchange
    except ssl.SSLError as exc:
        return ServerReading(version=None, chosen=None, refusal=exc.reason or str(exc))
    messages = dict(_handshake_messages(outgoing.read()))
    ske = messages[_SERVER_KEY_EXCHANGE]
    assert ske[0] == _NAMED_CURVE, "expected an ECDHE ServerKeyExchange (the offer is ECDHE only)"
    point_length = ske[3]
    return ServerReading(
        version=_u16(messages[_SERVER_HELLO], 0),
        chosen=_u16(ske, 4 + point_length),
        refusal=None,
    )


@dataclass(frozen=True)
class ClientReading:
    """What a client context offered in the ClientHello it emitted."""

    sigalgs: list[int]
    versions: list[int]


def client_offer(ctx: ssl.SSLContext) -> ClientReading:
    """Start a handshake on ``ctx`` and parse the ClientHello it emits. Nothing is sent anywhere."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname="localhost")
    with pytest.raises(ssl.SSLWantReadError):
        tls.do_handshake()
    hellos = [body for kind, body in _handshake_messages(outgoing.read()) if kind == _CLIENT_HELLO]
    assert len(hellos) == 1, f"expected one ClientHello, parsed {len(hellos)}"
    extensions = _client_hello_extensions(hellos[0])
    versions_ext = extensions.get(_EXT_SUPPORTED_VERSIONS)
    versions = (
        [_u16(versions_ext, 1 + k) for k in range(0, versions_ext[0], 2)]
        if versions_ext is not None
        else [_u16(hellos[0], 0)]
    )
    return ClientReading(
        sigalgs=_u16_list(extensions[_EXT_SIGNATURE_ALGORITHMS]), versions=versions
    )


# --- the population: derived from code ---------------------------------------------------------------

_GATE = "harden_cipher_suites"
_PKG = Path(messagefoundry.__file__).resolve().parent


def derived_sites() -> set[str]:
    """Every ``harden_cipher_suites(...)`` call under ``messagefoundry/``, keyed
    ``<file>::<enclosing function>::<connector= expression>``.

    The connector expression separates two sites in one function (MLLP's listener and destination
    arms), and it is the label each context carries in its own refusal message."""
    sites: set[str] = set()
    for path in sorted(_PKG.rglob("*.py")):
        rel = path.relative_to(_PKG.parent).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))

        def walk(node: ast.AST, scope: tuple[str, ...], rel: str = rel) -> None:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    walk(child, (*scope, child.name))
                    continue
                if isinstance(child, ast.Call):
                    func = child.func
                    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
                    if name == _GATE:
                        connector = next(
                            (ast.unparse(k.value) for k in child.keywords if k.arg == "connector"),
                            "?",
                        )
                        sites.add(f"{rel}::{'.'.join(scope)}::{connector}")
                walk(child, scope)

        walk(tree, ())
    return sites


@dataclass(frozen=True)
class Kit:
    """What a site's factory may need: an RSA server identity and the test's monkeypatch."""

    cert: str
    key: str
    monkeypatch: pytest.MonkeyPatch


def _mllp_listener(k: Kit) -> object:
    settings = {"tls": True, "tls_cert_file": k.cert, "tls_key_file": k.key}
    return mllp._mllp_ssl_context(settings, server=True)


def _dicom_listener(k: Kit) -> object:
    settings = {"tls": True, "tls_cert_file": k.cert, "tls_key_file": k.key}
    return dicom._server_ssl_context(settings)


def _postgres_verify_off(k: Kit) -> object:
    k.monkeypatch.setenv(settings_module.INSECURE_TLS_ESCAPE_ENV, "1")
    return postgres._build_ssl(StoreSettings(trust_server_certificate=True))


def _rest_verify_off(k: Kit) -> object:
    return rest._insecure_opener()


def _ldap3(k: Kit) -> object:
    kwargs = {
        "validate": ssl.CERT_REQUIRED,
        "ciphers": ":".join(tls_policy.APPROVED_TLS12_SUITES),
    }
    tls_policy.assert_ldap3_tls_suites(kwargs, connector="LDAPS (measurement)")
    return None


#: Every derived site, with how to build it. Each factory calls the REAL builder; the context
#: measured is the one that builder handed to ``harden_cipher_suites``, captured by a spy.
_SITES: dict[str, Callable[[Kit], object]] = {
    "messagefoundry/api/tls.py::build_api_ssl_context::'API/UI listener'": lambda k: (
        api_tls.build_api_ssl_context(ApiSettings(tls_cert_file=k.cert, tls_key_file=k.key))
    ),
    "messagefoundry/transports/mllp.py::_mllp_ssl_context::'MLLP listener'": _mllp_listener,
    "messagefoundry/transports/dicom.py::_server_ssl_context::'DICOM listener'": _dicom_listener,
    "messagefoundry/transports/mllp.py::_mllp_ssl_context::'MLLP destination'": lambda k: (
        mllp._mllp_ssl_context({"tls": True, "host": "localhost"}, server=False)
    ),
    "messagefoundry/transports/dicom.py::_client_ssl_context::'DICOM destination'": lambda k: (
        dicom._client_ssl_context({"tls": True, "host": "localhost"})
    ),
    "messagefoundry/auth/oidc_http.py::build_idp_opener::"
    "'OIDC identity provider (token + JWKS)'": lambda k: oidc_http.build_idp_opener(None),
    "messagefoundry/config/tls_policy.py::build_asserted_https_handler::connector": lambda k: (
        tls_policy.build_asserted_https_handler(connector="urllib default handler (measurement)")
    ),
    "messagefoundry/config/tls_policy.py::assert_ldap3_tls_suites::connector": _ldap3,
    "messagefoundry/config/tls_policy.py::assert_hvac_tls_suites.narrowed_context::connector": (
        lambda k: tls_policy.assert_hvac_tls_suites({}, connector="Vault (measurement)")
    ),
    "messagefoundry/config/tls_policy.py::build_anchored_https_handler::connector": lambda k: (
        tls_policy.build_anchored_https_handler(
            anchor=tls_policy.SYSTEM_TRUST_ANCHOR, connector="HTTP family (measurement)"
        )
    ),
    "messagefoundry/config/tls_policy.py::build_smtp_tls_context::cell": lambda k: (
        tls_policy.build_smtp_tls_context(host="localhost", cell="SMTP (measurement)")
    ),
    "messagefoundry/logging_setup.py::_build_tls_context::'syslog TLS forwarder'": lambda k: (
        logging_setup._build_tls_context(
            logging_setup.SyslogForward(host="localhost", protocol="tls", tls_verify=False)
        )
    ),
    "messagefoundry/store/postgres.py::_build_ssl::"
    "'Postgres store (TLS verification disabled)'": _postgres_verify_off,
    "messagefoundry/store/postgres.py::_verifying_context::connector": lambda k: (
        postgres._verifying_context(StoreSettings())
    ),
    "messagefoundry/transports/remotefile.py::_ftps_ssl_context::"
    "'remote-file (FTPS) connection'": lambda k: remotefile._ftps_ssl_context(
        {"host": "localhost"}
    ),
    "messagefoundry/transports/rest.py::_insecure_opener::"
    "'HTTP-family destination (TLS verification disabled)'": _rest_verify_off,
    "messagefoundry/transports/rest.py::_expiry_relaxed_opener::"
    "'HTTP-family destination (expired-certificate tolerance)'": lambda k: (
        rest._expiry_relaxed_opener("localhost")
    ),
    "messagefoundry/transports/soap.py::_client_cert_opener::'SOAP destination (mutual TLS)'": (
        lambda k: soap._client_cert_opener(k.cert, k.key, None)
    ),
    "messagefoundry/verify/smoke.py::live_smoke_ssl_context::'verify live smoke'": lambda k: (
        smoke.live_smoke_ssl_context()
    ),
}


@pytest.fixture(scope="module")
def rsa_identity(tmp_path_factory: pytest.TempPathFactory) -> tuple[str, str]:
    """A self-signed RSA-2048 ``localhost`` certificate and its key, as PEM paths."""
    tmp = tmp_path_factory.mktemp("sigalg_rsa")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / "cert.pem", tmp / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[ssl.SSLContext]]:
    """Wrap ``harden_cipher_suites`` wherever the engine bound it, recording each context it is
    handed and then running the real assertion, so a measured context has passed the shipped gate."""
    original = tls_policy.harden_cipher_suites
    seen: list[ssl.SSLContext] = []

    def spy(ctx: ssl.SSLContext, *, connector: str) -> None:
        seen.append(ctx)
        original(ctx, connector=connector)

    rebound = 0
    for name, module in list(sys.modules.items()):
        if name.startswith("messagefoundry") and getattr(module, _GATE, None) is original:
            monkeypatch.setattr(module, _GATE, spy)
            rebound += 1
    assert rebound >= 2, "the spy bound almost nowhere, so it would capture nothing"
    yield seen


def build_site(site: str, kit: Kit, seen: list[ssl.SSLContext]) -> ssl.SSLContext:
    """Run the site's real builder and return the one context it handed the gate."""
    _SITES[site](kit)
    assert len(seen) == 1, f"{site}: the gate saw {len(seen)} contexts, expected exactly one"
    return seen[0]


def _is_server(ctx: ssl.SSLContext) -> bool:
    return ctx.protocol == ssl.PROTOCOL_TLS_SERVER


_SERVER_SITES = [s for s in _SITES if "listener" in s.rsplit("::", 1)[1]]
_CLIENT_SITES = [s for s in _SITES if s not in _SERVER_SITES]


# --- the population ------------------------------------------------------------------------------


def test_the_measured_population_is_the_derived_population() -> None:
    """A new ``harden_cipher_suites`` site fails here until it is measured; a removed one too."""
    derived = derived_sites()
    assert "messagefoundry/api/tls.py::build_api_ssl_context::'API/UI listener'" in derived, (
        "the derivation did not find the API listener, so it is not scanning the engine"
    )
    missing, stale = sorted(derived - set(_SITES)), sorted(set(_SITES) - derived)
    assert not missing and not stale, (
        f"harden_cipher_suites call sites and this module's measured list disagree. Unmeasured: "
        f"{missing}. Gone from the code: {stale}. Add a factory to _SITES that builds the new "
        f"context through its real builder; do not narrow the derivation to make this pass."
    )


@pytest.mark.parametrize("site", sorted(_SITES))
def test_each_site_builds_exactly_one_context_on_its_declared_side(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """The listener/destination split is read off the built context, not trusted from the label."""
    ctx = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    assert _is_server(ctx) == (site in _SERVER_SITES), (
        f"{site}: the context's protocol says {'server' if _is_server(ctx) else 'client'}, "
        f"which is not the side this module files it under"
    )


# --- server side: which scheme does each listener sign with ------------------------------------------


@pytest.mark.parametrize("site", _SERVER_SITES)
def test_listener_signs_with_rsa_pkcs1_when_that_is_all_the_peer_offers(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """TRIPWIRE. A TLS 1.2 peer offering only rsa_pkcs1_sha256 gets a PKCS#1 v1.5 handshake signature.

    Goes red the day a server-side pin (``set_server_sigalgs``, Python 3.15) or an OpenSSL default
    change stops this listener from signing with PKCS#1 v1.5. Update the 11.3.1 record with it."""
    ctx = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    reading = server_choice(ctx, [RSA_PKCS1_SHA256])
    assert reading.refusal is None, f"{site}: refused a PKCS#1-only peer ({reading.refusal})"
    assert reading.version == _TLS12
    assert reading.chosen == RSA_PKCS1_SHA256
    assert server_choice(ctx, [RSA_PKCS1_SHA384]).chosen == RSA_PKCS1_SHA384


@pytest.mark.parametrize("site", _SERVER_SITES)
def test_listener_controls_disagree_with_the_pkcs1_reading(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """The controls. Same suites, same groups, same certificate; only the offered schemes move.

    A PSS-only offer must come back rsa_pss_rsae_sha256, so the reading is not a constant. An
    ECDSA-only offer against an RSA certificate must fail the handshake, so the offer governs the
    choice. SHA-1 PKCS#1 v1.5 is refused by the default security level, which is a reading too."""
    ctx = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    pss = server_choice(ctx, [RSA_PSS_RSAE_SHA256])
    assert pss.refusal is None and pss.chosen == RSA_PSS_RSAE_SHA256, f"{site}: {pss}"
    ecdsa = server_choice(ctx, [ECDSA_SECP256R1_SHA256, ECDSA_SECP384R1_SHA384])
    assert ecdsa.chosen is None and ecdsa.refusal is not None, (
        f"{site}: an ECDSA-only offer against an RSA certificate completed with {ecdsa}"
    )
    sha1 = server_choice(ctx, [RSA_PKCS1_SHA1])
    assert sha1.chosen is None and sha1.refusal is not None, f"{site}: signed with SHA-1: {sha1}"


@pytest.mark.parametrize("site", _SERVER_SITES)
def test_listener_prefers_pss_when_the_peer_offers_both(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """A reading, pinned: with PKCS#1 v1.5 offered FIRST and PSS second, the listener still picks PSS,
    so a peer that offers PSS at all does not get PKCS#1 v1.5 from an engine listener at TLS 1.2."""
    ctx = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    both = server_choice(ctx, [RSA_PKCS1_SHA256, RSA_PSS_RSAE_SHA256])
    assert both.chosen == RSA_PSS_RSAE_SHA256, f"{site}: {both}"


def test_the_api_tls13_floor_refuses_the_tls12_hello(rsa_identity: tuple[str, str]) -> None:
    """The one refusal available on 3.14 today, priced: ``[api].tls_min_version = "1.3"`` refuses the
    TLS 1.2 ClientHello outright. No other listener exposes that knob. This test raises no floor; it
    reads the operator setting that already exists, against the same hello the other arms accept."""
    cert, key = rsa_identity
    floored = api_tls.build_api_ssl_context(
        ApiSettings(tls_cert_file=cert, tls_key_file=key, tls_min_version="1.3")
    )
    reading = server_choice(floored, [RSA_PKCS1_SHA256])
    assert reading.chosen is None and reading.refusal is not None, reading
    stock = api_tls.build_api_ssl_context(ApiSettings(tls_cert_file=cert, tls_key_file=key))
    assert server_choice(stock, [RSA_PKCS1_SHA256]).chosen == RSA_PKCS1_SHA256


# --- client side: which schemes does each destination offer ------------------------------------------


@pytest.mark.parametrize("site", _CLIENT_SITES)
def test_destination_offers_rsa_pkcs1_at_tls12(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """TRIPWIRE. Every engine client context offers TLS 1.2 and the rsa_pkcs1 SHA-2 schemes.

    A TLS 1.2 client must accept a ServerKeyExchange signed with any scheme it offered (RFC 5246
    section 7.4.1.4.1), so offering these is accepting a PKCS#1 v1.5 handshake signature from a
    peer that picks one. Goes red the day a client-side pin (``set_client_sigalgs``, Python 3.15)
    removes them. At TLS 1.3 these codepoints are valid only for certificate signatures."""
    ctx = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    reading = client_offer(ctx)
    assert _TLS12 in reading.versions, f"{site}: TLS 1.2 not offered ({reading.versions})"
    assert set(reading.sigalgs) >= PINNED_RSA_PKCS1, (
        f"{site}: rsa_pkcs1 schemes missing from the offer: "
        f"{sorted(hex(s) for s in PINNED_RSA_PKCS1 - set(reading.sigalgs))}"
    )
    assert RSA_PSS_RSAE_SHA256 in reading.sigalgs, f"{site}: PSS not offered"


def test_the_client_parser_can_say_no() -> None:
    """Control for the client half: the parser round-trips an offer it did not come from, and the
    PKCS#1 predicate returns False on an offer without it. Without this, a parser that returned a
    fixed list would pass every destination above."""
    for offer in ([RSA_PSS_RSAE_SHA256, ECDSA_SECP256R1_SHA256], [RSA_PKCS1_SHA256, 0x0807]):
        messages = _handshake_messages(_build_client_hello(offer))
        (body,) = [b for kind, b in messages if kind == _CLIENT_HELLO]
        parsed = _u16_list(_client_hello_extensions(body)[_EXT_SIGNATURE_ALGORITHMS])
        assert parsed == offer
    assert not ({RSA_PSS_RSAE_SHA256, ECDSA_SECP256R1_SHA256} & ALL_RSA_PKCS1)


# --- the seam ----------------------------------------------------------------------------------------


def test_the_runtime_still_has_no_signature_algorithm_seam() -> None:
    """TRIPWIRE, in the ``harden_kex_groups`` style. CPython 3.15 adds ``set_client_sigalgs`` and
    ``set_server_sigalgs``. When this goes red, a real pin excluding rsa_pkcs1 has become possible
    and the 11.3.1 disposition should be re-read. It is asserted unconditionally on purpose."""
    for name in ("set_client_sigalgs", "set_server_sigalgs"):
        assert not hasattr(ssl.SSLContext, name), (
            f"ssl.SSLContext.{name} exists on this interpreter, so the TLS 1.2 handshake signature "
            f"surface of ASVS 11.3.1 is now configurable (BACKLOG #1168). Re-read the record."
        )
    assert hasattr(ssl.SSLContext, "set_ciphers"), "control: the attribute probe itself works"


def test_the_urllib_contexts_are_the_ones_the_opener_uses(
    rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """The opener sites are measured through the context handed to the gate. This ties that context
    to the one the opener's HTTPS handler really holds, so the capture is not measuring a bystander."""
    opener = oidc_http.build_idp_opener(None)
    every: list[object] = opener.handlers  # type: ignore[attr-defined]
    handlers = [h for h in every if isinstance(h, urllib.request.HTTPSHandler)]
    assert len(handlers) == 1
    assert handlers[0]._context is captured[0]  # type: ignore[attr-defined]

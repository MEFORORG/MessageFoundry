# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""TLS 1.2 handshake signature algorithms on the engine's gated TLS contexts (BACKLOG #1168).

WHAT THIS IS. A MEASUREMENT with tripwires, not a fix, for ASVS 11.3.1. The 2026-09-22 owner ruling
on 11.3.1 commissioned "the TLS 1.2 handshake signature padding measurement" before the DIRECT
connector's fate returns to the owner. The 2026-08-21 decision packet's critic named that surface:
an engine-shaped client, with the shipped hardening assertion passing, completed a handshake whose
peer signature was PKCS#1 v1.5. This module records, per gated context, which signature schemes it
OFFERS (client side) and which one it CHOOSES (server side), and it goes red when the rsa_pkcs1
offer shrinks or widens. It narrows no signature algorithm and raises no protocol floor itself.

ONE NARROWING IS NOW BUILT, AND IT IS SHA-224 ONLY. This module said both of those were
interop-priced owner calls. The owner ruled on SHA-224 on 2026-09-29 (BACKLOG #1171, ASVS 11.4.1):
build it now behind a feature check, so an engine on Python 3.15 stops offering the SHA-224 schemes
at once, while 3.14 keeps today's behaviour. ``tls_policy.narrow_signature_algorithms`` is the one
statement of what it does and what it cannot reach; the last section below measures it. The rsa_pkcs1
SHA-2 schemes and the protocol floor are still owner calls, and nothing here narrows them.

WHY BYTE-LEVEL ON BOTH SIDES. CPython 3.14 exposes no signature-algorithm seam on ``SSLContext``:
no setter, and no way to read which scheme a handshake used (``set_client_sigalgs``,
``set_server_sigalgs`` and ``SSLSocket.client_sigalg``/``server_sigalg`` arrive in 3.15, the same
family as the ``set_groups`` that ``harden_kex_groups`` waits for). So the client half reads the
``signature_algorithms`` extension (0x000d) out of the ClientHello the context really emits, and the
server half feeds a hand-built TLS 1.2 ClientHello into the context and reads the
SignatureAndHashAlgorithm out of the ServerKeyExchange it really emits. Both run through
``ssl.MemoryBIO``: no socket, no network, no ``openssl`` binary, so no arm skips for want of a
tool. The one skip is the Vault site, which needs the [vault] extra's urllib3 to build its context
at all, as its sibling suite does; on an interpreter without that extra, 18 of the 19 derived sites
are measured, and the skip is reported. (The 2026-08-21 packet's own
instrument fault was reading cipher suites, which cannot tell a PKCS#1-only server from a PSS-only
one. Nothing below reads a suite to answer a signature question.)

A PROCESS-WIDE ROUTE DOES EXIST. An ``OPENSSL_CONF`` file whose ``system_default`` section sets
``SignatureAlgorithms`` to a list without the rsa_pkcs1 schemes was measured (CPython 3.14.6,
OpenSSL 3.5.7) to turn every pkcs1 tripwire below red: no client context offered rsa_pkcs1, and
every listener refused a PKCS#1-only peer. It is environment, not engine code, and it reaches every
context in the process at once. So a red here can mean the runner's OpenSSL configuration changed,
not only the engine.

WHICH CONTEXTS. Derived, not hand-counted: every call to ``harden_cipher_suites`` under
``messagefoundry/`` marks a context the engine builds and asserts, which is the "shipped hardening
gate" the critic's client passed. Each call site is keyed by file, enclosing function and the
``connector=`` expression it passes, and :data:`_SITES` must name exactly that set. A new call site
fails :func:`test_the_measured_population_is_the_derived_population` until someone says how to
build it here. That covers at least the gated contexts, over one predicate: contexts built without
that gate (at least the tray and ``apiclient`` copies and the deliberately unhardened ``tls_probe``
offer) are outside it and are not measured here.

THE SERVER READINGS DEPEND ON THE CERTIFICATE'S KEY TYPE. The listener arms load an RSA-2048
identity, because a TLS 1.2 handshake signature can only be PKCS#1 v1.5 or PSS under an RSA key.
The API listener's MINTED default identity (ADR 0172, ``ensure_api_tls_material``) is EC P-256, and
with it the listener signs with ECDSA and refuses a PKCS#1-only peer; the ECDSA arm below pins that.
The MLLP and DICOM listeners mint nothing, so their key type is whatever the operator supplies.

WHAT THE ASSERTIONS PIN, AND WHAT THEY DO NOT. On the client side the rsa_pkcs1 schemes offered must
include the three SHA-2 ones (0x0401, 0x0501, 0x0601) and must stay within those plus
rsa_pkcs1_sha224 (0x0301): shrinking or widening both go red, and SHA-1 (0x0201) is the widening
that matters. The whole ordered list is not pinned, because a Linux runner's OpenSSL may order or
extend the non-PKCS#1 part differently. When this goes red on purpose, update it together with the
11.3.1 record; do not delete the arm.
"""

from __future__ import annotations

import ast
import datetime
import os
import ssl
import struct
import sys
import urllib.request
from collections import Counter
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
from messagefoundry.auth.ldap import LdapAuthenticator
from messagefoundry.config import settings as settings_module
from messagefoundry.config import tls_policy
from messagefoundry.config.settings import ApiSettings, AuthSettings, StoreSettings
from messagefoundry.store import postgres
from messagefoundry.transports import dicom, mllp, remotefile, rest, soap
from messagefoundry.verify import smoke
from tests._ast_sites import callee_name
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

# --- TLS codepoints (RFC 8446 section 4.2.3; RFC 5246 section 7.4.1.4.1) ----------------------------

RSA_PKCS1_SHA1 = 0x0201
RSA_PKCS1_SHA224 = 0x0301
RSA_PKCS1_SHA256 = 0x0401
RSA_PKCS1_SHA384 = 0x0501
RSA_PKCS1_SHA512 = 0x0601
RSA_PSS_RSAE_SHA256 = 0x0804
ECDSA_SECP256R1_SHA256 = 0x0403
ECDSA_SECP384R1_SHA384 = 0x0503

RSA_PKCS1_MD5 = 0x0101
DSA_SHA224 = 0x0302
ECDSA_SHA224 = 0x0303

#: Every SHA-224 signature scheme in the RFC 5246 registry: the set BACKLOG #1171 removes.
SHA224_SCHEMES = frozenset({RSA_PKCS1_SHA224, DSA_SHA224, ECDSA_SHA224})
#: The ML-DSA schemes OpenSSL 3.5 adds through a provider, which ``ssl.get_sigalgs`` does not list.
MLDSA_SCHEMES = frozenset({0x0904, 0x0905, 0x0906})

#: At least the RSA PKCS#1 v1.5 codepoints of the RFC 5246 and RFC 8446 registries, MD5 included.
#: Each is PKCS#1 v1.5, the padding ASVS 11.3.1 names.
ALL_RSA_PKCS1 = frozenset(
    {
        RSA_PKCS1_MD5,
        RSA_PKCS1_SHA1,
        RSA_PKCS1_SHA224,
        RSA_PKCS1_SHA256,
        RSA_PKCS1_SHA384,
        RSA_PKCS1_SHA512,
    }
)
#: The floor of the client tripwire: offered today on every gated client context.
PINNED_RSA_PKCS1 = frozenset({RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512})
#: The ceiling of the client tripwire. SHA-224 may or may not be offered by a given OpenSSL build.
CEILING_RSA_PKCS1 = PINNED_RSA_PKCS1 | {RSA_PKCS1_SHA224}

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
_EXT_EXTENDED_MASTER_SECRET = 0x0017
_NAMED_CURVE = 3

#: ECDHE-RSA AEAD suites. The engine's listeners are narrowed to ECDHE/DHE AEAD suites, so a
#: ClientHello without one would fail on suite selection and read as a signature refusal.
ECDHE_RSA_AEAD = (0xC02F, 0xC030, 0xCCA8)
#: ECDHE-ECDSA AEAD suites, for the arm that loads an EC identity.
ECDHE_ECDSA_AEAD = (0xC02B, 0xC02C, 0xCCA9)
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


def _extensions(body: bytes, at: int) -> dict[int, bytes]:
    """The extension block starting at ``at`` (its two-byte length), as ``{type: data}``."""
    end = at + 2 + _u16(body, at)
    at += 2
    found: dict[int, bytes] = {}
    while at < end:
        kind, length = _u16(body, at), _u16(body, at + 2)
        found[kind] = body[at + 4 : at + 4 + length]
        at += 4 + length
    return found


def _client_hello_extensions(body: bytes) -> dict[int, bytes]:
    at = 2 + 32  # client_version, random
    at += 1 + body[at]  # session_id
    at += 2 + _u16(body, at)  # cipher_suites
    at += 1 + body[at]  # compression_methods
    return _extensions(body, at)


def _server_hello_version(body: bytes) -> int:
    """The NEGOTIATED version. TLS 1.3 keeps 0x0303 in legacy_version and puts the real one in the
    supported_versions extension, so the legacy field alone cannot tell 1.2 from 1.3."""
    at = 2 + 32  # legacy_version, random
    at += 1 + body[at]  # session_id
    at += 2 + 1  # cipher_suite, compression_method
    if at >= len(body):
        return _u16(body, 0)
    chosen = _extensions(body, at).get(_EXT_SUPPORTED_VERSIONS)
    return _u16(chosen, 0) if chosen is not None else _u16(body, 0)


def _build_client_hello(sigalgs: list[int], suites: tuple[int, ...] = ECDHE_RSA_AEAD) -> bytes:
    """A TLS 1.2 ClientHello record offering ``suites`` and exactly ``sigalgs``.

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
        # extended_master_secret: a build that requires it (a FIPS provider can) would otherwise
        # refuse every crafted hello, and the refusal would read as a signature-algorithm change.
        + ext(_EXT_EXTENDED_MASTER_SECRET, b"")
    )
    body = (
        struct.pack(">H", _TLS12)
        + os.urandom(32)
        + b"\x00"
        + u16_vector(suites)
        + b"\x01\x00"
        + struct.pack(">H", len(extensions))
        + extensions
    )
    message = bytes([_CLIENT_HELLO]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(message)) + message


@dataclass(frozen=True)
class ServerReading:
    """What a server context did with one crafted ClientHello."""

    version: int | None  #: the negotiated version, or None when the handshake failed
    chosen: int | None  #: the ServerKeyExchange SignatureAndHashAlgorithm
    refusal: str | None  #: the OpenSSL reason when the handshake failed


def server_choice(
    ctx: ssl.SSLContext, sigalgs: list[int], suites: tuple[int, ...] = ECDHE_RSA_AEAD
) -> ServerReading:
    """Feed ``ctx`` a TLS 1.2 ClientHello offering ``sigalgs`` and read the scheme it signs with."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_side=True)
    incoming.write(_build_client_hello(sigalgs, suites))
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass  # the server flight is written and it now waits for ClientKeyExchange
    except ssl.SSLError as exc:
        return ServerReading(version=None, chosen=None, refusal=exc.reason or str(exc))
    messages = dict(_handshake_messages(outgoing.read()))
    version = _server_hello_version(messages[_SERVER_HELLO])
    assert version == _TLS12, f"negotiated {version:#06x}, so there is no ServerKeyExchange to read"
    ske = messages[_SERVER_KEY_EXCHANGE]
    assert ske[0] == _NAMED_CURVE, "expected an ECDHE ServerKeyExchange (the offer is ECDHE only)"
    point_length = ske[3]
    return ServerReading(version=version, chosen=_u16(ske, 4 + point_length), refusal=None)


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


def offer_problems(reading: ClientReading) -> list[str]:
    """Where a client offer departs from the pinned shape. Empty means the tripwire holds."""
    problems: list[str] = []
    if _TLS12 not in reading.versions:
        problems.append(f"TLS 1.2 not offered ({[f'{v:#06x}' for v in reading.versions]})")
    pkcs1 = set(reading.sigalgs) & ALL_RSA_PKCS1
    if missing := PINNED_RSA_PKCS1 - pkcs1:
        problems.append(f"rsa_pkcs1 no longer offered: {sorted(f'{s:#06x}' for s in missing)}")
    if widened := pkcs1 - CEILING_RSA_PKCS1:
        problems.append(f"rsa_pkcs1 offer WIDENED to: {sorted(f'{s:#06x}' for s in widened)}")
    return problems


# --- the population: derived from code ---------------------------------------------------------------

_GATE = "harden_cipher_suites"
_PKG = Path(messagefoundry.__file__).resolve().parent


def _gate_calls(node: ast.AST, rel: str, scope: tuple[str, ...], out: list[str]) -> None:
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            _gate_calls(child, rel, (*scope, child.name), out)
            continue
        if isinstance(child, ast.Call) and callee_name(child) == _GATE:
            connector = next(
                (ast.unparse(k.value) for k in child.keywords if k.arg == "connector"), "?"
            )
            out.append(f"{rel}::{'.'.join(scope)}::{connector}")
        _gate_calls(child, rel, scope, out)


def derived_sites() -> Counter[str]:
    """Every ``harden_cipher_suites(...)`` call under ``messagefoundry/``, keyed
    ``<file>::<enclosing function>::<connector= expression>``, as a multiset.

    The connector expression separates two sites in one function (MLLP's listener and destination
    arms). A multiset, so two calls sharing one key are counted rather than collapsed. Any other
    route to the gate is refused outright, because this scan and the spy both look for its name: an
    import under another name, or the bare name used as a value (``_h = harden_cipher_suites``,
    ``partial(harden_cipher_suites, ...)``) rather than called."""
    found: list[str] = []
    for path in sorted(_PKG.rglob("*.py")):
        text = path.read_text(encoding="utf-8-sig")  # -sig: a leading BOM is dropped
        if _GATE not in text:
            continue
        rel = path.relative_to(_PKG.parent).as_posix()
        # A plain parse, not the shared parse_source cache: these trees are used once, and caching
        # them would evict the trees other AST guards in the same worker reuse.
        tree = ast.parse(text)
        called = {id(n.func) for n in ast.walk(tree) if isinstance(n, ast.Call)}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                aliased = [a.asname for a in node.names if a.name == _GATE]
                renamed = [a for a in aliased if a not in (None, _GATE)]
                assert not renamed, f"{rel} imports {_GATE} as {renamed}; this scan cannot see it"
            if isinstance(node, ast.Name) and node.id == _GATE and isinstance(node.ctx, ast.Load):
                assert id(node) in called, (
                    f"{rel}:{node.lineno} uses {_GATE} as a value, not a call; a call through that "
                    f"value is invisible to this scan and to the spy"
                )
        _gate_calls(tree, rel, (), found)
    return Counter(found)


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


def _ldaps(k: Kit) -> object:
    """The real caller: ``LdapAuthenticator`` asserts the kwargs from its own ``_tls_kwargs``. The
    context measured is the one the gate rebuilds from those kwargs, which is a replica: ldap3 builds
    its own inside ``Tls.wrap_socket`` and holds none to compare against (the gate's docstring)."""
    return LdapAuthenticator(
        AuthSettings(
            ad_enabled=True,
            ad_server="ldaps://dc.test.invalid",
            ad_user_search_base="OU=Staff,DC=test,DC=invalid",
            ad_bind_dn="CN=svc-mefor,OU=Service,DC=test,DC=invalid",
            ad_bind_password="synthetic",
        )
    )


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
    "messagefoundry/config/tls_policy.py::assert_ldap3_tls_suites::connector": _ldaps,
    "messagefoundry/config/tls_policy.py::assert_hvac_tls_suites.narrowed_context::connector": (
        lambda k: tls_policy.assert_hvac_tls_suites({}, connector="Vault (measurement)")
    ),
    # A PINNED anchor, so the builder takes its own arm (the gate call this key names). The system
    # anchor does not narrow and delegates to build_asserted_https_handler, a different site.
    "messagefoundry/config/tls_policy.py::build_anchored_https_handler::connector": lambda k: (
        tls_policy.build_anchored_https_handler(
            anchor=tls_policy.TrustAnchor(cafile=k.cert, load_system_roots=False),
            connector="HTTP family (measurement)",
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
    "'HTTP-family destination (TLS verification disabled)'": lambda k: rest._insecure_opener(),
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

_SERVER_SITES = [s for s in _SITES if "listener" in s.rsplit("::", 1)[1]]
_CLIENT_SITES = [s for s in _SITES if s not in _SERVER_SITES]

#: The one site that needs an optional extra: urllib3 builds its context, and only [vault] brings it.
_VAULT_SITE = (
    "messagefoundry/config/tls_policy.py::assert_hvac_tls_suites.narrowed_context::connector"
)
#: Sites whose product exposes no context to tie the capture to: the hvac factory builds a fresh one
#: per connection, and ldap3 builds its own at connect time from the kwargs the gate replicated.
_HOLDS_NO_CONTEXT = frozenset(
    {_VAULT_SITE, "messagefoundry/config/tls_policy.py::assert_ldap3_tls_suites::connector"}
)
_VAULT_EXTRA = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)


def _params(sites: list[str]) -> list[Any]:
    """The sites as parameters, with the Vault site marked to skip when its extra is absent."""
    return [
        pytest.param(s, id=s, marks=_VAULT_EXTRA) if s == _VAULT_SITE else s for s in sorted(sites)
    ]


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


@dataclass(frozen=True)
class GateCall:
    """One call the spy saw: the context, and which site made the call."""

    ctx: ssl.SSLContext
    file: str  #: the caller's file, relative to the repository root
    function: str  #: the caller's qualified name, ``<locals>`` segments dropped
    connector: object  #: the ``connector=`` value it passed


@pytest.fixture
def captured(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[GateCall]]:
    """Wrap ``harden_cipher_suites`` wherever the engine bound it, recording each context it is
    handed and the site that handed it, then running the real assertion, so a measured context has
    passed the shipped gate."""
    original = tls_policy.harden_cipher_suites
    seen: list[GateCall] = []

    def spy(ctx: ssl.SSLContext, *args: Any, **kwargs: Any) -> None:
        caller = sys._getframe(1).f_code
        seen.append(
            GateCall(
                ctx=ctx,
                file=Path(caller.co_filename).resolve().relative_to(_PKG.parent).as_posix(),
                function=caller.co_qualname.replace(".<locals>", ""),
                connector=kwargs.get("connector"),
            )
        )
        original(ctx, *args, **kwargs)

    rebound = 0
    for name, module in list(sys.modules.items()):
        if name.startswith("messagefoundry") and getattr(module, _GATE, None) is original:
            monkeypatch.setattr(module, _GATE, spy)
            rebound += 1
    assert rebound >= 2, "the spy bound almost nowhere, so it would capture nothing"
    yield seen
    # A module first imported while the spy was live bound the spy itself, and monkeypatch will not
    # restore an attribute it did not set. Put the real gate back there too.
    for name, module in list(sys.modules.items()):
        if name.startswith("messagefoundry") and getattr(module, _GATE, None) is spy:
            setattr(module, _GATE, original)


def build_site(site: str, kit: Kit, seen: list[GateCall]) -> tuple[ssl.SSLContext, object]:
    """Run the site's real builder; return the one context it handed the gate, and what it built.

    The call must come from the site the key names, file and function, and with the key's connector
    when that is a literal. Otherwise a factory that reaches the gate through another function (a
    builder delegating to a sibling) would be filed under a site it never measured."""
    built = _SITES[site](kit)
    assert len(seen) == 1, f"{site}: the gate saw {len(seen)} contexts, expected exactly one"
    call = seen[0]
    file, function, connector = site.split("::")
    assert (call.file, call.function) == (file, function), (
        f"{site}: the gate call came from {call.file}::{call.function}, a different site"
    )
    if connector[:1] in ("'", '"'):
        assert call.connector == ast.literal_eval(connector), (
            f"{site}: connector {call.connector!r}"
        )
    return call.ctx, built


def _held_context(built: object) -> ssl.SSLContext | None:
    """The context a builder's product will hand its connections, where the product exposes one.

    Reads urllib's handler through the engine's own fail-closed reader, and requires exactly one
    HTTPS handler, so an opener carrying two cannot pass on whichever comes first."""
    if isinstance(built, ssl.SSLContext):
        return built
    if isinstance(built, urllib.request.OpenerDirector):
        every: list[object] = built.handlers  # type: ignore[attr-defined]
    else:
        every = [built]
    https = [h for h in every if isinstance(h, urllib.request.HTTPSHandler)]
    if not https:
        return None
    assert len(https) == 1, f"{len(https)} HTTPS handlers, so which one serves is ambiguous"
    return tls_policy.urllib_handler_context(https[0], connector="sigalg measurement")


# --- the population ------------------------------------------------------------------------------


def test_the_measured_population_is_the_derived_population() -> None:
    """A new ``harden_cipher_suites`` site fails here until it is measured; a removed one too."""
    derived = derived_sites()
    assert "messagefoundry/api/tls.py::build_api_ssl_context::'API/UI listener'" in derived, (
        "the derivation did not find the API listener, so it is not scanning the engine"
    )
    repeated = sorted(k for k, n in derived.items() if n > 1)
    assert not repeated, (
        f"two gate calls share one key, so one of them would go unmeasured: {repeated}. Give each "
        f"its own connector= label, then add a factory for the new one to _SITES."
    )
    missing, stale = sorted(set(derived) - set(_SITES)), sorted(set(_SITES) - set(derived))
    assert not missing and not stale, (
        f"harden_cipher_suites call sites and this module's measured list disagree. Unmeasured: "
        f"{missing}. Gone from the code: {stale}. Add a factory to _SITES that builds the new "
        f"context through its real builder; do not narrow the derivation to make this pass."
    )


@pytest.mark.parametrize("site", _params(list(_SITES)))
def test_each_site_builds_one_context_on_its_declared_side(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """The listener/destination split is read off the built context, not trusted from the label.
    Where the builder's product holds a context, it must be the one the gate saw, so a capture
    cannot be measuring a bystander."""
    ctx, built = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    is_server = ctx.protocol == ssl.PROTOCOL_TLS_SERVER
    assert is_server == (site in _SERVER_SITES), (
        f"{site}: the context's protocol says {'server' if is_server else 'client'}, "
        f"which is not the side this module files it under"
    )
    held = _held_context(built)
    if held is not None:
        assert held is ctx, f"{site}: the product holds a different context from the gated one"


def test_the_products_that_hold_no_context_are_the_named_ones(
    rsa_identity: tuple[str, str],
) -> None:
    """Liveness for the identity check above, which is skipped per site when nothing is held. The
    set of sites holding nothing must be exactly the named ones, compared as a set, so one site
    that stops exposing its context cannot be cancelled out by another that starts."""
    holding_none: set[str] = set()
    for site in _SITES:
        if site == _VAULT_SITE and not extra_is_installed(OPTIONAL_EXTRAS["vault"]):
            holding_none.add(site)  # cannot be built here; its measuring arms skip and say so
            continue
        with pytest.MonkeyPatch.context() as mp:
            if _held_context(_SITES[site](Kit(*rsa_identity, mp))) is None:
                holding_none.add(site)
    assert holding_none == _HOLDS_NO_CONTEXT, sorted(holding_none ^ _HOLDS_NO_CONTEXT)


# --- server side: which scheme does each listener sign with ------------------------------------------


@pytest.mark.parametrize("site", _params(_SERVER_SITES))
def test_listener_signs_with_rsa_pkcs1_when_that_is_all_the_peer_offers(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """TRIPWIRE. A TLS 1.2 peer offering only an rsa_pkcs1 SHA-2 scheme gets a PKCS#1 v1.5 handshake
    signature from an RSA-keyed listener, for each of the three.

    Goes red the day a server-side pin (``set_server_sigalgs``, Python 3.15), an OpenSSL default or
    the process's OpenSSL configuration stops this. Update the 11.3.1 record with it."""
    ctx, _ = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    for scheme in sorted(PINNED_RSA_PKCS1):
        reading = server_choice(ctx, [scheme])
        assert reading.refusal is None, f"{site}: refused a {scheme:#06x}-only peer: {reading}"
        assert reading.chosen == scheme, f"{site}: {reading}"


@pytest.mark.parametrize("site", _params(_SERVER_SITES))
def test_listener_controls_disagree_with_the_pkcs1_reading(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """The controls. Same suites, same groups, same certificate; only the offered schemes move.

    A PSS-only offer must come back rsa_pss_rsae_sha256, so the reading is not a constant. An
    ECDSA-only offer against an RSA certificate must fail the handshake, so the offer governs the
    choice. SHA-1 PKCS#1 v1.5 is refused by the default security level; signing with it would be
    the server-side widening, so this doubles as that tripwire."""
    ctx, _ = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    pss = server_choice(ctx, [RSA_PSS_RSAE_SHA256])
    assert pss.refusal is None and pss.chosen == RSA_PSS_RSAE_SHA256, f"{site}: {pss}"
    ecdsa = server_choice(ctx, [ECDSA_SECP256R1_SHA256, ECDSA_SECP384R1_SHA384])
    assert ecdsa.chosen is None and ecdsa.refusal is not None, (
        f"{site}: an ECDSA-only offer against an RSA certificate completed with {ecdsa}"
    )
    sha1 = server_choice(ctx, [RSA_PKCS1_SHA1])
    assert sha1.chosen is None and sha1.refusal is not None, f"{site}: signed with SHA-1: {sha1}"


@pytest.mark.parametrize("site", _params(_SERVER_SITES))
def test_listener_prefers_rsae_pss_when_the_peer_offers_both(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """A reading, pinned: with rsa_pkcs1_sha256 offered FIRST and rsa_pss_rsae_sha256 second, the
    listener still picks PSS. This is about rsa_pss_RSAE only. A peer whose only PSS offer is
    rsa_pss_pss_* (which needs a PSS-keyed certificate) still gets PKCS#1 v1.5 from an RSA-keyed
    listener, so this is no claim about "a peer that offers PSS at all"."""
    ctx, _ = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    both = server_choice(ctx, [RSA_PKCS1_SHA256, RSA_PSS_RSAE_SHA256])
    assert both.chosen == RSA_PSS_RSAE_SHA256, f"{site}: {both}"


def test_the_api_tls13_floor_refuses_the_tls12_hello(rsa_identity: tuple[str, str]) -> None:
    """One of at least three refusals available on 3.14 today: ``[api].tls_min_version = "1.3"``
    refuses the TLS 1.2 ClientHello outright, and no other listener exposes that knob. The others
    are an EC identity on any listener (the next test) and the process-wide ``OPENSSL_CONF`` route
    (the module docstring). This test raises no floor; it reads the operator setting that already
    exists, against the same hello the other arms accept."""
    cert, key = rsa_identity
    floored = api_tls.build_api_ssl_context(
        ApiSettings(tls_cert_file=cert, tls_key_file=key, tls_min_version="1.3")
    )
    reading = server_choice(floored, [RSA_PKCS1_SHA256])
    assert reading.chosen is None and reading.refusal is not None, reading
    stock = api_tls.build_api_ssl_context(ApiSettings(tls_cert_file=cert, tls_key_file=key))
    assert server_choice(stock, [RSA_PKCS1_SHA256]).chosen == RSA_PKCS1_SHA256


def test_the_minted_ec_api_identity_never_signs_with_pkcs1(tmp_path: Path) -> None:
    """The API listener's own default identity (ADR 0172), minted through the engine's real path
    (``ensure_api_tls_material`` with no operator certificate), is EC. Under it the listener signs
    with ECDSA and refuses a PKCS#1-only peer, so the RSA readings above describe an
    operator-supplied RSA certificate, not the listener's minted default."""
    api = ApiSettings()
    material = api_tls.ensure_api_tls_material(api, state_dir=tmp_path)
    assert material is not None, "no operator certificate, so the engine must mint one"
    cert, key = material
    assert Path(cert).parent == tmp_path, "the pair came from somewhere other than the mint"
    serving = api.model_copy(update={"tls_cert_file": cert, "tls_key_file": key})
    ctx = api_tls.build_api_ssl_context(serving)
    ecdsa = server_choice(ctx, [ECDSA_SECP256R1_SHA256], ECDHE_ECDSA_AEAD)
    assert ecdsa.chosen == ECDSA_SECP256R1_SHA256, ecdsa
    pkcs1 = server_choice(ctx, [RSA_PKCS1_SHA256], ECDHE_ECDSA_AEAD + ECDHE_RSA_AEAD)
    assert pkcs1.chosen is None and pkcs1.refusal is not None, pkcs1


# --- client side: which schemes does each destination offer ------------------------------------------


@pytest.mark.parametrize("site", _params(_CLIENT_SITES))
def test_destination_offers_rsa_pkcs1_at_tls12(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """TRIPWIRE. Each gated client context offers TLS 1.2 and the rsa_pkcs1 SHA-2 schemes, and no
    rsa_pkcs1 scheme beyond those plus SHA-224.

    A TLS 1.2 client must accept a ServerKeyExchange signed with any scheme it offered (RFC 5246
    section 7.4.1.4.1), so offering these is accepting a PKCS#1 v1.5 handshake signature from a
    peer that picks one. At TLS 1.3 these codepoints are valid only for certificate signatures.
    Goes red the day a pin removes them, or a lowered security level adds SHA-1. On a client
    context the pin that shapes this offer is ``set_server_sigalgs`` (Python 3.15), not
    ``set_client_sigalgs``: see ``tls_policy.narrow_signature_algorithms``. The SHA-224 pin it now
    applies keeps this tripwire green, because the ceiling admits SHA-224 absent."""
    ctx, _ = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    reading = client_offer(ctx)
    assert not offer_problems(reading), f"{site}: {offer_problems(reading)}"
    assert RSA_PSS_RSAE_SHA256 in reading.sigalgs, f"{site}: PSS not offered"


def test_the_client_tripwire_can_disagree() -> None:
    """Controls for the client half, through the SAME ``client_offer`` and ``offer_problems`` the
    tripwire uses, on real contexts. Each changes one thing and must trip exactly its own clause:

    * ``@SECLEVEL=4`` drops rsa_pkcs1_sha256 from the offer: the SHRINK clause fires.
    * ``@SECLEVEL=0`` adds rsa_pkcs1_sha1: the WIDEN clause fires.
    * a TLS 1.3 floor drops TLS 1.2 from supported_versions: the version clause fires.
    The stock context, the baseline, trips none of them."""
    assert not offer_problems(client_offer(ssl.create_default_context()))

    shrunk = ssl.create_default_context()
    shrunk.set_ciphers("DEFAULT:@SECLEVEL=4")
    (problem,) = offer_problems(client_offer(shrunk))
    assert "no longer offered" in problem and f"{RSA_PKCS1_SHA256:#06x}" in problem, problem

    widened = ssl.create_default_context()
    widened.set_ciphers("DEFAULT:@SECLEVEL=0")
    (problem,) = offer_problems(client_offer(widened))
    assert "WIDENED" in problem and f"{RSA_PKCS1_SHA1:#06x}" in problem, problem

    tls13 = ssl.create_default_context()
    tls13.minimum_version = ssl.TLSVersion.TLSv1_3
    (problem,) = offer_problems(client_offer(tls13))
    assert "TLS 1.2 not offered" in problem, problem


def test_the_hello_parser_round_trips_an_offer_it_did_not_come_from() -> None:
    """Control for the shared parsing path: a hand-built hello parses back to exactly its offer."""
    for offer in ([RSA_PSS_RSAE_SHA256, ECDSA_SECP256R1_SHA256], [RSA_PKCS1_SHA256, 0x0807]):
        (body,) = [
            b
            for kind, b in _handshake_messages(_build_client_hello(offer))
            if kind == _CLIENT_HELLO
        ]
        assert _u16_list(_client_hello_extensions(body)[_EXT_SIGNATURE_ALGORITHMS]) == offer


# --- the seam ----------------------------------------------------------------------------------------


def test_the_runtime_still_has_no_signature_algorithm_seam() -> None:
    """TRIPWIRE, in the ``harden_kex_groups`` style. CPython 3.15 adds ``set_client_sigalgs`` and
    ``set_server_sigalgs``. When this goes red, a real pin excluding rsa_pkcs1 has become possible
    and the 11.3.1 disposition should be re-read. It is asserted unconditionally on purpose.

    It is also the signal that the SHA-224 pin (BACKLOG #1171) has started acting. The SHA-224
    section below then runs its 3.15 branch, and its readings are the first measurement of it."""
    for name in ("set_client_sigalgs", "set_server_sigalgs"):
        assert not hasattr(ssl.SSLContext, name), (
            f"ssl.SSLContext.{name} exists on this interpreter, so the TLS 1.2 handshake signature "
            f"surface of ASVS 11.3.1 is now configurable (BACKLOG #1168), and the SHA-224 pin of "
            f"BACKLOG #1171 is live. Re-read both records."
        )
    assert hasattr(ssl.SSLContext, "set_ciphers"), "control: the attribute probe itself works"


# --- the SHA-224 pin (BACKLOG #1171, owner ruling 2026-09-29) -----------------------------------------

#: Shaped like ``ssl.get_sigalgs()`` on OpenSSL 3.5: IANA names in libssl's table order, the three
#: SHA-224 schemes included. One is upper-cased to prove the match ignores case.
_CATALOGUE = (
    "ecdsa_secp256r1_sha256",
    "ecdsa_sha224",
    "ecdsa_sha1",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "RSA_PKCS1_SHA224",
    "dsa_sha256",
    "dsa_sha224",
)
_CATALOGUE_WITHOUT_SHA224 = (
    "ecdsa_secp256r1_sha256:ecdsa_sha1:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:dsa_sha256"
)


class _SigalgCapableContext(ssl.SSLContext):
    """A stand-in for a CPython 3.15 context: a real context that also has ``set_server_sigalgs``.
    It records the argument instead of applying it, so the branch 3.14 cannot reach runs here."""

    sigalg_calls: list[str]

    def set_server_sigalgs(self, sigalgs: str) -> None:
        self.sigalg_calls = [*getattr(self, "sigalg_calls", []), sigalgs]


@pytest.fixture
def catalogue(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """``ssl.get_sigalgs`` returning :data:`_CATALOGUE`, with the per-process cache emptied on both
    sides so no reading leaks into another test."""
    monkeypatch.setattr(ssl, "get_sigalgs", lambda: list(_CATALOGUE), raising=False)
    tls_policy._sigalgs_without_sha224.cache_clear()
    yield
    tls_policy._sigalgs_without_sha224.cache_clear()


def _pin_acts_here() -> bool:
    """Whether the pin acts on this interpreter, asked of the pin itself on a throwaway context."""
    return tls_policy.narrow_signature_algorithms(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))


@pytest.mark.usefixtures("catalogue")
def test_the_pin_passes_openssls_catalogue_minus_sha224_in_order() -> None:
    ctx = _SigalgCapableContext(ssl.PROTOCOL_TLS_CLIENT)
    assert tls_policy.narrow_signature_algorithms(ctx) is True
    assert ctx.sigalg_calls == [_CATALOGUE_WITHOUT_SHA224]
    # Control: the catalogue did hold three SHA-224 names, so the filter removed something.
    assert sum("sha224" in n.lower() for n in _CATALOGUE) == 3


@pytest.mark.usefixtures("catalogue")
def test_both_narrowing_routes_reach_the_pin() -> None:
    """The default narrowing and the operator-string route both pin, so no seam can skip it."""
    default = _SigalgCapableContext(ssl.PROTOCOL_TLS_SERVER)
    tls_policy.narrow_to_approved_suites(default)
    operator = _SigalgCapableContext(ssl.PROTOCOL_TLS_SERVER)
    tls_policy.apply_operator_tls_ciphers(operator, "ECDHE-ECDSA-AES256-GCM-SHA384")
    assert default.sigalg_calls == [_CATALOGUE_WITHOUT_SHA224]
    assert operator.sigalg_calls == [_CATALOGUE_WITHOUT_SHA224]


@pytest.mark.usefixtures("catalogue")
def test_the_pin_reaches_the_inner_truststore_context() -> None:
    """truststore forwards only the methods it names; the pin must reach the context that
    handshakes. The outer wrapper is a real ``ssl.SSLContext``, so on 3.15 a call on it would
    succeed and change nothing."""
    truststore = pytest.importorskip("truststore")
    ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    assert hasattr(ctx, "_ctx"), "truststore moved its inner context; re-derive the pin"
    inner = _SigalgCapableContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx._ctx = inner
    assert tls_policy.narrow_signature_algorithms(ctx) is True
    assert inner.sigalg_calls == [_CATALOGUE_WITHOUT_SHA224]


@pytest.mark.usefixtures("catalogue")
def test_a_list_the_build_refuses_raises_runtime_error() -> None:
    class _Refusing(ssl.SSLContext):
        def set_server_sigalgs(self, sigalgs: str) -> None:
            raise ssl.SSLError("unrecognized signature algorithm")

    with pytest.raises(RuntimeError, match="without SHA-224"):
        tls_policy.narrow_signature_algorithms(_Refusing(ssl.PROTOCOL_TLS_CLIENT))


def test_a_catalogue_of_only_sha224_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing left once SHA-224 is gone is a refusal, not the "cannot list" no-op."""
    monkeypatch.setattr(ssl, "get_sigalgs", lambda: ["rsa_pkcs1_sha224"], raising=False)
    tls_policy._sigalgs_without_sha224.cache_clear()
    ctx = _SigalgCapableContext(ssl.PROTOCOL_TLS_CLIENT)
    try:
        with pytest.raises(RuntimeError, match="nothing but SHA-224"):
            tls_policy.narrow_signature_algorithms(ctx)
    finally:
        tls_policy._sigalgs_without_sha224.cache_clear()
    assert getattr(ctx, "sigalg_calls", []) == []


def test_an_unreadable_catalogue_pins_nothing_and_warns_once(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A 3.15 linked to an OpenSSL older than 3.4: the setter exists, the catalogue raises."""

    def unreadable() -> list[str]:
        raise NotImplementedError("Getting signature algorithms requires OpenSSL 3.4 or later.")

    monkeypatch.setattr(ssl, "get_sigalgs", unreadable, raising=False)
    monkeypatch.setattr(tls_policy, "_SIGALGS_PIN_WARNED", False)
    tls_policy._sigalgs_without_sha224.cache_clear()
    try:
        ctx = _SigalgCapableContext(ssl.PROTOCOL_TLS_CLIENT)
        with caplog.at_level("WARNING", logger=tls_policy.logger.name):
            assert tls_policy.narrow_signature_algorithms(ctx) is False
            assert tls_policy.narrow_signature_algorithms(ctx) is False
    finally:
        tls_policy._sigalgs_without_sha224.cache_clear()
    assert getattr(ctx, "sigalg_calls", []) == [], "a list was applied from no catalogue"
    warned = [r for r in caplog.records if "SHA-224" in r.getMessage()]
    assert len(warned) == 1, [r.getMessage() for r in warned]


def test_without_the_setter_nothing_is_called(monkeypatch: pytest.MonkeyPatch) -> None:
    """The 3.14 branch: no setter, so the catalogue is never read and ``False`` is the report.

    Driven with a stand-in that has no setter on any interpreter, and with a real context where the
    real one has none, which is CPython 3.14."""
    reads: list[int] = []

    def spy() -> list[str]:
        reads.append(1)
        return list(_CATALOGUE)

    monkeypatch.setattr(ssl, "get_sigalgs", spy, raising=False)
    tls_policy._sigalgs_without_sha224.cache_clear()

    class _NoSetter:
        pass

    try:
        assert tls_policy.narrow_signature_algorithms(_NoSetter()) is False  # type: ignore[arg-type]
        if not hasattr(ssl.SSLContext, "set_server_sigalgs"):
            real = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            assert tls_policy.narrow_signature_algorithms(real) is False
            tls_policy.narrow_to_approved_suites(real)
    finally:
        tls_policy._sigalgs_without_sha224.cache_clear()
    assert reads == [], "the catalogue was read on a runtime that cannot apply it"


def _version_matched_stock(ctx: ssl.SSLContext) -> ssl.SSLContext:
    """A stock client context with ``ctx``'s protocol bounds, the control for its offer."""
    stock = ssl.create_default_context()
    stock.minimum_version = ctx.minimum_version
    stock.maximum_version = ctx.maximum_version
    return stock


@pytest.mark.parametrize("site", _params(_CLIENT_SITES))
def test_destination_sha224_offer_follows_the_runtime(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """Where the pin acts, no SHA-224 scheme is offered, and the offer only ever shrinks, by
    SHA-224 and the ML-DSA schemes the catalogue omits. Where it cannot act, which is 3.14, the
    offer equals a stock context's with the same protocol bounds, whole and in order."""
    ctx, _ = build_site(site, Kit(*rsa_identity, monkeypatch), captured)
    offered = client_offer(ctx).sigalgs
    stock = client_offer(_version_matched_stock(ctx)).sigalgs
    if _pin_acts_here():
        assert not set(offered) & SHA224_SCHEMES, f"{site}: SHA-224 still offered: {offered}"
        assert set(offered) <= set(stock), f"{site}: the pin widened the offer"
        dropped = set(stock) - set(offered)
        assert dropped <= SHA224_SCHEMES | MLDSA_SCHEMES, f"{site}: also dropped {sorted(dropped)}"
    else:
        assert offered == stock, f"{site}: the offer moved on a runtime with no pin"


@pytest.mark.parametrize("site", _params(_SERVER_SITES))
def test_listener_sha224_signature_follows_the_runtime(
    site: str, rsa_identity: tuple[str, str], monkeypatch: pytest.MonkeyPatch, captured: list[Any]
) -> None:
    """A TLS 1.2 peer offering only rsa_pkcs1_sha224. A stock server context with the same RSA
    certificate is the control: it must sign with SHA-224, so a refusal from the listener is the
    pin's doing. Where the pin acts the listener refuses; where it cannot, it does what stock does."""
    cert, key = rsa_identity
    ctx, _ = build_site(site, Kit(cert, key, monkeypatch), captured)
    stock_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    stock_ctx.load_cert_chain(cert, key)
    stock = server_choice(stock_ctx, [RSA_PKCS1_SHA224])
    assert stock.chosen == RSA_PKCS1_SHA224, (
        f"control: a stock server did not sign SHA-224: {stock}"
    )
    reading = server_choice(ctx, [RSA_PKCS1_SHA224])
    if _pin_acts_here():
        assert reading.chosen is None and reading.refusal is not None, f"{site}: {reading}"
    else:
        assert reading.chosen == RSA_PKCS1_SHA224, f"{site}: {reading}"

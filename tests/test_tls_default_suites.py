# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #300: the approved AEAD suites are the DEFAULT TLS 1.2 list on every context the engine builds.

Two owner rulings allowed it, and the ADR 0188 amendment records both. The interop rationale for the
six CBC-SHA2 suites the interpreter enables reaches only MLLP and DICOM (2026-08-22, BACKLOG #1170),
and on 2026-09-23 the owner removed them from MLLP and DICOM as well, with no peer census run.

What this file proves, per hop, and why each instrument is there:

* **A real handshake.** Each hop's BUILT context is driven through an in-memory TLS handshake
  against a peer that offers only a CBC-SHA2 suite (must fail) and against one that offers only an
  AEAD suite (must succeed). A suite-list read would show what the context offers; only a handshake
  shows what it refuses. The peers are capped at TLS 1.2, because TLS 1.3 is AEAD-only and out of
  ``set_ciphers``' reach, so a TLS 1.3 handshake would succeed for a reason unrelated to this change.
* **The control.** The same CBC-only peer handshakes cleanly with an UNTOUCHED stock context of the
  same shape. Without it, a peer that could not handshake with anybody would make every refusal
  below pass for the wrong reason.
* **The order.** Nothing checked suite ORDER before this item. Each hop's TLS 1.2 list must equal
  ``APPROVED_TLS12_SUITES`` as a list, and that tuple's order must follow a stated rule.
* **The copies.** ``apiclient/client.py`` and ``ide/src/engineClient.ts`` cannot import the engine's
  tuple, so each carries a copy, pinned here to it, order included.
* **The call sites.** Every engine module that asserts a suite list must also narrow one, counted the
  same way ``tests/test_tls_policy.py`` counts the assertion against the key-exchange pin.
"""

from __future__ import annotations

import ast
import datetime
import re
import ssl
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from _ast_sites import call_sites
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from messagefoundry.api.tls import build_api_ssl_context
from messagefoundry.apiclient import client as apiclient
from messagefoundry.auth.oidc_http import build_idp_opener
from messagefoundry.config.settings import ApiSettings, StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import (
    APPROVED_TLS12_SUITES,
    TrustAnchor,
    build_smtp_tls_context,
    narrow_to_approved_suites,
    urllib_handler_context,
)
from messagefoundry.config.wiring import Http, build_inbound_connection
from messagefoundry.logging_setup import SyslogForward, _build_tls_context
from messagefoundry.pipeline import alert_sinks
from messagefoundry.pipeline.wiring_runner import _source_config
from messagefoundry.store import postgres
from messagefoundry.transports import dicom, mllp, remotefile, rest, soap
from messagefoundry.transports.base import build_source
from messagefoundry.transports.http_listener import HttpSource
from messagefoundry.verify.smoke import live_smoke_ssl_context

_ROOT = Path(__file__).resolve().parent.parent

#: One CBC-SHA2 suite and one AEAD suite the ECDSA test certificate can serve. Both are in the
#: interpreter's default list on every supported build, which is what makes the control meaningful.
CBC_ONLY = "ECDHE-ECDSA-AES128-SHA256"
AEAD_ONLY = "ECDHE-ECDSA-AES128-GCM-SHA256"

#: Whether this build's interpreter default offers anything beyond the approved list. The controls
#: below need it to: on a build whose default is ALREADY the approved list, a stock context cannot
#: talk to a CBC-only peer either, and "the narrowing did it" cannot be shown. They SKIP there rather
#: than fail, because the product is still correct on such a build; only the control is unavailable.
_DEFAULT_OFFERS_MORE = bool(
    {str(c["name"]) for c in ssl.create_default_context().get_ciphers()}
    - set(APPROVED_TLS12_SUITES)
    - {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"}
)
_needs_wider_default = pytest.mark.skipif(
    not _DEFAULT_OFFERS_MORE, reason="this build's default offers only the approved suites"
)

_NB = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
_NA = datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC)


# --- a tiny PKI: one CA and one localhost leaf, RFC 5280-conformant for VERIFY_X509_STRICT ---------


@dataclass(frozen=True)
class _Pki:
    ca: str
    cert: str
    key: str


def _write_key(path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> _Pki:
    """A CA and a ``localhost`` leaf it signs. SKI, AKI and KeyUsage are present because
    ``harden_verify_flags`` turns on ``VERIFY_X509_STRICT``, which refuses a chain without them."""
    d = tmp_path_factory.mktemp("pki")
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BACKLOG 300 test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB)
        .not_valid_after(_NA)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NB)
        .not_valid_after(_NA)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path, cert_path, key_path = d / "ca.pem", d / "leaf.pem", d / "leaf-key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    _write_key(key_path, leaf_key)
    return _Pki(ca=str(ca_path), cert=str(cert_path), key=str(key_path))


# --- the handshake instrument ----------------------------------------------------------------------


def _handshake(client: ssl.SSLContext, server: ssl.SSLContext) -> str:
    """Drive a real TLS handshake between two contexts in memory; return the negotiated suite.

    Raises :class:`ssl.SSLError` from whichever side gives up. No socket, no port, no thread: two
    ``MemoryBIO`` pairs pumped until both sides report done."""
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    c = client.wrap_bio(c_in, c_out, server_hostname="localhost")
    s = server.wrap_bio(s_in, s_out, server_side=True)
    done = {"c": False, "s": False}
    for _ in range(50):
        for name, obj in (("c", c), ("s", s)):
            if done[name]:
                continue
            try:
                obj.do_handshake()
                done[name] = True
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if done["c"] and done["s"]:
            cipher = c.cipher()
            assert cipher is not None
            return cipher[0]
    raise AssertionError("handshake neither completed nor failed within 50 rounds")


def _peer_server(pki: _Pki, suites: str) -> ssl.SSLContext:
    """A TLS 1.2-only server offering exactly ``suites``, presenting the leaf."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(pki.cert, pki.key)
    ctx.set_ciphers(suites)
    return ctx


def _peer_client(pki: _Pki, suites: str) -> ssl.SSLContext:
    """A TLS 1.2-only client offering exactly ``suites``, trusting the test CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(pki.ca)
    ctx.set_ciphers(suites)
    return ctx


def _tls12(ctx: ssl.SSLContext) -> list[str]:
    """The TLS 1.2 suites ``ctx`` offers, in its preference order (TLS 1.3 is outside the claim)."""
    return [str(c["name"]) for c in ctx.get_ciphers() if c["protocol"] != "TLSv1.3"]


def _https_context(opener: urllib.request.OpenerDirector) -> ssl.SSLContext:
    """The context inside ``opener``'s one ``HTTPSHandler``."""
    handlers: list[urllib.request.BaseHandler] = opener.handlers  # type: ignore[attr-defined]
    handler = next(h for h in handlers if isinstance(h, urllib.request.HTTPSHandler))
    return urllib_handler_context(handler, connector="test")


def _trusting(ctx: ssl.SSLContext, pki: _Pki) -> ssl.SSLContext:
    """Add the test CA to a FRESH hop context whose own anchor is the OS store. Adding a root does
    not touch the suite list, which is the only thing under test."""
    ctx.load_verify_locations(pki.ca)
    return ctx


# --- every hop, built exactly as its connector builds it ------------------------------------------

#: Client-side hops: each builder returns the context the connector would hand to its handshake.
CLIENT_HOPS: dict[str, Callable[[_Pki], ssl.SSLContext]] = {
    "SMTP (EMAIL / DIRECT / alert email)": lambda p: build_smtp_tls_context(
        host="localhost", cell="test SMTP", ca_file=p.ca
    ),
    "HTTP family, default anchor": lambda p: _trusting(
        _https_context(rest._no_redirect_opener()), p
    ),
    "HTTP family, pinned anchor": lambda p: _https_context(
        rest._no_redirect_opener(trust_anchor=TrustAnchor(cafile=p.ca, load_system_roots=False))
    ),
    "HTTP family, augment anchor": lambda p: _https_context(
        rest._no_redirect_opener(trust_anchor=TrustAnchor(cafile=p.ca, load_system_roots=True))
    ),
    "HTTP family, verification disabled": lambda p: _https_context(rest._insecure_opener()),
    "HTTP family, expired-certificate tolerance": lambda p: _https_context(
        rest._expiry_relaxed_opener(
            "localhost", trust_anchor=TrustAnchor(cafile=p.ca, load_system_roots=False)
        )
    ),
    "SOAP, mutual TLS": lambda p: _https_context(
        soap._client_cert_opener(
            p.cert, p.key, None, trust_anchor=TrustAnchor(cafile=p.ca, load_system_roots=False)
        )
    ),
    "alert webhook": lambda p: _trusting(
        _https_context(alert_sinks._build_no_redirect_opener()), p
    ),
    "OIDC identity provider": lambda p: _https_context(build_idp_opener(p.ca, enforcing=False)),
    "syslog TLS forwarder": lambda p: _build_tls_context(
        SyslogForward(host="localhost", protocol="tls", tls_ca_file=p.ca)
    ),
    "FTPS": lambda p: remotefile._ftps_ssl_context({"host": "localhost", "tls_ca_file": p.ca}),
    "Postgres store, pinned CA": lambda p: postgres._build_ssl(
        StoreSettings(
            backend=StoreBackend.POSTGRES,
            server="localhost",
            database="mefor",
            username="mefor",
            ssl_root_cert=p.ca,
        )
    ),
    "verify live smoke": lambda p: live_smoke_ssl_context(ca_file=p.ca),
    "apiclient (pinned cacert)": lambda p: apiclient._build_verify_context(p.ca, None, None),
    "MLLP destination": lambda p: _built(
        mllp._mllp_ssl_context(
            {"tls": True, "host": "localhost", "tls_ca_file": p.ca}, server=False
        )
    ),
    "DICOM destination": lambda p: _built(
        dicom._client_ssl_context({"tls": True, "host": "localhost", "tls_ca_file": p.ca})
    ),
}


def _built(ctx: ssl.SSLContext | None) -> ssl.SSLContext:
    assert ctx is not None, "tls=true must build a context"
    return ctx


def _listener_settings(p: _Pki) -> dict[str, Any]:
    return {"tls": True, "tls_cert_file": p.cert, "tls_key_file": p.key}


def _http_listener(p: _Pki) -> ssl.SSLContext:
    ic = build_inbound_connection(
        "IB_HTTP_300",
        Http(port=0, tls=True, tls_cert_file=p.cert, tls_key_file=p.key),
        router="r",
    )
    source = build_source(_source_config(ic, "127.0.0.1", {}))
    assert isinstance(source, HttpSource)
    return _built(source._ssl)


#: Server-side hops: each builder returns the context the listener would serve with.
SERVER_HOPS: dict[str, Callable[[_Pki], ssl.SSLContext]] = {
    "API / UI listener": lambda p: build_api_ssl_context(
        ApiSettings(tls_cert_file=p.cert, tls_key_file=p.key)
    ),
    "MLLP listener": lambda p: _built(mllp._mllp_ssl_context(_listener_settings(p), server=True)),
    "DICOM listener": lambda p: _built(dicom._server_ssl_context(_listener_settings(p))),
    "HTTP listener": _http_listener,
}


# --- the controls: the CBC-only peers are real, and a stock context still talks to them ------------


@_needs_wider_default
def test_control_a_stock_client_context_handshakes_with_the_cbc_only_server(pki: _Pki) -> None:
    """CONTROL for every client refusal below. The untouched interpreter default still offers
    ``CBC_ONLY``, so this handshake completes on it. If it failed, every refusal below would be
    explained by a broken peer rather than by the narrowing."""
    stock = ssl.create_default_context(cafile=pki.ca)
    assert _handshake(stock, _peer_server(pki, CBC_ONLY)) == CBC_ONLY


@_needs_wider_default
def test_control_a_stock_server_context_handshakes_with_the_cbc_only_client(pki: _Pki) -> None:
    """CONTROL for every server refusal below, the same argument from the other side."""
    stock = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    stock.load_cert_chain(pki.cert, pki.key)
    assert _handshake(_peer_client(pki, CBC_ONLY), stock) == CBC_ONLY


# --- per hop: refuses CBC-only, accepts AEAD, offers the approved list in order --------------------


@pytest.mark.parametrize("hop", sorted(CLIENT_HOPS))
def test_client_hop_refuses_a_cbc_only_server(hop: str, pki: _Pki) -> None:
    with pytest.raises(ssl.SSLError):
        _handshake(CLIENT_HOPS[hop](pki), _peer_server(pki, CBC_ONLY))


@pytest.mark.parametrize("hop", sorted(CLIENT_HOPS))
def test_client_hop_accepts_an_aead_server(hop: str, pki: _Pki) -> None:
    """The positive half. A refusal alone is also what a context that refused EVERYTHING would do."""
    assert _handshake(CLIENT_HOPS[hop](pki), _peer_server(pki, AEAD_ONLY)) == AEAD_ONLY


@pytest.mark.parametrize("hop", sorted(SERVER_HOPS))
def test_server_hop_refuses_a_cbc_only_client(hop: str, pki: _Pki) -> None:
    with pytest.raises(ssl.SSLError):
        _handshake(_peer_client(pki, CBC_ONLY), SERVER_HOPS[hop](pki))


@pytest.mark.parametrize("hop", sorted(SERVER_HOPS))
def test_server_hop_accepts_an_aead_client(hop: str, pki: _Pki) -> None:
    assert _handshake(_peer_client(pki, AEAD_ONLY), SERVER_HOPS[hop](pki)) == AEAD_ONLY


@pytest.mark.parametrize("hop", sorted(CLIENT_HOPS | SERVER_HOPS))
def test_every_hop_offers_the_approved_list_in_order(hop: str, pki: _Pki) -> None:
    """The ORDER check (BACKLOG #300). A list comparison, so a reordered default fails here even
    when every suite in it is approved."""
    ctx = (CLIENT_HOPS | SERVER_HOPS)[hop](pki)
    assert _tls12(ctx) == list(APPROVED_TLS12_SUITES), f"{hop}: {_tls12(ctx)}"


def test_the_shared_module_level_openers_are_narrowed_too() -> None:
    """The two openers built once at import and shared by every connection that needs no extra
    handler. The per-hop tests build FRESH ones so they can add a trust root without touching shared
    state; this reads the shared objects themselves."""
    for opener in (rest._NO_REDIRECT_OPENER, alert_sinks._NO_REDIRECT_OPENER):
        assert _tls12(_https_context(opener)) == list(APPROVED_TLS12_SUITES)


def test_the_apiclient_os_trust_store_branch_is_narrowed_too() -> None:
    """``cacert=None`` takes the ``truststore`` branch, which verifies against the OS store, so no
    test certificate can complete a handshake there. The suite list is the claim, so read that."""
    pytest.importorskip("truststore")
    assert _tls12(apiclient._build_verify_context(None, None, None)) == list(APPROVED_TLS12_SUITES)


def test_an_operator_api_tls_ciphers_still_wins_over_the_default(pki: _Pki) -> None:
    """The narrowed default is only the DEFAULT: a configured ``[api].tls_ciphers`` is applied as
    written, so the listener must offer that one suite and nothing else at TLS 1.2."""
    one = "ECDHE-ECDSA-AES256-GCM-SHA384"
    ctx = build_api_ssl_context(
        ApiSettings(tls_cert_file=pki.cert, tls_key_file=pki.key, tls_ciphers=one)
    )
    assert _tls12(ctx) == [one]


# --- the order rule, and the claim that narrowing never reorders ---------------------------------


def _rank(name: str) -> tuple[int, int]:
    """ECDHE before DHE; within one key exchange AES-256-GCM, then AES-128-GCM, then ChaCha20."""
    kx = 0 if name.startswith("ECDHE-") else 1
    cipher = 0 if "AES256-GCM" in name else 1 if "AES128-GCM" in name else 2
    return kx, cipher


def test_the_approved_order_follows_the_stated_rule() -> None:
    assert list(APPROVED_TLS12_SUITES) == sorted(APPROVED_TLS12_SUITES, key=_rank)
    assert len(set(APPROVED_TLS12_SUITES)) == len(APPROVED_TLS12_SUITES), "a suite is listed twice"


def test_the_rank_rule_can_reject_a_wrong_order() -> None:
    """CONTROL for the test above: a sort-equality check is vacuous if every order sorts to itself."""
    swapped = list(APPROVED_TLS12_SUITES)
    swapped[0], swapped[-1] = swapped[-1], swapped[0]
    assert swapped != sorted(swapped, key=_rank)


@_needs_wider_default
def test_narrowing_removes_suites_and_never_reorders_the_ones_it_keeps() -> None:
    """The tuple's comment claims it IS the interpreter default's order with the six CBC-SHA2 suites
    taken out. Measured against the local default rather than restated, because the default list is
    a property of the linked OpenSSL."""
    default = _tls12(ssl.create_default_context())
    kept = [n for n in default if n in APPROVED_TLS12_SUITES]
    assert kept == list(APPROVED_TLS12_SUITES)
    assert set(default) - set(APPROVED_TLS12_SUITES), "control: the default must offer more"


# --- narrow_to_approved_suites carries the security level over; it neither raises nor lowers it ----


@pytest.mark.parametrize("level", [1, 2, 3])
def test_narrowing_keeps_the_context_security_level(level: int) -> None:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.set_ciphers(f"@SECLEVEL={level}:ALL")
    assert ctx.security_level == level, "control: the level did not take before narrowing"
    narrow_to_approved_suites(ctx)
    assert ctx.security_level == level


# --- the two client copies of the tuple ------------------------------------------------------------


def test_the_apiclient_copy_matches_the_engine_tuple() -> None:
    """``apiclient/`` may not import ``config/`` (CLAUDE.md section 4), so it keeps a copy."""
    assert apiclient._APPROVED_TLS12_SUITES == APPROVED_TLS12_SUITES


def test_the_ide_copy_matches_the_engine_tuple() -> None:
    """``ide/src/engineClient.ts`` is TypeScript and cannot read the tuple at all. Read the array
    literal out of the source and compare it, order included."""
    text = (_ROOT / "ide" / "src" / "engineClient.ts").read_text(encoding="utf-8")
    match = re.search(r"export const TLS_12_SUITES: readonly string\[\] = \[(.*?)\];", text, re.S)
    assert match, "TLS_12_SUITES array literal not found in ide/src/engineClient.ts"
    names = re.findall(r'"([^"]+)"', match.group(1))
    assert tuple(names) == APPROVED_TLS12_SUITES


# --- the call-site count: every engine module that asserts a suite list narrows one -----------------


def _call_counts() -> dict[str, tuple[int, int]]:
    """``{module: (assertions, narrowings)}`` for every engine module outside ``tls_policy.py``,
    counted as real call nodes by ``tests/_ast_sites.call_sites``, so a docstring or comment that
    names a function cannot stand in for a call."""
    counts: dict[str, tuple[int, int]] = {}
    for path in sorted((_ROOT / "messagefoundry").rglob("*.py")):
        if path.name == "tls_policy.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        asserts = len(call_sites(tree, "harden_cipher_suites", bare_only=True))
        narrows = sum(
            len(call_sites(tree, name, bare_only=True))
            for name in ("narrow_to_approved_suites", "apply_connection_tls_ciphers")
        )
        counts[path.relative_to(_ROOT).as_posix()] = (asserts, narrows)
    return counts


def test_every_module_that_asserts_a_suite_list_also_narrows_one() -> None:
    """Call-site coverage, counted per file like the key-exchange guard in ``test_tls_policy.py``.

    ``harden_cipher_suites`` asserts and never narrows, by design, so a NEW context builder could
    assert on the interpreter's list, CBC-SHA2 included, and pass every other test. Each assertion
    must be matched by a narrowing: ``narrow_to_approved_suites`` directly, or
    ``apply_connection_tls_ciphers`` (MLLP / DICOM), which narrows when no operator string is set.
    ``tls_policy.py`` is excluded, as in that guard: it defines the functions and also asserts on
    LIBRARY-built contexts (ldap3, hvac, urllib3) that the engine cannot narrow.
    """
    counts = _call_counts()
    problems = [f"{m}: {a} assert, {n} narrow" for m, (a, n) in counts.items() if a > n]
    assert not problems, (
        f"module(s) assert a TLS suite list without narrowing it to the approved default "
        f"(BACKLOG #300): {problems}. Call narrow_to_approved_suites(ctx) before "
        f"harden_cipher_suites."
    )
    # Liveness receipt: a scan that found no call at all would pass over nothing.
    narrows = sum(n for _, n in counts.values())
    assert narrows >= 10, f"expected the known narrowing sites, found {narrows}"

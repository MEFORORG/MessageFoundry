# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Call-site coverage for the forward-secrecy assertion (ASVS 12.1.2), one test per hardened site.

``tests/test_tls_policy.py`` covers the FUNCTION and derives its call-site list from the presence of
``harden_kex_groups(`` in a file. That predicate can only find a HALF-hardened site: a context that
pins key-exchange groups but skips the cipher assertion. Every site hardened here calls neither
helper today, so that scan passes over all of them in silence — the instrument that guarded the
residual could not detect the residual. This file is the other half: it names each construction and
proves the assertion is reached inside it.

**How these tests prove the call is REACHED, not merely present.** Two instruments, because the
sites come in two shapes:

* Sites that BUILD a context (``every_suite_looks_weak``). The fixture patches
  ``tls_policy._is_forward_secret`` to report every suite non-forward-secret, then the test builds
  the site's context exactly as the engine does and requires a ``ValueError`` naming that site's
  connector label. A decoy call cannot satisfy it: the raise can only come from
  ``harden_cipher_suites`` running against the real context the site returns.
* Sites that hand urllib's own context through an opener (``asserted_contexts``). Presence of a
  context proves nothing there — see that fixture — so those tests require the context the opener
  will actually use to be the SAME OBJECT the assertion ran on.

Delete the call from any one site and that site's test goes red while the rest stay green, verified
by mutation one site at a time. ``every_suite_looks_weak`` is a POSITIVE CONTROL in its own right:
:func:`test_the_patch_makes_a_shipped_context_raise` asserts a plain default context raises under it,
so a test that saw no raise would be reporting a missing call rather than an inert instrument.
"""

from __future__ import annotations

import ast
import contextlib
import datetime
import re
import socket
import ssl
import threading
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import ldap3
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry import logging_setup
from messagefoundry.auth import ldap as ldap_auth
from messagefoundry.auth import oidc_http, trust_anchors
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.config import secretprovider_vault, tls_policy, tls_probe
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AuthSettings,
    StoreBackend,
    StoreSettings,
)
from messagefoundry.config.wiring import FHIR, Rest, Soap
from messagefoundry.pipeline import alert_sinks
from messagefoundry.store import crypto_transit, keyprovider_vault, postgres
from messagefoundry.transports import build_destination, database, rest, soap
from messagefoundry.transports.http_auth import with_http_digest
from tests._ast_sites import call_sites, find_funcs
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

# Imported at module scope ON PURPOSE. `rest` and `alert_sinks` build their shared opener AT IMPORT,
# so a first import inside the every_suite_looks_weak fixture would raise during module execution and
# fail the test for the wrong reason. Importing here puts them in sys.modules before any patch runs,
# which also means the assertions below exercise the same module objects the engine uses.


def _cipher_names(ctx: ssl.SSLContext) -> list[str]:
    return [str(c["name"]) for c in ctx.get_ciphers()]


def _tls12_names(ctx: ssl.SSLContext) -> list[str]:
    """The TLS 1.2 suites ``ctx`` offers, in order, classified by protocol as the guards do."""
    return [str(c["name"]) for c in ctx.get_ciphers() if c.get("protocol") != "TLSv1.3"]


@pytest.fixture
def every_suite_looks_weak(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Make the shipped assertion fire on ANY context, so reaching it is observable.

    The engine's real default suite list is entirely forward-secret on every supported runtime, so a
    correctly-wired call site raises nothing and is indistinguishable from a missing one. Reporting
    the whole list as weak inverts that: the call now raises wherever it runs, and only where it runs.
    """
    monkeypatch.setattr(tls_policy, "_is_forward_secret", lambda cipher: False)
    yield


def _self_signed(tmp_path: Path) -> tuple[Path, Path]:
    """A self-signed EC cert + key PEM under ``tmp_path``; returns ``(cert_path, key_path)``."""
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


@pytest.fixture
def asserted_contexts(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, ssl.SSLContext]]:
    """Record every ``(connector, context)`` pair the shipped assertion actually ran on.

    The second instrument in this file, and the one the opener tests need. "Does this opener hold an
    SSLContext?" CANNOT fail on CPython 3.14: ``urllib.request.HTTPSHandler(context=None)`` builds a
    context in its own constructor, so a handler the engine never touched still answers yes. Measured
    the hard way, after a first version of these tests passed under every mutation. Identity is the
    discriminating question: is the context this opener carries the SAME OBJECT the assertion ran on?

    Wraps rather than replaces ``harden_cipher_suites``, so the real check still runs.
    """
    seen: list[tuple[str, ssl.SSLContext]] = []
    real = tls_policy.harden_cipher_suites

    def spy(ctx: ssl.SSLContext, *, connector: str) -> None:
        seen.append((connector, ctx))
        real(ctx, connector=connector)

    monkeypatch.setattr(tls_policy, "harden_cipher_suites", spy)
    return seen


def _opener_context(opener: urllib.request.OpenerDirector) -> ssl.SSLContext | None:
    """The ``SSLContext`` ``opener``'s https handler will hand every connection it opens."""
    for handler in opener.handlers:  # type: ignore[attr-defined]  # typeshed omits it
        if hasattr(handler, "https_open"):
            ctx = getattr(handler, "_context", None)
            if isinstance(ctx, ssl.SSLContext):
                return ctx
    return None


def _assert_opener_context_was_checked(
    opener: urllib.request.OpenerDirector,
    recorded: list[tuple[str, ssl.SSLContext]],
    *,
    label: str,
    site: str,
) -> None:
    """Require that the context ``opener`` carries is one the assertion ran on, under ``label``."""
    ctx = _opener_context(opener)
    assert ctx is not None, f"{site}: the opener's https handler carries no SSLContext at all"
    matches = [lbl for lbl, seen in recorded if seen is ctx]
    assert matches, (
        f"{site}: the context this opener will use was never passed to harden_cipher_suites. "
        f"The assertion ran on {[lbl for lbl, _ in recorded]}, none of which is this object, so "
        f"this hop's suite list is inherited and unchecked."
    )
    assert label in matches[0], f"{site}: asserted under {matches[0]!r}, expected {label!r}"


_HTTPS = "https://partner.example.org/ingest"


def _spec_for(connector_type: ConnectorType) -> Any:
    """The wiring spec for one HTTP-family connector, so the digest test covers all three."""
    return {
        ConnectorType.REST: lambda: Rest(url=_HTTPS),
        ConnectorType.FHIR: lambda: FHIR(url=_HTTPS),
        ConnectorType.SOAP: lambda: Soap(url=_HTTPS),
    }[connector_type]()


def _pg_settings(**overrides: Any) -> StoreSettings:
    """A minimally-valid Postgres ``[store]`` block, so the TLS arms are reachable at all."""
    return StoreSettings(
        backend=StoreBackend.POSTGRES,
        server="db.example.org",
        database="mefor",
        username="mefor",
        **overrides,
    )


# --- the positive control ------------------------------------------------------------------------


def test_the_patch_makes_a_shipped_context_raise(every_suite_looks_weak: None) -> None:
    """Liveness receipt for every test below: under the patch, a plain default context RAISES.

    Without this, a site test that saw no raise would be ambiguous between 'the call is missing' and
    'the instrument is inert'. This is the run's non-zero reading.
    """
    with pytest.raises(ValueError, match="non-forward-secret"):
        tls_policy.harden_cipher_suites(ssl.create_default_context(), connector="control")


def test_without_the_patch_the_same_context_is_silent() -> None:
    """The other half of the control: the shipped default really is all-forward-secret, so a raise in
    any test below can only come from the patch, never from a genuinely weak shipped suite list."""
    tls_policy.harden_cipher_suites(ssl.create_default_context(), connector="control")


# --- HTTP-family egress: transports/rest.py -------------------------------------------------------


def test_rest_shared_verifying_opener_asserts(every_suite_looks_weak: None) -> None:
    """``_no_redirect_opener`` — the default REST / FHIR / DICOMweb / fhir_lookup egress path, and the
    construction the module-level ``_NO_REDIRECT_OPENER`` is itself built from."""

    with pytest.raises(ValueError, match="HTTP-family destination"):
        rest._no_redirect_opener()


def test_rest_insecure_opener_asserts(every_suite_looks_weak: None) -> None:
    """``_insecure_opener`` — the audited ``verify_tls=false`` escape. Verification is off but the hop
    is still encrypted, so the suite list still decides whether recorded traffic stays private."""

    with pytest.raises(ValueError, match="TLS verification disabled"):
        rest._insecure_opener()


def test_rest_expiry_relaxed_opener_asserts(every_suite_looks_weak: None) -> None:
    """``_expiry_relaxed_opener`` — the ``tls_allow_expired`` path, shared verbatim by SOAP."""

    with pytest.raises(ValueError, match="expired-certificate tolerance"):
        rest._expiry_relaxed_opener("partner.example.org")


def test_rest_shared_opener_context_is_the_one_that_was_asserted(
    asserted_contexts: list[tuple[str, ssl.SSLContext]],
) -> None:
    """The assertion ran on the object this opener will actually send through, not a look-alike.

    Worth stating precisely, because the loose version of this claim is false: a context always
    existed here. urllib's default ``HTTPSHandler`` builds one in its own constructor. What was
    missing was any engine reference to it, so nothing ever checked its suite list. Identity is
    therefore the test, not presence."""

    opener = rest._no_redirect_opener()
    _assert_opener_context_was_checked(
        opener,
        asserted_contexts,
        label="HTTP-family destination",
        site="rest._no_redirect_opener",
    )


def test_the_rest_opener_handshake_is_unchanged_by_the_assertion() -> None:
    """The assertion must change nothing about the connection beyond the suite list, and this is
    what proves it. The suite list is narrowed on purpose since BACKLOG #300.

    A first version of this change substituted a hand-built ``ssl.create_default_context()`` for
    urllib's. Measured on CPython 3.14.6 / OpenSSL 3.5.7, those are NOT the same context: urllib's
    carries ``post_handshake_auth=True`` and an ALPN ``http/1.1`` advertisement that a hand-built one
    does not. That would have quietly altered every default HTTP-family handshake. The shipped code
    asserts urllib's own context instead of replacing it; this pins that, on the one half of the
    difference that is readable back (ALPN is write-only).
    """
    engine = _opener_context(rest._NO_REDIRECT_OPENER)
    stock = _opener_context(urllib.request.build_opener(rest._NoRedirectHandler))
    assert engine is not None and stock is not None
    assert engine.post_handshake_auth == stock.post_handshake_auth, (
        "the engine's HTTP-family context no longer matches urllib's default on post-handshake auth "
        "- the assertion has started substituting a context instead of checking urllib's"
    )

    # The ONE deliberate difference (BACKLOG #300): the TLS 1.2 list is the approved names, in order,
    # where urllib's default also carries the six CBC-SHA2 suites. TLS 1.3 is out of set_ciphers'
    # reach, so it must still match urllib's exactly.
    def tls13(ctx: ssl.SSLContext) -> list[str]:
        return [c["name"] for c in ctx.get_ciphers() if c["protocol"] == "TLSv1.3"]

    def tls12(ctx: ssl.SSLContext) -> list[str]:
        return [c["name"] for c in ctx.get_ciphers() if c["protocol"] != "TLSv1.3"]

    assert tls13(engine) == tls13(stock)
    assert tls12(engine) == list(tls_policy.APPROVED_TLS12_SUITES)
    assert engine.verify_mode == stock.verify_mode
    assert engine.check_hostname == stock.check_hostname
    assert engine.minimum_version == stock.minimum_version


# --- the HTTP Digest rebuild branches: rest.py, fhir.py, soap.py ----------------------------------
#
# NOT IN THE CLASSIFICATION, found while building. Each of the three HTTP-family connectors rebuilds a
# per-connection opener when HTTP Digest auth is configured, so `add_handler` never mutates the shared
# one. All three rebuilt it with a bare `build_opener(_NoRedirectHandler)`, which lets urllib fill in
# an HTTPSHandler the engine never names — so a digest-authenticated destination would have dropped
# straight back onto an unasserted context while its non-digest sibling was covered. Each now rebuilds
# through `_no_redirect_opener()`, the helper written for exactly this case.


@pytest.mark.parametrize(
    ("connector_type", "name"),
    [
        (ConnectorType.REST, "OB_REST"),
        (ConnectorType.FHIR, "OB_FHIR"),
        (ConnectorType.SOAP, "OB_SOAP"),
    ],
)
def test_digest_rebuilt_opener_context_is_the_one_that_was_asserted(
    connector_type: ConnectorType,
    name: str,
    asserted_contexts: list[tuple[str, ssl.SSLContext]],
) -> None:
    """A digest-authenticated destination's rebuilt opener carries an asserted context too."""
    settings = with_http_digest(_spec_for(connector_type), user="u", password="p").settings
    dest = build_destination(Destination(name=name, type=connector_type, settings=settings))
    opener = dest._opener  # type: ignore[attr-defined]
    assert any(isinstance(h, urllib.request.HTTPDigestAuthHandler) for h in opener.handlers), (
        "this destination did not take the digest rebuild branch, so the test proves nothing"
    )
    _assert_opener_context_was_checked(
        opener,
        asserted_contexts,
        label="HTTP-family destination",
        site=f"{name} digest rebuild branch",
    )


# --- SOAP mutual TLS: transports/soap.py ----------------------------------------------------------


def test_soap_client_cert_opener_asserts(every_suite_looks_weak: None, tmp_path: Path) -> None:
    """``_client_cert_opener`` — the SOAP mTLS destination, asserted after the TLS floor and the
    client chain are applied."""

    cert, key = _self_signed(tmp_path)
    with pytest.raises(ValueError, match="SOAP destination"):
        soap._client_cert_opener(str(cert), str(key), None)


# --- alert webhooks: pipeline/alert_sinks.py ------------------------------------------------------


def test_alert_webhook_opener_asserts(every_suite_looks_weak: None) -> None:
    """``_build_no_redirect_opener`` — every outbound https webhook POST (Slack, Teams, PagerDuty, a
    custom endpoint). A second, distinct opener of the same shape: fixing rest.py did not touch it."""

    with pytest.raises(ValueError, match="alert webhook destination"):
        alert_sinks._build_no_redirect_opener()


def test_alert_webhook_opener_context_is_the_one_that_was_asserted(
    asserted_contexts: list[tuple[str, ssl.SSLContext]],
) -> None:
    """The webhook opener carries the very context the assertion ran on, as the REST one does."""
    _assert_opener_context_was_checked(
        alert_sinks._build_no_redirect_opener(),
        asserted_contexts,
        label="alert webhook destination",
        site="alert_sinks._build_no_redirect_opener",
    )


# --- the OIDC identity-provider hop: auth/oidc_http.py --------------------------------------------


def test_oidc_idp_opener_asserts_without_a_pinned_ca(every_suite_looks_weak: None) -> None:
    """``build_idp_opener`` — the token-endpoint + JWKS hop, OS-trust-store arm."""

    with pytest.raises(ValueError, match="OIDC identity provider"):
        oidc_http.build_idp_opener(None)


def test_oidc_idp_opener_asserts_with_a_pinned_ca(
    every_suite_looks_weak: None, tmp_path: Path
) -> None:
    """The pinned-CA arm of the same builder — a second return path, so a second test."""

    cert, _key = _self_signed(tmp_path)
    with pytest.raises(ValueError, match="OIDC identity provider"):
        oidc_http.build_idp_opener(str(cert))


# --- off-box syslog: logging_setup.py -------------------------------------------------------------


def test_syslog_tls_forwarder_asserts(every_suite_looks_weak: None, tmp_path: Path) -> None:
    """``_build_tls_context`` — the RFC 5425 syslog-over-TLS forwarder to the SIEM."""

    cert, _key = _self_signed(tmp_path)
    forward = logging_setup.SyslogForward(
        host="siem.example.org", port=6514, protocol="tls", tls_ca_file=str(cert)
    )
    with pytest.raises(ValueError, match="syslog TLS forwarder"):
        logging_setup._build_tls_context(forward)


def test_syslog_tls_forwarder_asserts_on_the_verify_off_arm(
    every_suite_looks_weak: None, tmp_path: Path
) -> None:
    """The documented ``tls_verify=false`` opt-out drops peer authentication, not encryption, so the
    assertion must run there too — after the CERT_NONE downgrade, on the final context."""

    cert, _key = _self_signed(tmp_path)
    forward = logging_setup.SyslogForward(
        host="siem.example.org",
        port=6514,
        protocol="tls",
        tls_ca_file=str(cert),
        tls_verify=False,
    )
    with pytest.raises(ValueError, match="syslog TLS forwarder"):
        logging_setup._build_tls_context(forward)


# --- the engine-to-store hop: store/postgres.py ---------------------------------------------------


def test_postgres_pinned_ca_context_asserts(every_suite_looks_weak: None, tmp_path: Path) -> None:
    """``_build_ssl``, ``ssl_root_cert`` arm — a private CA pinned for the store hop."""

    cert, _key = _self_signed(tmp_path)
    settings = _pg_settings(ssl_root_cert=str(cert))
    with pytest.raises(ValueError, match="Postgres store"):
        postgres._build_ssl(settings)


def test_postgres_trust_server_certificate_context_asserts(
    escape_at_warn: None, every_suite_looks_weak: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_build_ssl``, ``trust_server_certificate`` arm — reachable only behind the dev escape, still
    encrypted, so still asserted."""

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    settings = _pg_settings(trust_server_certificate=True)
    with pytest.raises(ValueError, match="Postgres store"):
        postgres._build_ssl(settings)


def test_postgres_default_arm_context_asserts(every_suite_looks_weak: None) -> None:
    """``_build_ssl``, the default system-trust arm.

    This pinned ``is True`` as a stated residual until BACKLOG #300: asyncpg built the context, so no
    object existed in engine code for the assertion to run against. The engine builds it now, so the
    arm is asserted like its two siblings."""

    with pytest.raises(ValueError, match=r"Postgres store \(system trust\)"):
        postgres._build_ssl(_pg_settings())


# --- the AD LDAPS bind: auth/ldap.py --------------------------------------------------------------
#
# BACKLOG #1317 remainder, then #2494. ldap3 2.9.1 builds its TLS context inside `Tls.wrap_socket` and
# takes no `ssl_context=`. Until #2494 the engine could only assert a REPLICA of that context. Since
# #2494 the engine builds the context itself (`tls_policy.assert_ldap3_tls_suites` returns the
# factory) and `auth.ldap_tls.NarrowedTls` wraps each connection with it. So the IDENTITY instrument
# the openers get works here too: the context on the wrapped socket must be one the assertion ran on.


def _ad_settings(**overrides: Any) -> AuthSettings:
    """A minimally-valid AD block whose bind is LDAPS, so the TLS arm is reachable at all."""
    fields: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc1.example.test:636",
        "ad_user_search_base": "DC=example,DC=test",
        "ad_bind_dn": "CN=svc,DC=example,DC=test",
        "ad_bind_password": "not-a-real-password",
        "ad_tls_verify": True,
    }
    fields.update(
        overrides
    )  # merged, not splatted: an override must REPLACE a default, not collide
    return AuthSettings(**fields)


def _context_ldap3_builds(tls: Any) -> ssl.SSLContext:
    """The ``SSLContext`` ``tls.wrap_socket`` really wraps with: CAPTURED, not reconstructed.

    ``wrap_socket`` needs a real socket, so it gets one end of a ``socketpair`` and
    ``do_handshake=False``; the context is then readable off the returned ``SSLSocket``. No peer, no
    handshake, no network. For a plain ``ldap3.Tls`` this runs ldap3's own construction; for the
    engine's ``NarrowedTls`` it runs the engine's factory, as a real bind would.
    """

    class _Server:
        host = "dc1.example.test"

    class _Connection:
        def __init__(self, sock: socket.socket) -> None:
            self.socket: Any = sock
            self.server = _Server()

    left, right = socket.socketpair()
    conn = _Connection(left)
    try:
        tls.wrap_socket(conn, do_handshake=False)
        ctx = conn.socket.context
        assert isinstance(ctx, ssl.SSLContext), "wrap_socket left no SSLContext on the socket"
        return ctx
    finally:
        conn.socket.close()
        left.close()
        right.close()


def test_ad_ldaps_bind_asserts(every_suite_looks_weak: None) -> None:
    """``LdapAuthenticator.__init__`` — the service-account and user binds to Active Directory.

    The factory runs once at construction, so a bad context fails app startup: ``AuthService``
    builds this eagerly. It runs again for every connection after that.
    """

    with pytest.raises(ValueError, match="LDAPS bind to AD"):
        ldap_auth.LdapAuthenticator(_ad_settings())


def test_a_plaintext_ldap_bind_has_no_tls_context_to_assert(every_suite_looks_weak: None) -> None:
    """The discriminating negative: same fixture, same constructor, DIFFERENT input, no raise.

    ``ldap://`` builds no ``Tls`` at all, so there is no context to assert and the assertion must not
    fire. Under a fixture that makes every reachable assertion raise, constructing this cleanly is what
    proves the LDAPS test above is keyed on the scheme and not merely on the constructor running.

    ``ad_allow_insecure_ldap`` is required to reach this arm at all — ``AuthSettings`` refuses a
    non-``ldaps://`` bind without it — so this also records that the cleartext-LDAP path is reachable
    only behind that documented dev override.
    """

    auth = ldap_auth.LdapAuthenticator(
        _ad_settings(ad_server="ldap://dc1.example.test:389", ad_allow_insecure_ldap=True)
    )
    assert auth._server().tls is None


@pytest.mark.parametrize("validate", [ssl.CERT_REQUIRED, ssl.CERT_NONE])
def test_every_ldaps_connection_wraps_with_a_context_the_assertion_ran_on(
    validate: ssl.VerifyMode,
    tmp_path: Path,
    asserted_contexts: list[tuple[str, ssl.SSLContext]],
) -> None:
    """IDENTITY, the instrument every opener site gets (BACKLOG #2494).

    Each connection must wrap with a FRESH context the assertion ran on, not one built beside it.
    Both verification modes, because ``validate`` is the argument that differs between deployments,
    and a CA so the ``ca_certs_data`` arm runs.
    """
    from messagefoundry.auth.ldap_tls import NarrowedTls

    ca, _key = _self_signed(tmp_path)
    tls = NarrowedTls(
        validate=validate, ca_certs_data=ca.read_text("ascii"), connector="ldaps identity probe"
    )

    first, second = _context_ldap3_builds(tls), _context_ldap3_builds(tls)
    checked = [ctx for label, ctx in asserted_contexts if label == "ldaps identity probe"]
    assert len(checked) == 3, "construction plus one per connection"
    assert first is checked[1] and second is checked[2] and first is not second
    assert first.verify_mode == validate == tls.validate and first.check_hostname is False
    assert first.minimum_version == ssl.TLSVersion.TLSv1_2
    assert _tls12_names(first) == list(tls_policy.APPROVED_TLS12_SUITES)


def test_every_server_the_bind_builds_carries_the_one_engine_tls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_server()`` runs up to three times per login. Each ``Server`` must carry the engine's
    ``NarrowedTls``, anchored at the checked bytes, never a path, and with no ``ciphers``."""
    from messagefoundry.auth.ldap_tls import NarrowedTls

    ca, _key = _self_signed(tmp_path)
    # The constructor checks the anchor since BACKLOG #2034; pin its ACL and path verdicts to clean so
    # the result does not depend on this machine's temp directory.
    monkeypatch.setattr(trust_anchors, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(trust_anchors, "anchor_path_verdict", lambda _p: PathVerdict(ok=True))
    auth = ldap_auth.LdapAuthenticator(_ad_settings(ad_tls_ca_cert_file=str(ca)))

    tls = auth._server().tls
    assert isinstance(tls, NarrowedTls) and auth._server().tls is tls
    assert tls.validate == ssl.CERT_REQUIRED
    assert tls.ca_certs_data == ca.read_text("ascii") and tls.ca_certs_file is None
    assert tls.ciphers is None  # the engine's context carries the suites, not ldap3's lever


def test_the_ldaps_assertion_holds_the_context_to_the_approved_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The list check after ``harden_cipher_suites`` must fail on its own, or it is decoration.

    Widening the tuple the narrowing applies puts a CBC suite on the context. That suite is
    forward-secret, encrypting, authenticated and 256-bit, so only the list check can see it.
    """

    widened = (*tls_policy.APPROVED_TLS12_SUITES, "ECDHE-ECDSA-AES256-SHA384")
    monkeypatch.setattr(tls_policy, "APPROVED_TLS12_SUITES", widened)
    with pytest.raises(ValueError, match="not narrowed to the approved list"):
        tls_policy.assert_ldap3_tls_suites(
            validate=ssl.CERT_REQUIRED, ca_certs_data=None, connector="AD LDAPS"
        )


def test_the_shipped_ldaps_bind_offers_exactly_the_approved_list(tmp_path: Path) -> None:
    """The POSITIVE control, taken off the socket the shipped bind's ``Tls`` really wraps."""

    auth = ldap_auth.LdapAuthenticator(_ad_settings())
    real = _context_ldap3_builds(auth._server().tls)
    assert _tls12_names(real) == list(tls_policy.APPROVED_TLS12_SUITES)
    assert all(n in tls_policy._APPROVED_TLS_SUITES for n in _cipher_names(real))


def test_ldap3_swallows_a_rejected_cipher_string_and_strips_every_tls12_suite() -> None:
    """Why ldap3's own ``ciphers=`` lever was never trustworthy, kept as a measurement.

    ``ldap3/core/tls.py`` wraps ``set_ciphers`` in ``except ssl.SSLError: pass``. A cipher string
    OpenSSL rejects therefore vanishes without a log line, and the hop silently loses its ENTIRE TLS
    1.2 suite list while still reporting a configured cipher policy (SDS-3.7). Since BACKLOG #2494
    the engine no longer uses that lever, and ``NarrowedTls`` takes no ``ciphers=``. If ldap3 ever stops
    swallowing, this goes red; leaving the lever out still stands, because the lever still cannot reach TLS 1.3.
    """

    baseline = _context_ldap3_builds(ldap3.Tls(validate=ssl.CERT_REQUIRED))
    poisoned = _context_ldap3_builds(
        ldap3.Tls(validate=ssl.CERT_REQUIRED, ciphers="THIS-IS-NOT-A-SUITE")
    )
    assert _tls12_names(baseline), "the baseline offered no TLS 1.2 suites; this proves nothing"
    assert not _tls12_names(poisoned), (
        "ldap3 no longer strips the TLS 1.2 suites on a rejected cipher string; re-derive this "
        "test's docstring before relying on that reason"
    )


# --- the Vault hops: the engine supplies the context, built by urllib3's own constructor ----------
#
# ADR 0180 DECLINED to build this assertion, and its stated reason was not that the hop was fine — it
# was that "no CI leg installs the [vault] extra", so the control could never be executed. That is the
# silent-control shape, and shipping into it would have been worse than the gap. The extra is now on
# the `test` leg (.github/workflows/ci.yml), which is what makes these tests, and therefore the
# assertion, real. Without the extra every test below SKIPS — and `tests/_extras_probe.py` now lists
# `vault`, so such a run announces itself as INCOMPLETE rather than reporting a quiet green.


_vault_extra = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)


def _context_urllib3_builds_for(client: Any) -> ssl.SSLContext:
    """The ``SSLContext`` urllib3's OWN connect path wraps ``client``'s socket with, CAPTURED.

    The Vault twin of :func:`_context_ldap3_builds`. urllib3 reaches ``ssl_wrap_socket`` inside
    ``_ssl_wrap_socket_and_match_hostname``, but only AFTER the TCP connect succeeds — so the client
    is pointed at a real listener that accepts and immediately closes. The handshake then fails at
    once (EOF), which is fine: the spy already holds the context. No peer certificate, no off-box
    network — but urllib3's own connect code really ran, with the arguments the shipped client
    really produces.

    The spy sits at ``ssl_wrap_socket`` rather than ``create_urllib3_context`` since BACKLOG #300.
    The engine now SUPPLIES the context, so urllib3 builds none, and a spy on the constructor would
    capture nothing. ``ssl_wrap_socket`` receives the context either way, so this reads the object
    the handshake uses whoever built it.
    """
    import urllib3.connection  # noqa: PLC0415  (optional [vault] extra; module-scope would break base)
    import urllib3.util.ssl_  # noqa: PLC0415  (the module urllib3.connection imports it from)

    captured: list[ssl.SSLContext] = []
    real = urllib3.util.ssl_.ssl_wrap_socket

    def spy(*args: Any, **kwargs: Any) -> Any:
        ctx = kwargs.get("ssl_context")
        assert isinstance(ctx, ssl.SSLContext), "urllib3 no longer passes ssl_context by keyword"
        captured.append(ctx)
        return real(*args, **kwargs)

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def accept_then_close() -> None:
        try:
            conn, _ = listener.accept()
            conn.close()
        except OSError:  # the listener was closed from under us; the client already has its EOF
            pass

    server = threading.Thread(target=accept_then_close, daemon=True)
    server.start()
    monkey = pytest.MonkeyPatch()
    try:
        monkey.setattr(urllib3.connection, "ssl_wrap_socket", spy)
        monkey.setattr(client, "url", f"https://127.0.0.1:{port}")
        with contextlib.suppress(Exception):  # the handshake MUST fail; only the context matters
            client.sys.read_health_status()
    finally:
        monkey.undo()
        listener.close()
        server.join(timeout=5)

    assert len(captured) == 1, (
        f"urllib3 wrapped {len(captured)} sockets on one Vault request, not 1 — so 'the context "
        f"this hop uses' is no longer one object"
    )
    return captured[0]


@_vault_extra
def test_the_vault_kv_secret_provider_asserts_its_tls_suites(every_suite_looks_weak: None) -> None:
    """``config/secretprovider_vault._build_client`` — the connector-credential KV read.

    Asserted inside ``_build_client`` rather than at the caller, because that function is the single
    construction point and the assertion reads the SAME kwargs dict the client is built from.
    """

    with pytest.raises(ValueError, match=secretprovider_vault._VAULT_KV_CONNECTOR):
        secretprovider_vault._build_client("https://vault.example.test:8200", "s.token")


@_vault_extra
def test_the_vault_transit_key_provider_asserts_its_tls_suites(
    every_suite_looks_weak: None,
) -> None:
    """``store/keyprovider_vault._build_client`` — the store-DEK unwrap, and the Transit cipher.

    ``store/crypto_transit.py`` imports THIS ``_build_client``, so the engine's third hvac client is
    covered by this one site. That is why two construction points cover three clients.
    """

    with pytest.raises(ValueError, match=keyprovider_vault._VAULT_TRANSIT_CONNECTOR):
        keyprovider_vault._build_client("https://vault.example.test:8200", "s.token")


@_vault_extra
def test_the_transit_cipher_client_is_the_asserted_one(
    asserted_contexts: list[tuple[str, ssl.SSLContext]],
) -> None:
    """The third hvac client must reach the assertion, and by IDENTITY of the function, not by prose.

    ADR 0180's scope note records that ``crypto_transit`` shares ``keyprovider_vault._build_client``.
    A shared function is only shared while nobody copies it, so this pins the object rather than the
    claim: rebind one and this goes red.
    """

    # The re-import IS the subject, so the unexported name is read on purpose.
    assert crypto_transit._build_client is keyprovider_vault._build_client  # type: ignore[attr-defined]


@_vault_extra
@pytest.mark.parametrize(
    ("module", "label"),
    [
        (secretprovider_vault, secretprovider_vault._VAULT_KV_CONNECTOR),
        (keyprovider_vault, keyprovider_vault._VAULT_TRANSIT_CONNECTOR),
    ],
    ids=["kv", "transit"],
)
def test_the_vault_hop_handshakes_on_the_asserted_context(
    module: Any, label: str, asserted_contexts: list[tuple[str, ssl.SSLContext]]
) -> None:
    """IDENTITY, the check the urllib openers get, and the one a replica could only stand in for.

    Since BACKLOG #300 the engine builds the Vault hop's contexts itself, one per connection, and
    asserts each as it builds it. So the object urllib3 wraps the socket with can be compared with
    the objects the assertion ran on. Those come off the ``asserted_contexts`` spy, and the
    handshake's off ``ssl_wrap_socket``. Mutation: drop the per-connection hook, and urllib3 builds
    its own context; red.
    """

    client = module._build_client("https://vault.example.test:8200", "s.token")
    at_construction = [ctx for seen_label, ctx in asserted_contexts if seen_label == label]
    assert len(at_construction) == 1, "construction did not assert this hop's context exactly once"

    real = _context_urllib3_builds_for(client)
    asserted = [ctx for seen_label, ctx in asserted_contexts if seen_label == label]
    assert len(asserted) == 2, "the connection did not assert the context it built"
    assert real is asserted[-1], (
        "the Vault hop handshakes on a context the assertion never checked, so the narrowing and "
        "the assertion no longer reach the wire"
    )


@_vault_extra
def test_the_shipped_vault_hop_offers_no_weak_suite() -> None:
    """The POSITIVE control, and it is the half a reverted fix would still pass without.

    Deliberately WITHOUT ``every_suite_looks_weak``: this measures the real suite list the Vault hops
    negotiate over and requires it to be non-empty and clean on all three properties the shipped
    predicates test. A refusal pinned alone cannot tell a working control from one that refuses
    everything; a clean list pinned alone cannot fail when the call is deleted. Both are needed.
    """

    client = secretprovider_vault._build_client("https://vault.example.test:8200", "s.token")
    real = _context_urllib3_builds_for(client)
    ciphers = real.get_ciphers()
    assert ciphers, "the Vault hop offered no suites at all, so this test proves nothing"
    for cipher in ciphers:
        assert tls_policy._is_forward_secret(cipher), f"{cipher['name']} is not forward-secret"
        assert tls_policy._is_encrypting(cipher), f"{cipher['name']} offers no confidentiality"
        assert tls_policy._is_peer_authenticated(cipher), f"{cipher['name']} authenticates no peer"
    # BACKLOG #300: and it is the approved list, in order, not merely a clean one.
    assert _tls12_names(real) == list(tls_policy.APPROVED_TLS12_SUITES)
    assert all(n in tls_policy._APPROVED_TLS_SUITES for n in _cipher_names(real))


@_vault_extra
def test_the_vault_assertion_refuses_a_context_the_narrowing_did_not_reach(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The list check must fail on its own, or it is decoration (BACKLOG #300).

    With the narrowing made a no-op, the context keeps urllib3's default list. Every suite in it
    passes :func:`harden_cipher_suites`'s four properties, so only the list check can refuse it.
    """

    monkeypatch.setattr(tls_policy, "narrow_to_approved_suites", lambda ctx: None)
    with pytest.raises(ValueError, match="not narrowed to the approved list"):
        tls_policy.assert_hvac_tls_suites(
            {"url": "https://vault.example.test:8200"}, connector="Vault KV secret provider"
        )


@_vault_extra
def test_the_vault_assertion_refuses_a_client_argument_it_cannot_replicate() -> None:
    """An unreplicable ``hvac.Client`` argument must REFUSE, not be replicated wrongly or ignored.

    ``session=`` is the one that matters: it is the documented way to give this hop a different TLS
    context, so an assertion that accepted it would keep reporting a clean suite list for a context
    the hop had stopped using. It is also why BACKLOG #300 mounts the narrowed context on the adapter
    instead: given a session, hvac replaces ``verify=`` with the session's own. Deliberately without
    ``every_suite_looks_weak``, so this raise stands on its own and a reader can tell the refusal
    apart from a suite-list failure.
    """

    with pytest.raises(ValueError, match="session"):
        tls_policy.assert_hvac_tls_suites(
            {"url": "https://vault.example.test:8200", "session": object()},
            connector="Vault KV secret provider",
        )


@_vault_extra
def test_the_vault_assertion_admits_a_ca_bundle_path_as_verify() -> None:
    """#1180 puts ``verify=<path>`` in the very dict this assertion is handed, and it must pass.

    Both Vault providers resolve the operator's trust anchor INTO the kwargs dict, precisely so the
    assertion sees what the client will be built with. A blanket refusal of ``verify`` therefore made
    every CA-anchored Vault hop refuse to come up. A path chooses WHICH roots verify the peer and
    leaves the suite list alone (measured: ``cert_reqs`` does not move it), so it is admitted.
    """

    tls_policy.assert_hvac_tls_suites(
        {
            "url": "https://vault.example.test:8200",
            "token": "s.token",
            "allow_redirects": False,
            "verify": "/etc/mefor/vault-ca.pem",
        },
        connector="Vault KV secret provider",
    )


@_vault_extra
@pytest.mark.parametrize("verify", [False, True, "", 0, 1])
def test_the_vault_assertion_still_refuses_verify_as_an_on_off_switch(verify: object) -> None:
    """DEFENCE IN DEPTH, not a live path, and worth saying which it is.

    ``verify=False`` is the knob that turns peer verification off, and an assertion that accepted it
    would report a clean suite list for a hop that authenticates nobody. No shipped caller can reach
    this today: ``vault_client_verify_kwargs`` is typed ``dict[str, str]`` and returns a path or
    nothing. The arm exists so a future caller that starts passing a switch is refused rather than
    quietly accepted. ``""`` and ``0`` are here because requests reads every falsy value as "do not
    verify", and ``bool`` is a subclass of ``int`` -- the shorter spellings of this check all admit at
    least one of them.
    """

    with pytest.raises(ValueError, match="not the path of a CA bundle"):
        tls_policy.assert_hvac_tls_suites(
            {"url": "https://vault.example.test:8200", "verify": verify},
            connector="Vault KV secret provider",
        )


@_vault_extra
def test_the_only_ssl_context_on_the_hvac_stack_is_the_engines() -> None:
    """ADR 0180 found no layer of the hvac stack carries a context; BACKLOG #300 supplies them.

    Re-run rather than quoted, because it is a property of three third-party libraries. hvac itself
    still carries none, requests seeds no pool with one, and requests has not brought back its
    module-level preloaded context. The contexts on the stack are the engine's, built per
    connection by the strict adapter's factory. If a library layer starts carrying its own, the
    engine's may no longer be the one that handshakes, and the identity test above is where that
    shows.
    """

    from messagefoundry.transports.strict_requests import StrictReplyAdapter  # noqa: PLC0415

    client = secretprovider_vault._build_client("https://vault.example.test:8200", "s.token")
    assert not [a for a in dir(client) if "ssl" in a.lower() or "context" in a.lower()]

    session = client.adapter.session
    adapter = session.get_adapter("https://vault.example.test:8200")
    assert isinstance(adapter, StrictReplyAdapter)
    assert "ssl_context" not in adapter.poolmanager.connection_pool_kw
    assert _tls12_names(adapter._ssl_context_factory()) == list(tls_policy.APPROVED_TLS12_SUITES)

    import requests.adapters  # noqa: PLC0415  (optional [vault] extra)

    assert getattr(requests.adapters, "_preloaded_ssl_context", None) is None, (
        "requests has reinstated the module-level preloaded SSLContext it carried in 2.32 — re-check "
        "that the engine's mounted context is still the one the Vault hop handshakes on"
    )


# --- the preserved exemption: config/tls_probe.py -------------------------------------------------


def test_the_tls_floor_probe_context_is_deliberately_not_hardened() -> None:
    """``_offer_context`` must stay unasserted, and this test says why by measuring it.

    The probe offers ``ALL:@SECLEVEL=0`` so that a withdrawn protocol version is genuinely ASKED for;
    without it modern OpenSSL refuses to send the ClientHello and the probe would measure the
    engine's refusal to ask rather than the peer's refusal to answer. That offer resolves to a wide
    suite list including non-forward-secret suites, so ``harden_cipher_suites`` WOULD raise here.
    Adding it would empty the offer and turn a floor probe that can fail into one that cannot.
    """

    ctx = tls_probe._offer_context(ssl.TLSVersion.TLSv1)
    weak = [c for c in ctx.get_ciphers() if not tls_policy._is_forward_secret(c)]
    assert weak, (
        "the probe's ALL:@SECLEVEL=0 offer resolved to forward-secret suites only, so this test no "
        "longer demonstrates why the exemption exists; re-derive it before changing the exemption"
    )
    with pytest.raises(ValueError, match="non-forward-secret"):
        tls_policy.harden_cipher_suites(ctx, connector="tls floor probe (must stay exempt)")

    # And the engine must NOT be calling it there.
    source = Path(tls_probe.__file__).read_text(encoding="utf-8")
    calls = [
        line
        for line in source.splitlines()
        if "harden_cipher_suites(" in line and not line.lstrip().startswith("#")
    ]
    assert not calls, f"tls_probe must not assert cipher suites on its offer context: {calls}"


def test_the_shared_https_handler_factory_asserts(every_suite_looks_weak: None) -> None:
    """``build_asserted_https_handler`` - the one construction both openers share, so they cannot
    drift onto different handlers."""
    with pytest.raises(ValueError, match="a label"):
        tls_policy.build_asserted_https_handler(connector="a label")


def test_the_handler_factory_refuses_when_it_cannot_reach_the_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """It reads a private ``_context``, so it must FAIL CLOSED if a future CPython renames it.

    A ``getattr(..., None)`` that shrugged and returned would leave a security control reporting
    success forever - the failure ``harden_kex_groups`` documents at length. Simulated by handing the
    factory a handler class with no ``_context``.
    """

    class _NoContextHandler(urllib.request.HTTPSHandler):
        def __init__(self) -> None:
            super().__init__()
            del self._context  # type: ignore[attr-defined]  # a private stdlib attribute

    monkeypatch.setattr(urllib.request, "HTTPSHandler", _NoContextHandler)
    with pytest.raises(ValueError, match="cannot reach the TLS context"):
        tls_policy.build_asserted_https_handler(connector="a label")


# --- the libraries ADR 0180 scoped OUT, and the premises that scoped them -------------------------
#
# BACKLOG #1317 names three third-party TLS surfaces: ldap3, hvac and ODBC Driver 18. ADR 0180 built
# the first (above) and ruled the other two out in PROSE, each on a measurement taken once. A
# scope-out is a compensating control like any other, so SDS-3.7 applies to it: it must not rest on a
# premise nothing re-checks. Neither premise was checked by anything until these tests.
#
# ONE OF THE TWO TRIGGERS HAS SINCE FIRED, so the two are no longer the same shape and must not be
# read as if they were:
#
# * ODBC stays a TRIGGER. A red does not mean the engine got worse; it means the reason that arm was
#   left unasserted has stopped being true and the arm is now buildable. Build it and amend ADR 0180
#   -- never delete the test.
# * hvac is now a GUARD, in the opposite direction. Its trigger fired when the `test` leg started
#   installing the `[vault]` extra, the assertion was built above, and ADR 0180 carries the amendment.
#   A red there means the arm that WAS built has stopped being executed, which is the failure a
#   scope-out trigger cannot detect.

#: Ways a module can hold an ``SSLContext`` the engine could assert on. Shared by the ODBC subjects
#: and by the control below, so a clean result on the subjects is a reading rather than a dead regex.
_HOLDS_A_CONTEXT_RE = re.compile(
    r"^\s*import\s+ssl\b|^\s*from\s+ssl\s+import\b|ssl\.SSLContext|ssl\.create_default_context"
)

#: The two ODBC modules. ADR 0180 measured only the first and generalised to "ODBC Driver 18".
_ODBC_MODULES = (
    "messagefoundry/store/sqlserver.py",
    "messagefoundry/transports/database.py",
)

#: A module that DOES build a context, so the scan can be shown to find one.
_ODBC_SCAN_CONTROL = "messagefoundry/store/postgres.py"


def _context_lines(path: Path) -> list[str]:
    """Every non-comment line in ``path`` that reaches for an ``ssl`` context."""
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if _HOLDS_A_CONTEXT_RE.search(line) and not line.lstrip().startswith("#")
    ]


def test_the_odbc_scope_out_premise_still_holds(request: Any) -> None:
    """ADR 0180 rules ODBC Driver 18 out PERMANENTLY, and this re-measures why.

    TLS on that hop is connection-string keywords (``Encrypt`` / ``TrustServerCertificate`` /
    ``ServerCertificate``) terminated inside the native driver, so the suite list belongs to the
    driver and the OS TLS stack rather than to the interpreter's OpenSSL. No Python-side context
    exists to assert and no replica is possible.

    **The ADR measured ``store/sqlserver.py`` alone and generalised.** The ODBC *transport* --
    ``transports/database.py``, the DATABASE destination and the ADR 0010 ``db_lookup`` hop -- carries
    the same keywords on a hop that moves message content, and was never named. Both are measured
    here, so the ruling covers the surface it claims.
    """

    root = Path(request.config.rootpath)
    control = _context_lines(root / _ODBC_SCAN_CONTROL)
    assert control, (
        f"the scan found no ssl context in {_ODBC_SCAN_CONTROL}, which is chosen BECAUSE it builds "
        f"them -- the scan is broken, so a clean result on the ODBC modules would mean nothing"
    )

    holding = {rel: _context_lines(root / rel) for rel in _ODBC_MODULES}
    assert not any(holding.values()), (
        f"an ODBC module now reaches for an ssl context: {holding}. ADR 0180 ruled this arm out "
        f"BECAUSE no Python-side context exists there; that premise has changed, so re-derive the "
        f"ruling and assert the context (BACKLOG #1317) rather than deleting this test"
    )


def test_the_sqlserver_hop_asserts_no_suites_and_pins_what_it_can_control(
    asserted_contexts: list[tuple[str, ssl.SSLContext]],
) -> None:
    """The other half of the same ruling: what the ODBC hop CANNOT do, and what it does instead.

    Building the SQL Server DSN reaches ``harden_cipher_suites`` zero times -- there is nothing to
    hand it. What the engine *can* express on that hop it does express, and this pins those two
    keywords so the scope-out never reads as "TLS is unhandled here". ``Encrypt``/
    ``TrustServerCertificate`` are the posture; the suite list is the driver's.

    The spy is the same one the opener tests use, and its liveness is proved by
    ``test_rest_shared_opener_context_is_the_one_that_was_asserted`` recording a context under the
    same fixture -- so an empty list here reports an absent call, not an inert instrument.
    """

    dsn, weakened = database._build_connection(
        {
            "server": "sql.example.test",
            "database": "mefor",
            "username": "mefor",
            "password": "not-a-real-password",
            "encrypt": True,
            "trust_server_certificate": False,
        },
        connection="OB_TEST_DB",
    )

    assert not weakened
    assert "Encrypt=yes;" in dsn and "TrustServerCertificate=no;" in dsn, (
        f"the SQL Server preset no longer pins the TLS posture it CAN control: {dsn}"
    )
    assert not asserted_contexts, (
        f"the ODBC DSN path asserted a cipher context ({[lbl for lbl, _ in asserted_contexts]}). "
        f"ADR 0180 says no such context exists on this hop -- re-derive the ruling"
    )


#: Extras installed by a CI workflow, e.g. ``-e ".[dev,harness,fhir]"``.
_CI_EXTRAS_RE = re.compile(r'-e\s+"\.\[([^\]]+)\]"')


def _ci_installed_extras(root: Path) -> set[str]:
    """Every project extra any workflow under ``.github/workflows/`` installs.

    Comment lines are skipped: several workflows discuss ``-e ".[extras]"`` in their rationale, and a
    comment naming an extra is not a leg installing it.
    """
    extras: set[str] = set()
    for workflow in sorted((root / ".github" / "workflows").glob("*.yml")):
        for line in workflow.read_text(encoding="utf-8").splitlines():
            if line.lstrip().startswith("#"):
                continue
            for match in _CI_EXTRAS_RE.finditer(line):
                extras.update(part.strip() for part in match.group(1).split(","))
    return extras


#: The name every hvac construction point must CALL. Held as a string because the scan below reads
#: source rather than importing (the modules it reads lazy-import hvac), and checked against the
#: shipped module so a rename cannot leave the needle pointing at nothing.
_HVAC_ASSERTION = "assert_hvac_tls_suites"

#: The factory the scan looks inside. Both hvac modules name it identically.
_HVAC_FACTORY = "_build_client"

#: The two hvac construction points. ``store/crypto_transit.py`` is absent ON PURPOSE: it imports
#: ``keyprovider_vault._build_client`` rather than building a client of its own, which
#: :func:`test_the_transit_cipher_client_is_the_asserted_one` pins by identity rather than by prose.
_HVAC_BUILD_SITES = (
    "messagefoundry/config/secretprovider_vault.py",
    "messagefoundry/store/keyprovider_vault.py",
)


def _factory_calls_the_assertion(path: Path) -> bool:
    """Does ``path``'s ``_build_client`` CALL the assertion — parsed, not string-matched?

    A substring scan is not good enough here and that was measured, not assumed: both modules carry
    ``from ... import assert_hvac_tls_suites`` at module scope, so deleting the call from the factory
    body leaves the name in the file and a substring scan stays green over a removed security control.
    Parsing asks the question this test means to ask -- is the call INSIDE the factory -- which also
    reds if the call is moved somewhere that never runs.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    factories = find_funcs(tree, _HVAC_FACTORY)
    return any(call_sites(factory, _HVAC_ASSERTION, bare_only=True) for factory in factories)


def test_the_hvac_arm_stays_built_and_stays_executable(request: Any) -> None:
    """ADR 0180 left the Vault (hvac) arm UNMEASURED, and this was that scope-out's trigger. It FIRED.

    The premise was never that the hop was fine. It was that ``urllib3`` was absent and **no CI leg
    installed the ``[vault]`` extra**, so a cipher assertion there would have been a security control
    no test in this project could execute. The ADR named its own precondition, the `test` leg now
    installs the extra, and the assertion above was built against urllib3's OWN
    ``create_urllib3_context()`` rather than a hand-rolled look-alike (ADR 0180 Amendment A).

    **So this test is now a GUARD, and both halves point the other way.** The failure a fired trigger
    cannot see is the arm being built and then quietly stopping running, which is the silent-control
    shape ADR 0158 catalogues:

    * Drop the extra from CI and every ``_vault_extra`` test SKIPS. A suite that skips its way
      past a security control reports green, so the extra is pinned here rather than trusted.
    * Delete the call from a ``_build_client`` and, on an interpreter without the extra, nothing else
      in this file notices -- every test that would have caught it is skipped. The source scan is the
      half that still runs there.

    Read a red here as the control having stopped being executed, and restore it. The one thing that
    is NOT a fix is relaxing either half.
    """

    root = Path(request.config.rootpath)

    extras = _ci_installed_extras(root)
    assert "webauthn" in extras, (
        f"control: the workflow scan should see the extras CI really installs, but read {extras}"
    )
    assert "vault" in extras, (
        "no CI workflow installs the [vault] extra any more, so every test guarded by _vault_extra "
        "skips and the hvac cipher assertion (ASVS 12.1.2) is a security control nothing executes. "
        "Restore it on the leg that runs tests/ -- ADR 0180 Amendment A is what that install line "
        "makes true (BACKLOG #1317)"
    )

    assert callable(getattr(tls_policy, _HVAC_ASSERTION, None)), (
        f"control: tls_policy.{_HVAC_ASSERTION} is the name the scan below looks for, and it is no "
        f"longer a callable there -- so a clean scan would mean the needle had gone stale, not that "
        f"the call sites were wired"
    )
    unasserted = [rel for rel in _HVAC_BUILD_SITES if not _factory_calls_the_assertion(root / rel)]
    assert not unasserted, (
        f"{_HVAC_FACTORY} no longer calls {_HVAC_ASSERTION} in {unasserted}. That hop's suite list "
        f"is inherited from urllib3 and unchecked again; restore the call (BACKLOG #1317, ADR 0180 "
        f"Amendment A) rather than relaxing this test"
    )


def _covered_files() -> list[tuple[str, str]]:
    """(module file, connector label) for every site this file claims to cover, for the scan below."""
    return [
        ("messagefoundry/transports/rest.py", "HTTP-family destination"),
        ("messagefoundry/transports/soap.py", "SOAP destination"),
        ("messagefoundry/pipeline/alert_sinks.py", "alert webhook destination"),
        ("messagefoundry/auth/oidc_http.py", "OIDC identity provider"),
        ("messagefoundry/logging_setup.py", "syslog TLS forwarder"),
        ("messagefoundry/store/postgres.py", "Postgres store"),
        ("messagefoundry/auth/ldap.py", "LDAPS bind to AD"),
    ]


def test_every_covered_file_still_names_its_connector_label(request: Any) -> None:
    """A rename receipt. The tests above match on a connector label; if a label is reworded in the
    engine and the test's ``match`` is reworded with it, both move together and nothing notices that
    a THIRD reader (an operator reading the error, a scorecard citing it) now sees something else.
    This pins the label text to the file it is emitted from."""
    root = Path(request.config.rootpath)
    missing = [
        f"{rel}: {label!r}"
        for rel, label in _covered_files()
        if label not in (root / rel).read_text(encoding="utf-8")
    ]
    assert not missing, (
        f"connector label(s) no longer present in the file that emits them: {missing}"
    )

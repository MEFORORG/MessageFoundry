# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

import contextlib
import datetime
import socket
import ssl
import threading
import urllib.request
from collections.abc import Iterator, Mapping
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
from messagefoundry.auth import oidc_http
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
from messagefoundry.transports import build_destination, rest, soap
from messagefoundry.transports.http_auth import with_http_digest
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

# Imported at module scope ON PURPOSE. `rest` and `alert_sinks` build their shared opener AT IMPORT,
# so a first import inside the every_suite_looks_weak fixture would raise during module execution and
# fail the test for the wrong reason. Importing here puts them in sys.modules before any patch runs,
# which also means the assertions below exercise the same module objects the engine uses.


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
    for handler in opener.handlers:
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
    """The assertion must change NOTHING about the connection, and this is what proves it.

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
    assert [c["name"] for c in engine.get_ciphers()] == [c["name"] for c in stock.get_ciphers()]
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
    every_suite_looks_weak: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_build_ssl``, ``trust_server_certificate`` arm — reachable only behind the dev escape, still
    encrypted, so still asserted."""

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    settings = _pg_settings(trust_server_certificate=True)
    with pytest.raises(ValueError, match="Postgres store"):
        postgres._build_ssl(settings)


def test_postgres_default_arm_still_hands_asyncpg_the_job() -> None:
    """The stated residual, pinned so it cannot be quietly reclassified as covered.

    The secure default returns bare ``True`` and asyncpg builds the context, so no object exists in
    engine code for the assertion to run against. This test records that fact rather than claiming
    the site is hardened."""

    assert postgres._build_ssl(_pg_settings()) is True


# --- the AD LDAPS bind: auth/ldap.py --------------------------------------------------------------
#
# BACKLOG #1317 remainder. The one site in this file where the IDENTITY instrument above cannot be
# used at all. `ldap3.Tls` holds no SSLContext (measured: zero SSLContext attributes on the object) and
# exposes no `ssl_context=` parameter -- it stores the arguments and builds the context inside
# `Tls.wrap_socket` at connect time. So the engine can never hold the object this hop will use, and
# "is this the same object?" has no answer here.
#
# Two measurements stand in for it, and together they cover both halves of the drift risk:
#   * CONTEXT half -- `test_the_ldaps_replica_matches_the_context_ldap3_actually_builds` drives ldap3's
#     REAL wrap_socket over a socketpair and compares the captured context to the replica.
#   * ARGUMENT half -- `test_the_asserted_ldaps_arguments_are_the_ones_the_bind_uses` requires the
#     kwargs the assertion ran on to be the kwargs `_server()` hands `ldap3.Tls`.


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
    """The ``SSLContext`` ldap3's OWN ``wrap_socket`` builds for ``tls`` — CAPTURED, not reconstructed.

    This is what keeps the replica honest. ``wrap_socket`` needs a real socket, so it gets one end of a
    ``socketpair`` and ``do_handshake=False``; the context is then readable off the returned
    ``SSLSocket``. No peer, no handshake, no network — but ldap3's own construction code really ran.
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
        assert isinstance(ctx, ssl.SSLContext), "ldap3 did not leave an SSLContext on the socket"
        return ctx
    finally:
        conn.socket.close()
        left.close()
        right.close()


def test_ad_ldaps_bind_asserts(every_suite_looks_weak: None) -> None:
    """``LdapAuthenticator.__init__`` — the service-account and user binds to Active Directory.

    Asserted at construction rather than inside ``_server()``: the suite list is fixed by configuration
    and cannot change between calls, ``AuthService`` builds this eagerly at app construction, and
    ``_server()`` runs up to three times per login (so a per-call replica would reload the OS trust
    store on the login path to re-derive an answer that cannot have changed).
    """

    with pytest.raises(ValueError, match="AD LDAPS bind"):
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
def test_the_ldaps_replica_matches_the_context_ldap3_actually_builds(
    validate: ssl.VerifyMode,
    tmp_path: Path,
    asserted_contexts: list[tuple[str, ssl.SSLContext]],
) -> None:
    """The replica must resolve to the same suite list as the context ldap3 really builds.

    This is the substitute for the identity check every other site in this file gets, and it compares
    against ldap3's OWN construction rather than a second reading of its source. The replica is not
    re-derived here either — it is taken off the ``asserted_contexts`` spy, so this compares the exact
    object the shipped control checked against the exact object the hop will use.

    Both verification modes, because ``validate`` is the one replicated argument that differs between
    deployments. A CA file is supplied so the ``ca_certs_file`` arm is exercised: the replica
    deliberately does not load it, and this is the measurement that says doing so would change nothing
    about the suite list.
    """

    ca, _key = _self_signed(tmp_path)
    kwargs: dict[str, object] = {"validate": validate, "ca_certs_file": str(ca)}

    tls_policy.assert_ldap3_tls_suites(kwargs, connector="ldaps equivalence probe")
    replicas = [ctx for label, ctx in asserted_contexts if label == "ldaps equivalence probe"]
    assert len(replicas) == 1, "the assertion did not run exactly once on its own replica"
    replica = replicas[0]

    real = _context_ldap3_builds(ldap3.Tls(**kwargs))
    assert [c["name"] for c in real.get_ciphers()] == [c["name"] for c in replica.get_ciphers()], (
        "the replica no longer resolves to the suite list ldap3's own wrap_socket produces, so the "
        "AD LDAPS assertion is now checking a context this hop will not use"
    )
    assert real.verify_mode == replica.verify_mode
    assert real.check_hostname == replica.check_hostname


def test_the_asserted_ldaps_arguments_are_the_ones_the_bind_uses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What was ASSERTED must be what ``_server()`` hands ``ldap3.Tls`` — the other half of the drift.

    An equivalent context is worthless if the bind is built from different arguments, and the two live
    in different methods. ``_tls_kwargs()`` is the single definition both read; this measures that they
    really do agree, so a future edit to ``_server()`` alone cannot silently leave the assertion
    checking a stale shape.
    """

    ca, _key = _self_signed(tmp_path)
    seen: list[Mapping[str, object]] = []
    real = tls_policy.assert_ldap3_tls_suites

    def spy(tls_kwargs: Mapping[str, object], *, connector: str) -> None:
        seen.append(dict(tls_kwargs))
        real(tls_kwargs, connector=connector)

    monkeypatch.setattr(ldap_auth, "assert_ldap3_tls_suites", spy)
    auth = ldap_auth.LdapAuthenticator(_ad_settings(ad_tls_ca_cert_file=str(ca)))
    assert len(seen) == 1, "the AD LDAPS bind did not assert its TLS suites exactly once"

    tls = auth._server().tls
    assert seen[0] == {"validate": tls.validate, "ca_certs_file": tls.ca_certs_file}


def test_the_ldaps_assertion_refuses_a_tls_argument_it_cannot_replicate() -> None:
    """An unreplicable ``Tls`` argument must REFUSE, not be replicated wrongly or ignored.

    Deliberately without ``every_suite_looks_weak``: this raise has to stand on its own, so a reader
    can tell the refusal apart from a suite-list failure.
    """

    with pytest.raises(ValueError, match="ciphers"):
        tls_policy.assert_ldap3_tls_suites(
            {"validate": ssl.CERT_REQUIRED, "ciphers": "ECDHE-RSA-AES256-GCM-SHA384"},
            connector="AD LDAPS bind",
        )


def test_the_ldaps_assertion_refuses_when_the_verify_mode_is_unknown() -> None:
    """No ``validate`` means the peer-verification mode ldap3 will apply is unknown — refuse it."""

    with pytest.raises(ValueError, match="no `validate` given"):
        tls_policy.assert_ldap3_tls_suites({"ca_certs_file": None}, connector="AD LDAPS bind")


def test_ldap3_swallows_a_rejected_cipher_string_and_strips_every_tls12_suite() -> None:
    """The measurement the refusal above exists for — and it is why ``ciphers=`` is not the fix here.

    ``ldap3/core/tls.py`` wraps ``set_ciphers`` in ``except ssl.SSLError: pass``. A cipher string
    OpenSSL rejects therefore vanishes without a log line, and the hop silently loses its ENTIRE TLS 1.2
    suite list while still reporting a configured cipher policy — a control that cannot report its own
    failure (SDS-3.7). If ldap3 ever stops swallowing it, this test goes red and the refusal's rationale
    should be re-derived rather than assumed.
    """

    def tls12(ctx: ssl.SSLContext) -> list[str]:
        return [c["name"] for c in ctx.get_ciphers() if not str(c["name"]).startswith("TLS_")]

    baseline = _context_ldap3_builds(ldap3.Tls(validate=ssl.CERT_REQUIRED))
    poisoned = _context_ldap3_builds(
        ldap3.Tls(validate=ssl.CERT_REQUIRED, ciphers="THIS-IS-NOT-A-SUITE")
    )
    assert tls12(baseline), "the baseline offered no TLS 1.2 suites, so this test proves nothing"
    assert not tls12(poisoned), (
        "ldap3 no longer strips the TLS 1.2 suites on a rejected cipher string; re-derive why "
        "assert_ldap3_tls_suites refuses `ciphers=` before relying on that refusal's stated reason"
    )


# --- the Vault hops: a replica again, and this one is pinned to urllib3's own constructor ---------
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
    """The ``SSLContext`` urllib3's OWN connect path builds for ``client`` — CAPTURED, not rebuilt.

    The Vault twin of :func:`_context_ldap3_builds`, and it keeps this replica honest the same way.
    urllib3 constructs the context inside ``_ssl_wrap_socket_and_match_hostname``, but only AFTER the
    TCP connect succeeds — so the client is pointed at a real listener that accepts and immediately
    closes. The handshake then fails at once (EOF), which is fine: the context was already built, and
    the spy holds it. No peer certificate, no TLS, no off-box network — but urllib3's own construction
    code really ran, with the arguments the shipped client really produces.
    """
    import urllib3.connection  # noqa: PLC0415  (optional [vault] extra; module-scope would break base)

    captured: list[ssl.SSLContext] = []
    real = urllib3.connection.create_urllib3_context

    def spy(**kwargs: Any) -> ssl.SSLContext:
        ctx = real(**kwargs)
        captured.append(ctx)
        return ctx

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
        monkey.setattr(urllib3.connection, "create_urllib3_context", spy)
        monkey.setattr(client, "url", f"https://127.0.0.1:{port}")
        with contextlib.suppress(Exception):  # the handshake MUST fail; only the context matters
            client.sys.read_health_status()
    finally:
        monkey.undo()
        listener.close()
        server.join(timeout=5)

    assert len(captured) == 1, (
        f"urllib3 built {len(captured)} contexts on one Vault request, not 1 — the replica in "
        f"assert_hvac_tls_suites can no longer stand for 'the context this hop uses'"
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

    assert crypto_transit._build_client is keyprovider_vault._build_client


@_vault_extra
def test_the_vault_replica_matches_the_context_urllib3_actually_builds(
    asserted_contexts: list[tuple[str, ssl.SSLContext]],
) -> None:
    """The replica must resolve to the same suite list as the context urllib3 really builds.

    This is the substitute for the identity check the urllib openers get, and — like the LDAPS twin —
    it compares against the library's OWN construction rather than a second reading of its source. The
    replica is taken off the ``asserted_contexts`` spy, so this compares the exact object the shipped
    control checked against the exact object the hop will use.

    If urllib3 ever changes how it builds that context (its own defaults, or the arguments requests
    hands it), this goes red and ``assert_hvac_tls_suites`` must be re-derived rather than trusted.
    """

    client = secretprovider_vault._build_client("https://vault.example.test:8200", "s.token")
    replicas = [
        ctx for label, ctx in asserted_contexts if label == secretprovider_vault._VAULT_KV_CONNECTOR
    ]
    assert len(replicas) == 1, "the assertion did not run exactly once on its own replica"
    replica = replicas[0]

    real = _context_urllib3_builds_for(client)
    assert [c["name"] for c in real.get_ciphers()] == [c["name"] for c in replica.get_ciphers()], (
        "the replica no longer resolves to the suite list urllib3's own connect path produces, so "
        "the Vault assertion is now checking a context this hop will not use"
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
    ciphers = _context_urllib3_builds_for(client).get_ciphers()
    assert ciphers, "the Vault hop offered no suites at all, so this test proves nothing"
    for cipher in ciphers:
        assert tls_policy._is_forward_secret(cipher), f"{cipher['name']} is not forward-secret"
        assert tls_policy._is_encrypting(cipher), f"{cipher['name']} offers no confidentiality"
        assert tls_policy._is_peer_authenticated(cipher), f"{cipher['name']} authenticates no peer"


@_vault_extra
def test_the_vault_assertion_refuses_a_client_argument_it_cannot_replicate() -> None:
    """An unreplicable ``hvac.Client`` argument must REFUSE, not be replicated wrongly or ignored.

    ``session=`` is the one that matters: it is the documented way to give this hop a different TLS
    context, and a replica that accepted it would keep reporting a clean suite list for a context the
    hop had stopped using. Deliberately without ``every_suite_looks_weak``, so this raise stands on
    its own and a reader can tell the refusal apart from a suite-list failure.
    """

    with pytest.raises(ValueError, match="session"):
        tls_policy.assert_hvac_tls_suites(
            {"url": "https://vault.example.test:8200", "session": object()},
            connector="Vault KV secret provider",
        )


@_vault_extra
def test_hvac_holds_no_ssl_context_of_its_own_at_any_layer() -> None:
    """The measurement the whole replica rests on — re-run rather than quoted.

    ADR 0180 concluded a replica was the only instrument because no layer of the hvac stack exposes a
    context the engine could assert directly. That is a property of three third-party libraries, not
    of this repo, so it is pinned here: if any layer ever starts carrying an ``ssl_context``, this
    goes RED and the replica should be REPLACED by the identity check the urllib openers get, which
    is strictly stronger. A red here is good news, not a regression.
    """

    client = secretprovider_vault._build_client("https://vault.example.test:8200", "s.token")
    assert not [a for a in dir(client) if "ssl" in a.lower() or "context" in a.lower()]

    session = client.adapter.session
    adapter = session.get_adapter("https://vault.example.test:8200")
    assert "ssl_context" not in adapter.poolmanager.connection_pool_kw, (
        "requests now seeds the pool with its own SSLContext — the engine can reach that object, so "
        "assert it by identity instead of replicating urllib3's construction"
    )

    import requests.adapters  # noqa: PLC0415  (optional [vault] extra)

    assert getattr(requests.adapters, "_preloaded_ssl_context", None) is None, (
        "requests has reinstated the module-level preloaded SSLContext it carried in 2.32 — that is "
        "a reachable object and the Vault assertion should hold it rather than rebuild it"
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
            del self._context

    monkeypatch.setattr(urllib.request, "HTTPSHandler", _NoContextHandler)
    with pytest.raises(ValueError, match="cannot reach the TLS context"):
        tls_policy.build_asserted_https_handler(connector="a label")


def _covered_files() -> list[tuple[str, str]]:
    """(module file, connector label) for every site this file claims to cover, for the scan below."""
    return [
        ("messagefoundry/transports/rest.py", "HTTP-family destination"),
        ("messagefoundry/transports/soap.py", "SOAP destination"),
        ("messagefoundry/pipeline/alert_sinks.py", "alert webhook destination"),
        ("messagefoundry/auth/oidc_http.py", "OIDC identity provider"),
        ("messagefoundry/logging_setup.py", "syslog TLS forwarder"),
        ("messagefoundry/store/postgres.py", "Postgres store"),
        ("messagefoundry/auth/ldap.py", "AD LDAPS bind"),
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

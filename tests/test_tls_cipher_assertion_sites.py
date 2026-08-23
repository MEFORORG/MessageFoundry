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

import datetime
import ssl
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry import logging_setup
from messagefoundry.auth import oidc_http
from messagefoundry.config import tls_policy, tls_probe
from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, StoreBackend, StoreSettings
from messagefoundry.config.wiring import FHIR, Rest, Soap
from messagefoundry.pipeline import alert_sinks
from messagefoundry.store import postgres
from messagefoundry.transports import build_destination, rest, soap
from messagefoundry.transports.http_auth import with_http_digest

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

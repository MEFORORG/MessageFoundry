# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The revocation-hop guard on the LDAPS AD bind, and its own CRL setting (BACKLOG #2193 slice (b),
ADR 0173).

Every LDAPS bind carries a password, the service account's and then a user's, over a context that
verifies the domain controller. Stdlib ssl checks no OCSP or CRL, so before this a revoked but
unexpired DC certificate was accepted with no refusal and no record. The owner ruling of 2026-10-27
gave the hop the guard the other verifying hops take, and ``[auth].ad_tls_crl_file``.

The arms follow ``tests/test_revocation_guard_remaining_hops.py``, where each alone proves too
little:

* **refused** under an enforcing posture with no CRL. This is the control the other arms relax.
* **admitted** with an ``ad_tls_crl_file`` that reaches the bind's OWN context, read off the context
  ``wrap_socket`` really builds for a bind, and **still refused** where the CRL never reaches it.
* **fail closed**: a configured CRL that cannot be loaded refuses, at construction and at a later
  bind, and a loaded CRL that revokes the DC's certificate refuses the handshake.

Nothing here dials a directory. The handshakes run in memory. Every certificate and CRL is
synthetic.
"""

from __future__ import annotations

import ast
import datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from messagefoundry.auth import ldap as ldap_auth
from messagefoundry.auth import ldap_tls
from messagefoundry.auth.ldap import LdapAuthenticator, LdapError
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import ServiceSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    InsecureHopRefused,
    context_checks_revocation,
)
from messagefoundry.privilege_probes import read_ldap_bind
from messagefoundry.store.store import MessageStore
from tests._ast_sites import call_sites, parse_source
from tests.test_hop_refusal_revocation import (
    _crl_coverage_ca,
    _crl_coverage_server,
    _handshake,
)
from tests.test_revocation_guard_remaining_hops import _guard_log
from tests.test_tls_cipher_assertion_sites import _ad_settings, _context_ldap3_builds

ENFORCING = HopPosture(enforcing=True)
NOT_ENFORCING = HopPosture(enforcing=False)

REMOTE_DC = (
    "ldaps://dc1.example.test:636"  # off the box, never dialled: construction reads settings
)
LOOPBACK_DC = "ldaps://127.0.0.1:636"
DC_HOST = "dc1.example.test"

_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _no_blanket_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The blanket attestation must not stand in for the hop's own facts."""
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)


def _crl(
    ca_key: ec.EllipticCurvePrivateKey,
    ca: x509.Certificate,
    path: Path,
    *,
    revoked_serial: int | None = None,
) -> str:
    """A CRL from ``ca``, revoking ``revoked_serial`` when given. Synthetic."""
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(now - datetime.timedelta(hours=1))
        .next_update(now + datetime.timedelta(days=7))
    )
    if revoked_serial is not None:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder()
            .serial_number(revoked_serial)
            .revocation_date(now - datetime.timedelta(hours=2))
            .build()
        )
    path.write_bytes(builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))
    return str(path)


@pytest.fixture
def directory_pki(tmp_path: Path) -> dict[str, Any]:
    """A CA, a DC certificate it issues, the CA as a PEM anchor, and two CRLs from it: one that
    revokes nothing and one that revokes the DC. Synthetic."""
    ca_key, ca = _crl_coverage_ca("mefor-2193-ad-ca")
    server = _crl_coverage_server(ca_key, ca, DC_HOST, tmp_path)
    served = x509.load_pem_x509_certificate((tmp_path / f"{DC_HOST}.crt").read_bytes())
    anchor = tmp_path / "ad_ca.pem"
    anchor.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return {
        "server": server,
        "anchor": str(anchor),
        "clean_crl": _crl(ca_key, ca, tmp_path / "clean.crl.pem"),
        "revoking_crl": _crl(
            ca_key, ca, tmp_path / "revoking.crl.pem", revoked_serial=served.serial_number
        ),
    }


def _authenticator(
    posture: HopPosture | None, *, crl: str | None = None, **over: Any
) -> LdapAuthenticator:
    """The authenticator as AuthService builds it, with the posture passed. ``enforcing=False`` is
    the anchor's own dial, so a temp-directory ACL never refuses a test anchor."""
    fields: dict[str, Any] = {"ad_server": REMOTE_DC, **over}
    if crl is not None:
        fields["ad_tls_crl_file"] = crl
    return LdapAuthenticator(_ad_settings(**fields), enforcing=False, hop_posture=posture)


# --- the guard ------------------------------------------------------------------------------------


def test_an_off_box_ldaps_bind_is_refused_when_it_checks_no_revocation() -> None:
    # THE CONTROL. Before BACKLOG #2193 slice (b) this constructed: the bind took no guard at all.
    with pytest.raises(InsecureHopRefused, match="revocation") as exc:
        _authenticator(ENFORCING)
    text = str(exc.value)
    assert "[auth] AD LDAPS bind" in text
    # The refusal offers this hop's own lever, not the connection-shaped one it cannot use.
    assert "[auth].ad_tls_crl_file" in text
    assert "[tls].crl_file" not in text
    assert "tls_revocation_attested" not in text


def test_an_ldaps_bind_is_admitted_when_its_crl_reaches_the_bind_context(
    directory_pki: dict[str, Any],
) -> None:
    auth = _authenticator(
        ENFORCING, crl=directory_pki["clean_crl"], ad_tls_ca_cert_file=directory_pki["anchor"]
    )
    # Read off the context wrap_socket really builds for a bind, not the sample the guard read.
    assert context_checks_revocation(_context_ldap3_builds(auth._tls)) is True


def test_a_configured_crl_does_not_admit_a_bind_whose_context_lacks_it(
    directory_pki: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard reads the context, never the setting: a CRL that is configured but never reaches
    the bind's context leaves the refusal standing."""
    original = ldap_tls.NarrowedTls.__init__

    def _drop_the_crl(self: Any, **kwargs: Any) -> None:
        kwargs["crl_file"] = None
        original(self, **kwargs)

    # LdapAuthenticator imports the class lazily, so patching it on its own module is what reaches.
    monkeypatch.setattr(ldap_tls.NarrowedTls, "__init__", _drop_the_crl)
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _authenticator(ENFORCING, crl=directory_pki["clean_crl"])


def test_an_ldaps_bind_on_loopback_still_crosses() -> None:
    auth = _authenticator(ENFORCING, ad_server=LOOPBACK_DC)
    assert context_checks_revocation(auth._tls.handshake_context()) is False


def test_an_ldaps_bind_warns_but_builds_when_not_enforcing() -> None:
    with _guard_log() as log:
        _authenticator(NOT_ENFORCING)
    assert log.has("revocation") and log.has("[auth] AD LDAPS bind"), log.state()


def test_an_ldaps_bind_built_with_no_posture_is_unchanged() -> None:
    _authenticator(None)


def test_an_ldaps_server_that_names_no_host_is_refused_whatever_the_posture() -> None:
    for posture in (ENFORCING, NOT_ENFORCING, None):
        with pytest.raises(LdapError, match="names no host"):
            _authenticator(posture, ad_server="ldaps://:636")


def test_the_guard_judges_the_host_ldap3_dials_not_the_one_a_url_parser_reads() -> None:
    """``urlsplit`` reads ``127.0.0.1`` out of this address, and ldap3 dials ``dc.corp@127.0.0.1``.
    A guard on the URL reader's host would let it cross as on the box. The control is the plain
    loopback address, which does cross."""
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _authenticator(ENFORCING, ad_server="ldaps://dc.corp@127.0.0.1:636")
    _authenticator(ENFORCING, ad_server=LOOPBACK_DC)


def test_a_refused_bind_never_resolves_the_bind_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard runs before the service-account secret is resolved, like the plain-bind and
    verify-off refusals, so a refused build fetches no password."""
    monkeypatch.setattr(
        ldap_auth, "resolve_connector_secret", lambda *a, **k: pytest.fail("password resolved")
    )
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _authenticator(ENFORCING)


# --- fail closed ----------------------------------------------------------------------------------


@pytest.mark.parametrize("posture", [ENFORCING, NOT_ENFORCING, None], ids=str)
def test_a_configured_crl_that_cannot_be_loaded_refuses_the_bind(
    posture: HopPosture | None, tmp_path: Path
) -> None:
    """Under any posture, a CRL the operator set but the engine cannot load refuses, rather than
    building a context that checks nothing."""
    crl = tmp_path / "crl.pem"
    crl.write_text("this is not a PEM CRL\n", encoding="utf-8")
    with pytest.raises(ValueError, match=r"\[auth\]\.ad_tls_crl_file"):
        _authenticator(posture, crl=str(crl))


def test_a_crl_that_goes_missing_after_start_fails_the_next_bind(
    directory_pki: dict[str, Any], tmp_path: Path
) -> None:
    """Each bind builds a fresh context and loads the file again, so a CRL removed after start
    fails that bind closed instead of handshaking unchecked."""
    crl = tmp_path / "moving.crl.pem"
    crl.write_bytes(Path(directory_pki["clean_crl"]).read_bytes())
    auth = _authenticator(ENFORCING, crl=str(crl), ad_tls_ca_cert_file=directory_pki["anchor"])
    crl.unlink()
    with (
        _guard_log("messagefoundry.auth.ldap_tls") as log,
        pytest.raises(ValueError, match=r"\[auth\]\.ad_tls_crl_file"),
    ):
        _context_ldap3_builds(auth._tls)
    # ldap3 reports the refusal by type alone, so the setting is named in the operator log here.
    assert log.has("[auth].ad_tls_crl_file"), log.state()


def test_a_missing_ad_crl_path_is_refused_at_load() -> None:
    with pytest.raises(ValueError, match=r"\[auth\]\.ad_tls_crl_file"):
        _ad_settings(ad_tls_crl_file="Z:/no/such/dir/ad.crl.pem")


def test_the_crl_revokes_a_dc_certificate_on_the_bind_handshake(
    directory_pki: dict[str, Any],
) -> None:
    """The loaded CRL is really consulted on the bind's handshake. The clean CRL is the control:
    the same DC, the same anchor, accepted, so the refusal is the revocation and not the harness."""
    clean = _authenticator(
        ENFORCING, crl=directory_pki["clean_crl"], ad_tls_ca_cert_file=directory_pki["anchor"]
    )
    revoking = _authenticator(
        ENFORCING, crl=directory_pki["revoking_crl"], ad_tls_ca_cert_file=directory_pki["anchor"]
    )
    server = directory_pki["server"]
    assert _handshake(_context_ldap3_builds(clean._tls), server, DC_HOST) == "accepted"
    assert _handshake(_context_ldap3_builds(revoking._tls), server, DC_HOST) == (
        "certificate revoked"
    )


def test_a_crl_from_another_ca_fails_the_bind_closed(
    directory_pki: dict[str, Any], tmp_path: Path
) -> None:
    """A CRL that does not cover the DC's issuer still sets the check flag, so the guard admits the
    hop. The bind must then be refused for the missing CRL, never handshake unchecked."""
    other_key, other = _crl_coverage_ca("mefor-2193-other-ca")
    stray = _crl(other_key, other, tmp_path / "other.crl.pem")
    auth = _authenticator(ENFORCING, crl=stray, ad_tls_ca_cert_file=directory_pki["anchor"])
    assert _handshake(_context_ldap3_builds(auth._tls), directory_pki["server"], DC_HOST) == (
        "unable to get certificate CRL"
    )


# --- the posture reaches the guard ----------------------------------------------------------------


async def test_auth_service_passes_its_posture_to_the_guard() -> None:
    """``serve`` and ``provision-admin`` build the authenticator through ``AuthService``, with the
    posture passed as the lifespan passes it. The loopback DC is the control: the same service
    builds, so the refusal is the guard and not the harness."""
    store = await MessageStore.open(":memory:")
    try:
        with pytest.raises(InsecureHopRefused, match=r"\[auth\] AD LDAPS bind"):
            AuthService(store, _ad_settings(), hop_posture=ENFORCING)
        AuthService(store, _ad_settings(ad_server=LOOPBACK_DC), hop_posture=ENFORCING)
    finally:
        await store.close()


def test_the_privilege_probe_passes_its_posture_to_the_guard() -> None:
    """``read_ldap_bind`` builds the authenticator with the arguments AuthService gives it, so an
    enforcing probe is refused the same way, and reports it rather than binding."""
    settings = ServiceSettings.model_validate({"auth": _ad_settings().model_dump()})
    reading = read_ldap_bind(settings, ENFORCING)
    assert reading.bound is False
    assert reading.problem is not None and "revocation" in reading.problem


def _authenticator_builds() -> list[tuple[str, ast.Call]]:
    """Every ``LdapAuthenticator(...)`` call under ``messagefoundry/``, with its file."""
    found: list[tuple[str, ast.Call]] = []
    for path in sorted((_ROOT / "messagefoundry").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if "LdapAuthenticator" not in source:
            continue
        rel = path.relative_to(_ROOT).as_posix()
        found.extend((rel, call) for call in call_sites(parse_source(source), "LdapAuthenticator"))
    return found


def test_every_engine_build_of_the_authenticator_passes_a_posture() -> None:
    """A CENSUS PIN on the posture, beside the census entry for the guard call itself
    (``tests/test_revocation_guard_census.py``). That entry proves ``LdapAuthenticator.__init__``
    calls the guard. It cannot see a caller that stops passing ``hop_posture``, which would leave
    the guard the unstamped no-op with every behaviour test above still green. So every engine
    call that builds the authenticator must pass the keyword, a new one included, and pass it a
    name rather than a literal ``None``. A variable that is always ``None`` still passes this; the
    behaviour tests through ``AuthService`` and the probe hold the two callers that exist."""
    builds = _authenticator_builds()
    # At least AuthService and the privilege probe build it, so the loop below checks something.
    assert len(builds) >= 2, builds
    assert {rel for rel, _ in builds} >= {
        "messagefoundry/auth/service.py",
        "messagefoundry/privilege_probes.py",
    }, builds
    missing = []
    for rel, call in builds:
        given = {kw.arg: kw.value for kw in call.keywords}
        value = given.get("hop_posture")
        if value is None or (isinstance(value, ast.Constant) and value.value is None):
            missing.append(f"{rel}: {ast.unparse(call)}")
    assert not missing, f"LdapAuthenticator built with no hop_posture: {missing}"

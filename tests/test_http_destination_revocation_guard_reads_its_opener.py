# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The REST, SOAP, FHIR and DICOMweb revocation guard reads the opener the hop dials through.

Vault BACKLOG #2188. Each of the four destinations called ``refuse_unrevoked_verified_hop`` above the
statement that builds ``self._opener``, and passed it no ``opener=``. The guard then had no TLS
context to read, so a ``[tls].crl_file`` that really reached the hop could not relax the refusal.
Under the shipped default posture a site that chose a CRL as its remedy would have had every such
destination refused, with advice to configure the CRL it had already configured.

The guard now runs below the last statement that builds or replaces the opener, and reads it.

EVERY ARM HERE IS PAIRED. A guard that never fires passes each "builds" arm, and a guard that always
fires passes each "refuses" arm, so one without the other proves nothing. The "builds" arms also read
``VERIFY_CRL_CHECK_LEAF`` off the finished opener, so they pass because the CRL reached the context
and for no other reason.
"""

from __future__ import annotations

import datetime
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    InsecureHopRefused,
    TrustAnchorPolicy,
    active_hop_posture,
    context_checks_revocation,
)
from messagefoundry.config.wiring import FHIR, ConnectionSpec, DICOMweb, Rest, Soap
from messagefoundry.transports import build_destination, dicomweb, fhir, rest, soap
from messagefoundry.transports.http_auth import HttpAuthError
from messagefoundry.transports.rest import opener_tls_context

PROD_PHI = HopPosture(enforcing=True)

REMOTE = "10.0.0.5"  # a non-loopback host; nothing here dials it
LOOPBACK = "127.0.0.1"
SIDECAR = f"http://{LOOPBACK}:8123"

_CELLS: dict[str, tuple[ConnectorType, Callable[..., ConnectionSpec], str]] = {
    "REST": (ConnectorType.REST, Rest, f"https://{REMOTE}/x"),
    "SOAP": (ConnectorType.SOAP, Soap, f"https://{REMOTE}/svc"),
    "FHIR": (ConnectorType.FHIR, FHIR, f"https://{REMOTE}/fhir"),
    "DICOMWEB": (ConnectorType.DICOMWEB, DICOMweb, f"https://{REMOTE}/dicom-web"),
}
# How each destination names itself in its own refusal.
_LABEL = {
    "REST": "REST destination",
    "SOAP": "SOAP destination",
    "FHIR": "FHIR destination",
    "DICOMWEB": "DICOMweb destination",
}
# DICOMweb has no expiry relaxation and no Digest arm, so those two arms name the cells that do.
_EXPIRY_CELLS = ["REST", "SOAP", "FHIR"]
_DIGEST_CELLS = ["REST", "SOAP", "FHIR"]

_Settings = Mapping[str, object]
_NONE: _Settings = {}
_DIGEST: _Settings = {
    "http_auth": "digest",
    "http_auth_user": "u",
    "http_auth_password": "synthetic-pw",
}
_ECH: _Settings = {"ech_egress": True, "ech_sidecar": SIDECAR}


@pytest.fixture(autouse=True)
def _no_blanket_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """The blanket attestation and the insecure-TLS escape start unset, so neither masks a result."""
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


@pytest.fixture(scope="module")
def pki(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    """A throwaway CA, its bare CRL, and a client certificate with its key. All synthetic.

    ``crl`` is the documented bare-CRL shape (BACKLOG #1890): a CRL with no certificate beside it,
    which is what a hop on the system trust store accepts. ``ca_and_crl`` is the bundle shape that
    hop refuses, kept for the error-order arm."""
    now = datetime.datetime.now(datetime.UTC)
    day = datetime.timedelta(days=1)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-2188-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - day)
        .not_valid_after(now + 365 * day)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(now - 2 * day)
        .next_update(now + 30 * day)
        .sign(ca_key, hashes.SHA256())
    )
    client_key = ec.generate_private_key(ec.SECP256R1())
    client = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-2188-client")]))
        .issuer_name(ca.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - day)
        .not_valid_after(now + 30 * day)
        .sign(ca_key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("crl2188")
    pem = serialization.Encoding.PEM
    files = {
        "crl": crl.public_bytes(pem),
        "ca_and_crl": ca.public_bytes(pem) + crl.public_bytes(pem),
        "client_cert": client.public_bytes(pem),
        "client_key": client_key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    }
    paths: dict[str, str] = {}
    for name, content in files.items():
        path = directory / f"{name}.pem"
        path.write_bytes(content)
        paths[name] = str(path)
    return paths


def _build(
    cell: str,
    *,
    crl: str | None = None,
    revocation_attested: bool = False,
    url: str | None = None,
    extra: _Settings = _NONE,
) -> object:
    """Build one destination the way the loader does. ``crl`` is the instance ``[tls].crl_file``,
    and ``extra`` is laid over the settings the connection factory produced."""
    ctype, factory, default_url = _CELLS[cell]
    return build_destination(
        Destination(
            name="OB",
            type=ctype,
            settings={**factory(url=url or default_url).settings, **extra},
            trust_anchor_policy=TrustAnchorPolicy(crl_file=crl),
            tls_revocation_attested=revocation_attested,
            tls_revocation_attested_reason="revocation-checking PKI at the partner edge"
            if revocation_attested
            else None,
        ),
        egress=EgressSettings(deny_by_default=False),
    )


def _checks_a_crl(dest: object) -> bool:
    """Whether the opener this destination dials through carries ``VERIFY_CRL_CHECK_LEAF``."""
    opener = dest._opener  # type: ignore[attr-defined]
    return context_checks_revocation(opener_tls_context(opener, connector="probe"))


def _refused(cell: str, *, crl: str | None = None, extra: _Settings = _NONE) -> str:
    """Build under the enforcing posture, expect the revocation refusal, and return its text."""
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation") as exc:
        _build(cell, crl=crl, extra=extra)
    return str(exc.value)


# --- the defect: a CRL on the hop's own opener relaxes the refusal ---------------------------------


@pytest.mark.parametrize("cell", list(_CELLS))
def test_a_crl_that_reaches_the_hop_relaxes_the_refusal(cell: str, pki: dict[str, str]) -> None:
    with active_hop_posture(PROD_PHI):
        dest = _build(cell, crl=pki["crl"])
    assert _checks_a_crl(dest) is True
    # CONTROL: the same hop with no CRL is still refused, and the refusal names this destination.
    assert _LABEL[cell] in _refused(cell)


@pytest.mark.parametrize("cell", _EXPIRY_CELLS)
def test_the_expiry_relaxed_opener_carries_the_crl_to_the_guard(
    cell: str, pki: dict[str, str]
) -> None:
    """``tls_allow_expired`` builds its own opener. That opener loads the CRL too, so it crosses."""
    with active_hop_posture(PROD_PHI):
        dest = _build(cell, crl=pki["crl"], extra={"tls_allow_expired": True})
    assert _checks_a_crl(dest) is True
    _refused(cell, extra={"tls_allow_expired": True})


def test_soap_mutual_tls_carries_the_crl_to_the_guard(pki: dict[str, str]) -> None:
    """The client-certificate opener is SOAP's third verifying arm, and it takes precedence."""
    mtls: _Settings = {"client_cert_file": pki["client_cert"], "client_key_file": pki["client_key"]}
    with active_hop_posture(PROD_PHI):
        dest = _build("SOAP", crl=pki["crl"], extra=mtls)
    assert _checks_a_crl(dest) is True
    _refused("SOAP", extra=mtls)


@pytest.mark.parametrize("cell", _DIGEST_CELLS)
def test_a_digest_handler_added_to_the_opener_does_not_hide_the_crl(
    cell: str, pki: dict[str, str]
) -> None:
    """Digest adds a handler to the opener after it is built. The guard runs below that, and the
    handler it added is not an https handler, so the CRL context is still the one that is read."""
    with active_hop_posture(PROD_PHI):
        dest = _build(cell, crl=pki["crl"], extra=_DIGEST)
    assert _checks_a_crl(dest) is True
    # CONTROL: Digest with no CRL rebuilds a per-connection opener on the system trust store, which
    # carries no CRL. The guard reads that rebuilt opener and refuses.
    _refused(cell, extra=_DIGEST)


def test_a_loopback_hop_gets_no_crl_and_still_builds(pki: dict[str, str]) -> None:
    """The on-box carve-out is untouched: the anchor loads no CRL for loopback and the guard allows."""
    with active_hop_posture(PROD_PHI):
        dest = _build("REST", crl=pki["crl"], url=f"https://{LOOPBACK}:8443/x")
    assert _checks_a_crl(dest) is False


@pytest.mark.parametrize("cell", list(_CELLS))
def test_an_unstamped_build_is_unchanged(cell: str) -> None:
    _build(cell)  # no stamped posture: the construction gate is the authority, so this builds


# --- REST with an ECH sidecar: a CRL on the engine's opener must not relax the hop -----------------


def test_rest_with_an_ech_sidecar_and_a_crl_is_still_refused(pki: dict[str, str]) -> None:
    """With ECH the engine dials the loopback sidecar, and the sidecar verifies the destination.

    No context the engine holds checks that peer, so the guard is handed no opener on this arm. The
    opener built before the sidecar swap DOES carry the CRL, which is what a guard placed above the
    swap would have read."""
    assert _LABEL["REST"] in _refused("REST", crl=pki["crl"], extra=_ECH)
    # CONTROL 1: the same CRL relaxes the same destination without the sidecar, so the refusal above
    # is the ECH arm and not a CRL that failed to load.
    with active_hop_posture(PROD_PHI):
        assert _checks_a_crl(_build("REST", crl=pki["crl"])) is True
    # CONTROL 2: the ECH settings are valid, and the per-connection attestation still crosses.
    with active_hop_posture(PROD_PHI):
        dest = _build("REST", crl=pki["crl"], revocation_attested=True, extra=_ECH)
    assert _checks_a_crl(dest) is False  # the sidecar hop's opener carries no CRL


# --- which opener the guard is handed, by identity ------------------------------------------------
#
# The arms above read the OUTCOME. These read the ARGUMENT, which is what the outcome cannot show in
# two places. Handing the ECH arm its swapped plain opener refuses today exactly as handing it none
# does, so only the argument tells the two apart. And a statement that replaced the opener below the
# guard would leave every outcome arm green while the guard judged an opener the hop never uses.

_MODULE = {"REST": rest, "SOAP": soap, "FHIR": fhir, "DICOMWEB": dicomweb}
_OPENER_ARMS = [
    ("REST", _NONE),
    ("REST", _DIGEST),
    ("REST", {"tls_allow_expired": True}),
    ("SOAP", _NONE),
    ("SOAP", _DIGEST),
    ("SOAP", {"tls_allow_expired": True}),
    ("FHIR", _NONE),
    ("FHIR", _DIGEST),
    ("FHIR", {"tls_allow_expired": True}),
    ("DICOMWEB", _NONE),
]


def _record_guard_openers(cell: str, monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record the ``opener`` each guard call in this destination's module is handed."""
    seen: list[object] = []
    real = rest.refuse_unrevoked_verified_hop

    def spy(*args: Any, **kwargs: Any) -> None:
        seen.append(kwargs.get("opener"))
        real(*args, **kwargs)

    monkeypatch.setattr(_MODULE[cell], "refuse_unrevoked_verified_hop", spy)
    return seen


@pytest.mark.parametrize(("cell", "extra"), _OPENER_ARMS)
@pytest.mark.parametrize("with_crl", [True, False])
def test_the_guard_is_handed_the_opener_the_destination_keeps(
    cell: str,
    extra: _Settings,
    with_crl: bool,
    pki: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen = _record_guard_openers(cell, monkeypatch)
    dest = _build(cell, crl=pki["crl"] if with_crl else None, extra=extra)
    assert len(seen) == 1
    assert seen[0] is dest._opener  # type: ignore[attr-defined]


def test_the_rest_ech_arm_hands_the_guard_no_opener(
    pki: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    seen = _record_guard_openers("REST", monkeypatch)
    _build("REST", crl=pki["crl"], extra=_ECH)
    assert seen == [None]


# --- the new error order: the revocation refusal comes last ----------------------------------------
#
# Each arm is a site with TWO faults: a hop the guard would refuse (no CRL, no attestation), plus one
# configuration error. The configuration error is now the one reported. Before #2188 the guard ran
# first on each of these, so every arm below raised the revocation refusal instead.


def _config_error(
    cell: str, match: str, *, crl: str | None = None, extra: _Settings = _NONE
) -> ValueError:
    with active_hop_posture(PROD_PHI), pytest.raises(ValueError, match=match) as exc:
        _build(cell, crl=crl, extra=extra)
    # InsecureHopRefused is a ValueError, so the type alone would pass on the wrong refusal.
    assert not isinstance(exc.value, InsecureHopRefused)
    return exc.value


@pytest.mark.parametrize("cell", list(_CELLS))
@pytest.mark.parametrize("shape", ["missing", "not-pem"])
def test_a_bad_ca_file_is_reported_before_the_revocation_refusal(
    cell: str, shape: str, tmp_path: Path
) -> None:
    """A ``tls_ca_file`` the opener build cannot load raises ``OSError``, which is what ``ssl``
    raises: ``FileNotFoundError`` for a missing file and ``ssl.SSLError`` for one with no
    certificate. Neither is a ``ValueError``, so neither can be the posture refusal."""
    ca = tmp_path / "ca.pem"
    if shape == "not-pem":
        ca.write_text("not a certificate\n", encoding="ascii")
    with active_hop_posture(PROD_PHI), pytest.raises(OSError):
        _build(cell, extra={"tls_ca_file": str(ca)})


@pytest.mark.parametrize("cell", list(_CELLS))
def test_a_bad_crl_file_is_reported_before_the_revocation_refusal(
    cell: str, pki: dict[str, str]
) -> None:
    """A CRL file that also holds a certificate is refused on the system trust store (#1890)."""
    _config_error(cell, r"crl_file", crl=pki["ca_and_crl"])


@pytest.mark.parametrize("cell", _DIGEST_CELLS)
def test_a_digest_configuration_error_is_reported_before_the_revocation_refusal(cell: str) -> None:
    error = _config_error(cell, "http_auth_user", extra={"http_auth": "digest"})
    assert isinstance(error, HttpAuthError)


@pytest.mark.parametrize("cell", _DIGEST_CELLS)
def test_the_bearer_and_digest_conflict_is_reported_before_the_revocation_refusal(
    cell: str,
) -> None:
    # The token endpoint is on loopback, so its own revocation guard allows it and cannot stand in.
    bearer: _Settings = {
        "oauth2_token_url": f"https://{LOOPBACK}:8443/token",
        "oauth2_client_id": "cid",
        "oauth2_client_secret": "synthetic-secret",
    }
    error = _config_error(cell, "BOTH", extra={**bearer, **_DIGEST})
    assert isinstance(error, HttpAuthError)


def test_soap_builds_its_bearer_provider_before_the_revocation_guard() -> None:
    """SOAP alone built its bearer provider below the old guard position. With both hops refusable,
    the token hop's refusal is now the one reported, and it names the token endpoint."""
    text = _refused(
        "SOAP",
        extra={
            "oauth2_token_url": f"https://{REMOTE}/token",
            "oauth2_client_id": "cid",
            "oauth2_client_secret": "synthetic-secret",
        },
    )
    assert "OAuth2 token endpoint" in text
    assert _LABEL["SOAP"] not in text

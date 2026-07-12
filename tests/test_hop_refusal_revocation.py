# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""#201 (ADR 0078 amendment) posture-keyed revocation refusal for OUTBOUND verifying-TLS connectors.

ADR 0078 ENFORCED "no in-engine OCSP/CRL → refuse an unproven off-loopback in-process ``[api]`` TLS bind"
for the LISTENER. This residual extends the SAME posture-keyed start-time refusal to every OUTBOUND
connector that VERIFIES a downstream server cert over stdlib ``ssl`` (which has no OCSP/CRL): MLLP-over-TLS
egress, the REST/SOAP/FHIR https paths, and the Postgres asyncpg store hop. The chain is validated but a
revoked-but-unexpired peer cert would still be accepted, so a production-PHI verified hop off-loopback is
REFUSED at construction / ``messagefoundry check`` / dry-run (store: at open) unless revocation is
attested (per-connection ``tls_revocation_attested`` or the blanket ``MEFOR_TLS_REVOCATION_ATTESTED`` env).

Loopback / synthetic (non-PHI) / attested hops are byte-identical; a non-production PHI hop WARNs. It
COMPOSES with #200: #200 refuses the CLEARTEXT / verify-off hop, so revocation fires ONLY on a VERIFYING
hop — the two gates key on disjoint conditions and never double-refuse one hop.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    active_hop_posture,
    revocation_hop_disposition,
)
from messagefoundry.config.wiring import DICOMweb, FHIR, Rest, Soap
from messagefoundry.store.postgres import _build_ssl
from messagefoundry.transports import build_destination
from messagefoundry.transports.email import EmailDestination
from messagefoundry.transports.mllp import MLLPDestination

# The three postures the gradient keys on (the AI-derived is_phi/production).
PROD_PHI = HopPosture(is_phi=True, production=True)
STAGING_PHI = HopPosture(is_phi=True, production=False)
SYNTHETIC = HopPosture(is_phi=False, production=True)  # not is_phi → always ALLOW

REMOTE = "10.0.0.5"  # a non-loopback host (never resolves; treated as remote/off-box)
LOOPBACK = "127.0.0.1"


@pytest.fixture(autouse=True)
def _no_blanket_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts with the blanket revocation-attest env UNSET (the secure default = refuse), so a
    test that wants it opts in explicitly. Also clears the #200 escape so it can't mask a result."""
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


# --- the pure predicate (the shared authority) ------------------------------------------------------


def test_revocation_hop_disposition_matrix() -> None:
    def disp(
        *,
        is_phi: bool,
        production: bool,
        is_loopback_hop: bool = False,
        proxy_proven: bool = False,
        attested: bool = False,
    ) -> HopDisposition:
        return revocation_hop_disposition(
            is_phi=is_phi,
            production=production,
            is_loopback_hop=is_loopback_hop,
            proxy_proven=proxy_proven,
            attested=attested,
        )

    # loopback → ALLOW (on-box, not a network exposure) even on prod-PHI.
    assert disp(is_phi=True, production=True, is_loopback_hop=True) is HopDisposition.ALLOW
    # a proven revocation-checking terminator → ALLOW.
    assert disp(is_phi=True, production=True, proxy_proven=True) is HopDisposition.ALLOW
    # attested → ALLOW.
    assert disp(is_phi=True, production=True, attested=True) is HopDisposition.ALLOW
    # synthetic (no PHI) → ALLOW.
    assert disp(is_phi=False, production=True) is HopDisposition.ALLOW
    # production PHI, unproven → REFUSE.
    assert disp(is_phi=True, production=True) is HopDisposition.REFUSE
    # non-production PHI → WARN (crosses, loud-logged).
    assert disp(is_phi=True, production=False) is HopDisposition.WARN


# --- the guard: construction gate + unstamped no-op + attestation audit ------------------------------


def _guard(host: str, *, attested: bool = False, proxy_proven: bool = False) -> RevocationHopGuard:
    # capture() snapshots current_hop_posture(), so call it inside the test's active_hop_posture scope.
    return RevocationHopGuard.capture(
        host=host,
        cell="test",
        description="verified TLS egress (no revocation check)",
        attested=attested,
        proxy_proven=proxy_proven,
    )


def test_guard_refuses_prod_phi_remote() -> None:
    with active_hop_posture(PROD_PHI):
        with pytest.raises(InsecureHopRefused, match="revocation"):
            _guard(REMOTE).enforce_construction()


def test_guard_allows_loopback_synthetic_nonprod_attested() -> None:
    with active_hop_posture(PROD_PHI):
        _guard(LOOPBACK).enforce_construction()  # on-box
        _guard(REMOTE, attested=True).enforce_construction()  # attested
        _guard(REMOTE, proxy_proven=True).enforce_construction()  # proven terminator
    with active_hop_posture(SYNTHETIC):
        _guard(REMOTE).enforce_construction()  # no PHI
    with active_hop_posture(STAGING_PHI):
        _guard(REMOTE).enforce_construction()  # non-prod PHI → WARN (constructs)


def test_guard_unstamped_is_noop() -> None:
    # No active_hop_posture: current_hop_posture() is None → the guard no-ops (the build_check gate is the
    # authority; re-refusing at a live serve build would break every legit attested/non-prod lane).
    _guard(REMOTE).enforce_construction()


def test_guard_blanket_env_allows_prod_phi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI):
        _guard(REMOTE).enforce_construction()  # blanket env folded into attested → ALLOW


def test_guard_audits_attestation_that_suppresses_prod_refusal(caplog) -> None:
    with active_hop_posture(PROD_PHI):
        with caplog.at_level("WARNING"):
            _guard(REMOTE, attested=True).enforce_construction()
    assert any("operator attestation" in r.message for r in caplog.records)


# --- MLLP-over-TLS egress (verify path) -------------------------------------------------------------


def mllp_cfg(host: str, *, revocation_attested: bool = False, **over: object) -> Destination:
    settings: dict[str, object] = {"host": host, "port": 5000, "tls": True, **over}
    return Destination(
        name="OB_MLLP",
        type=ConnectorType.MLLP,
        settings=settings,
        tls_revocation_attested=revocation_attested,
    )


def test_mllp_tls_verify_refuses_prod_phi_remote() -> None:
    with active_hop_posture(PROD_PHI):
        with pytest.raises(InsecureHopRefused, match="revocation"):
            MLLPDestination(mllp_cfg(REMOTE))


def test_mllp_tls_verify_allows_attested_loopback_synthetic_nonprod() -> None:
    with active_hop_posture(PROD_PHI):
        MLLPDestination(mllp_cfg(REMOTE, revocation_attested=True))
        MLLPDestination(mllp_cfg(LOOPBACK))
    with active_hop_posture(SYNTHETIC):
        MLLPDestination(mllp_cfg(REMOTE))
    with active_hop_posture(STAGING_PHI):
        MLLPDestination(mllp_cfg(REMOTE))  # non-prod PHI → WARN, constructs


def test_mllp_tls_verify_unstamped_is_noop() -> None:
    MLLPDestination(mllp_cfg(REMOTE))  # no stamped posture → byte-identical


def test_mllp_blanket_env_allows_prod_phi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI):
        MLLPDestination(mllp_cfg(REMOTE))


def test_mllp_sets_revocation_guard_only_on_verify_path() -> None:
    # verify-ON TLS hop carries a revocation guard; a cleartext (tls off) hop does not (its cleartext
    # #200 guard handles it — the two guards are disjoint, never both set).
    with active_hop_posture(SYNTHETIC):  # synthetic so neither guard refuses
        verified = MLLPDestination(mllp_cfg(REMOTE))
        cleartext = MLLPDestination(
            Destination(name="OB", type=ConnectorType.MLLP, settings={"host": REMOTE, "port": 5000})
        )
    assert verified._revocation_guard is not None and verified._hop_guard is None
    assert cleartext._revocation_guard is None and cleartext._hop_guard is not None


# --- compose with #200: cleartext / verify-off refuse via #200, NOT double-counted ------------------


def test_mllp_cleartext_refuses_via_200_not_revocation() -> None:
    # A plaintext (tls off) prod-PHI remote hop is refused by the #200 cleartext gate (message names the
    # CLEARTEXT hop), not the #201 revocation gate — revocation only matters on a VERIFYING hop.
    cfg = Destination(name="OB", type=ConnectorType.MLLP, settings={"host": REMOTE, "port": 5000})
    with active_hop_posture(PROD_PHI):
        with pytest.raises(InsecureHopRefused, match="cleartext"):
            MLLPDestination(cfg)


def test_mllp_verify_off_refuses_via_mllp_context_not_revocation() -> None:
    # tls_verify=false is a NON-verifying hop (CERT_NONE), refused by _mllp_ssl_context (#200 escape
    # clamp), so the revocation gate (verify path only) never fires — no double-refusal, no contradiction.
    cfg = Destination(
        name="OB",
        type=ConnectorType.MLLP,
        settings={"host": REMOTE, "port": 5000, "tls": True, "tls_verify": False},
    )
    with active_hop_posture(PROD_PHI):
        with pytest.raises(ValueError, match="tls_verify=false"):
            MLLPDestination(cfg)


# --- REST / SOAP / FHIR https (verify path) ---------------------------------------------------------

_HTTPS = {
    "REST": (ConnectorType.REST, Rest, "https://api.example.com/x"),
    "SOAP": (ConnectorType.SOAP, Soap, "https://api.example.com/svc"),
    "FHIR": (ConnectorType.FHIR, FHIR, "https://fhir.example.org/fhir"),
    # DICOMweb STOW-RS reuses REST's verifying urllib opener → same posture-keyed guard (#201 residual).
    "DICOMWEB": (ConnectorType.DICOMWEB, DICOMweb, "https://pacs.example.org/dicom-web"),
}
_HTTPS_LOOPBACK = {
    "REST": (ConnectorType.REST, Rest, "https://127.0.0.1:8443/x"),
    "SOAP": (ConnectorType.SOAP, Soap, "https://localhost:8443/svc"),
    "FHIR": (ConnectorType.FHIR, FHIR, "https://127.0.0.1:8443/fhir"),
    "DICOMWEB": (ConnectorType.DICOMWEB, DICOMweb, "https://127.0.0.1:8443/dicom-web"),
}
_HTTP_CELLS = list(_HTTPS)


def _build_https(spec: tuple[object, object, str], *, revocation_attested: bool = False) -> object:
    ctype, factory, url = spec
    return build_destination(
        Destination(
            name="OB",
            type=ctype,  # type: ignore[arg-type]
            settings=factory(url=url).settings,
            tls_revocation_attested=revocation_attested,
        )
    )


@pytest.mark.parametrize("cell", _HTTP_CELLS)
def test_https_verified_refuses_prod_phi_remote(cell: str) -> None:
    with active_hop_posture(PROD_PHI):
        with pytest.raises(InsecureHopRefused, match="revocation"):
            _build_https(_HTTPS[cell])


@pytest.mark.parametrize("cell", _HTTP_CELLS)
def test_https_verified_allows_attested(cell: str) -> None:
    with active_hop_posture(PROD_PHI):
        _build_https(_HTTPS[cell], revocation_attested=True)


@pytest.mark.parametrize("cell", _HTTP_CELLS)
def test_https_verified_allows_loopback(cell: str) -> None:
    with active_hop_posture(PROD_PHI):
        _build_https(_HTTPS_LOOPBACK[cell])


@pytest.mark.parametrize("cell", _HTTP_CELLS)
def test_https_verified_warns_but_builds_staging(cell: str) -> None:
    with active_hop_posture(STAGING_PHI):
        _build_https(_HTTPS[cell])  # non-prod PHI → WARN, constructs


@pytest.mark.parametrize("cell", _HTTP_CELLS)
def test_https_verified_allows_synthetic(cell: str) -> None:
    with active_hop_posture(SYNTHETIC):
        _build_https(_HTTPS[cell])  # no PHI on the wire


@pytest.mark.parametrize("cell", _HTTP_CELLS)
def test_https_verified_unstamped_is_noop(cell: str) -> None:
    _build_https(_HTTPS[cell])  # no stamped posture → byte-identical


@pytest.mark.parametrize("cell", _HTTP_CELLS)
def test_https_verified_blanket_env_allows_prod(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI):
        _build_https(_HTTPS[cell])


# --- Postgres asyncpg store hop (_build_ssl verify path) --------------------------------------------


def _pg(server: str = REMOTE, **kw: object) -> StoreSettings:
    base: dict[str, object] = {
        "backend": StoreBackend.POSTGRES,
        "server": server,
        "database": "mefor",
        "username": "mefor",
    }
    base.update(kw)
    return StoreSettings(**base)


def test_store_verify_refuses_prod_phi_remote() -> None:
    with pytest.raises(ValueError, match="revocation"):
        _build_ssl(_pg(), posture=PROD_PHI)


def test_store_verify_allows_loopback_synthetic_nonprod() -> None:
    assert _build_ssl(_pg(server=LOOPBACK), posture=PROD_PHI) is True  # on-box
    assert _build_ssl(_pg(), posture=SYNTHETIC) is True  # no PHI
    assert _build_ssl(_pg(), posture=STAGING_PHI) is True  # non-prod PHI → WARN, returns verifying


def test_store_verify_unstamped_is_noop() -> None:
    # posture=None (a backup/restore util / test) → byte-identical (the shipped default verifying True).
    assert _build_ssl(_pg()) is True


def test_store_verify_blanket_env_allows_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    assert _build_ssl(_pg(), posture=PROD_PHI) is True


def test_store_pinned_ca_also_refuses_prod_phi_remote(tmp_path: object) -> None:
    # The ssl_root_cert (pinned-CA) branch is ALSO a verifying hop → refused the same way on prod-PHI.
    ca = tmp_path / "db-ca.pem"  # type: ignore[operator]
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    with pytest.raises(ValueError, match="revocation"):
        _build_ssl(_pg(ssl_root_cert=str(ca)), posture=PROD_PHI)


# --- SMTP-over-TLS email (use_tls verify path; a different construction seam) ------------------------


def email_cfg(host: str, *, revocation_attested: bool = False, **over: object) -> Destination:
    settings: dict[str, object] = {
        "host": host,
        "sender": "engine@example.org",
        "recipients": ["clinician@example.org"],
        **over,
    }
    return Destination(
        name="OB_EMAIL",
        type=ConnectorType.EMAIL,
        settings=settings,
        tls_revocation_attested=revocation_attested,
    )


def test_email_tls_refuses_prod_phi_remote() -> None:
    # use_tls defaults True (STARTTLS): a verified SMTP hop with no revocation check → refuse on prod-PHI.
    with active_hop_posture(PROD_PHI):
        with pytest.raises(InsecureHopRefused, match="revocation"):
            EmailDestination(email_cfg(REMOTE))


def test_email_tls_allows_attested_loopback_synthetic_nonprod() -> None:
    with active_hop_posture(PROD_PHI):
        EmailDestination(email_cfg(REMOTE, revocation_attested=True))
        EmailDestination(email_cfg(LOOPBACK))
    with active_hop_posture(SYNTHETIC):
        EmailDestination(email_cfg(REMOTE))
    with active_hop_posture(STAGING_PHI):
        EmailDestination(email_cfg(REMOTE))  # non-prod PHI → WARN, constructs


def test_email_tls_unstamped_is_noop() -> None:
    EmailDestination(email_cfg(REMOTE))  # no stamped posture → byte-identical


def test_email_blanket_env_allows_prod_phi(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI):
        EmailDestination(email_cfg(REMOTE))


def test_email_cleartext_refuses_via_settings_not_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # use_tls=false is a NON-verifying (cleartext) hop, refused by the email destination's own cleartext
    # guard (message names cleartext), so the revocation gate (verify path only) never fires here.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(PROD_PHI):
        with pytest.raises(ValueError, match="cleartext"):
            EmailDestination(email_cfg(REMOTE, use_tls=False))

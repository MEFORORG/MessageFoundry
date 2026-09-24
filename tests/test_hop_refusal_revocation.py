# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""#201 (ADR 0078 amendment) posture-keyed revocation refusal for OUTBOUND verifying-TLS connectors.

ADR 0078 ENFORCED "no in-engine OCSP/CRL → refuse an unproven off-loopback in-process ``[api]`` TLS bind"
for the LISTENER. This residual extends the SAME posture-keyed start-time refusal to every OUTBOUND
connector that VERIFIES a downstream server cert over stdlib ``ssl`` (which has no OCSP/CRL): MLLP-over-TLS
egress, the REST/SOAP/FHIR https paths, and the Postgres asyncpg store hop. The chain is validated but a
revoked-but-unexpired peer cert would still be accepted, so a production-PHI verified hop off-loopback is
REFUSED at construction / ``messagefoundry check`` / dry-run (store: at open) unless revocation is
attested (per-connection ``tls_revocation_attested``) or really checked.

**BACKLOG #299 clamped the blanket ``MEFOR_TLS_REVOCATION_ATTESTED`` env.** It used to be OR'd into the
per-connection attestation, so setting it once crossed every verifying outbound hop in an enforcing
instance. It now ranks BELOW the enforcing refusal: under ``enforcing`` only the hop's own facts cross it
(loopback, a CRL actually loaded on that hop's context, a proven terminator, or the per-connection flag),
while a non-enforcing posture still crosses on the env exactly as before. Several tests here asserted the
pre-clamp ALLOW and now assert the refusal; each says so at its own docstring.

Loopback / attested / proxy-proven hops are byte-identical; a non-enforcing hop WARNs. The fourth
relaxation, a synthetic instance, went with BACKLOG #1279 -- every instance carries patient data. It
COMPOSES with #200: #200 refuses the CLEARTEXT / verify-off hop, so revocation fires ONLY on a VERIFYING
hop — the two gates key on disjoint conditions and never double-refuse one hop.
"""

from __future__ import annotations

import ssl

import pytest

from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType, Destination, SignatureAlgorithm
from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    TrustAnchorPolicy,
    active_hop_posture,
    build_anchored_https_handler,
    context_checks_revocation,
    revocation_hop_disposition,
    urllib_handler_context,
)
from messagefoundry.config.wiring import FHIR, DICOMweb, Rest, Soap
from messagefoundry.logging_setup import SyslogForward, _build_tls_context
from messagefoundry.store.postgres import _build_ssl
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import build_destination
from messagefoundry.transports.dicom import _client_ssl_context as _dicom_client_ssl_context
from messagefoundry.transports.email import EmailDestination
from messagefoundry.transports.mllp import MLLPDestination
from messagefoundry.transports.remotefile import _ftps_ssl_context
from messagefoundry.transports.rest import http_family_trust_anchor, opener_tls_context
from messagefoundry.transports.smart import (
    SmartAuthError,
    SmartBackendTokenProvider,
    token_provider_from_settings,
)
from tests.test_auth_oidc_service import _FakeLdap
from tests.test_auth_oidc_service import _settings as _oidc_settings

# The postures the gradient keys on. `is_phi` went with BACKLOG #1279 -- only the dial is left.
PROD_PHI = HopPosture(enforcing=True)
STAGING_PHI = HopPosture(enforcing=False)
# Pre-#1279 this was the blanket carve-out ("not is_phi → ALLOW"). It is enforcing, so it REFUSES.
SYNTHETIC_NOW_ENFORCING = HopPosture(enforcing=True)

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
        enforcing: bool,
        is_loopback_hop: bool = False,
        proxy_proven: bool = False,
        attested: bool = False,
        crl_checked: bool = False,
        blanket_attested: bool = False,
    ) -> HopDisposition:
        return revocation_hop_disposition(
            enforcing=enforcing,
            is_loopback_hop=is_loopback_hop,
            proxy_proven=proxy_proven,
            attested=attested,
            crl_checked=crl_checked,
            blanket_attested=blanket_attested,
        )

    # loopback → ALLOW (on-box, not a network exposure) even on enforcing-PHI.
    assert disp(enforcing=True, is_loopback_hop=True) is HopDisposition.ALLOW
    # a proven revocation-checking terminator → ALLOW.
    assert disp(enforcing=True, proxy_proven=True) is HopDisposition.ALLOW
    # a PER-CONNECTION attestation → ALLOW.
    assert disp(enforcing=True, attested=True) is HopDisposition.ALLOW
    # BACKLOG #299: this hop's own context checks a CRL → ALLOW, the relaxation that replaces a
    # declaration with a real in-engine check.
    assert disp(enforcing=True, crl_checked=True) is HopDisposition.ALLOW
    # A fourth ALLOW arm sat here -- `not is_phi`, the synthetic instance -- and went with BACKLOG
    # #1279. Every instance carries patient data, so it had no input left to fire on and this row,
    # which used to ALLOW, now falls through to the refusal below.
    #
    # enforcing, unproven → REFUSE.
    assert disp(enforcing=True) is HopDisposition.REFUSE
    # non-enforcing → WARN (crosses, loud-logged).
    assert disp(enforcing=False) is HopDisposition.WARN


def test_blanket_attestation_does_not_defeat_an_enforcing_posture() -> None:
    """BACKLOG #299, the attestation clamp: the blanket env ranks BELOW the enforcing refusal.

    Before the clamp ``RevocationHopGuard.capture`` OR'd ``MEFOR_TLS_REVOCATION_ATTESTED`` into the
    per-connection ``attested`` argument, so this first assertion returned ALLOW and one process-wide
    environment variable crossed every verifying outbound hop in an enforcing instance."""
    # ENFORCING + blanket env only → REFUSE. This is the row that flipped.
    assert (
        revocation_hop_disposition(
            enforcing=True,
            is_loopback_hop=False,
            proxy_proven=False,
            attested=False,
            blanket_attested=True,
        )
        is HopDisposition.REFUSE
    )
    # The clamp is scoped to the enforcing posture: a non-enforcing hop still ALLOWs on the blanket env,
    # byte-identical to the pre-clamp behaviour (it would otherwise WARN).
    assert (
        revocation_hop_disposition(
            enforcing=False,
            is_loopback_hop=False,
            proxy_proven=False,
            attested=False,
            blanket_attested=True,
        )
        is HopDisposition.ALLOW
    )
    # And the clamp never removes a hop's OWN way out: each per-hop relaxation still crosses an
    # enforcing hop while the blanket env alone does not.
    for relaxation in ("is_loopback_hop", "proxy_proven", "attested", "crl_checked"):
        kwargs: dict[str, bool] = {
            "is_loopback_hop": False,
            "proxy_proven": False,
            "attested": False,
            "crl_checked": False,
        }
        kwargs[relaxation] = True
        assert (
            revocation_hop_disposition(enforcing=True, blanket_attested=True, **kwargs)
            is HopDisposition.ALLOW
        ), relaxation


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
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        _guard(REMOTE).enforce_construction()


def test_guard_allows_loopback_nonprod_attested() -> None:
    with active_hop_posture(PROD_PHI):
        _guard(LOOPBACK).enforce_construction()  # on-box
        _guard(REMOTE, attested=True).enforce_construction()  # attested
        _guard(REMOTE, proxy_proven=True).enforce_construction()  # proven terminator
    with active_hop_posture(STAGING_PHI):
        _guard(REMOTE).enforce_construction()  # non-prod PHI → WARN (constructs)


def test_guard_unstamped_is_noop() -> None:
    # No active_hop_posture: current_hop_posture() is None → the guard no-ops (the build_check gate is the
    # authority; re-refusing at a live serve build would break every legit attested/non-prod lane).
    _guard(REMOTE).enforce_construction()


def test_guard_blanket_env_no_longer_crosses_an_enforcing_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #299 clamp, at the guard. This test asserted the OPPOSITE until the clamp landed: the
    blanket env was OR'd into ``attested`` inside ``capture``, so it ALLOWed here."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        _guard(REMOTE).enforce_construction()
    # The refusal names the blanket env, so an operator who set it is told why it stopped working.
    with active_hop_posture(PROD_PHI):
        guard = _guard(REMOTE)
    assert TLS_REVOCATION_ATTESTED_ENV in guard._detail()
    # A per-connection attestation still crosses the same hop, and a non-enforcing posture still
    # crosses on the env alone.
    with active_hop_posture(PROD_PHI):
        _guard(REMOTE, attested=True).enforce_construction()
    with active_hop_posture(STAGING_PHI):
        _guard(REMOTE).enforce_construction()


def test_guard_keeps_the_blanket_env_apart_from_the_per_connection_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The clamp is only expressible because ``capture`` stops collapsing the two claims into one field."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI):
        guard = _guard(REMOTE)
    assert guard.blanket_attested is True
    assert guard.attested is False  # NOT OR'd in — that fold is what the clamp removed


def test_guard_audits_attestation_that_suppresses_prod_refusal(caplog) -> None:
    with active_hop_posture(PROD_PHI), caplog.at_level("WARNING"):
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
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        MLLPDestination(mllp_cfg(REMOTE))


def test_mllp_tls_verify_allows_attested_loopback_nonprod() -> None:
    with active_hop_posture(PROD_PHI):
        MLLPDestination(mllp_cfg(REMOTE, revocation_attested=True))
        MLLPDestination(mllp_cfg(LOOPBACK))
    with active_hop_posture(STAGING_PHI):
        MLLPDestination(mllp_cfg(REMOTE))  # non-prod PHI → WARN, constructs


def test_mllp_tls_verify_unstamped_is_noop() -> None:
    MLLPDestination(mllp_cfg(REMOTE))  # no stamped posture → byte-identical


def test_mllp_blanket_env_no_longer_crosses_an_enforcing_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #299 clamp, through a real connector. Asserted the opposite before the clamp."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        MLLPDestination(mllp_cfg(REMOTE))
    # Per-connection attestation and a non-enforcing posture are untouched by the clamp.
    with active_hop_posture(PROD_PHI):
        MLLPDestination(mllp_cfg(REMOTE, revocation_attested=True))
    with active_hop_posture(STAGING_PHI):
        MLLPDestination(mllp_cfg(REMOTE))


def test_mllp_sets_revocation_guard_only_on_verify_path() -> None:
    # verify-ON TLS hop carries a revocation guard; a cleartext (tls off) hop does not (its cleartext
    # #200 guard handles it — the two guards are disjoint, never both set).
    #
    # A synthetic declaration used to suppress BOTH gates. ADR 0153 took the data label off the
    # CLEARTEXT one (so the cleartext leg carries an explicit declaration instead) and BACKLOG #1279
    # took it off the revocation one too, so the asymmetry this test pinned is gone: BOTH gates now
    # read the hop's own facts. What is still worth pinning is that only ONE guard is set per hop --
    # a verify-ON hop carries the revocation guard, a cleartext hop carries the #200 guard, never both.
    # The verified leg is attested so it constructs; the gate itself is covered above.
    with active_hop_posture(SYNTHETIC_NOW_ENFORCING):
        verified = MLLPDestination(mllp_cfg(REMOTE, revocation_attested=True))
        cleartext = MLLPDestination(
            Destination(
                name="OB",
                type=ConnectorType.MLLP,
                settings={"host": REMOTE, "port": 5000},
                cleartext_accepted=True,
                cleartext_reason="legacy peer has no TLS",
            )
        )
    assert verified._revocation_guard is not None and verified._hop_guard is None
    assert cleartext._revocation_guard is None and cleartext._hop_guard is not None


# --- compose with #200: cleartext / verify-off refuse via #200, NOT double-counted ------------------


def test_mllp_cleartext_refuses_via_200_not_revocation() -> None:
    # A plaintext (tls off) prod-PHI remote hop is refused by the #200 cleartext gate (message names the
    # CLEARTEXT hop), not the #201 revocation gate — revocation only matters on a VERIFYING hop.
    cfg = Destination(name="OB", type=ConnectorType.MLLP, settings={"host": REMOTE, "port": 5000})
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="cleartext"):
        MLLPDestination(cfg)


def test_mllp_verify_off_refuses_via_mllp_context_not_revocation() -> None:
    # tls_verify=false is a NON-verifying hop (CERT_NONE), refused by _mllp_ssl_context (#200 escape
    # clamp), so the revocation gate (verify path only) never fires — no double-refusal, no contradiction.
    cfg = Destination(
        name="OB",
        type=ConnectorType.MLLP,
        settings={"host": REMOTE, "port": 5000, "tls": True, "tls_verify": False},
    )
    with active_hop_posture(PROD_PHI), pytest.raises(ValueError, match="tls_verify=false"):
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
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
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
def test_https_verified_unstamped_is_noop(cell: str) -> None:
    _build_https(_HTTPS[cell])  # no stamped posture → byte-identical


@pytest.mark.parametrize("cell", _HTTP_CELLS)
def test_https_verified_blanket_env_no_longer_crosses_enforcing(
    cell: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #299 clamp across the whole HTTP family. Asserted the opposite before the clamp."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        _build_https(_HTTPS[cell])
    with active_hop_posture(STAGING_PHI):
        _build_https(_HTTPS[cell])  # non-enforcing still crosses on the env


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


def test_store_verify_allows_loopback_nonprod() -> None:
    assert _build_ssl(_pg(server=LOOPBACK), posture=PROD_PHI) is True  # on-box
    assert _build_ssl(_pg(), posture=STAGING_PHI) is True  # non-enforcing → WARN, returns verifying


def test_store_verify_unstamped_is_noop() -> None:
    # posture=None (a backup/restore util / test) → byte-identical (the shipped default verifying True).
    assert _build_ssl(_pg()) is True


def test_the_blanket_env_does_not_cross_the_enforcing_store_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE DEFECT THIS ARM PINS. ``_refuse_store_revocation`` used to hand-roll the gate and pass
    ``tls_revocation_attested()`` -- the process-wide env -- into ``revocation_hop_disposition``'s
    PER-CONNECTION ``attested`` slot. That slot ranks ABOVE the enforcing REFUSE, so the engine-to-store
    hop crossed on one env var while every guard-routed sibling refused: the #299 clamp was defeated on
    exactly the hop carrying the PHI store. This test asserted that crossing (``is True``) before the
    collapse onto ``RevocationHopGuard``, whose ``capture`` reads the env into the separate
    ``blanket_attested`` field that ranks BELOW the refusal."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _build_ssl(_pg(), posture=PROD_PHI)
    # NEGATIVE CONTROL, and it has to be read off the DISPOSITION rather than off the return value.
    # `_build_ssl(..., posture=STAGING_PHI) is True` was the obvious control and it is a FALSE one: it
    # returns True whether the env was read (ALLOW) or not (WARN, which also crosses), so it passes in
    # exactly the world it exists to exclude. The guard's own field is the discriminating observable.
    assert (
        RevocationHopGuard.capture(
            host=REMOTE,
            cell="control",
            description="control",
            attested=False,
            posture=STAGING_PHI,
        ).blanket_attested
        is True
    )
    # ...and the env still CROSSES a non-enforcing hop, byte-identical to the pre-clamp behaviour, so
    # only the enforcing rung moved.
    assert _build_ssl(_pg(), posture=STAGING_PHI) is True


def test_store_pinned_ca_also_refuses_prod_phi_remote(crl_bundle: str) -> None:
    """The ssl_root_cert (pinned-CA) branch is ALSO a verifying hop, so it is refused the same way.

    It takes a REAL CA PEM now. The guard moved BELOW the context build on this branch (it has to read
    the finished object to see a CRL), so a placeholder PEM no longer reaches the refusal -- it dies
    earlier in ``create_default_context(cafile=...)`` with an SSLError, and the test would pass on a
    hop that never got built. The `crl_bundle` file doubles as a plain CA anchor: loading it as
    `cafile=` alone does not set VERIFY_CRL_CHECK_LEAF, so this stays an unrevoked verifying hop."""
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _build_ssl(_pg(ssl_root_cert=crl_bundle), posture=PROD_PHI)


def test_the_store_crl_closes_its_own_gate_on_the_pinned_ca_branch(
    ca_only: str, crl_bundle: str
) -> None:
    """``[store].ssl_crl_file`` (BACKLOG #299) is the store hop's OWN way across an enforcing posture.

    Closing the clamp above removed this hop's only existing one, and ``StoreSettings`` carries no
    per-store revocation attestation -- so without a knob a remote Postgres store on an enforcing
    posture would be refused with no remediation the error text could honestly name. The CRL loads onto
    the pinned-CA branch, the one arm where engine code builds the context asyncpg uses, and the guard
    reads ``VERIFY_CRL_CHECK_LEAF`` off that very object rather than off the setting.

    The two arguments take DIFFERENT files on purpose. Passing the bundle for both cannot tell them
    apart, so ``harden_crl_check(ctx, settings.ssl_root_cert)`` -- an argument swap -- would pass."""
    ctx = _build_ssl(_pg(ssl_root_cert=ca_only, ssl_crl_file=crl_bundle), posture=PROD_PHI)
    assert isinstance(ctx, ssl.SSLContext)
    # The line above passed for the RIGHT reason: the CRL really landed on the returned context.
    assert context_checks_revocation(ctx) is True
    # NEGATIVE CONTROL: the SAME hop with the SAME CA and no CRL is still refused, so the crossing is
    # attributable to the CRL rather than to the guard having stopped firing on this branch.
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _build_ssl(_pg(ssl_root_cert=ca_only), posture=PROD_PHI)


def test_the_store_refusal_names_a_lever_that_exists_for_it() -> None:
    """SDS-3.7 applied to the refusal TEXT. The guard's connection-shaped default names
    ``[tls].crl_file``, an egress terminator and a connection's ``tls_revocation_attested``; none
    reaches the store, which resolves no trust anchor and is not a connection. Telling that operator to
    set one of them is a refusal whose remedy cannot be performed. ``ssl_crl_file`` is named WITH
    ``ssl_root_cert`` because the CRL only loads on the pinned-CA branch -- from the default path the
    operator has to set both, and half the instruction is still a remedy that fails."""
    with pytest.raises(InsecureHopRefused) as exc:
        _build_ssl(_pg(), posture=PROD_PHI)
    assert "[store].ssl_crl_file" in str(exc.value)
    assert "[store].ssl_root_cert" in str(exc.value)
    assert "tls_revocation_attested=true on this connection" not in str(exc.value)


def test_the_default_store_path_has_no_context_for_a_crl_to_reach(crl_bundle: str) -> None:
    """THE RESIDUAL, pinned so it is not mistaken for a gap in the guard. On the DEFAULT path (no
    ``ssl_root_cert``) ``_build_ssl`` returns ``True`` and asyncpg builds the context, so there is no
    engine-side object for a CRL to load into -- ``ssl_crl_file`` alone cannot close this arm, and
    loopback is its only way across an enforcing posture. Closing it means building the verifying
    default context here instead, which changes what asyncpg receives: a separate decision.

    The residual is REFUSED AT LOAD rather than left silent. A setting that is read, ignored and still
    reports success is how an operator comes to believe revocation checking is on when it is not --
    worse than an absent control, and the reason `_ssl_crl_file_reachable` exists."""
    with pytest.raises(ValueError, match=r"requires \[store\].ssl_root_cert"):
        _pg(ssl_crl_file=crl_bundle)
    # The hop itself is still refused off-loopback, and still crosses on loopback -- the residual is
    # that loopback is the ONLY way across here, which is exactly what the refusal text says.
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _build_ssl(_pg(), posture=PROD_PHI)
    assert _build_ssl(_pg(server=LOOPBACK), posture=PROD_PHI) is True


def test_the_store_crl_is_refused_where_it_could_not_be_loaded(crl_bundle: str) -> None:
    """The other two silent-no-op shapes `_ssl_crl_file_reachable` closes. Neither server-DB sibling
    can load a CRL: SQL Server pins through an ODBC keyword string and never sees an SSLContext, and
    SQLite has no TLS at all. Refuse rather than ignore, the `_ssl_root_cert_backend` convention."""
    for backend in (StoreBackend.SQLSERVER, StoreBackend.SQLITE):
        with pytest.raises(ValueError, match="requires the postgres backend"):
            StoreSettings(
                backend=backend,
                server=REMOTE,
                database="mefor",
                username="mefor",
                ssl_crl_file=crl_bundle,
            )
    # A missing path is caught at LOAD too, naming [store].ssl_crl_file -- harden_crl_check would
    # catch it at store open but hard-codes the prefix "[tls] crl file" for every call site, so it
    # would report a store setting against the wrong config section.
    with pytest.raises(ValueError, match=r"\[store\].ssl_crl_file path does not exist"):
        _pg(ssl_root_cert=crl_bundle, ssl_crl_file=str(crl_bundle) + ".absent")


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
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        EmailDestination(email_cfg(REMOTE))


def test_email_tls_allows_attested_loopback_nonprod() -> None:
    with active_hop_posture(PROD_PHI):
        EmailDestination(email_cfg(REMOTE, revocation_attested=True))
        EmailDestination(email_cfg(LOOPBACK))
    with active_hop_posture(STAGING_PHI):
        EmailDestination(email_cfg(REMOTE))  # non-enforcing → WARN, constructs


def test_the_synthetic_arm_is_gone_and_those_hops_now_refuse() -> None:
    """BACKLOG #1279: the `not is_phi -> ALLOW` arm went, so its inputs REFUSE.

    Pinned once, on every cell that carried a SYNTHETIC arm before, rather than left implicit in six
    deleted lines. Each of these constructed silently on an instance declared synthetic; each refuses
    now, because there is no declaration that reaches this gate any more. The only relaxations left are
    the three the disposition still names: on-box, a proven terminator, an operator attestation.
    """
    with active_hop_posture(SYNTHETIC_NOW_ENFORCING):
        with pytest.raises(InsecureHopRefused, match="revocation"):
            _guard(REMOTE).enforce_construction()
        with pytest.raises(InsecureHopRefused, match="revocation"):
            MLLPDestination(mllp_cfg(REMOTE))
        with pytest.raises(InsecureHopRefused, match="revocation"):
            EmailDestination(email_cfg(REMOTE))
        for cell in _HTTP_CELLS:
            with pytest.raises(InsecureHopRefused, match="revocation"):
                _build_https(_HTTPS[cell])
    # The store hop takes its posture as an argument rather than off the contextvar, so it is asserted
    # separately rather than dropped -- it carried a SYNTHETIC arm too.
    with pytest.raises(ValueError, match="revocation"):
        _build_ssl(_pg(), posture=SYNTHETIC_NOW_ENFORCING)
    # ...and the three real relaxations still cross it, so this is a tightening rather than a wall.
    with active_hop_posture(SYNTHETIC_NOW_ENFORCING):
        _guard(LOOPBACK).enforce_construction()
        _guard(REMOTE, attested=True).enforce_construction()
        _guard(REMOTE, proxy_proven=True).enforce_construction()


def test_email_tls_unstamped_is_noop() -> None:
    EmailDestination(email_cfg(REMOTE))  # no stamped posture → byte-identical


def test_email_blanket_env_no_longer_crosses_enforcing(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #299 clamp on the SMTP hop. Asserted the opposite before the clamp."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        EmailDestination(email_cfg(REMOTE))
    with active_hop_posture(PROD_PHI):
        EmailDestination(email_cfg(REMOTE, revocation_attested=True))
    with active_hop_posture(STAGING_PHI):
        EmailDestination(email_cfg(REMOTE))


def test_email_cleartext_refuses_via_settings_not_revocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # use_tls=false is a NON-verifying (cleartext) hop, refused by the email destination's own cleartext
    # guard (message names cleartext), so the revocation gate (verify path only) never fires here.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(PROD_PHI), pytest.raises(ValueError, match="cleartext"):
        EmailDestination(email_cfg(REMOTE, use_tls=False))


# --- BACKLOG #299: [tls].crl_file reaches each hop's OWN context, and closes that hop's guard --------
#
# The item records per-hop CRL scoping as the binding risk: one instance-wide crl_file must never
# silence a guard on a hop whose handshake does not consult it. So every assertion below reads
# VERIFY_CRL_CHECK_LEAF off the context the connector will really hand to wrap_socket, via
# context_checks_revocation -- never off the setting, and never off a look-alike built beside it.


@pytest.fixture(scope="module")
def crl_bundle(tmp_path_factory: pytest.TempPathFactory) -> str:
    """A throwaway CA bundled with its own fresh CRL -- the shape harden_crl_check loads. Synthetic."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.UTC)
    day = datetime.timedelta(days=1)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mefor-299-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - day)
        .not_valid_after(now + 365 * day)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca.subject)
        .last_update(now - 2 * day)
        .next_update(now + 30 * day)
        .sign(key, hashes.SHA256())
    )
    directory = tmp_path_factory.mktemp("crl299")
    path = directory / "ca_and_crl.pem"
    path.write_bytes(
        ca.public_bytes(serialization.Encoding.PEM) + crl.public_bytes(serialization.Encoding.PEM)
    )
    # The SAME CA with NO CRL appended, written beside it. A test that needs a trust anchor and a CRL
    # in two different arguments must not pass one file for both: that cannot tell the arguments
    # apart, so an argument-swap bug reads as a pass. Measured -- `create_default_context(cafile=<the
    # bundle>)` already reports `cert_store_stats()["crl"] == 1`, which pre-satisfies harden_crl_check's
    # own "the CRL really landed" assertion and leaves it proving nothing about which argument loaded it.
    (directory / "ca_only.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return str(path)


@pytest.fixture(scope="module")
def ca_only(crl_bundle: str) -> str:
    """The `crl_bundle` CA with its CRL stripped -- a valid anchor that sets NO VERIFY_CRL_CHECK_LEAF.
    Depends on `crl_bundle` so the two files are always the same CA and a test using both is anchoring
    the CRL it loads."""
    from pathlib import Path as _Path

    return str(_Path(crl_bundle).with_name("ca_only.pem"))


def _crl_policy(crl: str) -> TrustAnchorPolicy:
    """The shipped default plus a CRL -- `system` mode, no internal CA. The arm most hops reach."""
    return TrustAnchorPolicy(crl_file=crl)


def test_mllp_outbound_context_checks_revocation_with_a_configured_crl(crl_bundle: str) -> None:
    cfg = Destination(
        name="OB_MLLP",
        type=ConnectorType.MLLP,
        settings={"host": REMOTE, "port": 5000, "tls": True},
        trust_anchor_policy=_crl_policy(crl_bundle),
    )
    with active_hop_posture(PROD_PHI):
        dest = MLLPDestination(cfg)  # constructs: the CRL closes the guard that otherwise refuses
    assert context_checks_revocation(dest._ssl) is True
    # NEGATIVE CONTROL on the SAME connector: no CRL, and both the flag and the refusal come back.
    bare = Destination(
        name="OB_MLLP",
        type=ConnectorType.MLLP,
        settings={"host": REMOTE, "port": 5000, "tls": True},
    )
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        MLLPDestination(bare)


def test_dicom_scu_context_checks_revocation_with_a_configured_crl(crl_bundle: str) -> None:
    # The SCU (outbound C-STORE), not the SCP. dicom.py's only harden_crl_check call site sits in the
    # SCP's `if ca:` mTLS branch, so this hop had no revocation checking at all.
    ctx = _dicom_client_ssl_context(
        {"tls": True, "host": REMOTE, "port": 11112},
        trust_anchor_policy=_crl_policy(crl_bundle),
    )
    assert context_checks_revocation(ctx) is True
    bare = _dicom_client_ssl_context({"tls": True, "host": REMOTE, "port": 11112})
    assert context_checks_revocation(bare) is False


def test_ftps_context_checks_revocation_with_a_configured_crl(crl_bundle: str) -> None:
    ctx = _ftps_ssl_context(
        {"host": REMOTE, "tls_verify": True}, trust_anchor_policy=_crl_policy(crl_bundle)
    )
    assert context_checks_revocation(ctx) is True
    bare = _ftps_ssl_context({"host": REMOTE, "tls_verify": True})
    assert context_checks_revocation(bare) is False


def test_smtp_context_checks_revocation_with_a_configured_crl(crl_bundle: str) -> None:
    cfg = email_cfg(REMOTE)
    cfg = cfg.model_copy(update={"trust_anchor_policy": _crl_policy(crl_bundle)})
    with active_hop_posture(PROD_PHI):
        dest = EmailDestination(cfg)  # constructs: the CRL closes the guard
    assert context_checks_revocation(dest._tls_context) is True


@pytest.mark.parametrize("cell", _HTTP_CELLS)
def test_http_family_opener_context_checks_revocation_with_a_configured_crl(
    cell: str, crl_bundle: str
) -> None:
    """The HTTP family resolves the same anchor through ``http_family_trust_anchor``.

    A CRL-only anchor has to ``narrow``, or these cells fall back to the module-level opener that was
    built at import time and can carry no CRL -- the hop would then keep an unrevoked context."""
    _ctype, factory, url = _HTTPS[cell]
    anchor = http_family_trust_anchor(
        factory(url=url).settings, url=url, trust_anchor_policy=_crl_policy(crl_bundle)
    )
    assert anchor.narrows is True  # or the shared unrevoked opener is reused
    handler = build_anchored_https_handler(anchor=anchor, connector="probe")
    assert context_checks_revocation(urllib_handler_context(handler, connector="probe")) is True
    # NEGATIVE CONTROL: no CRL, no flag, and the anchor does not narrow.
    bare = http_family_trust_anchor(factory(url=url).settings, url=url, trust_anchor_policy=None)
    assert bare.narrows is False
    bare_handler = build_anchored_https_handler(anchor=bare, connector="probe")
    assert (
        context_checks_revocation(urllib_handler_context(bare_handler, connector="probe")) is False
    )


def test_a_loopback_hop_gets_no_crl_and_still_crosses(crl_bundle: str) -> None:
    # The exemption, end to end: an on-box peer is usually issued by a local PKI the org CRL does not
    # cover, and VERIFY_CRL_CHECK_LEAF refuses a peer whose issuer has no CRL in the store. The guard
    # already ALLOWs loopback, so applying the CRL there would break working traffic for no gain.
    cfg = Destination(
        name="OB_MLLP",
        type=ConnectorType.MLLP,
        settings={"host": LOOPBACK, "port": 5000, "tls": True},
        trust_anchor_policy=_crl_policy(crl_bundle),
    )
    with active_hop_posture(PROD_PHI):
        dest = MLLPDestination(cfg)
    assert context_checks_revocation(dest._ssl) is False


# --- BACKLOG #1498 (ADR 0173 section 4.3, AC-4): parity for two hops #201 left unguarded ----------
#
# The cells above carried the guard; three verifying hops did not, and two of those carry
# authentication material. This section closes two of the three -- the SMART token endpoint and the
# [logging] syslog TLS forwarder. The third, the OIDC token and JWKS legs, was held out of #1498 and
# is built under BACKLOG #1887; its arms are the last section of this file.
#
# The two reach the guard by different seams, so they get separate arms rather than one
# parametrisation: SMART goes through the https-scheme-keyed refuse_unrevoked_verified_hop wrapper
# (it rides urllib's shared opener and builds no context of its own), while the forwarder calls
# capture() directly with its own context, the way EMAIL and MLLP do.
#
# THE NOT-REFUSED ARMS ARE THE LOAD-BEARING HALF, for the same reason the #299 arms above are: a
# guard that refuses everything passes a refusal arm. Each hop pairs its refusal with a loopback arm,
# and the forwarder adds a real-CRL arm -- the only one that proves the FINISHED context reached the
# guard rather than a setting being read.


@pytest.fixture(scope="module")
def smart_key() -> str:
    """An EC P-384 private key PEM for the SMART signer. Synthetic, never leaves the process.

    A real key is needed because the revocation guard sits at the END of ``__init__`` -- below
    ``self._opener``, since it reads that opener's TLS context -- so every earlier construction check
    must PASS before the guard is reached, the signer included. That placement is deliberate and is
    itself under test by `test_a_smart_token_hop_whose_own_context_checks_a_crl_is_not_refused`.

    EC rather than RSA: nothing here verifies a signature, and the two nearest sibling fixtures in this
    file already use EC because the keygen is orders of magnitude cheaper."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return (
        ec.generate_private_key(ec.SECP384R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


def _smart_provider(token_url: str, key: str, **kw: object) -> None:
    """Construct the SMART provider through all of its construction gates.

    Returning without raising means the revocation guard ALLOWED this hop, which is what makes the
    not-refused arms below discriminating: there is no earlier error standing in for the guard's
    verdict."""
    SmartBackendTokenProvider(
        token_url=token_url,
        client_id="cid",
        private_key=key,
        algorithm=SignatureAlgorithm.ES384,
        **kw,  # type: ignore[arg-type]
    )


def test_the_smart_token_hop_is_refused_when_it_checks_no_revocation(smart_key: str) -> None:
    # THE CONTROL for this hop. The arms below are rungs of its escape ladder, so it must fail first.
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        _smart_provider(f"https://{REMOTE}/token", smart_key)


def test_the_smart_token_hop_on_loopback_still_crosses(smart_key: str) -> None:
    # The on-box carve-out: a token endpoint on this host is not a network exposure.
    with active_hop_posture(PROD_PHI):
        _smart_provider(f"https://{LOOPBACK}:8443/token", smart_key)


def test_the_smart_token_hop_crosses_on_a_per_connection_revocation_attestation(
    smart_key: str,
) -> None:
    # Distinct from the #200 tls_hop_attested that sits beside it in the same settings mapping.
    with active_hop_posture(PROD_PHI):
        _smart_provider(f"https://{REMOTE}/token", smart_key, revocation_attested=True)


def test_a_cleartext_smart_token_hop_is_the_200_gates_refusal_not_this_one(smart_key: str) -> None:
    """DISJOINTNESS, and why no hop is ever double-refused. An ``http`` token endpoint has no TLS, so
    the cleartext-credential refusal owns it and the revocation gate must stay silent. Asserting the
    MESSAGE and not merely the type is the point: both are ``ValueError`` subclasses, so a type-only
    assertion would pass when the wrong gate fired."""
    with active_hop_posture(PROD_PHI), pytest.raises(SmartAuthError, match="cleartext"):
        _smart_provider(f"http://{REMOTE}/token", smart_key)


def test_the_smart_revocation_attestation_comes_from_its_own_settings_key(smart_key: str) -> None:
    """The WIRING rather than the guard: ``tls_revocation_attested`` must arrive from the resolved
    settings the way the runner supplies it for a ``Destination``, and must NOT be satisfied by its
    #200 twin. A cell that read ``tls_hop_attested`` here would cross on the wrong operator claim --
    the exact conflation ``config/models.py`` keeps the two fields separate to prevent."""
    base = {
        "smart_token_url": f"https://{REMOTE}/token",
        "smart_client_id": "cid",
        "smart_private_key": smart_key,
        "smart_algorithm": "ES384",
    }
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        token_provider_from_settings({**base, "tls_hop_attested": True})
    # And the right key DOES cross it.
    with active_hop_posture(PROD_PHI):
        assert token_provider_from_settings({**base, "tls_revocation_attested": True}) is not None


def _forward(host: str, ca: str, **kw: object) -> SyslogForward:
    """A verifying TLS forwarder target.

    ``ca`` is REQUIRED rather than defaulted to None, because `LoggingSettings` validation refuses
    ``protocol='tls'`` with verification on and no CA anchor, and `_build_tls_context`'s docstring
    relies on that ("the default path is always CA-anchored"). A fixture that omitted it would build a
    context off the OS trust store -- a posture this builder never takes in production -- so the arms
    would pass while testing a state the engine cannot reach. The `crl_bundle` file doubles as a plain
    CA anchor: loading it as `cafile=` does not set VERIFY_CRL_CHECK_LEAF, which only
    `forward_tls_crl_file` does, so a CA-only hop is still an unrevoked hop."""
    return SyslogForward(host=host, protocol="tls", tls_ca_file=ca, hop_posture=PROD_PHI, **kw)  # type: ignore[arg-type]


def test_the_syslog_tls_forwarder_is_refused_when_it_checks_no_revocation(
    crl_bundle: str,
) -> None:
    # It ships the audit evidence stream, and its #200 sibling (forward_hop_disposition) returns ALLOW
    # for verified TLS -- so before #1498 nothing anywhere decided this hop's revocation posture.
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _build_tls_context(_forward(REMOTE, crl_bundle))
    # ...and for the RIGHT reason: the CA anchor alone leaves the flag off, so this is an unrevoked
    # verifying hop rather than a hop that failed to build.
    assert context_checks_revocation(_build_tls_context(_forward(LOOPBACK, crl_bundle))) is False


def test_the_syslog_tls_forwarder_on_loopback_still_crosses(crl_bundle: str) -> None:
    """ADR 0080's documented local-agent topology -- point the forwarder at 127.0.0.1 and let a local
    rsyslog/Vector add TLS -- stays byte-identical. Refusing it would break a shipped deployment."""
    _build_tls_context(_forward(LOOPBACK, crl_bundle))


def test_a_non_enforcing_syslog_forwarder_warns_instead_of_refusing(crl_bundle: str) -> None:
    """The WARN rung every sibling cell in this file carries. A `warn`-dialled instance must cross
    rather than refuse -- and it must not cross silently, which is the whole point of the gate."""
    ctx = _build_tls_context(
        SyslogForward(host=REMOTE, protocol="tls", tls_ca_file=crl_bundle, hop_posture=STAGING_PHI)
    )
    assert ctx.verify_mode is ssl.CERT_REQUIRED


def test_the_blanket_env_does_not_cross_the_enforcing_syslog_forwarder(
    crl_bundle: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The #299 clamp reaches this hop too, and that is worth pinning separately: the guard folds the
    blanket env in through `capture`, so it would be easy to assume it crosses. It ranks BELOW the
    enforcing REFUSE, so an instance-wide env var cannot silence a hop nobody enumerated -- and the
    forwarder has no per-hop revocation attestation at all, so loopback or a real CRL are the only
    ways across here."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _build_tls_context(_forward(REMOTE, crl_bundle))
    # NEGATIVE CONTROL, or the assertion above would also pass if the env were simply never read: on a
    # non-enforcing posture the same env DOES cross, byte-identical to the pre-clamp behaviour.
    _build_tls_context(
        SyslogForward(host=REMOTE, protocol="tls", tls_ca_file=crl_bundle, hop_posture=STAGING_PHI)
    )


def test_the_blanket_env_does_not_cross_the_enforcing_smart_token_hop(
    smart_key: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same clamp on the SMART hop. Its per-connection `tls_revocation_attested` crosses (proved
    above); the process-wide env must not, because it cannot say which hop's PKI was reviewed."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        _smart_provider(f"https://{REMOTE}/token", smart_key)
    # NEGATIVE CONTROL: on a non-enforcing posture the same env DOES cross, so the refusal above is
    # the clamp firing rather than the env never being read.
    with active_hop_posture(STAGING_PHI):
        _smart_provider(f"https://{REMOTE}/token", smart_key)


def test_a_smart_token_hop_whose_own_context_checks_a_crl_is_not_refused(
    smart_key: str, crl_bundle: str
) -> None:
    """THE FALSE-REFUSAL REGRESSION. The guard was first placed above `self._opener`, so `context=`
    could not be passed and a token hop whose resolved anchor really carried a CRL was refused anyway
    -- while being told to configure the CRL it already had. A `[tls].crl_file` matching the token
    host makes the anchor narrow, which builds a per-provider opener carrying
    VERIFY_CRL_CHECK_LEAF, and that must cross."""
    settings = {
        "smart_token_url": f"https://{REMOTE}/token",
        "smart_client_id": "cid",
        "smart_private_key": smart_key,
        "smart_algorithm": "ES384",
    }
    with active_hop_posture(PROD_PHI):
        assert (
            token_provider_from_settings(settings, trust_anchor_policy=_crl_policy(crl_bundle))
            is not None
        )
    # NEGATIVE CONTROL: the same hop with no CRL policy is still refused, so the arm above passed
    # because the CRL reached the context and not because the guard stopped firing.
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused, match="revocation"):
        token_provider_from_settings(settings)


def test_the_syslog_tls_forwarder_crosses_on_a_crl_that_really_loaded(crl_bundle: str) -> None:
    """The FINISHED context really reaches the guard. ``forward_tls_crl_file`` (#299) shuts the gap
    this gate refuses on, so the guard must read ``VERIFY_CRL_CHECK_LEAF`` off that context rather
    than refusing because a setting it cannot see was absent."""
    ctx = _build_tls_context(_forward(REMOTE, crl_bundle, tls_crl_file=crl_bundle))
    assert context_checks_revocation(ctx) is True  # the line above passed for the RIGHT reason


def test_a_verify_off_syslog_forwarder_takes_no_revocation_guard(crl_bundle: str) -> None:
    """DISJOINTNESS on this hop. ``forward_tls_verify=false`` is CERT_NONE: no verified chain, so no
    revocation status could matter, and the #200 forward-hop gate owns that arm. A guard here would be
    a second gate deciding one hop."""
    ctx = _build_tls_context(_forward(REMOTE, crl_bundle, tls_verify=False))
    assert ctx.verify_mode is ssl.CERT_NONE


def test_a_syslog_forwarder_with_no_posture_is_unchanged() -> None:
    """The shipped ``posture is None`` no-op every hop guard has -- the ``build_check`` gate is the
    authority. This arm is what keeps a direct construction, an embedding and a test working."""
    _build_tls_context(SyslogForward(host=REMOTE, protocol="tls"))


def test_the_forwarder_refusal_names_a_lever_that_exists_for_it(crl_bundle: str) -> None:
    """SDS-3.7 applied to the refusal TEXT rather than to the gate. The guard's default remediation
    names ``[tls].crl_file``, an egress terminator and a connection's ``tls_revocation_attested``, and
    all three are unreachable for a hop that is not a connection -- ``[tls].crl_file`` reaches a
    context only through a ``Destination``'s trust-anchor policy, and there is no connection to carry
    the flag. A refusal whose remedy cannot be performed is a control resting on a false premise, so
    this hop substitutes the setting that actually closes its own gate."""
    with pytest.raises(InsecureHopRefused) as exc:
        _build_tls_context(_forward(REMOTE, crl_bundle))
    assert "[logging].forward_tls_crl_file" in str(exc.value)
    assert "tls_revocation_attested=true on this connection" not in str(exc.value)


def test_a_default_context_already_carries_the_strict_flag_a_raw_one_does_not() -> None:
    """WHY the ``harden_verify_flags`` half of ADR 0173 section 4.3 is an ASSERTION and not a fix.

    That section measured the call at zero in ``logging_setup.py`` and ``auth/oidc_http.py`` against a
    positive control of seven files that carry it, and read the absence as a gap. The grep is right;
    the inference does not follow. Measured 2026-09-22 on CPython 3.14.6 / OpenSSL 3.5.7:
    ``ssl.create_default_context()`` sets ``VERIFY_X509_STRICT`` **itself**, while a raw
    ``ssl.SSLContext(...)`` does not. Both hops in question build through the former, so both already
    had strict path validation; the seven control files build raw contexts, where the call is
    load-bearing.

    Pinned as two arms so the claim cannot later be re-read as a closed gap. The first version of the
    test below asserted the opposite and failed, which is how this was found."""
    assert ssl.create_default_context().verify_flags & ssl.VERIFY_X509_STRICT
    assert not ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).verify_flags & ssl.VERIFY_X509_STRICT


def test_the_verifying_forwarder_context_asserts_strict_path_validation(crl_bundle: str) -> None:
    """The property that matters, read off the context ``wrap_socket`` will really use. Deliberately
    NOT paired with a "the CERT_NONE arm lacks it" assertion: per the measurement above the flag
    arrives with ``create_default_context`` before ``tls_verify`` is consulted, so such an arm would
    assert a falsehood."""
    assert _build_tls_context(_forward(LOOPBACK, crl_bundle)).verify_flags & ssl.VERIFY_X509_STRICT


# --- BACKLOG #1887 (ADR 0173 section 4.3, AC-4): the OIDC token and JWKS legs -----------------------
#
# The third hop of the rider. Both legs share ONE opener and ONE context, built in
# auth/oidc_http.py:build_idp_opener, and AuthService guards them just after that opener exists. The
# posture is threaded through AuthService(hop_posture=), because the service is built in the API
# lifespan outside every active_hop_posture scope -- so every arm below passes it as the lifespan
# does, and none stamps the contextvar.
#
# TWO GUARDS, NOT ONE. The legs may be different hosts with different loopback status. The
# independence arms are the only ones here that can tell two guards from one keyed on a single host;
# nothing inherited from the syslog set exercises that, because that hop has one host.
#
# As above, THE NOT-REFUSED ARMS ARE THE LOAD-BEARING HALF: loopback, a CRL that really loaded, and
# no posture must all construct.


async def _oidc_service(
    *,
    token_host: str = REMOTE,
    jwks_host: str = REMOTE,
    posture: HopPosture | None = PROD_PHI,
    **over: object,
) -> AuthService:
    """Construct AuthService with OIDC on, the way the API lifespan does: posture passed, not ambient.

    Returning means BOTH guards allowed their leg, because the guards run inside ``__init__`` and no
    earlier construction check can stand in for their verdict. The opener opens no socket, so an
    unreachable host is fine here. The directory is the OIDC suite's fake: a real LdapAuthenticator
    would bring its own LDAPS hop into these arms, a second guard that could fire in place of these."""
    settings = _oidc_settings(
        oidc_issuer=f"https://{REMOTE}",
        oidc_authorization_endpoint=f"https://{REMOTE}/authorize",
        oidc_token_endpoint=f"https://{token_host}:8443/token",
        oidc_jwks_uri=f"https://{jwks_host}:8443/jwks",
        oidc_allowed_endpoints=[REMOTE, LOOPBACK],
        **over,
    )
    store = await MessageStore.open(":memory:")
    try:
        return AuthService(store, settings, ldap=_FakeLdap(), hop_posture=posture)  # type: ignore[arg-type]
    finally:
        await store.close()


async def test_the_oidc_legs_are_refused_when_they_check_no_revocation() -> None:
    # THE CONTROL for this hop, and the proof the posture is threaded through AuthService at all: if
    # the seam dropped it, the guard would read the ambient posture, which is None here, and no-op.
    with pytest.raises(InsecureHopRefused, match="revocation"):
        await _oidc_service()


async def test_the_oidc_legs_on_loopback_still_cross() -> None:
    # The on-box carve-out: an identity provider on this host is not a network exposure.
    await _oidc_service(token_host=LOOPBACK, jwks_host=LOOPBACK)


async def test_the_oidc_legs_cross_on_a_crl_that_really_loaded(crl_bundle: str) -> None:
    """The FINISHED context reaches both guards. ``[auth].oidc_tls_crl_file`` (#299) closes the gap
    this gate refuses on, so each guard must read ``VERIFY_CRL_CHECK_LEAF`` off the opener's context
    rather than refusing because a setting it cannot see was absent. Both hosts are off-box, so this
    crosses on the CRL alone."""
    service = await _oidc_service(oidc_tls_crl_file=crl_bundle)
    ctx = opener_tls_context(service._oidc_opener, connector="test")
    assert context_checks_revocation(ctx) is True  # the line above passed for the RIGHT reason


async def test_the_oidc_legs_with_no_posture_are_unchanged() -> None:
    """The shipped ``posture is None`` no-op every hop guard has. The lifespan passes None when the
    instance declares no ``[ai]``, and every direct construction in the OIDC suite passes nothing."""
    await _oidc_service(posture=None)


@pytest.mark.parametrize(
    ("token_host", "jwks_host", "refused_leg"),
    [
        pytest.param(LOOPBACK, REMOTE, "OIDC JWKS endpoint", id="off-box-jwks"),
        pytest.param(REMOTE, LOOPBACK, "OIDC token endpoint", id="off-box-token"),
    ],
)
async def test_each_oidc_leg_is_guarded_on_its_own_host(
    token_host: str, jwks_host: str, refused_leg: str
) -> None:
    """THE INDEPENDENCE ARM. One leg on-box and the other off it: the off-box leg must still refuse.
    A single guard keyed on the token host would let the ``off-box-jwks`` case cross, and one keyed on
    the JWKS host would let ``off-box-token`` cross, so each case catches a different wrong shape.
    Matching the leg's own cell is what makes it discriminating: a type-only assertion would pass if
    the wrong leg had refused."""
    with pytest.raises(InsecureHopRefused, match=refused_leg):
        await _oidc_service(token_host=token_host, jwks_host=jwks_host)


async def test_a_non_enforcing_oidc_instance_warns_on_both_legs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The WARN rung. A ``warn``-dialled instance crosses, and not silently -- and it warns ONCE PER
    LEG, which is a second view of the independence above: two guards, two warnings.

    The warning call is recorded on the module logger itself rather than through ``caplog``. Measured
    2026-09-23: a ``caplog`` version passed alone and failed once under ``-n 8`` beside the rest of the
    auth suite. The cause was not isolated; logger state left by another test in the same worker is
    the likely one. Recording the call does not depend on any handler or level being in place."""
    from messagefoundry.config import tls_policy

    warned: list[str] = []
    monkeypatch.setattr(
        tls_policy.logger, "warning", lambda msg, *args: warned.append(msg % args if args else msg)
    )
    await _oidc_service(posture=STAGING_PHI)
    assert any("OIDC token endpoint" in m and "revocation" in m for m in warned)
    assert any("OIDC JWKS endpoint" in m and "revocation" in m for m in warned)


async def test_the_blanket_env_does_not_cross_the_enforcing_oidc_legs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The #299 clamp reaches these legs too. They have no per-hop revocation attestation at all, so
    under an enforcing posture loopback or a real CRL are the only ways across."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(InsecureHopRefused, match="revocation"):
        await _oidc_service()
    # NEGATIVE CONTROL: on a non-enforcing posture the same env DOES cross, so the refusal above is
    # the clamp firing rather than the env never being read.
    await _oidc_service(posture=STAGING_PHI)


async def test_the_oidc_refusal_names_a_lever_that_exists_for_it() -> None:
    """SDS-3.7 applied to the refusal TEXT. The default remediation names ``[tls].crl_file`` and a
    connection's ``tls_revocation_attested``, and neither reaches this opener: it resolves no trust
    anchor, and there is no connection to carry the flag. The legs name their own CRL key instead."""
    with pytest.raises(InsecureHopRefused) as exc:
        await _oidc_service()
    assert "[auth].oidc_tls_crl_file" in str(exc.value)
    assert "tls_revocation_attested=true on this connection" not in str(exc.value)

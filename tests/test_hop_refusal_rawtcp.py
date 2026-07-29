# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""#200 (ADR 0092) posture-keyed cleartext-hop refusal for the raw-TCP / DIMSE / plain-FTP OUTBOUND
transports (cell group ``rawtcp-ftp``).

These connectors put PHI on a hop with no TLS (mllp/dicom when ``tls`` is off) or no TLS option at all
(tcp/x12/anonymous-ftp), and that cleartext PHI egress was UNGUARDED off-loopback before #200. The
transports now consume the ONE pure authority (``config.tls_policy``) through the shared
:class:`~messagefoundry.transports.mllp.InsecureHopGuard`:

* the ENFORCED construction gate (fires at ``messagefoundry check`` / dry-run / reload / the serve
  pre-flight, where the derived posture is stamped via ``active_hop_posture``) refuses a production-PHI
  cleartext hop off-loopback; and
* a zero-I/O send-time backstop re-asserts it at the byte crossing.

**Amended by ADR 0153**: the authority no longer reads the data label, so a ``synthetic`` instance is
NOT carved out any more — it refuses exactly like a PHI one. Loopback and per-connection-attested hops
still ALLOW (byte-identical); a non-enforcing instance WARNs (crosses, loud-logged); a per-connection
``cleartext_accepted`` declaration WARNs + audits even under ENFORCE; and ``MEFOR_ALLOW_INSECURE_TLS``
can no longer influence the decision at all. A hop built OUTSIDE the stamped gate (a live serve build
after the pre-flight, or a direct test/embedding — posture unstamped) is still a no-op, so no existing
lane breaks.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV
from messagefoundry.config.tls_policy import (
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    active_hop_posture,
)
from messagefoundry.transports.dicom import DicomScuDestination
from messagefoundry.transports.mllp import InsecureHopGuard, MLLPDestination
from messagefoundry.transports.remotefile import RemoteFileDestination, _anon_ftp_guard
from messagefoundry.transports.tcp import TcpDestination
from messagefoundry.transports.x12 import X12Destination

# The three postures. Only `enforcing` reaches the cleartext authority now (ADR 0153) — `is_phi` is
# retained on HopPosture for the revocation / inbound-bind / verify-off gates, which still read it.
PROD_PHI = HopPosture(is_phi=True, enforcing=True)
STAGING_PHI = HopPosture(is_phi=True, enforcing=False)
# Pre-0153 this was the blanket carve-out ("not is_phi → ALLOW"). It is enforcing, so it now REFUSES.
SYNTHETIC = HopPosture(is_phi=False, enforcing=True)

REMOTE = "10.0.0.5"  # a non-loopback host (never resolves; treated as remote/off-box)
LOOPBACK = "127.0.0.1"


# --- config builders (one plaintext outbound per transport) ------------------


# ADR 0153 retro-fitted "the flag REQUIRES a reason" onto tls_hop_attested, so every builder below
# supplies a default reason whenever its flag is set rather than leaving the pair incoherent at load.
_ATTEST_REASON = "proxy-terminated trusted segment"
_ACCEPT_REASON = "vendor firmware predates TLS; segment is not isolated"


def _hop_fields(
    attested: bool, reason: str | None, accepted: bool, accept_reason: str | None
) -> dict[str, object]:
    """The four hop-declaration fields every Destination builder below shares.

    ``reason``/``accept_reason`` fall back to a non-empty string whenever their flag is set, because
    BOTH pairs are now load-validated as flag-implies-reason (ADR 0153 decision 2)."""
    return {
        "tls_hop_attested": attested,
        "tls_hop_attested_reason": (
            reason if reason is not None or not attested else _ATTEST_REASON
        ),
        "cleartext_accepted": accepted,
        "cleartext_reason": (
            accept_reason if accept_reason is not None or not accepted else _ACCEPT_REASON
        ),
    }


def mllp_cfg(
    host: str,
    *,
    tls: bool = False,
    attested: bool = False,
    reason: str | None = None,
    accepted: bool = False,
    accept_reason: str | None = None,
    revocation_attested: bool = False,
) -> Destination:
    settings: dict[str, object] = {"host": host, "port": 5000}
    if tls:
        settings["tls"] = True
    return Destination(
        name="OB_MLLP",
        type=ConnectorType.MLLP,
        settings=settings,
        tls_revocation_attested=revocation_attested,
        **_hop_fields(attested, reason, accepted, accept_reason),
    )


def tcp_cfg(
    host: str,
    *,
    attested: bool = False,
    reason: str | None = None,
    accepted: bool = False,
    accept_reason: str | None = None,
) -> Destination:
    return Destination(
        name="OB_TCP",
        type=ConnectorType.TCP,
        settings={"host": host, "port": 5000, "framing": "stx_etx"},
        **_hop_fields(attested, reason, accepted, accept_reason),
    )


def x12_cfg(
    host: str,
    *,
    attested: bool = False,
    reason: str | None = None,
    accepted: bool = False,
    accept_reason: str | None = None,
) -> Destination:
    return Destination(
        name="OB_X12",
        type=ConnectorType.X12,
        settings={"host": host, "port": 5000},
        **_hop_fields(attested, reason, accepted, accept_reason),
    )


def dicom_cfg(
    host: str,
    *,
    tls: bool = False,
    attested: bool = False,
    reason: str | None = None,
    accepted: bool = False,
    accept_reason: str | None = None,
) -> Destination:
    settings: dict[str, object] = {"ae_title": "MF_SCU", "host": host, "port": 104}
    if tls:
        settings["tls"] = True
    return Destination(
        name="OB_DICOM",
        type=ConnectorType.DIMSE,
        settings=settings,
        **_hop_fields(attested, reason, accepted, accept_reason),
    )


def ftp_cfg(
    host: str,
    *,
    attested: bool = False,
    reason: str | None = None,
    accepted: bool = False,
    accept_reason: str | None = None,
    protocol: str = "ftp",
) -> Destination:
    settings: dict[str, object] = {
        "host": host,
        "remote_dir": "/in",
        "protocol": protocol,
    }
    fields = _hop_fields(attested, reason, accepted, accept_reason)
    if attested:
        # The anonymous-ftp guard reads the ATTESTATION off the settings mapping (that is how the
        # runner threads it for this transport), so mirror it there exactly as _dest_config does.
        settings["tls_hop_attested"] = True
        settings["tls_hop_attested_reason"] = fields["tls_hop_attested_reason"]
    return Destination(name="OB_FTP", type=ConnectorType.REMOTEFILE, settings=settings, **fields)


# Each entry builds ONE plaintext outbound connector from a config-builder; used to run the whole
# posture matrix uniformly across all five transports.
PLAINTEXT_BUILDERS = [
    pytest.param(mllp_cfg, MLLPDestination, id="mllp"),
    pytest.param(tcp_cfg, TcpDestination, id="tcp"),
    pytest.param(x12_cfg, X12Destination, id="x12"),
    pytest.param(dicom_cfg, DicomScuDestination, id="dicom"),
    pytest.param(ftp_cfg, RemoteFileDestination, id="anon-ftp"),
]


# --- construction gate: REFUSE a production-PHI cleartext hop off-loopback ----


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_refuses_prod_phi_remote_cleartext(build_cfg, connector) -> None:
    with active_hop_posture(PROD_PHI):  # the ENFORCED gate (posture stamped)  # noqa: SIM117
        with pytest.raises(InsecureHopRefused):
            connector(build_cfg(REMOTE))


# --- construction gate: ALLOW loopback / synthetic (byte-identical) -----------


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_allows_loopback(build_cfg, connector) -> None:
    with active_hop_posture(PROD_PHI):
        connector(build_cfg(LOOPBACK))  # on-box hop — never a network exposure


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_refuses_synthetic_instance(build_cfg, connector) -> None:
    """ADR 0153's headline: a ``synthetic`` data label no longer buys a cleartext hop.

    This test asserted ALLOW before 0153. The label is authored in the same file as the hosts it
    governs, by the same hand, and a typo in it was indistinguishable from a declaration — with every
    transport hop in the product as its blast radius. The instance is enforcing, so it now refuses."""
    with active_hop_posture(SYNTHETIC), pytest.raises(InsecureHopRefused):
        connector(build_cfg(REMOTE))


# --- construction gate: WARN (cross) a non-production PHI hop -----------------


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_warns_but_crosses_staging_phi(build_cfg, connector) -> None:
    with active_hop_posture(STAGING_PHI):
        connector(build_cfg(REMOTE))  # dev/staging PHI → WARN, not REFUSE (constructs fine)


# --- construction gate: per-connection attestation ALLOWs even prod-PHI -------


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_attested_allows_prod_phi(build_cfg, connector, caplog) -> None:
    with active_hop_posture(PROD_PHI), caplog.at_level("WARNING"):
        connector(build_cfg(REMOTE, attested=True, reason="proxy-terminated trusted segment"))
    # The attestation suppressed a would-be production refusal, so it is AUDITED (loud-logged).
    assert any("operator attestation" in r.message for r in caplog.records)


# --- unstamped posture (live serve build / direct test) is a byte-identical no-op ---


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_unstamped_is_noop(build_cfg, connector) -> None:
    # No active_hop_posture: current_hop_posture() is None. The enforced gate (build_check) already
    # validated the config before serve, so the live-build connector must NOT re-refuse — otherwise
    # every legitimate non-prod cleartext lane would fail at serve. Constructs without raising.
    connector(build_cfg(REMOTE))


# --- TLS-on connectors carry no cleartext guard ------------------------------


def test_mllp_tls_has_no_hop_guard() -> None:
    # A verified TLS hop needs no CLEARTEXT guard (#200). It DOES now carry a #201 revocation guard on a
    # prod-PHI remote hop, so attest revocation to keep the subject here (the cleartext guard is None).
    with active_hop_posture(PROD_PHI):
        dest = MLLPDestination(mllp_cfg(REMOTE, tls=True, revocation_attested=True))
    assert dest._hop_guard is None  # a verified TLS hop needs no cleartext guard


def test_dicom_tls_has_no_hop_guard() -> None:
    with active_hop_posture(PROD_PHI):
        dest = DicomScuDestination(dicom_cfg(REMOTE, tls=True))
    assert dest._hop_guard is None


# --- escape clamp: MEFOR_ALLOW_INSECURE_TLS only downgrades on NON-production --


def test_global_escape_can_no_longer_influence_a_cleartext_hop(monkeypatch) -> None:
    """ADR 0153 decision 5: the variable is UNHOOKED from this authority (not deleted).

    Asserted in BOTH directions — that it does not relax an enforcing hop, and that it does not change
    the non-enforcing one either. A one-directional check would still pass if the escape were quietly
    re-hooked as a WARN arm, which is exactly the regression the decision forbids."""
    with active_hop_posture(STAGING_PHI):
        TcpDestination(tcp_cfg(REMOTE))  # non-enforcing → WARN, escape unset
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused):
        TcpDestination(tcp_cfg(REMOTE))  # enforcing → REFUSE, escape unset
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    with active_hop_posture(STAGING_PHI):
        TcpDestination(tcp_cfg(REMOTE))  # unchanged by the escape
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused):
        TcpDestination(tcp_cfg(REMOTE))  # STILL refuses with the escape set


# --- ADR 0153 decision 2: the honest per-connection acceptance ----------------


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_cleartext_accepted_crosses_an_enforcing_hop_and_is_audited(
    build_cfg, connector, caplog
) -> None:
    """It yields WARN, never ALLOW — crossed, but logged AND audited at every construction."""
    with active_hop_posture(PROD_PHI), caplog.at_level("WARNING"):
        connector(build_cfg(REMOTE, accepted=True, accept_reason="vendor firmware predates TLS"))
    # The generic WARN half...
    assert any("insecure transport hop permitted" in r.message for r in caplog.records)
    # ...and the DEDICATED audit record naming the declaration + its reason, which is what tells an
    # auditor this hop was crossed on an operator's accepted risk rather than on a warn-mode dial.
    audit = [
        r for r in caplog.records if "cleartext hop crossed on an operator acceptance" in r.message
    ]
    assert audit, "an accepted cleartext hop must produce an audit record at every construction"
    assert "vendor firmware predates TLS" in audit[0].getMessage()


def test_acceptance_and_attestation_are_distinguishable_in_the_trail(caplog) -> None:
    """The one distinction the audit trail exists to preserve (ADR 0153 decision 2's table).

    ``tls_hop_attested`` = "this hop IS secure by means the engine cannot see" → ALLOW, and its record
    says *attestation*. ``cleartext_accepted`` = "this hop is NOT secure and we accept that" → WARN, and
    its record says *accepted*. Collapsing the two would leave the trail unable to tell a
    proxy-terminated hop from plaintext PHI on a flat network."""
    with active_hop_posture(PROD_PHI), caplog.at_level("WARNING"):
        TcpDestination(tcp_cfg(REMOTE, attested=True, reason="proxy-terminated trusted segment"))
    attested_records = [r.getMessage() for r in caplog.records]
    assert any("operator attestation" in m for m in attested_records)
    assert not any("cleartext hop crossed on an operator acceptance" in m for m in attested_records)

    caplog.clear()
    with active_hop_posture(PROD_PHI), caplog.at_level("WARNING"):
        TcpDestination(tcp_cfg(REMOTE, accepted=True, accept_reason="no TLS on this device"))
    accepted_records = [r.getMessage() for r in caplog.records]
    assert any("cleartext hop crossed on an operator acceptance" in m for m in accepted_records)
    assert not any("operator attestation" in m for m in accepted_records)


def test_tcp_and_x12_acceptance_is_permanent_not_transitional() -> None:
    """ADR 0153 decision 4: Tcp()/X12() have NO TLS support, so there is no `tls = true` to migrate to.

    Pinned as a test so a future reader cannot mistake the standing declaration for unfinished
    migration work: neither factory accepts a `tls` argument (BACKLOG #311 tracks adding one)."""
    import inspect

    from messagefoundry.config.wiring import X12, Tcp

    assert "tls" not in inspect.signature(Tcp).parameters
    assert "tls" not in inspect.signature(X12).parameters
    # ...and without the declaration the hop simply refuses under ENFORCE — there is no other escape
    # short of an attestation, which would be a false statement about a plaintext-only transport.
    with active_hop_posture(PROD_PHI), pytest.raises(InsecureHopRefused):
        X12Destination(x12_cfg(REMOTE))
    with active_hop_posture(PROD_PHI):
        X12Destination(x12_cfg(REMOTE, accepted=True, accept_reason="X12 VAN link has no TLS"))


# --- send-time backstop (zero-I/O, before the first payload byte) -------------


def refuse_guard() -> InsecureHopGuard:
    """A guard whose captured posture forces REFUSE (prod-PHI, remote, unattested)."""
    return InsecureHopGuard(
        host=REMOTE,
        port=5000,
        cell="test",
        description="cleartext egress",
        attested=False,
        attested_reason=None,
        posture=PROD_PHI,
    )


@pytest.mark.parametrize(
    ("build_cfg", "connector"),
    [
        pytest.param(tcp_cfg, TcpDestination, id="tcp"),
        pytest.param(x12_cfg, X12Destination, id="x12"),
        pytest.param(mllp_cfg, MLLPDestination, id="mllp"),
        pytest.param(dicom_cfg, DicomScuDestination, id="dicom"),
        pytest.param(ftp_cfg, RemoteFileDestination, id="anon-ftp"),
    ],
)
async def test_send_asserts_before_any_io(build_cfg, connector) -> None:
    # Build the connector OUTSIDE the stamped gate (constructs cleanly, guard.posture is None), then
    # swap in a REFUSE guard: send() must raise at the byte-crossing assertion BEFORE it opens any
    # socket / association / FTP connection (the remote host is never dialed — no network needed).
    dest = connector(build_cfg(LOOPBACK))
    dest._hop_guard = refuse_guard()
    with pytest.raises(InsecureHopRefused):
        await dest.send("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|1|P|2.5\r")


def test_assert_send_matrix() -> None:
    # REFUSE posture → raises.
    with pytest.raises(InsecureHopRefused):
        refuse_guard().assert_send()

    # ALLOW (loopback) → silent.
    InsecureHopGuard(
        host=LOOPBACK,
        port=1,
        cell="t",
        description="d",
        attested=False,
        attested_reason=None,
        posture=PROD_PHI,
    ).assert_send()

    # WARN (staging PHI) → crosses silently at send time (the construction gate already logged it).
    InsecureHopGuard(
        host=REMOTE,
        port=1,
        cell="t",
        description="d",
        attested=False,
        attested_reason=None,
        posture=STAGING_PHI,
    ).assert_send()

    # Unstamped posture (None) → no-op (never refuses a live serve delivery).
    InsecureHopGuard(
        host=REMOTE,
        port=1,
        cell="t",
        description="d",
        attested=False,
        attested_reason=None,
        posture=None,
    ).assert_send()


# --- pure-disposition sanity (the shared authority, keyed identically) --------


def test_guard_disposition_precedence() -> None:
    def disp(
        host: str, *, posture: HopPosture, attested: bool, accepted: bool = False
    ) -> HopDisposition:
        g = InsecureHopGuard(
            host=host,
            port=1,
            cell="t",
            description="d",
            attested=attested,
            attested_reason=None,
            posture=posture,
            cleartext_accepted=accepted,
        )
        return g._disposition(posture)

    assert disp(LOOPBACK, posture=PROD_PHI, attested=False) is HopDisposition.ALLOW
    assert disp(REMOTE, posture=PROD_PHI, attested=True) is HopDisposition.ALLOW
    # ADR 0153: the synthetic carve-out is GONE — an enforcing instance refuses whatever its label.
    assert disp(REMOTE, posture=SYNTHETIC, attested=False) is HopDisposition.REFUSE
    assert disp(REMOTE, posture=PROD_PHI, attested=False) is HopDisposition.REFUSE
    assert disp(REMOTE, posture=STAGING_PHI, attested=False) is HopDisposition.WARN
    # ...and the new arm 3: an acceptance WARNs (crosses) even under ENFORCE, and never ALLOWs.
    assert disp(REMOTE, posture=PROD_PHI, attested=False, accepted=True) is HopDisposition.WARN
    assert disp(LOOPBACK, posture=PROD_PHI, attested=False, accepted=True) is HopDisposition.ALLOW


# --- anonymous-ftp guard: encrypted / credentialed protocols carry no guard ---


@pytest.mark.parametrize("protocol", ["ftps", "sftp"])
def test_anon_guard_none_for_encrypted_protocols(protocol: str) -> None:
    assert _anon_ftp_guard(ftp_cfg(REMOTE, protocol=protocol).settings) is None


def test_anon_guard_none_for_credentialed_ftp() -> None:
    settings = {"host": REMOTE, "remote_dir": "/in", "protocol": "ftp", "username": "u"}
    # Credentialed plain-ftp is covered by _validate_common's cleartext-credential refusal, not the
    # anonymous body-PHI guard.
    assert _anon_ftp_guard(settings) is None


# --- decision 5: do NOT loosen the already-shipped refusals in these files ----


def test_mllp_verify_off_still_refuses_under_staging_phi() -> None:
    # The MLLP outbound tls_verify=false refusal (shipped, escape-keyed) must NOT be loosened to
    # warn-and-cross by the posture gradient: it still refuses a staging-PHI hop with no escape.
    cfg = Destination(
        name="OB",
        type=ConnectorType.MLLP,
        settings={"host": REMOTE, "port": 5000, "tls": True, "tls_verify": False},
    )
    with active_hop_posture(STAGING_PHI), pytest.raises(ValueError, match="tls_verify=false"):
        MLLPDestination(cfg)


def test_credentialed_plain_ftp_still_refuses_under_staging_phi() -> None:
    # The credentialed plain-ftp refusal (shipped, escape-keyed) is likewise not loosened: a
    # staging-PHI credentialed ftp with no escape still refuses (cleartext credential on the wire).
    cfg = Destination(
        name="OB",
        type=ConnectorType.REMOTEFILE,
        settings={
            "host": REMOTE,
            "remote_dir": "/in",
            "protocol": "ftp",
            "username": "u",
            "password": "p",
        },
    )
    with active_hop_posture(STAGING_PHI), pytest.raises(ValueError, match="CLEARTEXT"):
        RemoteFileDestination(cfg)

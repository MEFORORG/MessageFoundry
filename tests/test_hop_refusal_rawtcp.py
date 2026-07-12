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

Loopback / synthetic / per-connection-attested hops ALLOW (byte-identical); a non-production PHI hop
WARNs (crosses, loud-logged); the global escape may only downgrade REFUSE→WARN on non-production. A hop
built OUTSIDE the stamped gate (a live serve build after the pre-flight, or a direct test/embedding —
posture unstamped) is a no-op, so no existing lane breaks.
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

# The three postures the gradient keys on (the AI-derived is_phi/production).
PROD_PHI = HopPosture(is_phi=True, production=True)
STAGING_PHI = HopPosture(is_phi=True, production=False)
SYNTHETIC = HopPosture(is_phi=False, production=True)  # not is_phi → always ALLOW

REMOTE = "10.0.0.5"  # a non-loopback host (never resolves; treated as remote/off-box)
LOOPBACK = "127.0.0.1"


# --- config builders (one plaintext outbound per transport) ------------------


def mllp_cfg(
    host: str, *, tls: bool = False, attested: bool = False, reason: str | None = None
) -> Destination:
    settings: dict[str, object] = {"host": host, "port": 5000}
    if tls:
        settings["tls"] = True
    return Destination(
        name="OB_MLLP",
        type=ConnectorType.MLLP,
        settings=settings,
        tls_hop_attested=attested,
        tls_hop_attested_reason=reason,
    )


def tcp_cfg(host: str, *, attested: bool = False, reason: str | None = None) -> Destination:
    return Destination(
        name="OB_TCP",
        type=ConnectorType.TCP,
        settings={"host": host, "port": 5000, "framing": "stx_etx"},
        tls_hop_attested=attested,
        tls_hop_attested_reason=reason,
    )


def x12_cfg(host: str, *, attested: bool = False, reason: str | None = None) -> Destination:
    return Destination(
        name="OB_X12",
        type=ConnectorType.X12,
        settings={"host": host, "port": 5000},
        tls_hop_attested=attested,
        tls_hop_attested_reason=reason,
    )


def dicom_cfg(
    host: str, *, tls: bool = False, attested: bool = False, reason: str | None = None
) -> Destination:
    settings: dict[str, object] = {"ae_title": "MF_SCU", "host": host, "port": 104}
    if tls:
        settings["tls"] = True
    return Destination(
        name="OB_DICOM",
        type=ConnectorType.DIMSE,
        settings=settings,
        tls_hop_attested=attested,
        tls_hop_attested_reason=reason,
    )


def ftp_cfg(
    host: str, *, attested: bool = False, reason: str | None = None, protocol: str = "ftp"
) -> Destination:
    settings: dict[str, object] = {
        "host": host,
        "remote_dir": "/in",
        "protocol": protocol,
    }
    if attested:
        settings["tls_hop_attested"] = True
        if reason is not None:
            settings["tls_hop_attested_reason"] = reason
    return Destination(name="OB_FTP", type=ConnectorType.REMOTEFILE, settings=settings)


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
    with active_hop_posture(PROD_PHI):  # the ENFORCED gate (posture stamped)
        with pytest.raises(InsecureHopRefused):
            connector(build_cfg(REMOTE))


# --- construction gate: ALLOW loopback / synthetic (byte-identical) -----------


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_allows_loopback(build_cfg, connector) -> None:
    with active_hop_posture(PROD_PHI):
        connector(build_cfg(LOOPBACK))  # on-box hop — never a network exposure


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_allows_synthetic_instance(build_cfg, connector) -> None:
    with active_hop_posture(SYNTHETIC):
        connector(build_cfg(REMOTE))  # not is_phi → no PHI on the wire → ALLOW


# --- construction gate: WARN (cross) a non-production PHI hop -----------------


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_warns_but_crosses_staging_phi(build_cfg, connector) -> None:
    with active_hop_posture(STAGING_PHI):
        connector(build_cfg(REMOTE))  # dev/staging PHI → WARN, not REFUSE (constructs fine)


# --- construction gate: per-connection attestation ALLOWs even prod-PHI -------


@pytest.mark.parametrize(("build_cfg", "connector"), PLAINTEXT_BUILDERS)
def test_construction_attested_allows_prod_phi(build_cfg, connector, caplog) -> None:
    with active_hop_posture(PROD_PHI):
        with caplog.at_level("WARNING"):
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
    with active_hop_posture(PROD_PHI):
        dest = MLLPDestination(mllp_cfg(REMOTE, tls=True))
    assert dest._hop_guard is None  # a verified TLS hop needs no cleartext guard


def test_dicom_tls_has_no_hop_guard() -> None:
    with active_hop_posture(PROD_PHI):
        dest = DicomScuDestination(dicom_cfg(REMOTE, tls=True))
    assert dest._hop_guard is None


# --- escape clamp: MEFOR_ALLOW_INSECURE_TLS only downgrades on NON-production --


def test_escape_downgrades_staging_phi_but_never_prod(monkeypatch) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    # Non-production PHI is already WARN; the escape keeps it crossing (still no refusal).
    with active_hop_posture(STAGING_PHI):
        TcpDestination(tcp_cfg(REMOTE))
    # Production PHI: the escape is CLAMPED to non-production, so it can NEVER satisfy a prod-PHI hop —
    # the production REFUSE arm still wins even with the escape set (decision 2 behaviour change).
    with active_hop_posture(PROD_PHI):
        with pytest.raises(InsecureHopRefused):
            TcpDestination(tcp_cfg(REMOTE))


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
    def disp(host: str, *, posture: HopPosture, attested: bool) -> HopDisposition:
        g = InsecureHopGuard(
            host=host,
            port=1,
            cell="t",
            description="d",
            attested=attested,
            attested_reason=None,
            posture=posture,
        )
        return g._disposition(posture)

    assert disp(LOOPBACK, posture=PROD_PHI, attested=False) is HopDisposition.ALLOW
    assert disp(REMOTE, posture=PROD_PHI, attested=True) is HopDisposition.ALLOW
    assert disp(REMOTE, posture=SYNTHETIC, attested=False) is HopDisposition.ALLOW
    assert disp(REMOTE, posture=PROD_PHI, attested=False) is HopDisposition.REFUSE
    assert disp(REMOTE, posture=STAGING_PHI, attested=False) is HopDisposition.WARN


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
    with active_hop_posture(STAGING_PHI):
        with pytest.raises(ValueError, match="tls_verify=false"):
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
    with active_hop_posture(STAGING_PHI):
        with pytest.raises(ValueError, match="CLEARTEXT"):
            RemoteFileDestination(cfg)

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Config/wiring tests for the DICOM DIMSE connector (ADR 0025) — the DICOM() factory, the binary
content type, the inbound host-rejection + peer-IP allowlist, the generalized non-loopback bind-guard
(check_dimse_tls_exposure), and the fail-closed egress arm. These need NO [dicom] extra (they exercise
the config layer; pydicom is only imported when the SCP actually starts), so they run on every CI leg."""

from __future__ import annotations

import pytest

from messagefoundry import DICOM
from messagefoundry.config.models import ConnectorType, ContentType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import WiringError, build_inbound_connection
from messagefoundry.pipeline.wiring_runner import (
    _allowlist_for,
    check_dimse_tls_exposure,
    check_egress_allowed,
)


def _dimse_source(host: str, *, tls: bool = False) -> Source:
    return Source(
        type=ConnectorType.DIMSE, settings={"ae_title": "MEFOR_SCP", "host": host, "tls": tls}
    )


def _dimse_dest(host: str, port: int = 104) -> Destination:
    return Destination(
        name="OB", type=ConnectorType.DIMSE, settings={"ae_title": "X", "host": host, "port": port}
    )


# --- factory + content type --------------------------------------------------


def test_dicom_factory_builds_dimse_spec() -> None:
    spec = DICOM(ae_title="MEFOR_SCP", port=11112, calling_ae_allowlist=["MODALITY1"])
    assert spec.type is ConnectorType.DIMSE
    assert spec.settings["ae_title"] == "MEFOR_SCP"
    assert spec.settings["port"] == 11112
    assert spec.settings["calling_ae_allowlist"] == ["MODALITY1"]
    assert spec.settings["max_object_bytes"]  # a default cap is set


def test_content_type_dicom_is_binary() -> None:
    assert ContentType.DICOM.is_binary is True
    assert ContentType("dicom") is ContentType.DICOM


# --- inbound wiring guards ---------------------------------------------------


def test_dicom_inbound_rejects_author_host() -> None:
    # The bind interface is a service setting ([inbound].bind_host); an author host is refused, and the
    # message names the DICOM() factory (not the DIMSE connector kind).
    with pytest.raises(WiringError) as exc:
        build_inbound_connection(
            "IB_DCM",
            # 192.0.2.10 = RFC 5737 TEST-NET-1, a non-routable documentation IP
            DICOM(ae_title="MEFOR_SCP", host="192.0.2.10"),
            router="R",
            content_type="dicom",
        )
    assert "DICOM(port=...)" in str(exc.value)


def test_dicom_inbound_rejects_strict_validation() -> None:
    with pytest.raises(WiringError):
        build_inbound_connection(
            "IB_DCM", DICOM(ae_title="MEFOR_SCP"), router="R", content_type="dicom", strict=True
        )


def test_dicom_inbound_accepts_peer_ip_allowlist() -> None:
    ic = build_inbound_connection(
        "IB_DCM",
        DICOM(ae_title="MEFOR_SCP"),
        router="R",
        content_type="dicom",
        source_ip_allowlist=["10.0.0.0/8", "127.0.0.1"],
    )
    assert ic.content_type is ContentType.DICOM
    assert tuple(ic.source_ip_allowlist) == ("10.0.0.0/8", "127.0.0.1")


# --- bind-guard: non-loopback cleartext SCP refused (ADR 0025 §9) ------------


def test_bind_guard_refuses_non_loopback_cleartext_scp() -> None:
    with pytest.raises(WiringError):
        check_dimse_tls_exposure(_dimse_source("0.0.0.0"), "IB", allow_insecure_bind=False)


def test_bind_guard_allows_loopback_and_tls_and_escape() -> None:
    check_dimse_tls_exposure(
        _dimse_source("127.0.0.1"), "IB", allow_insecure_bind=False
    )  # loopback
    check_dimse_tls_exposure(_dimse_source("0.0.0.0", tls=True), "IB", allow_insecure_bind=False)
    check_dimse_tls_exposure(_dimse_source("0.0.0.0"), "IB", allow_insecure_bind=True)  # warns, ok


def test_bind_guard_is_noop_for_non_dimse() -> None:
    # The DIMSE guard must not fire on an MLLP source (the MLLP guard handles that one).
    mllp = Source(type=ConnectorType.MLLP, settings={"host": "0.0.0.0"})
    check_dimse_tls_exposure(mllp, "IB", allow_insecure_bind=False)  # no raise


# --- egress arm: DIMSE shares the raw-TCP allowlist -------------------------


def test_allowlist_for_dimse_is_allowed_tcp() -> None:
    egress = EgressSettings(allowed_tcp=["10.0.0.5:104"])
    assert _allowlist_for(ConnectorType.DIMSE, egress) is egress.allowed_tcp


def test_dimse_egress_allows_listed_and_refuses_unlisted() -> None:
    egress = EgressSettings(allowed_tcp=["pacs.partner.org:104", "10.0.0.5"])
    check_egress_allowed(_dimse_dest("pacs.partner.org", 104), egress)  # exact host:port
    check_egress_allowed(_dimse_dest("10.0.0.5", 4242), egress)  # host-only entry → any port
    with pytest.raises(WiringError):
        check_egress_allowed(_dimse_dest("evil.example", 104), egress)


def test_dimse_egress_deny_by_default_refuses_unlisted_transport() -> None:
    egress = EgressSettings(deny_by_default=True)  # no allowed_tcp → DIMSE refused fail-closed
    with pytest.raises(WiringError):
        check_egress_allowed(_dimse_dest("pacs.partner.org", 104), egress)

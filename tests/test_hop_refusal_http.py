# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Posture-keyed transport-hop refusal — the HTTP-family cells (#200, ADR 0092).

Covers the four HTTP destinations (REST / SOAP / FHIR / DICOMweb) and the ``FhirLookup`` read path,
which shipped escape-only, construction-only cleartext/verify-off refusals and are re-keyed onto the ONE
authority (``tls_policy.insecure_hop_disposition``). Verifies, per cell:

* the posture gradient at CONSTRUCTION — production PHI REFUSES, a per-hop attestation / on-box loopback /
  synthetic instance ALLOWs, the clamped global escape only downgrades a NON-prod PHI hop to WARN;
* **decision 5 (no-loosen)** — a *staging* (non-prod) PHI cleartext hop that refused today STILL refuses,
  the gradient's non-prod WARN is floored back to REFUSE unless the escape/attestation applies;
* **decision 2 (escape clamp)** — ``MEFOR_ALLOW_INSECURE_TLS`` is inert on production;
* the fail-closed default — an UNSTAMPED posture is treated as production PHI;
* the zero-I/O SEND-TIME re-assertion (decision 4) fires at the byte-crossing, before any wire I/O.

Nothing hits the network: refusals fire at construction, and the one send test uses a fake opener.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.tls_policy import (
    HopPosture,
    InsecureHopRefused,
    active_hop_posture,
)
from messagefoundry.config.wiring import DICOMweb, FHIR, Rest, Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.fhir import FhirLookupExecutor
from messagefoundry.transports.rest import (
    InsecureHopGuard,
    refuse_cleartext_egress,
    refuse_verify_off,
)

# The four HTTP-family cells, each as (label, ConnectorType, cleartext-url, https-url) so one gradient
# body exercises them all. A cleartext http url to a non-loopback host is the shipped-strict egress cell.
_CLEARTEXT = {
    "REST": (ConnectorType.REST, Rest, "http://api.example.com/x"),
    "SOAP": (ConnectorType.SOAP, Soap, "http://api.example.com/svc"),
    "FHIR": (ConnectorType.FHIR, FHIR, "http://fhir.example.org/fhir"),
    "DICOMweb": (ConnectorType.DICOMWEB, DICOMweb, "http://pacs.example.org/dicom-web"),
}
_LOOPBACK = {
    "REST": (ConnectorType.REST, Rest, "http://127.0.0.1:8000/x"),
    "SOAP": (ConnectorType.SOAP, Soap, "http://localhost:8080/svc"),
    "FHIR": (ConnectorType.FHIR, FHIR, "http://127.0.0.1:8080/fhir"),
    "DICOMweb": (ConnectorType.DICOMWEB, DICOMweb, "http://127.0.0.1:8042/dicom-web"),
}
_HTTPS = {
    "REST": (ConnectorType.REST, Rest, "https://api.example.com/x"),
    "SOAP": (ConnectorType.SOAP, Soap, "https://api.example.com/svc"),
    "FHIR": (ConnectorType.FHIR, FHIR, "https://fhir.example.org/fhir"),
    "DICOMweb": (ConnectorType.DICOMWEB, DICOMweb, "https://pacs.example.org/dicom-web"),
}

_STAGING = HopPosture(is_phi=True, production=False)  # non-prod PHI (staging/dev)
_PROD = HopPosture(is_phi=True, production=True)  # production PHI
_SYNTHETIC = HopPosture(is_phi=False, production=False)  # no PHI on the wire

_CELLS = list(_CLEARTEXT)


def _build(spec: tuple[Any, Any, str], *, attested: bool = False, **over: Any) -> object:
    ctype, factory, url = spec
    settings = factory(url=url, **over).settings
    return build_destination(
        Destination(name="OB", type=ctype, settings=settings, tls_hop_attested=attested)
    )


# --- decision 5: a shipped cell keeps REFUSE for BOTH staging AND production PHI (no loosen) ----------


@pytest.mark.parametrize("cell", _CELLS)
def test_cleartext_staging_phi_still_refuses(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # THE decision-5 guarantee: a staging (non-prod) PHI cleartext hop that refused today must NOT be
    # loosened to warn-and-cross by the gradient — the arm-6 WARN is floored back to REFUSE.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_STAGING), pytest.raises(InsecureHopRefused):
        _build(_CLEARTEXT[cell])


@pytest.mark.parametrize("cell", _CELLS)
def test_cleartext_prod_phi_refuses(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD), pytest.raises(InsecureHopRefused):
        _build(_CLEARTEXT[cell])


# --- decision 2: the global escape is inert on production, downgrades only on non-prod ----------------


@pytest.mark.parametrize("cell", _CELLS)
def test_escape_inert_on_production(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(_PROD), pytest.raises(InsecureHopRefused):
        _build(_CLEARTEXT[cell])  # escape cannot satisfy a prod-PHI hop


@pytest.mark.parametrize("cell", _CELLS)
def test_escape_downgrades_on_non_prod(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(_STAGING):
        assert _build(_CLEARTEXT[cell]) is not None  # warns-and-builds, not refused


# --- the ALLOW arms: loopback, per-hop attestation, synthetic (non-PHI) -------------------------------


@pytest.mark.parametrize("cell", _CELLS)
def test_loopback_allowed_even_on_prod(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # On-box loopback is not a network exposure → allowed on any posture (byte-identical default).
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD):
        assert _build(_LOOPBACK[cell]) is not None


@pytest.mark.parametrize("cell", _CELLS)
def test_attestation_allows_prod_phi_cleartext(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # A per-hop attestation is the ONLY per-hop way across a prod-PHI hop (decision 3) — no escape.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD):
        assert _build(_CLEARTEXT[cell], attested=True) is not None


@pytest.mark.parametrize("cell", _CELLS)
def test_synthetic_instance_allows_cleartext(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    # No PHI rides the hop → allowed (the gradient's arm 3), even off-loopback with no escape.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_SYNTHETIC):
        assert _build(_CLEARTEXT[cell]) is not None


# --- fail-closed: an UNSTAMPED posture is treated as production PHI -----------------------------------


@pytest.mark.parametrize("cell", _CELLS)
def test_unstamped_posture_fails_closed_to_prod(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    # No active_hop_posture scope → current_hop_posture() is None → treated as production PHI → REFUSE.
    with pytest.raises(InsecureHopRefused):
        _build(_CLEARTEXT[cell])


@pytest.mark.parametrize("cell", _CELLS)
def test_unstamped_escape_still_inert(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with pytest.raises(InsecureHopRefused):
        _build(_CLEARTEXT[cell])  # fail-closed prod → escape inert


# --- verify_tls=false re-keyed onto the same authority (the shipped verify-off cell) ------------------


@pytest.mark.parametrize("cell", _CELLS)
def test_verify_off_prod_phi_refuses(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD), pytest.raises(InsecureHopRefused):
        _build(_HTTPS[cell], verify_tls=False)


@pytest.mark.parametrize("cell", _CELLS)
def test_verify_off_staging_refuses_without_escape(
    cell: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # decision 5 floor: verify-off refused staging PHI today, so it stays REFUSE (not warn) with no escape.
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_STAGING), pytest.raises(InsecureHopRefused):
        _build(_HTTPS[cell], verify_tls=False)


@pytest.mark.parametrize("cell", _CELLS)
def test_verify_off_attested_allowed_on_prod(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD):
        assert _build(_HTTPS[cell], verify_tls=False, attested=True) is not None


# --- SOAP WS-Security UsernameToken over cleartext http (the credentialed-cleartext variant) ----------


def test_soap_ws_username_cleartext_refused_on_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD), pytest.raises(InsecureHopRefused):
        _build(
            _CLEARTEXT["SOAP"],
            soap_version="1.2",
            ws_security=True,
            ws_username="u",
            ws_password="p",  # noqa: S106 — synthetic test credential, not a real secret
        )


def test_soap_ws_username_cleartext_attested_allowed_on_prod(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD):
        assert (
            _build(
                _CLEARTEXT["SOAP"],
                attested=True,
                soap_version="1.2",
                ws_security=True,
                ws_username="u",
                ws_password="p",  # noqa: S106 — synthetic test credential, not a real secret
            )
            is not None
        )


# --- the FhirLookup read path (a cleartext read pulls PHI back over the wire) -------------------------


def test_fhir_lookup_cleartext_read_refused_on_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD), pytest.raises(InsecureHopRefused):
        FhirLookupExecutor({"L": {"url": "http://fhir.example.org/fhir"}})


def test_fhir_lookup_cleartext_read_refused_staging(monkeypatch: pytest.MonkeyPatch) -> None:
    # decision 5: a cleartext lookup that refused today stays refused in staging (no loosen).
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_STAGING), pytest.raises(InsecureHopRefused):
        FhirLookupExecutor({"L": {"url": "http://fhir.example.org/fhir"}})


def test_fhir_lookup_loopback_read_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD):
        ex = FhirLookupExecutor({"L": {"url": "http://127.0.0.1:8080/fhir"}})
    assert ex.connections == frozenset({"L"})


def test_fhir_lookup_attested_read_allowed_on_prod(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD):
        ex = FhirLookupExecutor(
            {"L": {"url": "http://fhir.example.org/fhir", "tls_hop_attested": True}}
        )
    assert ex.connections == frozenset({"L"})


# --- the send-time guard object (zero-I/O re-assertion, decision 4) -----------------------------------


def test_send_guard_refuses_prod_phi_hop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    guard = InsecureHopGuard(posture=_PROD, attested=False, cell="HTTP cleartext egress")
    with pytest.raises(InsecureHopRefused):
        guard.assert_send("api.example.com", "http://api.example.com/x")


def test_send_guard_allows_attested_and_synthetic_and_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    # attested → ALLOW even on prod PHI
    InsecureHopGuard(posture=_PROD, attested=True, cell="c").assert_send(
        "api.example.com", "http://api.example.com/x"
    )
    # synthetic → ALLOW
    InsecureHopGuard(posture=_SYNTHETIC, attested=False, cell="c").assert_send(
        "api.example.com", "http://api.example.com/x"
    )
    # loopback host → ALLOW (on-box)
    InsecureHopGuard(posture=_PROD, attested=False, cell="c").assert_send(
        "127.0.0.1", "http://127.0.0.1/x"
    )


# --- helper-level: refuse_cleartext_egress / refuse_verify_off return a guard only when PERMITTED -----


def test_refuse_cleartext_egress_returns_guard_when_permitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(_STAGING):
        guard = refuse_cleartext_egress("http", "http://api.example.com/x")
    assert isinstance(guard, InsecureHopGuard)


def test_refuse_cleartext_egress_no_guard_for_loopback_or_https(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD):
        assert refuse_cleartext_egress("http", "http://127.0.0.1/x") is None  # loopback
        assert (
            refuse_cleartext_egress("https", "https://api.example.com/x") is None
        )  # not cleartext
        assert refuse_verify_off("http", "http://x/y", connector="REST") is None  # http has no TLS


# --- a secure (https-verified) connector attaches NO send guard (byte-identical send) -----------------


@pytest.mark.parametrize("cell", _CELLS)
def test_https_verified_connector_has_no_send_guard(
    cell: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(_PROD):
        dest = _build(_HTTPS[cell])
    assert dest._hop_guard is None  # type: ignore[attr-defined]


# --- end-to-end: the REST send-time assertion fires BEFORE any wire I/O -------------------------------


class _Resp:
    status = 200

    def read(self) -> bytes:
        return b""

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> bool:
        return False


class _Opener:
    def __init__(self) -> None:
        self.calls = 0

    def open(self, req: object, timeout: float | None = None) -> _Resp:
        self.calls += 1
        return _Resp()


async def test_rest_send_time_assertion_blocks_before_wire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Build a permitted cleartext REST dest (staging + escape → WARN), then revoke the escape: the
    # zero-I/O send-time re-assertion must REFUSE at the byte-crossing, before the opener is ever called.
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(_STAGING):
        dest = _build(_CLEARTEXT["REST"])
    opener = _Opener()
    dest._opener = opener  # type: ignore[attr-defined]
    assert dest._hop_guard is not None  # type: ignore[attr-defined]

    await dest.send("payload")  # escape still set → permitted, reaches the (fake) wire
    assert opener.calls == 1

    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(InsecureHopRefused):
        await dest.send("payload")  # escape revoked → send-time refusal, before any I/O
    assert opener.calls == 1  # the opener was NOT called on the refused send

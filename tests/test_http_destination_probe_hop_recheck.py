# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The four HTTP destination probes re-check the insecure hop, as each ``_post`` does (BACKLOG #2196).

ADR 0092 decision 4 has each destination re-assert a permitted insecure hop at send time, before a
byte crosses. ``_post`` did that; ``_probe``, which serves an operator's test connection, did not.
The REST and FHIR probes also mint a bearer for the hop, so a skipped re-check there put a fresh
token on a hop the send path would have refused.

Each case builds a destination whose cleartext hop is PERMITTED, proves the probe reaches the
(fake) opener, then swaps in a guard that now refuses. Nothing here touches the network.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import HopPosture, InsecureHopRefused, active_hop_posture
from messagefoundry.config.wiring import FHIR, DICOMweb, Rest, Soap
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DeliveryError, DestinationConnector
from messagefoundry.transports.rest import InsecureHopGuard

_PROD = HopPosture(enforcing=True)

# (ConnectorType, wiring factory, a cleartext URL to a non-loopback host).
_CELLS: dict[str, tuple[Any, Any, str]] = {
    "REST": (ConnectorType.REST, Rest, "http://api.example.com/x"),
    "SOAP": (ConnectorType.SOAP, Soap, "http://api.example.com/svc"),
    "FHIR": (ConnectorType.FHIR, FHIR, "http://fhir.example.org/fhir"),
    "DICOMweb": (ConnectorType.DICOMWEB, DICOMweb, "http://pacs.example.org/dicom-web"),
}
# The two probes that mint a bearer before they send.
_MINTING = ["REST", "FHIR"]


class _Resp:
    status = 200

    def read(self, amt: int = -1) -> bytes:
        return b""

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


class _Opener:
    def __init__(self) -> None:
        self.calls = 0

    def open(self, req: object, timeout: float | None = None) -> _Resp:
        self.calls += 1
        return _Resp()


class _TokenProvider:
    """Counts mints. The token is short, so the send-time length gate passes."""

    def __init__(self) -> None:
        self.mints = 0

    def access_token(self) -> str:
        self.mints += 1
        return "synthetic-token"

    def invalidate(self) -> None:
        return None


def _permitted(cell: str) -> tuple[DestinationConnector, _Opener]:
    """A destination whose cleartext hop the construction gate PERMITTED, on a fake opener.

    An enforcing posture plus a ``cleartext_accepted`` declaration is a WARN that crosses, so the
    destination carries a send-time guard that still permits the hop."""
    ctype, factory, url = _CELLS[cell]
    with active_hop_posture(_PROD):
        dest = build_destination(
            Destination(
                name="OB",
                type=ctype,
                settings=factory(url=url).settings,
                cleartext_accepted=True,
                cleartext_reason="vendor firmware predates TLS",
            ),
            egress=EgressSettings(deny_by_default=False),
        )
    opener = _Opener()
    dest._opener = opener  # type: ignore[attr-defined]
    assert dest._hop_guard is not None  # type: ignore[attr-defined]
    return dest, opener


def _refusing_guard() -> InsecureHopGuard:
    """A real send-time guard that refuses: enforcing, unattested, undeclared."""
    return InsecureHopGuard(
        posture=_PROD, attested=False, cell="HTTP cleartext egress", connection="OB"
    )


@pytest.mark.parametrize("cell", list(_CELLS))
async def test_a_probe_whose_hop_is_now_refused_raises_and_sends_nothing(
    cell: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest, opener = _permitted(cell)

    # Control: while the guard permits the hop, the same probe reaches the opener. Without this
    # the refusal below could pass on a probe that never sends anything.
    await dest.test_connection()
    assert opener.calls == 1

    dest._hop_guard = _refusing_guard()  # type: ignore[attr-defined]
    with pytest.raises(DeliveryError) as err:
        await dest.test_connection()
    # A plain DeliveryError, the type a probe's other failures carry. Not the raw refusal, which is
    # a ValueError, and not a subclass the test-connection route would classify differently.
    assert type(err.value) is DeliveryError
    assert isinstance(err.value.__cause__, InsecureHopRefused)
    assert str(err.value).startswith(f"{cell} probe refused: ")
    assert opener.calls == 1  # the refused probe sent nothing


@pytest.mark.parametrize("cell", _MINTING)
async def test_a_refused_probe_mints_no_bearer(cell: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest, opener = _permitted(cell)
    provider = _TokenProvider()
    dest._token_provider = provider  # type: ignore[attr-defined]

    # Control: a permitted probe does mint, so a zero below means the re-check ran first.
    await dest.test_connection()
    assert (provider.mints, opener.calls) == (1, 1)

    dest._hop_guard = _refusing_guard()  # type: ignore[attr-defined]
    with pytest.raises(DeliveryError):
        await dest.test_connection()
    assert (provider.mints, opener.calls) == (1, 1)  # no second mint, no second send


@pytest.mark.parametrize("cell", list(_CELLS))
async def test_a_probe_with_no_guard_is_unchanged(
    cell: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A secure or loopback hop carries no guard, and its probe still sends."""
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    dest, opener = _permitted(cell)
    dest._hop_guard = None  # type: ignore[attr-defined]
    await dest.test_connection()
    assert opener.calls == 1

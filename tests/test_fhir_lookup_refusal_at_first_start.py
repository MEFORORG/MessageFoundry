# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a first start does when a ``FhirLookup`` hop is refused: a pin of measured behaviour
(vault BACKLOG #2193).

``serve`` adds the registry and starts the runner with no ``build_check`` in between, so on a first
load the live builders are where a posture refusal fires. They do not treat every refusal alike:

* an **outbound** is built inside ``_start_outbound``, which isolates a failure to that one lane
  (ADR 0031). The lane is recorded failed and the rest of the graph starts;
* the **lookup executor** is built once for the whole graph, outside that isolation. A refusal there
  reaches the start's backstop, which unwinds everything and re-raises.

So an unattested off-box https ``FhirLookup`` under an enforcing posture stops the WHOLE start, where
an unattested DICOM-over-TLS outbound in the same position costs one lane. Both are fail-closed:
neither hop is ever dialled. The lookup's SMART token hop already aborted a start this way before
#2193; that change extended the same outcome to the read hop.

**This file records what the code does. It is not a statement that the difference is wanted.**
Whether a lookup build should get lane-style isolation is an open design question. A change there
should update these tests on purpose, not find them in the way by accident.

Nothing here dials: construction reads settings only, and the keys are synthetic.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    InsecureHopRefused,
)
from messagefoundry.config.wiring import (
    ConnectionSpec,
    FhirLookupSpec,
    OutboundConnection,
    Registry,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore

ENFORCING = HopPosture(enforcing=True)
REMOTE = "10.0.0.5"  # non-loopback, never dialled
LOOPBACK = "127.0.0.1"


@pytest.fixture(autouse=True)
def _no_blanket_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "first_start.db")
    yield s
    await s.close()


@pytest.fixture(scope="module")
def smart_key() -> str:
    """An EC private key PEM for the SMART signer. Synthetic, never leaves the process."""
    return (
        ec.generate_private_key(ec.SECP384R1())
        .private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        .decode()
    )


def _file_out(name: str, directory: Path) -> OutboundConnection:
    """A healthy outbound that starts in any posture: the control for 'the rest of the graph'."""
    return build_outbound_connection(
        name,
        ConnectionSpec(
            ConnectorType.FILE, {"directory": str(directory), "filename": "{MSH-10}.hl7"}
        ),
    )


def _runner(registry: Registry, store: MessageStore) -> RegistryRunner:
    return RegistryRunner(
        registry,
        store,
        poll_interval=0.02,
        env_values={},
        egress=EgressSettings(deny_by_default=False),
        hop_posture=ENFORCING,
    )


async def test_an_unattested_fhir_lookup_read_hop_aborts_the_whole_first_start(
    store: MessageStore, tmp_path: Path
) -> None:
    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path))
    registry.add_fhir_lookup(FhirLookupSpec("epic", {"url": f"https://{REMOTE}/fhir"}))
    runner = _runner(registry, store)
    with pytest.raises(InsecureHopRefused, match="FhirLookup 'epic'.*revocation"):
        await runner.start()
    # The backstop unwound the partial start: the healthy outbound did not stay up.
    assert not runner.running
    assert "OB_FILE" not in runner._destinations


async def test_an_unattested_smart_token_hop_on_a_lookup_aborts_a_first_start_the_same_way(
    store: MessageStore, tmp_path: Path, smart_key: str
) -> None:
    """The behaviour that predates #2193, kept beside the read-hop arm as its reference. The read
    here is on loopback, so the read-hop guard crosses and the refusal can only be the token hop's."""
    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path))
    registry.add_fhir_lookup(
        FhirLookupSpec(
            "epic",
            {
                "url": f"https://{LOOPBACK}:8443/fhir",
                "smart_token_url": f"https://{REMOTE}/token",
                "smart_client_id": "cid",
                "smart_private_key": smart_key,
                "smart_algorithm": "ES384",
            },
        )
    )
    runner = _runner(registry, store)
    with pytest.raises(InsecureHopRefused, match="token endpoint.*revocation"):
        await runner.start()
    assert not runner.running
    assert "OB_FILE" not in runner._destinations


async def test_an_unattested_dicom_tls_outbound_costs_one_lane_and_the_start_continues(
    store: MessageStore, tmp_path: Path
) -> None:
    """The contrast. The same refusal, from a guard #2193 added in the same change, on an outbound:
    the lane is recorded failed and the healthy outbound beside it still comes up."""
    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path))
    registry.add_outbound(
        build_outbound_connection(
            "OB_PACS",
            ConnectionSpec(
                ConnectorType.DIMSE,
                {"ae_title": "MF_SCU", "host": REMOTE, "port": 11112, "tls": True},
            ),
        )
    )
    runner = _runner(registry, store)
    await runner.start()
    try:
        assert runner.running
        reason = runner.outbound_failed("OB_PACS")
        assert reason is not None and "revocation" in reason
        assert "OB_PACS" not in runner._destinations  # never dialled: no connector was built
        assert runner.outbound_failed("OB_FILE") is None
        assert "OB_FILE" in runner._destinations
    finally:
        await runner.stop()


async def test_an_attested_fhir_lookup_lets_the_first_start_complete(
    store: MessageStore, tmp_path: Path
) -> None:
    # CONTROL for the first arm: the same graph with the declaration starts, so that arm's abort is
    # the guard's refusal and not some other fault in building a lookup here.
    registry = Registry()
    registry.add_outbound(_file_out("OB_FILE", tmp_path))
    registry.add_fhir_lookup(
        FhirLookupSpec(
            "epic",
            {"url": f"https://{REMOTE}/fhir"},
            tls_revocation_attested=True,
            tls_revocation_attested_reason="partner PKI runs OCSP at the site edge",
        )
    )
    runner = _runner(registry, store)
    await runner.start()
    try:
        assert runner.running
        assert "OB_FILE" in runner._destinations
    finally:
        await runner.stop()

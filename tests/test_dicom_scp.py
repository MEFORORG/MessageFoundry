# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Real-association loopback tests for the DICOM C-STORE SCP source (ADR 0025 Phase 1): a live
``pynetdicom`` SCU associates and C-STOREs into the ``DicomScpSource``, proving commit-before-SUCCESS
(via a stub ingress handler), the AE-title / peer-IP allowlists, the ``max_object_bytes`` cap, the
timeout-failure policy, the PHI-no-log rule, and clean shutdown."""

from __future__ import annotations

import asyncio
import datetime
import ipaddress
import logging
import ssl
from io import BytesIO
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")

from messagefoundry.config.models import ConnectorType, Source  # noqa: E402
from messagefoundry.parsing import RawMessage  # noqa: E402
from messagefoundry.parsing.dicom import DicomPeek  # noqa: E402
from messagefoundry.transports.dicom import DicomScpSource, _server_ssl_context  # noqa: E402
from tests._dicom_sample import make_deflated_bomb_stream, make_sr_part10  # noqa: E402

_SCP_AE = "MEFOR_SCP"


def _build_scp(captured: list[bytes], **settings_overrides: object) -> DicomScpSource:
    settings: dict[str, object] = {
        "ae_title": _SCP_AE,
        "host": "127.0.0.1",
        "port": 0,  # ephemeral — read the real port from .sockport
    }
    settings.update(settings_overrides)
    return DicomScpSource(Source(type=ConnectorType.DIMSE, settings=settings))


def _scu_cstore(
    port: int, data: bytes, *, calling_ae: str = "MODALITY1"
) -> tuple[bool, int | None]:
    """Run a blocking pynetdicom SCU: associate + C-STORE ``data``. Returns
    ``(established, status)`` — ``status`` is the DIMSE C-STORE status (``None`` if not established)."""
    from pydicom import dcmread
    from pynetdicom import AE

    ds = dcmread(BytesIO(data))
    ae = AE(ae_title=calling_ae)
    ae.add_requested_context(ds.SOPClassUID, ds.file_meta.TransferSyntaxUID)
    # Address the SCP's called AE title (it runs with require_called_ae_title=True).
    assoc = ae.associate("127.0.0.1", port, ae_title=_SCP_AE)
    if not assoc.is_established:
        return (False, None)
    try:
        status = assoc.send_c_store(ds)
        return (True, int(status.Status))
    finally:
        assoc.release()


async def _capture_handler_factory(captured: list[bytes]):
    async def handler(data: bytes) -> None:
        # Mimics the binary _handle_inbound: durably "commit" then return None (DIMSE owns the reply).
        captured.append(data)
        return None

    return handler


async def test_scp_receives_and_commits_before_success() -> None:
    captured: list[bytes] = []
    scp = _build_scp(captured)
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        port = scp.sockport
        data = make_sr_part10()
        established, status = await asyncio.to_thread(_scu_cstore, port, data)
        assert established is True
        assert status == 0x0000  # Success — returned only after the commit (handler ran)
        assert len(captured) == 1, "object must be committed before Success"
        # The committed bytes are a faithful Part-10 object: a codec round-trips them.
        peek = DicomPeek.parse(RawMessage.from_bytes(captured[0], "dicom"))
        sent = DicomPeek.parse(data)
        assert peek.sop_instance_uid == sent.sop_instance_uid
        assert peek.is_structured_report() is True
    finally:
        await scp.stop()


async def test_scp_rejects_unlisted_calling_ae() -> None:
    captured: list[bytes] = []
    scp = _build_scp(captured, calling_ae_allowlist=["MODALITY1"])
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        established, _ = await asyncio.to_thread(
            _scu_cstore, scp.sockport, make_sr_part10(), calling_ae="EVIL_AE"
        )
        assert established is False, "an unlisted calling AE must be refused at association"
        assert captured == []
    finally:
        await scp.stop()


async def test_scp_rejects_unlisted_peer_ip() -> None:
    captured: list[bytes] = []
    # An allowlist that excludes loopback → the C-STORE is refused before any commit.
    scp = _build_scp(captured, source_ip_allowlist=["10.0.0.0/8"])
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert established is True  # association ok; C-STORE refused
        assert status == 0x0124  # Refused: Not authorized
        assert captured == [], "a non-allowlisted peer's object must never be committed"
    finally:
        await scp.stop()


async def test_scp_rejects_oversized_object() -> None:
    captured: list[bytes] = []
    scp = _build_scp(captured, max_object_bytes=64)  # any real SR exceeds this
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert established is True
        assert status == 0xA700  # Refused: Out of Resources — over the cap, before commit
        assert captured == []
    finally:
        await scp.stop()


class _FakeRequestor:
    address = "127.0.0.1"
    ae_title = "MODALITY1"


class _FakeAssoc:
    requestor = _FakeRequestor()


class _FakeContext:
    def __init__(self, transfer_syntax: str) -> None:
        self.transfer_syntax = transfer_syntax


class _FakeRequest:
    def __init__(self, data_set: bytes) -> None:
        self.DataSet = BytesIO(data_set)


class _FakeStoreEvent:
    """A minimal EVT_C_STORE stand-in exposing only what ``_on_c_store`` reads before decode. Touching
    ``dataset`` / ``file_meta`` fails the test — the ASVS 5.2.3 guard MUST short-circuit a deflate bomb
    BEFORE pynetdicom inflates ``event.dataset``."""

    def __init__(self, *, transfer_syntax: str, data_set: bytes) -> None:
        self.assoc = _FakeAssoc()
        self.context = _FakeContext(transfer_syntax)
        self.request = _FakeRequest(data_set)

    @property
    def dataset(self) -> object:
        raise AssertionError(
            "event.dataset must not be touched for a deflate bomb (unbounded inflate)"
        )

    @property
    def file_meta(self) -> object:
        raise AssertionError("event.file_meta must not be touched for a deflate bomb")


def test_scp_rejects_deflated_decompression_bomb_before_decode() -> None:
    # ASVS 5.2.3 (SCP, binding): a negotiated Deflated Explicit VR LE context whose raw Data Set inflates
    # past the object cap is a DIMSE failure returned BEFORE event.dataset is ever decoded — nothing is
    # committed, and the guard runs in bounded memory (the fixture inflates to 64 MiB from a few KiB).
    captured: list[bytes] = []
    scp = _build_scp(
        captured, max_object_bytes=8 * 1024 * 1024
    )  # 8 MiB < the bomb's 64 MiB inflate
    bomb = make_deflated_bomb_stream(inflated_bytes=64 * 1024 * 1024)
    event = _FakeStoreEvent(transfer_syntax="1.2.840.10008.1.2.1.99", data_set=bomb)
    status = scp._on_c_store(event)
    assert (
        status == 0xA700
    )  # Refused: Out of Resources — over the inflate cap, before any decode/commit
    assert captured == []  # never committed


async def test_scp_commit_failure_returns_dimse_failure_not_success() -> None:
    # A failing ingress commit must surface as a DIMSE failure (the SCU re-sends), never a false Success.
    async def failing_handler(data: bytes) -> None:
        raise RuntimeError("store down")

    scp = _build_scp([])
    await scp.start(failing_handler)
    try:
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert established is True
        assert status not in (None, 0x0000), "a commit failure must not return Success"
    finally:
        await scp.stop()


async def test_scp_does_not_log_phi(caplog: pytest.LogCaptureFixture) -> None:
    captured: list[bytes] = []
    scp = _build_scp(captured)
    handler = await _capture_handler_factory(captured)
    await scp.start(handler)
    try:
        phi_name = "Secretpatient^Phicanary^DoNotLog"
        data = make_sr_part10(patient_name=phi_name)
        with caplog.at_level(logging.DEBUG, logger="messagefoundry.transports.dicom"):
            established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, data)
        assert established and status == 0x0000
        blob = "\n".join(r.getMessage() for r in caplog.records)
        assert phi_name not in blob and "Secretpatient" not in blob
    finally:
        await scp.stop()


async def test_scp_stop_is_idempotent() -> None:
    scp = _build_scp([])
    handler = await _capture_handler_factory([])
    await scp.start(handler)
    await scp.stop()
    await scp.stop()  # second stop must not raise


async def test_scp_stop_runs_off_loop_and_lets_in_flight_cstore_finish() -> None:
    # DICOM-14 (ADR 0025 §3, the 4-step teardown): stop() must (1) stop accepting new associations,
    # (2) let an in-flight C-STORE that has begun its commit still finish, and (4) join the off-loop
    # server thread — all with its blocking pynetdicom AE.shutdown()/join run OFF the event loop
    # (asyncio.to_thread), so shutting one SCP down never stalls other listeners/workers/API calls.
    #
    # This drives all three at once. A gated handler blocks mid-commit (the SCU's send_c_store is
    # parked waiting for the reply, which only lands once the commit returns Success). We then start
    # stop() CONCURRENTLY: its off-loop shutdown blocks in server_close()'s join of the in-flight
    # request thread — but because that join runs off the loop, the loop stays live to (a) advance a
    # concurrent ticker and (b) run the still-parked commit coroutine to completion once released.
    # If stop() blocked the loop instead, the commit coroutine could never run, its future.result()
    # would time out, and the SCU would see a failure — so the in-flight Success IS the off-loop proof.
    captured: list[bytes] = []
    commit_begun = asyncio.Event()
    release_commit = asyncio.Event()

    async def gated_handler(data: bytes) -> None:
        captured.append(data)  # commit "begun" — the durable write is under way
        commit_begun.set()
        await release_commit.wait()  # park mid-commit until the test releases it
        return None

    scp = _build_scp(captured)
    await scp.start(gated_handler)
    try:
        # Fire the SCU C-STORE off-thread; it parks inside send_c_store awaiting the reply.
        cstore = asyncio.create_task(asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10()))
        await asyncio.wait_for(commit_begun.wait(), timeout=15)
        assert len(captured) == 1, "the in-flight commit must have begun before we stop"

        # Begin teardown while the C-STORE is still parked mid-commit.
        stop_task = asyncio.create_task(scp.stop())
        await asyncio.sleep(0)  # let stop() reach its off-loop to_thread(server.shutdown)
        assert not stop_task.done(), "stop() must still be joining the in-flight request thread"

        # The loop is free during the blocking off-loop shutdown: a concurrent task keeps progressing.
        ticks = 0
        for _ in range(20):
            await asyncio.sleep(0.005)
            ticks += 1
        assert ticks == 20, "the event loop must keep running while stop() blocks off-loop"
        assert not stop_task.done(), "stop() is still blocked on the parked in-flight commit"

        # Release the in-flight commit: it must finish with Success (step 2), then stop() joins + returns.
        release_commit.set()
        established, status = await asyncio.wait_for(cstore, timeout=15)
        await asyncio.wait_for(stop_task, timeout=15)
        assert established is True
        assert status == 0x0000, (
            "an in-flight C-STORE mid-commit must still finish Success during stop"
        )
        assert scp._server is None, "teardown released the server handle"
    finally:
        await scp.stop()  # idempotent belt-and-braces if an assertion above fired early


async def test_scp_is_restartable_across_stop_start_cycles() -> None:
    # DICOM-14: the off-loop 4-step teardown must leave the source REUSABLE — a second start()/stop()
    # cycle rebinds (port 0 → fresh ephemeral port) and receives again. This pins that stop() fully
    # releases the AE/server (no half-torn-down state that would break a restart), the analog of the
    # MLLP listen-source's restartability the SCP is modelled on (ADR 0025 §3).
    captured: list[bytes] = []
    scp = _build_scp(captured)
    handler = await _capture_handler_factory(captured)
    for cycle in range(2):
        await scp.start(handler)
        try:
            established, status = await asyncio.to_thread(
                _scu_cstore, scp.sockport, make_sr_part10()
            )
            assert established is True, f"cycle {cycle}: association must establish after restart"
            assert status == 0x0000, f"cycle {cycle}: C-STORE must succeed after restart"
        finally:
            await scp.stop()
        assert scp._server is None, f"cycle {cycle}: stop() must release the server each cycle"
    assert len(captured) == 2, "both start/stop cycles committed their object"


# --- S12 audit anchors (ADDED-2): SCP server-side DICOM-over-TLS floor ---------
# test_dicom_wiring.py already pins the SCU *client* TLS floor; the SCP *server* context — the surface
# that RECEIVES PHI objects from modalities/PACS — had no dedicated floor test. The S12 audit verdict is
# CONFORMING; these pin the server SSLContext invariants (TLS 1.2+ floor + CERT_REQUIRED mTLS) so a
# refactor can't silently weaken the listener's TLS posture. Pure `ssl` — no live association.


def _server_cert(tmp_path: Path) -> tuple[str, str]:
    """A self-signed EC cert (SAN 127.0.0.1, CA:TRUE so it doubles as an mTLS trust anchor) + key PEM."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cp, kp = tmp_path / "scp-c.pem", tmp_path / "scp-k.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cp), str(kp)


def test_scp_tls_off_returns_none() -> None:
    assert _server_ssl_context({"tls": False}) is None


def test_scp_tls_requires_cert() -> None:
    # tls=true without a server identity must fail loud at build (dry-run/check), not at bind.
    with pytest.raises(ValueError, match="tls_cert_file"):
        _server_ssl_context({"tls": True})


def test_scp_tls_floor_is_1_2_no_mtls_by_default(tmp_path: Path) -> None:
    cert, key = _server_cert(tmp_path)
    ctx = _server_ssl_context({"tls": True, "tls_cert_file": cert, "tls_key_file": key})
    assert ctx is not None
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2  # TLS 1.2+ floor (no SSLv3/TLS1.0/1.1)
    # Without a tls_ca_file the SCP does not demand a client cert (server-auth-only DICOM-over-TLS).
    assert ctx.verify_mode == ssl.CERT_NONE


def test_scp_tls_ca_file_requires_client_cert(tmp_path: Path) -> None:
    # Opt-in mTLS: a tls_ca_file makes the SCP REQUIRE + verify a calling peer's client cert.
    cert, key = _server_cert(tmp_path)
    ctx = _server_ssl_context(
        {"tls": True, "tls_cert_file": cert, "tls_key_file": key, "tls_ca_file": cert}
    )
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_REQUIRED  # fail-closed mTLS — an unverified peer is rejected
    assert ctx.minimum_version == ssl.TLSVersion.TLSv1_2


async def test_scp_commit_timeout_returns_out_of_resources_not_success() -> None:
    # A commit that does not land within the per-commit timeout must surface as a DIMSE failure
    # (Out of Resources, 0xA700 — the SCU re-sends), never a false Success and never the
    # decode-failure status (0xC000). This pins the FutureTimeoutError branch of _commit, which is
    # distinct from the commit-*exception* branch covered by
    # test_scp_commit_failure_returns_dimse_failure_not_success above.
    #
    # Build with the default timeout so the AE's acse/dimse/network timeouts stay long (they are set
    # once at _start_server and would otherwise abort the association before the C-STORE reply),
    # then tighten ONLY the per-commit future.result() timeout right before the C-STORE. The handler
    # sleeps well past that tightened timeout so future.result() raises FutureTimeoutError.
    async def slow_handler(data: bytes) -> None:
        await asyncio.sleep(2)  # outlasts the monkeypatched 0.05s commit timeout

    scp = _build_scp([])
    await scp.start(slow_handler)
    try:
        scp._timeout = 0.05  # only future.result(); AE transport timeouts already bound at start
        established, status = await asyncio.to_thread(_scu_cstore, scp.sockport, make_sr_part10())
        assert established is True
        assert (
            status == 0xA700
        )  # Out of Resources — the commit-timeout branch (re-send), not Success
        assert status not in (0x0000, 0xC000), (
            "a commit timeout must be Out of Resources, not Success or Cannot Understand"
        )
    finally:
        await scp.stop()

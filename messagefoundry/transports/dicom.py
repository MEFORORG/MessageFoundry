# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DICOM DIMSE transport (ADR 0025) — the inbound **C-STORE SCP source** (Phase 1) and the outbound
**C-STORE SCU destination** + **C-ECHO** verification (Phase 2).

``DicomScpSource`` runs a ``pynetdicom`` Application Entity (AE) **C-STORE SCP** so modalities/PACS can
*send* image and SR objects to MessageFoundry. ``pynetdicom``'s AE server is **blocking/threaded, not
asyncio-native**, and its C-STORE callback runs on a foreign (acceptor) thread — so the SCP:

* starts/stops the AE server **off the event loop** (``asyncio.to_thread``), so binding/shutdown never
  stalls other listeners/workers/API calls;
* in the C-STORE callback (the foreign thread) re-encodes the received object to its **Part-10 bytes**
  and bridges them back onto the loop-owned ingress via ``asyncio.run_coroutine_threadsafe`` — the same
  loop-bridge pattern as ``db_lookup`` (ADR 0010) — blocking the **worker thread** (never the loop) on
  ``future.result(timeout)``;
* returns C-STORE **Success only after** the object is durably committed (**commit-before-SUCCESS**, the
  DIMSE analog of MLLP's commit-before-ACK; ADR 0001 / count-and-log). The bridged handler is the
  pipeline's ``_handle_inbound``, which — because ``content_type="dicom"`` is a **binary** type — carries
  the bytes as base64 via ``RawMessage.from_bytes`` (ADR 0028, the one encode) and commits them to the
  ingress stage. A codec later recovers them via ``RawMessage.raw_bytes``.

**Timeout-failure policy (protects no-duplicate + count-and-log):** a ``future.result(timeout)`` timeout
returns a DIMSE **failure** (never a false Success — a dropped/uncommitted object must be re-sent); the
already-scheduled commit may still land, so a re-ingest **must be idempotent** (de-dupe on
``SOPInstanceUID`` is a future hardening — for now a re-send may yield a documented duplicate). Any
**post-commit** failure (routing/transform/delivery) is an ``ERROR``/dead-letter disposition, never a
DIMSE failure (the sender was already told Success).

**Security (§9):** the calling-AE allowlist (``require_calling_aet``, association-level) + a peer-IP
allowlist (the ``[inbound].source_ip_allowlist``, checked before any commit) + ``require_called_aet`` +
a ``max_object_bytes`` cap (over-cap → DIMSE failure **before** commit) + DICOM-over-TLS. A non-loopback
cleartext SCP is refused at startup by the generalized bind-guard (see
:func:`messagefoundry.pipeline.wiring_runner.check_dimse_tls_exposure`). All log lines carry only
**routing-safe identifiers** (SOP class/instance UID, calling AE, peer IP) — **never** the dataset or
pixel data (PHI rule, ADR 0025 §1).

``DicomScuDestination`` is the outbound mirror (Phase 2): it **forwards** a DICOM object to a downstream
PACS over a C-STORE association (Mirth-sender parity) and verifies reachability with **C-ECHO**
(``test_connection``). ``pynetdicom``'s association is likewise blocking, so the SCU runs it **off the
event loop** (``asyncio.to_thread``) — the delivery worker awaits ``send``. It recovers the outgoing
object's bytes from the base64 carriage (ADR 0028 ``.raw_bytes``), classifies the C-STORE status onto the
engine's retry model (Out-of-Resources → transient :class:`DeliveryError`; any hard refusal → permanent
:class:`NegativeAckError` → dead-letter), and applies the same PHI-no-log rule (routing-safe identifiers
only). Egress is gated by ``[egress].allowed_tcp`` (a raw socket, like X12). The modern HTTP imaging lane
— the DICOMweb STOW-RS destination — is the sibling :mod:`messagefoundry.transports.dicomweb`.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Callable, Coroutine, Mapping
from concurrent.futures import TimeoutError as FutureTimeoutError
from io import BytesIO
from typing import Any, cast

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.tls_policy import (
    TrustAnchorPolicy,
    build_verifying_client_context,
    harden_kex_groups,
    harden_verify_flags,
    relax_verify_expiry,
    resolve_trust_anchor,
)
from messagefoundry.parsing.binary import BinaryCarriageError
from messagefoundry.parsing.binary import decode as _carriage_decode
from messagefoundry.parsing.dicom._deps import load_dcmread
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    peer_ip_allowed,
    register_destination,
    register_source,
)
from messagefoundry.transports.mllp import InsecureHopGuard

__all__ = ["DicomScpSource", "DicomScuDestination", "DEFAULT_MAX_OBJECT_BYTES"]

logger = logging.getLogger(__name__)

#: Per-object size cap default (bounds what is persisted; pynetdicom buffers the object during receive,
#: which max_associations + max_pdu_size bound). Overridable via DICOM(max_object_bytes=...).
DEFAULT_MAX_OBJECT_BYTES = 128 * 1024 * 1024

# DIMSE C-STORE response statuses (DICOM PS3.4 Annex B). Success commits; the failures below all mean
# "not stored — the SCU should re-send / give up" and never a silent drop.
_STATUS_SUCCESS = 0x0000
_STATUS_OUT_OF_RESOURCES = 0xA700  # over-cap, or a commit timeout/failure (re-send)
_STATUS_CANNOT_UNDERSTAND = 0xC000  # the object would not decode/re-encode
_STATUS_NOT_AUTHORIZED = 0x0124  # peer IP not in the allowlist

#: Loopback bind interfaces that need no peer controls (the common dev/single-box case). Copied (not
#: imported) from :data:`messagefoundry.pipeline.wiring_runner._LOOPBACK_HOSTS` to keep the dependency
#: direction one-way (transports never import pipeline).
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"})


def _server_ssl_context(s: dict[str, Any]) -> ssl.SSLContext | None:
    """Build the SCP's server ``SSLContext`` for DICOM-over-TLS, or ``None`` when ``tls`` is off. Built
    once at construction so a bad cert/key fails at build (dry-run/``check``), not at bind. TLS 1.2+
    floor; ``tls_ca_file`` opts into mTLS (require + verify a calling peer's client cert). Mirrors the
    MLLP inbound TLS posture (ADR 0002).

    ``tls_key_password`` decrypts a passphrase-encrypted private key (``env()``-sourced, mirroring
    MLLP's ``tls_key_password`` / the API listener's ``MEFOR_API_TLS_KEY_PASSWORD``); ``None`` (the
    default) loads an unencrypted key exactly as before."""
    if not s.get("tls"):
        return None
    cert, key, ca = s.get("tls_cert_file"), s.get("tls_key_file"), s.get("tls_ca_file")
    if not cert:
        raise ValueError(
            "DICOM inbound tls=true requires tls_cert_file (the SCP's server identity)"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Pass a deterministic empty-bytes passphrase callback (mirrors mllp.py / api TLS, WP-13b) so an
    # encrypted key with no/wrong passphrase fails fast with ssl.SSLError at build time (surfaced by
    # check/dry-run, ADR-0031 startup fault isolation) instead of blocking on OpenSSL's interactive
    # TTY prompt — there is no TTY under an NSSM service account / in a container. The callback is
    # never invoked for an unencrypted key, so prior behavior is preserved.
    key_password = s.get("tls_key_password")
    pw_arg: bytes | Callable[[], bytes] = (
        key_password if key_password is not None else (lambda: b"")
    )
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key) if key else None, password=pw_arg)
    if ca:  # opt-in mTLS: require + verify a calling peer's client cert against this trust anchor
        ctx.load_verify_locations(cafile=str(ca))
        ctx.verify_mode = ssl.CERT_REQUIRED
    harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
    harden_verify_flags(ctx)  # strict RFC 5280 validation of any mTLS client cert (ASVS 12.1.4)
    return ctx


class DicomScpSource(SourceConnector):
    """Inbound C-STORE SCP (ADR 0025 Phase 1). A **listen** source: it binds its own per-node port
    (``[inbound].bind_host`` + the configured ``port``) and ignores ``leader_gate`` (no shared-resource
    double-read)."""

    def __init__(self, config: Source) -> None:
        s = config.settings
        self._ae_title = str(s["ae_title"])
        # The bind interface is injected from [inbound].bind_host (authors never set a host on an
        # inbound); fall back to loopback — never bind all interfaces by accident (DIMSE has no
        # transport auth without the AE/IP allowlists + TLS).
        self._host = str(s.get("host") or "127.0.0.1")
        self._port = int(s.get("port", 104))
        contexts = s.get("presentation_contexts")
        self._presentation_contexts: list[str] | None = (
            [str(c) for c in contexts] if contexts else None
        )
        allow = s.get("calling_ae_allowlist")
        self._calling_ae_allowlist: list[str] | None = [str(a) for a in allow] if allow else None
        self._require_called_ae_title = bool(s.get("require_called_ae_title", True))
        sa = s.get("source_ip_allowlist")
        self._source_ip_allowlist: list[str] | None = [str(x) for x in sa] if sa else None
        mob = s.get("max_object_bytes", DEFAULT_MAX_OBJECT_BYTES)
        self._max_object_bytes: int | None = int(mob) if mob else None
        self._max_associations = int(s.get("max_associations", 10))
        self._max_pdu_size = int(s.get("max_pdu_size", 16384))
        self._timeout = float(s.get("timeout_seconds", 30.0))
        # Build the TLS context now so a bad cert/key fails at build, not at bind (like MLLP/LDAPS).
        self._ssl = _server_ssl_context(s)
        # Fail-closed peer controls (SEC-012, deny-by-default per ADR 0025 §9): a non-loopback SCP with
        # NO peer authentication is refused at construction. DIMSE has no transport auth on its own, so
        # a remotely-reachable SCP must gate peers by at least one of: the calling-AE allowlist, the
        # [inbound].source_ip_allowlist, or mTLS (tls + tls_ca_file → CERT_REQUIRED in
        # _server_ssl_context). This is the AUTHENTICATION analog of check_dimse_tls_exposure's cleartext
        # bind guard (which is the orthogonal CONFIDENTIALITY guard). Raising here integrates with
        # ADR-0031 startup fault isolation (the connection degrades, not the engine) and surfaces under
        # check/dry-run. Loopback binds (dev/single-box) are exempt.
        mtls_on = bool(s.get("tls")) and bool(s.get("tls_ca_file"))
        if self._host not in _LOOPBACK_HOSTS and not (
            self._calling_ae_allowlist or self._source_ip_allowlist or mtls_on
        ):
            raise ValueError(
                f"DICOM C-STORE SCP bound non-loopback host {self._host!r} with no peer controls: "
                "set at least one of calling_ae_allowlist, [inbound].source_ip_allowlist, or mTLS "
                "(tls_ca_file) to fail closed (egress deny-by-default ethos, ADR 0025 §9), or bind "
                "127.0.0.1."
            )
        self._handler: InboundHandler | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ae: Any = None
        self._server: Any = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        # leader_gate is ignored: a listen source binds its own per-node endpoint, so there is no
        # shared-resource double-read to gate (accepted only so the runner's call is uniform).
        self._handler = handler
        self._loop = asyncio.get_running_loop()  # captured ON the loop, before any off-loop work
        # start_server binds a socket + spawns acceptor threads — do it OFF the loop, then it is live.
        await asyncio.to_thread(self._start_server)

    def _start_server(self) -> None:
        # Imported lazily (the [dicom] extra); a missing extra surfaces as an internal/connection error
        # at start, not a per-message data error — like the FHIR/SQL-Server backends.
        from pynetdicom import AE, StoragePresentationContexts, evt
        from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]  # generated SOP-class const

        ae = AE(ae_title=self._ae_title)
        ae.maximum_associations = self._max_associations
        ae.maximum_pdu_size = self._max_pdu_size
        ae.require_called_aet = self._require_called_ae_title
        if self._calling_ae_allowlist:  # association-level AE-title allowlist (pynetdicom-native)
            ae.require_calling_aet = list(self._calling_ae_allowlist)
        ae.acse_timeout = self._timeout
        ae.dimse_timeout = self._timeout
        ae.network_timeout = self._timeout
        if self._presentation_contexts:
            for uid in self._presentation_contexts:
                ae.add_supported_context(uid)  # default transfer syntaxes (Implicit/Explicit VR)
            ae.add_supported_context(Verification)
        else:
            # Default: accept the standard storage SOP classes (includes the SR classes) + C-ECHO.
            ae.supported_contexts = StoragePresentationContexts
            ae.add_supported_context(Verification)
        handlers: list[Any] = [(evt.EVT_C_STORE, self._on_c_store)]
        self._ae = ae
        self._server = ae.start_server(
            (self._host, self._port),
            block=False,
            ssl_context=self._ssl,
            evt_handlers=handlers,
        )

    @property
    def sockport(self) -> int:
        """The actual bound port (useful when configured with port 0 in tests)."""
        assert self._server is not None
        port: int = self._server.socket.getsockname()[1]
        return port

    def _on_c_store(self, event: Any) -> int:
        """C-STORE callback — runs on a ``pynetdicom`` acceptor thread (NEVER the event loop). Returns a
        DIMSE status int. Any failure is caught and returned as a failure status; it must never raise
        (that would break the association). Logs carry only routing-safe identifiers."""
        try:
            requestor = event.assoc.requestor
            peer_ip = str(getattr(requestor, "address", "") or "")
            calling_ae = str(getattr(requestor, "ae_title", "") or "")
            # Peer-IP allowlist (defense-in-depth alongside the association-level AE-title allowlist):
            # refuse BEFORE any commit so a non-allowlisted peer's object is never stored.
            if self._source_ip_allowlist is not None and not peer_ip_allowed(
                (peer_ip, 0), self._source_ip_allowlist
            ):
                logger.warning(
                    "DICOM C-STORE from %s (AE %r) refused: peer IP not in source_ip_allowlist",
                    peer_ip,
                    calling_ae,
                )
                return _STATUS_NOT_AUTHORIZED
            # Re-encode the received object to its full Part-10 bytes (preamble + DICM + file meta).
            try:
                dataset = event.dataset
                dataset.file_meta = event.file_meta
                buffer = BytesIO()
                dataset.save_as(buffer, enforce_file_format=True)
                object_bytes = buffer.getvalue()
            except Exception as exc:  # noqa: BLE001 - untrusted object; never crash the association
                logger.error(
                    "DICOM C-STORE from %s (AE %r): object could not be decoded/encoded: %s",
                    peer_ip,
                    calling_ae,
                    safe_exc(exc),
                )
                return _STATUS_CANNOT_UNDERSTAND
            sop_instance = str(getattr(dataset, "SOPInstanceUID", "") or "")
            sop_class = str(getattr(dataset, "SOPClassUID", "") or "")
            # Size cap BEFORE the durable commit (the X12 max_interchange_bytes analog) — refuse an
            # over-cap object rather than persist it (count-and-log-safe; the SCU sees the failure).
            if self._max_object_bytes is not None and len(object_bytes) > self._max_object_bytes:
                logger.warning(
                    "DICOM C-STORE from %s (AE %r, SOP %s): object %d bytes over max_object_bytes %d",
                    peer_ip,
                    calling_ae,
                    sop_instance,
                    len(object_bytes),
                    self._max_object_bytes,
                )
                return _STATUS_OUT_OF_RESOURCES
            return self._commit(
                object_bytes, peer_ip=peer_ip, sop_instance=sop_instance, sop_class=sop_class
            )
        except Exception as exc:  # noqa: BLE001 - last-resort: a callback must never raise to pynetdicom
            logger.error("DICOM C-STORE failed unexpectedly: %s", safe_exc(exc))
            return _STATUS_CANNOT_UNDERSTAND

    def _commit(
        self, object_bytes: bytes, *, peer_ip: str, sop_instance: str, sop_class: str
    ) -> int:
        """Bridge the received bytes onto the loop-owned ingress and block THIS thread until durably
        committed (commit-before-SUCCESS). Returns the DIMSE status."""
        loop, handler = self._loop, self._handler
        if loop is None or handler is None:  # not started / already stopped
            return _STATUS_OUT_OF_RESOURCES
        # _handle_inbound is an async def (a Coroutine), but InboundHandler is typed as the broader
        # Awaitable; run_coroutine_threadsafe needs a Coroutine, so narrow it.
        coro = cast("Coroutine[Any, Any, str | None]", handler(object_bytes))
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        try:
            future.result(self._timeout)  # block the worker thread (never the loop) on the commit
        except FutureTimeoutError:
            # The scheduled commit may still land on the loop afterward, so DO NOT report Success — a
            # dropped/uncommitted object must be re-sent. Returning failure after a commit that DID land
            # yields a re-sent duplicate the idempotency rule absorbs (no silent drop). (#future: de-dupe
            # on SOPInstanceUID.)
            logger.error(
                "DICOM C-STORE commit timed out after %.1fs from %s (SOP %s) — returning failure",
                self._timeout,
                peer_ip,
                sop_instance,
            )
            return _STATUS_OUT_OF_RESOURCES
        except Exception as exc:  # noqa: BLE001 - any ingress failure → DIMSE failure (re-send), logged
            logger.error(
                "DICOM C-STORE commit failed from %s (SOP %s): %s",
                peer_ip,
                sop_instance,
                safe_exc(exc),
            )
            return _STATUS_CANNOT_UNDERSTAND
        logger.info(
            "DICOM C-STORE accepted from %s (SOP class %s, instance %s)",
            peer_ip,
            sop_class,
            sop_instance,
        )
        return _STATUS_SUCCESS

    async def stop(self) -> None:
        # Shut the blocking pynetdicom AE server down OFF the loop (it stops accepting new associations,
        # aborts active ones, and joins its threads) so teardown never stalls the loop. Idempotent.
        server = self._server
        if server is not None:
            await asyncio.to_thread(server.shutdown)
            self._server = None
        self._ae = None


def _client_ssl_context(
    s: dict[str, Any], *, trust_anchor_policy: TrustAnchorPolicy | None = None
) -> ssl.SSLContext | None:
    """Build the SCU's **client** ``SSLContext`` for DICOM-over-TLS dialing a downstream PACS, or
    ``None`` when ``tls`` is off. Built via :func:`ssl.create_default_context` (like MLLP/REST) so it
    verifies the peer's server cert (hostname + chain) and — crucially — loads the **system trust
    store** when ``tls_ca_file`` is unset (a bare ``SSLContext(PROTOCOL_TLS_CLIENT)`` would have an empty
    store and reject every cert). ``tls_ca_file`` pins a private trust anchor instead; ``tls_cert_file``/
    ``tls_key_file`` opt into mTLS. Verification is never disabled (a downstream is a PHI egress). TLS
    1.2+ floor. Built once at construction so a bad cert/key fails at build (dry-run/``check``), not at
    the first delivery — the client mirror of :func:`_server_ssl_context`. ``tls_key_password`` decrypts
    a passphrase-encrypted mTLS client key (``env()``-sourced, mirroring MLLP).

    ``trust_anchor_policy`` (#190, ADR 0093) supplies the instance ``[tls]`` internal-CA fallback when
    the connection names no ``tls_ca_file`` of its own: an internal hop verifies against the org internal
    CA per the resolved anchor. ``None`` (a direct test build) keeps the historical
    ``create_default_context(cafile=…)`` behaviour, byte-identical. It only selects WHICH roots verify the
    peer — verification is never disabled — so the internal CA never weakens a refusal."""
    if not s.get("tls"):
        return None
    ca = s.get("tls_ca_file")
    if trust_anchor_policy is not None:
        # #190 (ADR 0093): the connection's own tls_ca_file wins verbatim, else the internal-CA anchor.
        anchor = resolve_trust_anchor(
            connection_ca_file=str(ca) if ca else None,
            host=str(s.get("host", "")),
            policy=trust_anchor_policy,
        )
        ctx = build_verifying_client_context(anchor)
    else:
        # cafile=None → load_default_certs() (the OS trust store); cafile=path → pin that anchor only.
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca) if ca else None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    cert, key = s.get("tls_cert_file"), s.get("tls_key_file")
    if cert:  # opt-in mTLS: present a client cert to the peer SCP
        # Empty-bytes passphrase callback (parity with the SCP server context / mllp.py, WP-13b): an
        # encrypted client key with no/wrong passphrase fails fast with ssl.SSLError at construction
        # (check/dry-run) instead of blocking on OpenSSL's TTY prompt; never invoked for a plain key.
        key_password = s.get("tls_key_password")
        pw_arg: bytes | Callable[[], bytes] = (
            key_password if key_password is not None else (lambda: b"")
        )
        ctx.load_cert_chain(certfile=str(cert), keyfile=str(key) if key else None, password=pw_arg)
    harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
    harden_verify_flags(ctx)  # strict RFC 5280 validation of the peer's server cert (ASVS 12.1.4)
    # #129 (ADR 0094): opt-in granular expiry-only relaxation — honour an expired downstream PACS cert
    # while STILL validating chain + hostname (verification stays ON; default off = byte-identical).
    if s.get("tls_allow_expired"):
        relax_verify_expiry(ctx, host=str(s.get("host", "")))
    return ctx


def recover_dicom_object_bytes(payload: str, *, label: str) -> bytes:
    """Recover the outgoing DICOM object's bytes from the base64 carriage ``payload`` (ADR 0028 §3 — the
    one decode). A non-carriage / corrupt body is a Handler bug, not a transient fault, so it raises a
    **permanent** :class:`NegativeAckError` (a retry would re-send the identical bad body). PHI-safe: it
    names neither the body nor any element value. Shared by the DIMSE SCU and the DICOMweb destinations."""
    try:
        return _carriage_decode(payload)
    except BinaryCarriageError as exc:
        raise NegativeAckError(
            f"{label}: outgoing body is not a base64-carried DICOM object (no retry)",
            code="bad-carriage",
            permanent=True,
        ) from exc


class DicomScuDestination(DestinationConnector):
    """Outbound **C-STORE SCU** (ADR 0025 Phase 2): forward a DICOM object to a downstream PACS over a
    C-STORE association, and verify reachability with **C-ECHO** (``test_connection``). The blocking
    ``pynetdicom`` association runs **off the event loop** (``asyncio.to_thread``); the C-STORE status is
    classified onto the retry model (Out-of-Resources → transient :class:`DeliveryError`; any hard
    refusal → permanent :class:`NegativeAckError` → dead-letter). PHI rule: logs carry only routing-safe
    identifiers (SOP class/instance UID, peer host) — never the dataset or pixel data."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        host = s.get("host")
        if not host:
            raise ValueError(
                "DICOM C-STORE SCU (outbound) requires a 'host' setting (the downstream PACS); "
                "declare it as DICOM(host=..., called_ae_title=...)"
            )
        self._host = str(host)
        self._port = int(s.get("port", 104))
        self._calling_ae_title = str(s["ae_title"])
        called = s.get("called_ae_title")
        # pynetdicom's accept-any token when the peer AE title is left unset.
        self._called_ae_title = str(called) if called else "ANY-SCP"
        mob = s.get("max_object_bytes", DEFAULT_MAX_OBJECT_BYTES)
        self._max_object_bytes: int | None = int(mob) if mob else None
        self._max_pdu_size = int(s.get("max_pdu_size", 16384))
        self._timeout = float(s.get("timeout_seconds", 30.0))
        self._connect_timeout = float(s.get("connect_timeout", 10.0))
        # Build the client TLS context now so a bad cert/key fails at construction (check/dry-run), not
        # at the first delivery (like the SCP / MLLP / REST). #190 (ADR 0093): thread the instance [tls]
        # internal-CA trust-anchor policy so an internal hop that names no tls_ca_file of its own verifies
        # against the org internal CA.
        self._ssl = _client_ssl_context(s, trust_anchor_policy=config.trust_anchor_policy)
        # #200 (ADR 0092): a plaintext DIMSE association (DICOM-over-TLS off) is a cleartext PHI hop —
        # guard it on the posture gradient (a production-PHI hop off-loopback is refused at the enforced
        # construction gate). None when TLS is on: a verified association needs no cleartext guard.
        # tls_hop_attested opts a legitimately-secure hop (trusted segment) back in per-connection.
        self._hop_guard: InsecureHopGuard | None = (
            InsecureHopGuard.capture(
                host=self._host,
                port=self._port,
                cell="DICOM C-STORE SCU",
                description="plaintext DIMSE C-STORE association",
                attested=config.tls_hop_attested,
                attested_reason=config.tls_hop_attested_reason,
            )
            if self._ssl is None
            else None
        )
        if self._hop_guard is not None:
            self._hop_guard.enforce_construction()

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        if self._hop_guard is not None:
            # Zero-I/O byte-crossing backstop (#200) before the association carries any object byte
            # (defense in depth against a reload routing PHI around the construction gate).
            self._hop_guard.assert_send()
        object_bytes = recover_dicom_object_bytes(payload, label="DICOM C-STORE SCU")
        if self._max_object_bytes is not None and len(object_bytes) > self._max_object_bytes:
            # Over the configured cap — a config/Handler issue a retry of the same object won't fix.
            raise NegativeAckError(
                f"DICOM C-STORE object {len(object_bytes)} bytes over max_object_bytes "
                f"{self._max_object_bytes} (no retry)",
                code="over-max-object-bytes",
                permanent=True,
            )
        # The pynetdicom association is blocking — keep it off the event loop (the worker awaits this).
        await asyncio.to_thread(self._c_store, object_bytes)
        return None  # one-way DIMSE delivery (the C-STORE status is the only reply; no body to capture)

    def _build_ae(self) -> Any:
        from pynetdicom import AE

        ae = AE(ae_title=self._calling_ae_title)
        ae.acse_timeout = self._timeout
        ae.dimse_timeout = self._timeout
        ae.network_timeout = self._timeout
        ae.connection_timeout = self._connect_timeout
        return ae

    def _associate(self, ae: Any) -> Any:
        """Open a blocking association to the peer (DICOM-over-TLS when configured). Caller releases it."""
        return ae.associate(
            self._host,
            self._port,
            ae_title=self._called_ae_title,
            max_pdu=self._max_pdu_size,
            tls_args=(self._ssl, self._host) if self._ssl is not None else None,
        )

    def _c_store(self, object_bytes: bytes) -> None:
        """Blocking: parse → associate → C-STORE → classify. Runs on a worker thread (``to_thread``),
        never the loop. ``load_dcmread`` is called first (outside the try) so a missing ``[dicom]`` extra
        surfaces as a deploy ``RuntimeError`` (internal error), not a per-message data ``ERROR``."""
        dcmread = load_dcmread()
        try:
            dataset = dcmread(BytesIO(object_bytes))
            transfer_syntax = dataset.file_meta.TransferSyntaxUID
            sop_class = str(dataset.SOPClassUID)
        except Exception as exc:  # noqa: BLE001 - untrusted/forwarded object; never escape as internal
            raise NegativeAckError(
                "DICOM C-STORE SCU: outgoing object is not a parseable DICOM Part-10 object (no retry)",
                code="bad-object",
                permanent=True,
            ) from exc
        sop_instance = str(getattr(dataset, "SOPInstanceUID", "") or "")
        ae = self._build_ae()
        ae.add_requested_context(sop_class, transfer_syntax)
        assoc = self._associate(ae)
        if not assoc.is_established:
            # A peer that **answered** but accepted no presentation context for this object (rejected the
            # SOP class / transfer syntax — the only one we proposed) is a **deterministic** failure: a
            # retry re-proposes the identical context and is rejected again, so it must dead-letter rather
            # than wedge the FIFO lane forever. A bare connect/abort with no context decision is transient.
            rejected = list(getattr(assoc, "rejected_contexts", []) or [])
            accepted = list(getattr(assoc, "accepted_contexts", []) or [])
            if rejected and not accepted:
                raise NegativeAckError(
                    f"DICOM C-STORE SCU: {self._host}:{self._port} accepted no presentation context for "
                    f"SOP class {sop_class} (peer does not support it)",
                    code="no-accepted-context",
                    permanent=True,
                )
            raise DeliveryError(
                f"DICOM C-STORE SCU could not associate with {self._host}:{self._port} "
                f"(AE {self._called_ae_title!r})"
            )
        try:
            status_ds = assoc.send_c_store(dataset)
        except ValueError as exc:
            # pynetdicom raises ValueError when the peer accepted the association but not a usable context
            # for this object, or when the dataset cannot be encoded for the negotiated transfer syntax —
            # both **deterministic** for the same object+peer, so a retry repeats them. Permanent (no retry)
            # so the lane is never head-blocked. PHI-safe: routing identifiers only, never the dataset.
            raise NegativeAckError(
                f"DICOM C-STORE SCU to {self._host}:{self._port} could not send SOP class {sop_class} "
                "(no accepted context or unencodable dataset)",
                code="cstore-unsendable",
                permanent=True,
            ) from exc
        except Exception as exc:  # noqa: BLE001 - a genuine DIMSE/transport error mid-store is transient
            raise DeliveryError(
                f"DICOM C-STORE SCU to {self._host}:{self._port} failed: {safe_exc(exc)}"
            ) from exc
        finally:
            assoc.release()
        self._classify(status_ds, sop_class=sop_class, sop_instance=sop_instance)

    def _classify(self, status_ds: Any, *, sop_class: str, sop_instance: str) -> None:
        """Map the C-STORE response status onto the retry model. PHI-safe: only the status + routing
        identifiers are logged/raised, never the dataset."""
        status = getattr(status_ds, "Status", None)
        if status is None:
            # An empty status dataset means the association aborted / timed out with no response —
            # transient (the peer may recover); the SCU re-sends.
            raise DeliveryError(
                f"DICOM C-STORE SCU to {self._host}:{self._port} got no response status "
                "(aborted/timeout)"
            )
        code = int(status)
        if code == _STATUS_SUCCESS:
            logger.info(
                "DICOM C-STORE delivered to %s:%s (SOP class %s, instance %s)",
                self._host,
                self._port,
                sop_class,
                sop_instance,
            )
            return
        if 0xB000 <= code <= 0xBFFF:
            # Warning family (coercion of data elements, elements discarded, …): the peer STORED the
            # object — delivered, with a logged caveat.
            logger.warning(
                "DICOM C-STORE to %s:%s stored with warning 0x%04X (SOP instance %s)",
                self._host,
                self._port,
                code,
                sop_instance,
            )
            return
        if 0xA700 <= code <= 0xA7FF:
            # Refused: Out of Resources — the peer is up but momentarily unable. Transient → retry.
            raise DeliveryError(
                f"DICOM C-STORE to {self._host}:{self._port} refused out-of-resources (0x{code:04X})"
            )
        # Any other failure (Cannot Understand 0xCxxx, Dataset-does-not-match-SOP 0xA9xx, Not Authorized
        # 0x0124, SOP-class-not-supported 0x0122, …) is a hard rejection a retry of the identical object
        # won't fix → permanent dead-letter.
        raise NegativeAckError(
            f"DICOM C-STORE to {self._host}:{self._port} rejected with status 0x{code:04X}",
            code=f"0x{code:04X}",
            permanent=True,
        )

    async def test_connection(self) -> None:
        # C-ECHO is DICOM's connectivity ping (the probe_tcp_reachable analog for DIMSE). Blocking — run
        # it off the loop so the API's "Test Connection" never stalls the event loop.
        await asyncio.to_thread(self._c_echo)

    def _c_echo(self) -> None:
        from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]  # generated SOP-class const

        ae = self._build_ae()
        ae.add_requested_context(Verification)
        assoc = self._associate(ae)
        if not assoc.is_established:
            raise DeliveryError(
                f"DICOM C-ECHO could not associate with {self._host}:{self._port} "
                f"(AE {self._called_ae_title!r})"
            )
        try:
            status_ds = assoc.send_c_echo()
        finally:
            assoc.release()
        status = getattr(status_ds, "Status", None)
        if status is None or int(status) != _STATUS_SUCCESS:
            shown = "none" if status is None else f"0x{int(status):04X}"
            raise DeliveryError(
                f"DICOM C-ECHO to {self._host}:{self._port} failed (status {shown})"
            )


register_source(ConnectorType.DIMSE, DicomScpSource)
register_destination(ConnectorType.DIMSE, DicomScuDestination)

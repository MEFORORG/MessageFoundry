# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DICOM DIMSE transport (ADR 0025) — **Phase 1: the inbound C-STORE SCP source**.

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

**Phase 2 (designed, not built):** the outbound C-STORE SCU + C-ECHO destination and the DICOMweb
STOW-RS destination — see ADR 0025.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Callable, Coroutine
from concurrent.futures import TimeoutError as FutureTimeoutError
from io import BytesIO
from typing import Any, cast

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.tls_policy import harden_kex_groups, harden_verify_flags
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.base import (
    InboundHandler,
    SourceConnector,
    peer_ip_allowed,
    register_source,
)

__all__ = ["DicomScpSource", "DEFAULT_MAX_OBJECT_BYTES"]

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


def _server_ssl_context(s: dict[str, Any]) -> ssl.SSLContext | None:
    """Build the SCP's server ``SSLContext`` for DICOM-over-TLS, or ``None`` when ``tls`` is off. Built
    once at construction so a bad cert/key fails at build (dry-run/``check``), not at bind. TLS 1.2+
    floor; ``tls_ca_file`` opts into mTLS (require + verify a calling peer's client cert). Mirrors the
    MLLP inbound TLS posture (ADR 0002)."""
    if not s.get("tls"):
        return None
    cert, key, ca = s.get("tls_cert_file"), s.get("tls_key_file"), s.get("tls_ca_file")
    if not cert:
        raise ValueError(
            "DICOM inbound tls=true requires tls_cert_file (the SCP's server identity)"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key) if key else None)
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


register_source(ConnectorType.DIMSE, DicomScpSource)

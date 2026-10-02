# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
  pipeline's **receipt** handler (the one the HTTP listener uses), which — because
  ``content_type="dicom"`` is a **binary** type — carries the bytes as base64 via
  ``RawMessage.from_bytes`` (ADR 0028, the one encode), commits them to the ingress stage, and returns
  the committed message id. A codec later recovers them via ``RawMessage.raw_bytes``. When the handler
  instead refuses the object (it records ``ERROR`` and commits no ingress row), it returns ``None`` and
  the SCP answers a DIMSE **failure**: Success for an object the engine did not accept is
  accept-and-drop (BACKLOG #1910).

**Timeout-failure policy (protects no-duplicate + count-and-log):** a ``future.result(timeout)`` timeout
returns a DIMSE **failure** (never a false Success — a dropped/uncommitted object must be re-sent); the
already-scheduled commit may still land, so a re-ingest **must be idempotent** (de-dupe on
``SOPInstanceUID`` is a future hardening — for now a re-send may yield a documented duplicate). Any
**post-commit** failure (routing/transform/delivery) is an ``ERROR``/dead-letter disposition, never a
DIMSE failure (the sender was already told Success). A **pre-commit** refusal by the handler is the
opposite case: nothing was committed, so the sender is told.

**Security (§9):** the calling-AE allowlist (``require_calling_aet``, association-level) + a peer-IP
allowlist (the per-connection ``source_ip_allowlist`` passed to ``inbound(...)`` — there is no
``[inbound].source_ip_allowlist`` service key — applied when the connection is accepted, before
anything is read from it; see :func:`_admitting_server_class`) + ``require_called_aet`` +
a ``max_object_bytes`` cap (charged against the **raw received Data Set, before it is decoded**, so an
over-cap object is refused before any decode, re-encode or commit) + an **opt-in association-rate
bound** (``max_associations_per_second``, ASVS 2.4.1 / BACKLOG #1114 — off by default, waits before the
association request is read, and never drops or refuses; see :meth:`DicomScpSource._pace_association`
for why the unit is an association and not a message) + DICOM-over-TLS, whose inbound handshake is
bounded and runs off the accept loop. A non-loopback
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
import contextlib
import functools
import logging
import socket
import socketserver
import ssl
import threading
import time
from collections.abc import Callable, Coroutine, Mapping
from concurrent.futures import TimeoutError as FutureTimeoutError
from io import BytesIO
from typing import Any, ClassVar, cast

from messagefoundry.auth.trust_anchors import inbound_ca_cadata, refuse_an_unread_ca_pin
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.tls_policy import (
    TrustAnchorPolicy,
    apply_connection_tls_ciphers,
    build_verifying_client_context,
    current_hop_posture,
    harden_cipher_suites,
    harden_crl_check,
    harden_kex_groups,
    harden_verify_flags,
    relax_verify_expiry,
    resolve_trust_anchor,
)
from messagefoundry.keywrap import load_connection_cert_chain
from messagefoundry.parsing.binary import BinaryCarriageError
from messagefoundry.parsing.binary import decode as _carriage_decode
from messagefoundry.parsing.dicom import _inflate as _dicom_inflate
from messagefoundry.parsing.dicom._deps import load_dcmread, load_header_readers
from messagefoundry.parsing.dicom._inflate import (
    DEFLATED_EXPLICIT_VR_LE,
    bounded_inflate_or_error,
    guard_part10_deflate,
)
from messagefoundry.parsing.dicom.errors import DicomBombError
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    peer_ip_allowed,
    positive_cap,
    register_destination,
    register_source,
)
from messagefoundry.transports.mllp import (
    _TLS_HANDSHAKE_TIMEOUT,
    DEFAULT_MAX_CONNECTIONS,
    DEFAULT_MAX_CONNECTIONS_PER_HOST,
    InsecureHopGuard,
    _MessagePacer,
)

__all__ = [
    "DicomScpSource",
    "DicomScuDestination",
    "DEFAULT_MAX_OBJECT_BYTES",
    "DEFAULT_MAX_ASSOCIATIONS_PER_SECOND",
]

logger = logging.getLogger(__name__)

#: Per-object size cap default: it bounds what is persisted, and — charged against the raw received Data
#: Set before decode (see DicomScpSource._raw_over_cap) — what one received object costs in memory.
#: max_pdu_size bounds a fragment, NOT the object: pynetdicom accumulates every fragment of an incoming
#: object with no ceiling of its own. Overridable via DICOM(max_object_bytes=...).
#:
#: **The SCP never honours more than** :data:`_ENGINE_INGRESS_CEILING_BYTES`, whatever is configured
#: here (BACKLOG #1910). This default still reaches the outbound SCU unchanged.
DEFAULT_MAX_OBJECT_BYTES = 128 * 1024 * 1024

#: The largest object the engine's binary ingress will commit. The pipeline records anything larger as
#: ``ERROR`` and commits no ingress row, so an SCP that accepted one would answer Success for an object
#: the engine never processes. The SCP's effective cap is therefore ``min(max_object_bytes, this)``,
#: and an uncapped SCP (``0``/``None``) is capped here. The value mirrors
#: ``messagefoundry.pipeline.ingress_guards.INGRESS_MAX_BYTES``; it is read from ``parsing.peek`` rather
#: than imported from the pipeline because transports never import pipeline, and a test pins the two
#: equal.
_ENGINE_INGRESS_CEILING_BYTES = DEFAULT_MAX_MESSAGE_BYTES

#: Association-rate pacing for the SCP ships OFF, for exactly the reason
#: :data:`messagefoundry.transports.mllp.DEFAULT_MAX_MESSAGES_PER_SECOND` ships off (ruled 2026-08-11,
#: ASVS 2.4.1 / 15.2.2): this control makes a real peer WAIT, and a number this project guessed would
#: throttle a real modality — a worse failure than the unbounded intake it guards. The operator brings
#: their own number. The cell stays `partial` on the shipped default and the record says why.
DEFAULT_MAX_ASSOCIATIONS_PER_SECOND: float | None = None

# DIMSE C-STORE response statuses (DICOM PS3.4 Annex B, Table B.2-1). Success commits; every failure
# means "not stored" and is never a silent drop. The CLASS is what tells a sender whether to re-send
# (BACKLOG #2103). PS3.4 has no "too large" status. Out of Resources (A7xx) says the SCP cannot take
# the object NOW, and senders, this engine's own SCU among them, retry it. Cannot Understand (Cxxx)
# says the SCP will not take this object at all, and senders treat it as final. So a refusal that
# would repeat on a re-send answers Cxxx, and only a failure that may clear answers A7xx. Which path
# answers which is stated once, in docs/DICOM.md section 3.
_STATUS_SUCCESS = 0x0000
_STATUS_OUT_OF_RESOURCES = 0xA700  # transient: the commit may succeed on a re-send
_STATUS_CANNOT_UNDERSTAND = 0xC000  # final: this object will not be taken as sent
#: Final, and the same class as Cannot Understand: the object is over the SCP's object cap or inflates
#: past its inflate bound. Both limits are fixed, so a re-send is refused again. The low byte, which
#: PS3.4 leaves to the SCP, tells this refusal apart from a decode failure in a sender's log. It stays
#: clear of the C-STORE codes pynetdicom answers on its own: 0xC001 and 0xC002 for a malformed handler
#: status, and 0xC211 when the handler raises.
_STATUS_REFUSED_OVER_CAP = 0xC010
_STATUS_NOT_AUTHORIZED = 0x0124  # peer IP not in the allowlist: the backstop in _on_c_store

# A-ASSOCIATE-RJ fields for "busy, retry later" (DICOM PS3.8 section 9.3.4), sent while the engine's
# intake is paused (BACKLOG #290): rejected-transient, from the service provider's presentation
# function, for temporary congestion. pynetdicom uses the same result and source, with reason 0x02
# (local limit exceeded), when ``maximum_associations`` is full.
_RJ_RESULT_TRANSIENT = 0x02
_RJ_SOURCE_PRESENTATION = 0x03
_RJ_REASON_TEMPORARY_CONGESTION = 0x01

#: Loopback bind interfaces that need no peer controls (the common dev/single-box case). Copied (not
#: imported) from :data:`messagefoundry.pipeline.wiring_runner._LOOPBACK_HOSTS` to keep the dependency
#: direction one-way (transports never import pipeline).
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"})

#: A refused peer address earns one WARNING per this many seconds, however often it is refused
#: (vault BACKLOG #2583). A refused connection costs the peer nothing, so a line per refusal would let
#: a peer the allowlist turns away fill the service log. See :meth:`DicomScpSource._log_refused_peer`.
_REFUSAL_LOG_WINDOW_SECONDS = 60.0

#: How often a pending inbound TLS handshake looks at whether the listener is stopping. It is a poll
#: interval, not a bound: the bound is ``_TLS_HANDSHAKE_TIMEOUT``, the MLLP listener's constant,
#: imported so the two listeners cannot drift apart. pynetdicom polls its own sockets at 0.5 s too.
_HANDSHAKE_POLL_SECONDS = 0.5

#: Connections that may be inside their inbound TLS handshake at once: on one SCP, and from one peer
#: address. The handshake runs on the connection's own thread, so these are what bound how many such
#: threads exist. A connection over either is closed before a thread is started. They are the MLLP
#: listener's two shipped connection caps, read from it so the numbers cannot drift apart; its
#: constants say why 256 and why an eighth of it. Here they count a connection only while it is in
#: its handshake. Constants, not settings, for the reason ``_TLS_HANDSHAKE_TIMEOUT`` gives. A
#: handshake takes milliseconds, so senders that share one address behind a NAT do not meet the
#: per-address number in normal use.
_MAX_PENDING_HANDSHAKES = DEFAULT_MAX_CONNECTIONS
_MAX_PENDING_HANDSHAKES_PER_HOST = DEFAULT_MAX_CONNECTIONS_PER_HOST

#: The most refusal lines one SCP writes per window over every address together. The per-address
#: bound alone would still let many addresses earn a line each.
_REFUSAL_LOG_MAX_PER_WINDOW = 20


#: Why the allowlist refuses a peer. One wording for the accept gate and for the C-STORE backstop.
_NOT_IN_ALLOWLIST = "peer IP not in source_ip_allowlist"


def _address_host(client_address: Any) -> str:
    """The host part of a socket peer address, as ``accept()`` returns it. ``"?"`` when there is none."""
    if isinstance(client_address, tuple) and client_address:
        return str(client_address[0])
    return "?"


def _require_socketserver_routing(stock: type[Any]) -> None:
    """Refuse a pynetdicom whose threaded server no longer routes an accepted connection through the
    ``socketserver`` hooks :func:`_admitting_server_class` overrides.

    With a server that drove its own accept loop, the overrides would still be defined and would
    never be called: the address check and the handshake bound would lapse with nothing to show
    for it. So the SCP does not start on one. The pydicom deflate guard refuses a pydicom that
    renamed a reader for the same reason (``parsing.dicom._deps.load_header_readers``)."""
    routed = (
        issubclass(stock, socketserver.ThreadingMixIn)
        and issubclass(stock, socketserver.TCPServer)
        and stock.serve_forever is socketserver.BaseServer.serve_forever
        and stock.verify_request is socketserver.BaseServer.verify_request
        and stock.process_request is socketserver.ThreadingMixIn.process_request
        # The private method serve_forever calls for each connection, and the one that calls
        # get_request, verify_request and process_request in that order.
        and getattr(stock, "_handle_request_noblock", None)
        is getattr(socketserver.BaseServer, "_handle_request_noblock", None)
    )
    if not routed:
        raise RuntimeError(
            "the installed pynetdicom does not route an accepted connection through the socketserver "
            "hooks the DICOM server (SCP) applies its address allowlist and its handshake bound in; "
            "refusing to start the SCP with it"
        )


@functools.cache
def _admitting_server_class() -> type[Any]:
    """The association server the SCP runs: pynetdicom's threaded server with its admission steps
    moved ahead of the first read (vault BACKLOG #2583). Built on first use, because pynetdicom is the
    optional ``[dicom]`` extra and is never imported at module top.

    **Read against pynetdicom 3.0.4 and CPython's ``socketserver``; re-read both before raising the
    pynetdicom cap in the ``[dicom]`` extra.** ``pyproject.toml`` holds that cap at the release line
    this was read against, so a newer pynetdicom is stopped at install time; the comment above the
    extra there gives the bound and the steps to raise it. :func:`_require_socketserver_routing`
    refuses a pynetdicom that left this routing, and ``tests/test_dicom_scp_admission.py`` pins the
    rest.

    * ``AssociationServer.get_request`` accepts a connection and, on a TLS listener, runs the TLS
      handshake in the same call. That call is on the accept loop, and the accepted socket has no
      timeout, so one peer that connects and sends nothing would hold every other sender's handshake
      for as long as it stayed connected. ``get_request`` here only accepts.
    * ``socketserver`` calls ``verify_request`` on the accept loop, straight after ``get_request``
      and before any thread is started, and closes the connection when it returns ``False``. That is
      where the peer address is checked, so a peer outside ``source_ip_allowlist`` is closed before
      an association thread exists for it and before a byte is read from it.
    * ``ThreadingMixIn.process_request`` starts the connection's thread, still on the accept loop.
      On a TLS listener the connection takes a handshake slot first, counted per listener and per
      peer address against :data:`_MAX_PENDING_HANDSHAKES` and
      :data:`_MAX_PENDING_HANDSHAKES_PER_HOST`. One over either is closed with no thread started.
    * ``ThreadedAssociationServer.process_request_thread`` runs on the connection's own thread. The
      handshake runs there, against a deadline of ``_TLS_HANDSHAKE_TIMEOUT`` for the whole handshake.
      A peer that sends nothing, and one that sends its handshake slowly, are both dropped at it.
      The slot is given back in a ``finally`` there, however the handshake ends.
    * ``AE.start_server`` cannot start this class: its non-blocking branch names
      ``ThreadedAssociationServer`` itself. ``AE.make_server`` takes ``server_class`` and passes extra
      keywords to its constructor, and ``start_serving`` here does the rest of what that branch does.
    """
    from pynetdicom.transport import ThreadedAssociationServer
    from pynetdicom.utils import make_target

    _require_socketserver_routing(ThreadedAssociationServer)

    class _AdmittingAssociationServer(ThreadedAssociationServer):
        def __init__(
            self,
            *args: Any,
            admit: Callable[[Any], bool],
            refused: Callable[[str, str, str], None],
            stopping: threading.Event,
            **kwargs: Any,
        ) -> None:
            self._admit = admit
            self._refused = refused
            #: The SCP's own stop signal, set before it calls shutdown(). shutdown() joins every
            #: connection thread, so a thread inside a handshake has to see this to end early.
            self._stopping = stopping
            #: Handshakes in flight per peer address. Its values sum to the listener's total.
            self._pending: dict[str, int] = {}
            self._pending_lock = threading.Lock()
            #: When the next admission-check fault may be logged (monotonic). See verify_request.
            self._gate_fault_log_after = 0.0
            super().__init__(*args, **kwargs)

        def start_serving(self) -> None:
            """What ``AE.start_server(block=False)`` does once it has built its server: run the
            accept loop on a daemon thread and record the server on the AE. The base ``shutdown()``
            removes the server from that list, and raises if it is not there."""
            threading.Thread(
                target=make_target(self.serve_forever),
                name=f"AcceptorServer@{self.ae_title}",
                daemon=True,
            ).start()
            self.ae._servers.append(self)

        def get_request(self) -> tuple[socket.socket, Any]:
            return cast(socket.socket, self.socket).accept()

        def verify_request(self, request: Any, client_address: Any) -> bool:
            # On the accept loop. An exception here would end serve_forever, and with it the
            # listener, so anything the check raises is a refusal.
            try:
                return self._admit(client_address)
            except Exception as exc:  # noqa: BLE001 - fail closed, and keep the accept loop alive
                now = time.monotonic()
                if now >= self._gate_fault_log_after:
                    # Once per window: this state refuses every connection, and a line for each
                    # would be a way to fill the log. The line is best effort; the refusal is not.
                    self._gate_fault_log_after = now + _REFUSAL_LOG_WINDOW_SECONDS
                    with contextlib.suppress(Exception):
                        logger.error(
                            "DICOM server (SCP) %s: the admission check itself failed (%s). "
                            "Connections it cannot check are refused. This is logged at most "
                            "once every %gs.",
                            self.ae_title,
                            safe_exc(exc),
                            _REFUSAL_LOG_WINDOW_SECONDS,
                        )
                return False

        def process_request(self, request: Any, client_address: Any) -> None:
            # On the accept loop, for a connection verify_request admitted. A TLS connection takes
            # its handshake slot here, so one over a cap is closed before a thread exists for it.
            if self.ssl_context is None:
                super().process_request(request, client_address)
                return
            host = _address_host(client_address)
            full = self._take_handshake_slot(host)
            if full is not None:
                try:
                    self._refused(host, "a connection", full)
                finally:
                    self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self._release_handshake_slot(host)  # no thread was started to give it back
                raise

        def process_request_thread(self, request: Any, client_address: Any) -> None:
            context = self.ssl_context
            if context is not None:
                host = _address_host(client_address)
                try:
                    request = self._handshake(context, request, host)
                finally:
                    self._release_handshake_slot(host)
                if request is None:
                    return
            super().process_request_thread(request, client_address)

        def _take_handshake_slot(self, host: str) -> str | None:
            """Count one more handshake in flight for ``host``. Returns ``None`` when the slot is
            taken, else the reason there is none, and then nothing was counted."""
            with self._pending_lock:
                if sum(self._pending.values()) >= _MAX_PENDING_HANDSHAKES:
                    return f"{_MAX_PENDING_HANDSHAKES} TLS handshakes are already in progress"
                held = self._pending.get(host, 0)
                if held >= _MAX_PENDING_HANDSHAKES_PER_HOST:
                    return (
                        f"{_MAX_PENDING_HANDSHAKES_PER_HOST} TLS handshakes from this address "
                        "are already in progress"
                    )
                self._pending[host] = held + 1
                return None

        def _release_handshake_slot(self, host: str) -> None:
            with self._pending_lock:
                held = self._pending[host] - 1
                if held:
                    self._pending[host] = held
                else:
                    del self._pending[host]  # so the table holds only addresses in a handshake

        def _handshake(
            self, context: ssl.SSLContext, plain: socket.socket, host: str
        ) -> ssl.SSLSocket | None:
            """Run the server side of the TLS handshake within the bound. Returns the TLS socket
            with the accepted socket's own timeout restored, or ``None`` after closing the connection.

            The handshake runs in slices of :data:`_HANDSHAKE_POLL_SECONDS`, so that a stop is
            noticed without closing a socket under the thread that is reading it. A slice that ends
            with nothing to read raises a ``TimeoutError`` that carries no ``errno`` and leaves the
            SSL object as it was, which is the state a non-blocking handshake is resumed from, so
            the next slice resumes it. A ``TimeoutError`` that does carry one is the connection
            itself timing out, and ends the handshake.

            A handshake that fails is logged at DEBUG only. A peer can fail one as often as it can
            connect, so a line at a higher level would be a way to fill the log."""
            tls: ssl.SSLSocket | None = None
            try:
                restore = plain.gettimeout()  # None: accept() returns a blocking socket
                # No I/O: without do_handshake_on_connect this only builds the SSL object.
                tls = context.wrap_socket(plain, server_side=True, do_handshake_on_connect=False)
                deadline = time.monotonic() + _TLS_HANDSHAKE_TIMEOUT
                while True:
                    if self._stopping.is_set():
                        raise OSError("the listener is stopping")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("the handshake did not finish within its bound")
                    tls.settimeout(min(remaining, _HANDSHAKE_POLL_SECONDS))
                    try:
                        tls.do_handshake()
                    except TimeoutError as exc:
                        if exc.errno is not None:
                            raise
                        continue
                    break
                if self._stopping.is_set():  # finished after the stop began: refuse it unread
                    raise OSError("the listener is stopping")
                tls.settimeout(restore)
                return tls
            except (OSError, ValueError) as exc:  # ssl.SSLError and a timeout are both OSError
                logger.debug(
                    "TLS handshake with DICOM peer %s did not complete (bound %gs): %s",
                    host,
                    _TLS_HANDSHAKE_TIMEOUT,
                    safe_exc(exc),
                )
            with contextlib.suppress(OSError):
                (plain if tls is None else tls).close()
            return None

    return _AdmittingAssociationServer


def _server_ssl_context(s: dict[str, Any], *, name: str = "") -> ssl.SSLContext | None:
    """Build the SCP's server ``SSLContext`` for DICOM-over-TLS, or ``None`` when ``tls`` is off. Built
    once at construction so a bad cert/key fails at build (dry-run/``check``), not at bind. TLS 1.2+
    floor; ``tls_ca_file`` opts into mTLS (require + verify a calling peer's client cert). Mirrors the
    MLLP inbound TLS posture (ADR 0002).

    ``tls_key_password`` decrypts a passphrase-encrypted private key (``env()``-sourced, mirroring
    MLLP's ``tls_key_password`` / the API listener's ``MEFOR_API_TLS_KEY_PASSWORD``); ``None`` (the
    default) loads an unencrypted key exactly as before.

    ``name`` is the connection's, for the inbound CA's messages and audit label (BACKLOG #1142)."""
    refuse_an_unread_ca_pin(s, inbound=True, connector="DICOM listener")
    if not s.get("tls"):
        return None
    cert, key, ca = s.get("tls_cert_file"), s.get("tls_key_file"), s.get("tls_ca_file")
    if not cert:
        raise ValueError(
            "DICOM inbound tls=true requires tls_cert_file (the SCP's server identity)"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # The key's wrap is checked first (BACKLOG #1352, #1171): a weak wrap, or an encrypted key with no
    # passphrase, fails fast at build time (surfaced by check/dry-run, ADR-0031 startup fault
    # isolation) instead of blocking on OpenSSL's interactive TTY prompt -- there is no TTY under an
    # NSSM service account / in a container. A wrong passphrase still fails as ssl.SSLError, and the
    # empty-bytes callback stays behind the check as the backstop (mirrors mllp.py / api TLS, WP-13b).
    load_connection_cert_chain(ctx, cert, key, s.get("tls_key_password"))
    if ca:  # opt-in mTLS: require + verify a calling peer's client cert against this trust anchor
        # BACKLOG #1142, slice 3: the CA's pin, ACL, path and PEM checks, then the bytes they read,
        # never a second read of the file. This CA is the SCP's whole peer authentication decision
        # (the CONNECTIONS.md DICOM section), so a swapped file would admit any peer. Outside the
        # construction gate the check enforces, as mllp.py's does.
        posture = current_hop_posture()
        cadata = inbound_ca_cadata(name, s, enforcing=posture is None or posture.enforcing)
        ctx.load_verify_locations(cadata=cadata)
        ctx.verify_mode = ssl.CERT_REQUIRED
        # Opt-in revocation (#1005), after the CA load and inside the mTLS branch -- see mllp.py.
        # An HTTP proxy can terminate neither DIMSE nor MLLP, so for this listener the documented
        # out-of-engine delegation does not reach and there is no workaround.
        if crl := s.get("tls_crl_file"):
            harden_crl_check(ctx, str(crl))
    harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
    # Narrow first, assert last, both spelled here -- do NOT fold them into one call; see
    # apply_connection_tls_ciphers. Unset (the default) narrows to the approved AEAD suites
    # (BACKLOG #300, the ADR 0188 amendment); set, to the operator's validated string.
    apply_connection_tls_ciphers(ctx, s, connector="DICOM listener")  # opt-in per-hop suite list
    harden_cipher_suites(ctx, connector="DICOM listener")  # assert forward secrecy (ASVS 12.1.2)
    harden_verify_flags(ctx)  # strict RFC 5280 validation of any mTLS client cert (ASVS 12.1.4)
    return ctx


#: The end of the SCP's refusal for a ``max_object_bytes`` that is not above zero (BACKLOG #2103). The
#: shared default tells the operator to "use None or 0 to disable it", which is false on the SCP:
#: either value resolves to the ingress ceiling. Following that advice would leave the SCP at 16 MiB
#: while the operator believed it uncapped.
_SCP_OBJECT_CAP_OFF_HINT = (
    "None or 0 does not disable the SCP's object cap: either one resolves to the engine's binary "
    f"ingress ceiling of {_ENGINE_INGRESS_CEILING_BYTES} bytes, and no setting raises the cap above it"
)


class DicomScpSource(SourceConnector):
    """Inbound C-STORE SCP (ADR 0025 Phase 1). A **listen** source: it binds its own per-node port
    (``[inbound].bind_host`` + the configured ``port``) and ignores ``leader_gate`` (no shared-resource
    double-read)."""

    #: The C-STORE status must tell a committed object from a refused one, and only the receipt
    #: handler's ``None`` means "refused" (BACKLOG #1910). See :attr:`SourceConnector.wants_receipt`.
    wants_receipt: ClassVar[bool] = True

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
        # BACKLOG #1910: never accept an object the engine's ingress would refuse. The shipped 128 MiB
        # default, and an uncapped SCP, both resolve to the ingress ceiling.
        # None/0 in any spelling reads as uncapped, so a string "0" can no longer reach the inflate
        # bound below as a live zero that refuses every deflated object (BACKLOG #1872).
        configured = positive_cap(
            s.get("max_object_bytes", DEFAULT_MAX_OBJECT_BYTES),
            int,
            knob="max_object_bytes",
            transport="DICOM-SCP source",
            off_hint=_SCP_OBJECT_CAP_OFF_HINT,
        )
        self._max_object_bytes: int = min(
            configured or _ENGINE_INGRESS_CEILING_BYTES, _ENGINE_INGRESS_CEILING_BYTES
        )
        self._max_associations = int(s.get("max_associations", 10))
        self._max_pdu_size = int(s.get("max_pdu_size", 16384))
        self._timeout = float(s.get("timeout_seconds", 30.0))
        # Association-rate pacing (ASVS 2.4.1 / 15.2.2, BACKLOG #1114). The keys are NOT
        # max_messages_per_second/message_burst and are not read through mllp._pacing_settings, because
        # the UNIT here is an association, not a message — see _pace_association for why a message-rate
        # bound is the one thing this transport cannot honestly offer. The OFF-default semantics are
        # still shared: _MessagePacer.for_rate is the single place "unset" is interpreted, so this
        # connector cannot drift from the other four on what an absent key means.
        self.max_associations_per_second: float | None = positive_cap(
            s.get("max_associations_per_second", DEFAULT_MAX_ASSOCIATIONS_PER_SECOND),
            float,
            knob="max_associations_per_second",
            transport="DICOM-SCP source",
        )
        burst = positive_cap(
            s.get("association_burst"),
            float,
            knob="association_burst",
            transport="DICOM-SCP source",
        )
        self.association_burst: float = float(burst or self.max_associations_per_second or 0.0)
        self._pacer = _MessagePacer.for_rate(
            self.max_associations_per_second, self.association_burst
        )
        #: The pacer is driven from N concurrent pynetdicom association threads, so THIS consumer
        #: supplies the mutual exclusion. Its read-modify-write of the token bucket is not atomic, and
        #: the four intakes that came before all drive it from the single-threaded event loop, so it
        #: never needed a lock of its own. Never held across the wait.
        self._pacer_lock = threading.Lock()
        #: Set by stop() so a paced connection's wait is cut short instead of holding up shutdown.
        self._stopping = threading.Event()
        #: Whether this pause's first refused association was logged (BACKLOG #290). Written from
        #: association threads without a lock: a race costs at most one extra INFO line.
        self._pause_refusal_logged = False
        #: Refusal lines written inside the current window, as address -> when; see
        #: _log_refused_peer. The accept loop and the association threads both reach it, so it has
        #: a lock.
        self._refusal_logged: dict[str, float] = {}
        self._refusal_log_lock = threading.Lock()
        #: Every refusal since this SCP was built, logged or not. Each line that is written reports it.
        self._refusals = 0
        # Build the TLS context now so a bad cert/key fails at build, not at bind (like MLLP/LDAPS).
        self._ssl = _server_ssl_context(s, name=config.name or "")
        # Fail-closed peer controls (SEC-012, deny-by-default; tightened by BACKLOG #316):
        # a non-loopback SCP with no VERIFIABLE peer control is refused at construction. DIMSE has no
        # transport auth of its own, so a remotely-reachable SCP must gate peers by the per-connection
        # source_ip_allowlist (an inbound(...) keyword — NOT an [inbound] service-settings key, which does
        # not exist and is discarded silently) or mTLS (tls + tls_ca_file → CERT_REQUIRED in
        # _server_ssl_context). This is the AUTHENTICATION analog of check_dimse_tls_exposure's cleartext
        # bind guard (the orthogonal CONFIDENTIALITY guard). Raising here integrates with ADR-0031 startup
        # fault isolation (the connection degrades, not the engine) and surfaces under check/dry-run.
        # Loopback binds (dev/single-box) are exempt.
        #
        # calling_ae_allowlist deliberately does NOT satisfy this gate on its own. The original rule
        # counted the three controls as co-equal, but a Calling AE Title is a string the caller asserts
        # about ITSELF in the association request — no key, no signature, nothing to verify, and AE Titles
        # are published in conformance statements and visible in any capture. An SCP whose only control
        # was an AE-title list was reachable by anyone who could route to it and knew one string, while
        # passing a check named "fail-closed peer controls". It remains a useful FILTER (it catches a
        # misrouted sender and pins intent) and is still enforced at association time — it just has to be
        # PAIRED with a control that can actually be verified.
        mtls_on = bool(s.get("tls")) and bool(s.get("tls_ca_file"))
        if self._host not in _LOOPBACK_HOSTS and not (self._source_ip_allowlist or mtls_on):
            unpaired = (
                " You set calling_ae_allowlist, but an AE Title is asserted by the caller and cannot be"
                " verified, so it no longer satisfies this gate alone (BACKLOG #316) — keep it as a"
                " filter and add one of the two controls above."
                if self._calling_ae_allowlist
                else ""
            )
            raise ValueError(
                f"DICOM C-STORE server (SCP) bound non-loopback host {self._host!r} with no verifiable peer "
                "control: set source_ip_allowlist, or mTLS (tls + tls_ca_file), to fail closed "
                f"(deny-by-default, ADR 0025 §9), or bind 127.0.0.1.{unpaired} Authoring surface: pass "
                'them to inbound(...), e.g. inbound("pacs_in", DICOM(...), '
                'source_ip_allowlist=["10.0.0.0/8"]). That is the ONLY surface for a DICOM server (SCP) — the '
                "[inbound] section of messagefoundry.toml has no source_ip_allowlist key and discards it "
                "silently, and while connections.toml [[inbound]] tables do accept the key, none of "
                "their transports is DICOM."
            )
        self._handler: InboundHandler | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._ae: Any = None
        self._server: Any = None
        # BACKLOG #1962: say so when an operator's own setting is clamped. It runs after the last
        # refusal above, so a connection that never builds logs nothing about its limits. The factory
        # always passes the shipped default, so that value cannot be told from an explicit one. It
        # stays silent, because a warning on every default SCP would teach operators to ignore this.
        if configured != self._max_object_bytes and configured != DEFAULT_MAX_OBJECT_BYTES:
            logger.warning(
                "DICOM server (SCP) %r: max_object_bytes %s is above the engine's binary ingress ceiling of "
                "%d bytes, so the SCP refuses any larger object; the deflate inflate bound is %d bytes",
                config.name or "",
                "uncapped" if configured is None else configured,
                self._max_object_bytes,
                self._max_inflated_bytes,
            )

    @property
    def _max_inflated_bytes(self) -> int:
        """The pre-decode inflate bound: the lesser of the object cap and the codec's inflate ceiling
        (BACKLOG #2104). The ingress ceiling behind ``_max_object_bytes`` measures the re-encoded bytes,
        which stay deflated, so it cannot stand in for this bound. But ``DicomPeek`` and
        ``DicomDataset`` refuse any object that inflates past the codec's ceiling when the router parses
        it after commit, so an SCP that let one through would answer Success for an object recorded
        ``ERROR``. The ceiling is read from its module on each call, as ``guard_part10_deflate`` reads
        it, so the two cannot drift apart."""
        return min(self._max_object_bytes, _dicom_inflate.DEFAULT_MAX_INFLATED_BYTES)

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        # leader_gate is ignored: a listen source binds its own per-node endpoint, so there is no
        # shared-resource double-read to gate (accepted only so the runner's call is uniform).
        self._handler = handler
        self._stopping.clear()  # a restart must not inherit the previous stop's cut-short signal
        self._loop = asyncio.get_running_loop()  # captured ON the loop, before any off-loop work
        # start_server binds a socket + spawns acceptor threads — do it OFF the loop, then it is live.
        await asyncio.to_thread(self._start_server)

    def _start_server(self) -> None:
        # Imported lazily (the [dicom] extra); a missing extra surfaces as an internal/connection error
        # at start, not a per-message data error — like the FHIR/SQL-Server backends.
        from pynetdicom import AE, StoragePresentationContexts, evt
        from pynetdicom.sop_class import (  # type: ignore[attr-defined]
            Verification,  # generated SOP-class const
        )

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
        handlers: list[Any] = [
            (evt.EVT_C_STORE, self._on_c_store),
            # BACKLOG #290: the engine-wide intake pause, at the association level. Always bound,
            # because the runner injects a gate into every source; the handler reads
            # `intake_gate` live and returns at once when there is none or it is open.
            (evt.EVT_REQUESTED, self._refuse_association_while_paused),
        ]
        if self._pacer is not None:
            # Registered ONLY when a rate is configured, so an unpaced SCP — the shipped default —
            # pays for no pacing callback on its association path.
            handlers.append((evt.EVT_CONN_OPEN, self._pace_association))
            handlers.append((evt.EVT_ACCEPTED, self._charge_association))
        # AE.start_server(block=False) names pynetdicom's own server class, so build the SCP's
        # class through make_server, which binds, and let it start its accept loop.
        # Any: make_server is typed for pynetdicom's own classes, and start_serving is not theirs.
        server: Any = ae.make_server(
            (self._host, self._port),
            ssl_context=self._ssl,
            evt_handlers=handlers,
            server_class=_admitting_server_class(),
            admit=self._admit_connection,
            refused=self._log_refused_peer,
            stopping=self._stopping,
        )
        server.start_serving()
        self._ae = ae
        self._server = server

    @property
    def sockport(self) -> int:
        """The actual bound port (useful when configured with port 0 in tests)."""
        assert self._server is not None
        port: int = self._server.socket.getsockname()[1]
        return port

    def _admit_connection(self, client_address: Any) -> bool:
        """Whether a connection the listener has just accepted may go on (vault BACKLOG #2583).

        Runs on the accept loop, through ``verify_request`` of :func:`_admitting_server_class`, before
        any thread is started for the connection and before anything is read from it. ``False``
        closes the connection. So a peer outside ``source_ip_allowlist`` never reaches the TLS
        handshake and never gets an association, so it sends the SCP no object.

        The match is :func:`~messagefoundry.netaddr.peer_ip_allowed`, the one the other listeners
        use, so an entry means the same thing here as on an MLLP listener. No allowlist admits
        everyone, as it does there. A check that raises is a refusal.

        The calling AE title is not part of this: it is not known until the association request is
        read. ``calling_ae_allowlist`` is applied at that point, by pynetdicom, from
        ``require_calling_aet``, and an unlisted title is rejected before any object is sent.
        """
        reason = _NOT_IN_ALLOWLIST
        try:
            if peer_ip_allowed(client_address, self._source_ip_allowlist):
                return True
        except Exception as exc:  # noqa: BLE001 - on the accept loop: fail closed, never raise
            reason = f"the source_ip_allowlist check failed ({safe_exc(exc)})"
        self._log_refused_peer(_address_host(client_address), "a connection", reason)
        return False

    def _log_refused_peer(self, peer_ip: str, what: str, reason: str) -> None:
        """Log a refusal for ``peer_ip``, at most once per address per window.

        A refused connection is free to the peer, so it can be repeated as fast as the peer can
        connect, and the service's output is captured to files. One line per refusal would turn the
        refusal into a way to fill that volume. So an address earns one WARNING per
        :data:`_REFUSAL_LOG_WINDOW_SECONDS`, and every address together earns at most
        :data:`_REFUSAL_LOG_MAX_PER_WINDOW`.

        Each line carries the SCP's running count of refusals, logged or not, so the volume
        behind a quiet log is visible in the next line that is written. It is a total for the
        listener, not for the address the line names.

        The table holds an entry only for a line written inside the current window, so it never
        holds more than :data:`_REFUSAL_LOG_MAX_PER_WINDOW` addresses, whatever arrives. The MLLP
        listener's once-per-episode line is not reusable here: it is tied to that listener's table
        of live connections per host, and its episode ends when the host has none left. A refused
        peer never holds a connection, so it has no episode to end.
        """
        now = time.monotonic()
        with self._refusal_log_lock:
            self._refusals += 1
            total = self._refusals
            logged = self._refusal_logged
            cutoff = now - _REFUSAL_LOG_WINDOW_SECONDS
            for aged in [address for address, at in logged.items() if at <= cutoff]:
                del logged[aged]
            if peer_ip in logged or len(logged) >= _REFUSAL_LOG_MAX_PER_WINDOW:
                return
            logged[peer_ip] = now
        logger.warning(
            "DICOM server (SCP) %s refused %s from %s: %s. An address is logged at most once every "
            "%gs. %d refused in all since this server started.",
            self._ae_title,
            what,
            peer_ip,
            reason,
            _REFUSAL_LOG_WINDOW_SECONDS,
            total,
        )

    def _pace_association(self, event: Any) -> None:
        """Wait off whatever the association budget owes, BEFORE this connection is read from.

        ASVS 2.4.1 / 15.2.2, BACKLOG #1114. This is the one intake where the pace-before-decode
        property does **not** transfer to a message-rate bound, and that is why the unit here is an
        association. ``pynetdicom`` owns the read loop: by the time ``EVT_C_STORE`` fires, the object
        has already been read off the wire and decoded, so a wait there would delay a message the
        count-and-log invariant has already obliged us to account for — the same control with none of
        the property that makes it honest. ``EVT_CONN_OPEN`` is before the A-ASSOCIATE-RQ is read, so
        the excess is genuinely never taken in.

        **Measured, because a limiter that serialises the acceptor IS the denial of service it
        guards against** (pynetdicom 3.0.4, this connector's pinned version): ``EVT_CONN_OPEN`` runs
        on a per-connection thread, not on the accept loop. Three concurrent connections each blocking
        1.0 s here completed in 1.04 s total, at ``maximum_associations`` 10 and again at 1. So the
        wait delays only its own peer, never the loop and never a sibling.

        **Nothing is dropped, refused or answered differently.** The peer is back-pressured by TCP
        while we decline to read, then its association proceeds in full. The delay is bounded by the
        deficit (``associations / rate``) rather than being a hard stop, for the reason
        :class:`~messagefoundry.transports.mllp._MessagePacer` gives: refusing to read at all would pin
        capacity indefinitely.

        **Residual, stated because a knob that hides one is worse than no knob.** The waiting
        connection is already counted against ``max_associations``, so a rate low enough to make waits
        long needs a ``max_associations`` high enough to hold the peers waiting behind it — and a wait
        that outlasts the SCU's own ACSE timeout becomes an abort on the sender's side, which is a
        refusal this control is otherwise careful never to make. That is the DIMSE form of the general
        residual: a bound that demands a number cannot demand a sensible one.
        """
        pacer = self._pacer
        if pacer is None:  # pragma: no cover - the handler is only registered when one exists
            return
        # Released BEFORE the wait below. Held across it, one peer sleeping off its own debt would
        # block every other association's read of the bucket, which serialises the acceptor and turns
        # this knob into the denial of service it guards against.
        with self._pacer_lock:
            wait = pacer.deficit(now=time.monotonic())
        if wait > 0.0:
            # Event.wait, not sleep: stop() sets it, so shutdown is not held up by an outstanding debt.
            self._stopping.wait(wait)

    def _refuse_association_while_paused(self, event: Any) -> None:
        """Refuse a NEW association while the engine-wide intake gate is held (BACKLOG #290).

        Runs on the association's own thread, on ``EVT_REQUESTED``: the A-ASSOCIATE-RQ has been read
        and nothing else. No object has been sent, so there is nothing to count, commit or drop. The
        answer is A-ASSOCIATE-RJ with result *rejected-transient*, source *service provider
        (presentation)* and reason *temporary congestion*: the DICOM UL's "busy, retry later"
        (PS3.8 section 9.3.4). A sender reads it as a retryable refusal, not a configuration error.

        **Why refuse rather than wait.** The SCP could wait on ``EVT_CONN_OPEN``, before the request
        is read, the way :meth:`_pace_association` does. That wait is bounded by a rate deficit. A
        pause has no such bound: it lasts until the backlog drains or disk is freed. Waiting that long
        would hold a ``max_associations`` slot per sender, and would outlast the sender's own
        association timeout, which then drops the connection with no reason given. The rejection
        says what happened, at once.

        **A peer the association checks would refuse gets that refusal instead.** An unlisted calling
        AE or a wrong called AE is left to pynetdicom, which refuses it permanently right after this
        handler, reading the same ``AE`` settings this does. So the pause neither tells such a peer to
        retry nor reveals to it that intake is paused. ``source_ip_allowlist`` needs no mirror here:
        the SCP applies it when the connection is accepted (:meth:`_admit_connection`), so a peer
        outside it is closed before it can send an association request.

        **An association already accepted is left alone.** It finishes normally, and every C-STORE on
        it is still committed before its Success status. The pause is checked only here, so it never
        lands between receiving an object and committing it.

        This mirrors pynetdicom's own rejection path in ``ACSE._negotiate_as_acceptor``: send the RJ,
        fire ``EVT_REJECTED``, then ``kill()``, which waits for the DUL to finish sending it. It fails
        closed: pynetdicom swallows an exception from this handler and would then negotiate as normal,
        so any fault once the gate reads closed falls back to an abort. The gate is read from this
        foreign thread without a lock. That read is a single truth test of a set the loop owns, so at
        worst it sees a pause or a resume one check late.
        """
        gate = self.intake_gate
        if gate is None or gate.is_open:
            # Reset by the first association to arrive while intake is open, so a pause that follows
            # one with no association between them logs no second INFO line. The DEBUG line still does.
            self._pause_refusal_logged = False
            return
        assoc = event.assoc
        peer_ip = "?"
        try:
            peer_ip = str(getattr(assoc.requestor, "address", "") or "")
            request = assoc.requestor.primitive
            calling_ae = str(request.calling_ae_title or "").strip()
            ae = assoc.ae
            allowed = [a.strip() for a in ae.require_calling_aet]
            if (allowed and calling_ae not in allowed) or (
                ae.require_called_aet
                and str(request.called_ae_title or "").strip() != assoc.acceptor.ae_title.strip()
            ):
                return  # pynetdicom refuses it permanently next, as it does outside a pause
            if not self._pause_refusal_logged:
                # Once per pause, not per refusal: a sender retrying in a loop must not fill the log.
                self._pause_refusal_logged = True
                logger.info(
                    "DICOM server (SCP) %s refusing new associations as busy while engine intake is paused "
                    "(first: %s, AE %r); associations already open continue",
                    self._ae_title,
                    peer_ip,
                    calling_ae,
                )
            logger.debug(
                "DICOM association from %s (AE %r) refused: engine intake is paused",
                peer_ip,
                calling_ae,
            )
            from pynetdicom import evt

            assoc.acse.send_reject(
                _RJ_RESULT_TRANSIENT, _RJ_SOURCE_PRESENTATION, _RJ_REASON_TEMPORARY_CONGESTION
            )
            evt.trigger(assoc, evt.EVT_REJECTED, {})
        except Exception as exc:  # noqa: BLE001 - never let a failed refusal become an accept
            logger.error(
                "DICOM association from %s could not be refused while paused (%s); aborting it",
                peer_ip,
                safe_exc(exc),
            )
            assoc.abort()
        assoc.kill()

    def _charge_association(self, event: Any) -> None:
        """Charge one token once an association is ACCEPTED — the debt is paid by the next arrival.

        Charging at acceptance rather than at connection open is deliberate and mirrors the HTTP
        listener: a connection that is rejected (an unlisted calling AE, no acceptable presentation
        context) or that opens and never associates charges nothing. Charging earlier would let a peer
        that submits no object spend a real modality's budget, which turns the limiter into the denial
        of service it exists to prevent.
        """
        pacer = self._pacer
        if pacer is None:  # pragma: no cover - the handler is only registered when one exists
            return
        with self._pacer_lock:
            pacer.charge(1, now=time.monotonic())

    def _on_c_store(self, event: Any) -> int:
        """C-STORE callback — runs on a ``pynetdicom`` acceptor thread (NEVER the event loop). Returns a
        DIMSE status int. Any failure is caught and returned as a failure status; it must never raise
        (that would break the association). Logs carry only routing-safe identifiers."""
        try:
            requestor = event.assoc.requestor
            peer_ip = str(getattr(requestor, "address", "") or "")
            calling_ae = str(getattr(requestor, "ae_title", "") or "")
            # The peer-IP allowlist, a second time. _admit_connection applies it when the connection
            # is accepted, so a peer outside it should never reach this callback. That gate rides on
            # hooks in pynetdicom's server class, and this check does not: if the gate were ever not
            # run, a non-allowlisted peer's object would still be refused BEFORE any commit.
            if not peer_ip_allowed((peer_ip, 0), self._source_ip_allowlist):
                # Not through the per-address throttle: this is an object the SCP received and
                # refused, and every one of those is logged.
                logger.warning(
                    "DICOM C-STORE from %s (AE %r) refused: %s",
                    peer_ip,
                    calling_ae,
                    _NOT_IN_ALLOWLIST,
                )
                return _STATUS_NOT_AUTHORIZED
            # BACKLOG #1727: charge max_object_bytes against the RAW received Data Set FIRST. The
            # post-encode check below fires only after event.dataset has copied and decoded the whole
            # buffer and save_as has re-encoded it, so an over-cap object would be held several times
            # over before the cap refused it. This also bounds the raw bytes the deflate guard copies.
            raw_over_cap = self._raw_over_cap(event, peer_ip=peer_ip, calling_ae=calling_ae)
            if raw_over_cap is not None:
                return raw_over_cap
            # ASVS 5.2.3 (the network-facing SCP): when the negotiated presentation context is Deflated
            # Explicit VR LE, pynetdicom would inflate the received Data Set UNBOUNDED the instant we
            # touch event.dataset, and the raw-length charge above bounds only the COMPRESSED bytes, which
            # say nothing about how far they inflate. Pre-check the inflate in bounded memory over the RAW
            # event.request.DataSet bytes BEFORE event.dataset — an over-cap deflate bomb is a DIMSE
            # failure (never committed, never decoded). The bound is _max_inflated_bytes (BACKLOG #2104).
            deflate_bomb = self._deflated_over_cap(event, peer_ip=peer_ip, calling_ae=calling_ae)
            if deflate_bomb is not None:
                return deflate_bomb
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
            # Second charge, on the re-encoded Part-10 bytes the store would hold — the raw-length charge
            # above cannot see what the preamble, DICM and file meta add. Still BEFORE the durable commit
            # (the X12 max_interchange_bytes analog): refuse an over-cap object rather than persist it
            # (count-and-log-safe; the SCU sees the failure).
            if len(object_bytes) > self._max_object_bytes:
                logger.warning(
                    "DICOM C-STORE from %s (AE %r, SOP %s): object %d bytes over the SCP object cap %d",
                    peer_ip,
                    calling_ae,
                    sop_instance,
                    len(object_bytes),
                    self._max_object_bytes,
                )
                return _STATUS_REFUSED_OVER_CAP
            return self._commit(
                object_bytes, peer_ip=peer_ip, sop_instance=sop_instance, sop_class=sop_class
            )
        except Exception as exc:  # noqa: BLE001 - last-resort: a callback must never raise to pynetdicom
            logger.error("DICOM C-STORE failed unexpectedly: %s", safe_exc(exc))
            return _STATUS_CANNOT_UNDERSTAND

    def _raw_over_cap(self, event: Any, *, peer_ip: str, calling_ae: str) -> int | None:
        """Charge ``max_object_bytes`` against the RAW ``event.request.DataSet`` length BEFORE
        ``event.dataset`` decodes it, returning a DIMSE **failure** status for an over-cap object — else
        ``None`` (proceed). The re-encode below writes these same Data Set bytes with a preamble, ``DICM``
        and file meta in front, so a raw length over the cap means an over-cap Part-10 object. Reads the
        length through ``getbuffer()``, which does not copy (unlike ``getvalue()``). PHI-safe: logs the cap
        + routing identifiers, never bytes."""
        data_set = getattr(getattr(event, "request", None), "DataSet", None)
        if data_set is None:
            return None  # nothing received; the normal decode path handles an empty request
        with data_set.getbuffer() as raw:
            raw_bytes: int = raw.nbytes
        if raw_bytes <= self._max_object_bytes:
            return None
        logger.warning(
            "DICOM C-STORE from %s (AE %r): raw data set %d bytes over the SCP object cap %d — "
            "refusing before decode",
            peer_ip,
            calling_ae,
            raw_bytes,
            self._max_object_bytes,
        )
        return _STATUS_REFUSED_OVER_CAP

    def _deflated_over_cap(self, event: Any, *, peer_ip: str, calling_ae: str) -> int | None:
        """ASVS 5.2.3 SCP guard. When the accepted context's transfer syntax is Deflated Explicit VR LE,
        bound-inflate the RAW ``event.request.DataSet`` bytes (BEFORE ``event.dataset`` decodes them) and
        return a DIMSE **failure** status if the object inflates past the cap — else ``None`` (proceed).
        The bound is the lesser of the SCP's ``max_object_bytes`` and the codec's 16 MiB inflate ceiling
        (BACKLOG #2104), because the router's parse refuses anything that inflates further. PHI-safe:
        logs the cap + routing identifiers, never bytes."""
        transfer_syntax = str(getattr(getattr(event, "context", None), "transfer_syntax", "") or "")
        if transfer_syntax != DEFLATED_EXPLICIT_VR_LE:
            return None
        request = getattr(event, "request", None)
        data_set = getattr(request, "DataSet", None)
        if data_set is None:
            return None  # nothing to inflate; the normal decode path handles an empty request
        cap = self._max_inflated_bytes
        try:
            bounded_inflate_or_error(data_set.getvalue(), max_bytes=cap)
        except DicomBombError:
            logger.warning(
                "DICOM C-STORE from %s (AE %r): deflated object inflates past cap %d bytes — "
                "refusing before decode",
                peer_ip,
                calling_ae,
                cap,
            )
            return _STATUS_REFUSED_OVER_CAP
        return None

    def _commit(
        self, object_bytes: bytes, *, peer_ip: str, sop_instance: str, sop_class: str
    ) -> int:
        """Bridge the received bytes onto the loop-owned ingress and block THIS thread until durably
        committed (commit-before-SUCCESS). Returns the DIMSE status.

        The handler returns the committed message id, or ``None`` when it refused the object: it then
        recorded ``ERROR`` and committed no ingress row. That refusal is a DIMSE failure, never Success
        (BACKLOG #1910). It is Cannot Understand, the status the decode-failure path already answers for
        an object the engine will not take, rather than the Out of Resources a commit timeout answers:
        the refusal is deterministic, so the same object would be refused again on a re-send. A handler
        that RAISES, or does not answer in time, has committed nothing for a reason that may clear, such
        as a store that is down, so both answer Out of Resources and the sender re-sends (BACKLOG
        #2103)."""
        loop, handler = self._loop, self._handler
        if loop is None or handler is None:  # never started
            return _STATUS_OUT_OF_RESOURCES
        if loop.is_closed() or not loop.is_running():
            # The engine's loop has stopped under a live association. A callback scheduled now would
            # never run, and this thread would wait out timeout_seconds for nothing. Nothing was
            # committed and a re-send after a restart would be, so answer Out of Resources at once
            # (BACKLOG #2103).
            logger.error(
                "DICOM C-STORE from %s (SOP %s): the engine loop is not running",
                peer_ip,
                sop_instance,
            )
            return _STATUS_OUT_OF_RESOURCES
        # The runner's receipt handler is an async def (a Coroutine), but InboundHandler is typed as the
        # Awaitable; run_coroutine_threadsafe needs a Coroutine, so narrow it.
        coro = cast("Coroutine[Any, Any, str | None]", handler(object_bytes))
        try:
            future = asyncio.run_coroutine_threadsafe(coro, loop)
        except RuntimeError as exc:
            # The loop closed between the check above and this call. Same answer, same reason.
            coro.close()  # never scheduled; close it so it is not reported as never awaited
            logger.error(
                "DICOM C-STORE from %s (SOP %s): the engine loop is not running: %s",
                peer_ip,
                sop_instance,
                safe_exc(exc),
            )
            return _STATUS_OUT_OF_RESOURCES
        try:
            receipt = future.result(self._timeout)  # block the worker thread (never the loop)
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
            return _STATUS_OUT_OF_RESOURCES
        if receipt is None:
            logger.warning(
                "DICOM C-STORE refused by engine ingress from %s (SOP %s): recorded ERROR, "
                "returning failure",
                peer_ip,
                sop_instance,
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
        # Release any association thread parked on the pacing wait FIRST, so shutdown never waits out
        # a rate debt (BACKLOG #1114). A no-op when pacing is off, and idempotent.
        self._stopping.set()
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
    refuse_an_unread_ca_pin(s, inbound=False, connector="DICOM destination")
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
        # Parity with the SCP server context above: the wrap is checked, then loaded with the
        # empty-bytes callback as the backstop, so no client key reaches OpenSSL's TTY prompt.
        load_connection_cert_chain(ctx, cert, key, s.get("tls_key_password"))
    harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
    # See the SCP listener above: narrow first (ADR 0188), assert second, both visible here.
    apply_connection_tls_ciphers(ctx, s, connector="DICOM destination")  # opt-in per-hop suite list
    harden_cipher_suites(ctx, connector="DICOM destination")  # assert forward secrecy (ASVS 12.1.2)
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
                "DICOM C-STORE client (SCU, outbound) requires a 'host' setting (the downstream PACS); "
                "declare it as DICOM(host=..., called_ae_title=...)"
            )
        self._host = str(host)
        self._port = int(s.get("port", 104))
        self._calling_ae_title = str(s["ae_title"])
        called = s.get("called_ae_title")
        # pynetdicom's accept-any token when the peer AE title is left unset.
        self._called_ae_title = str(called) if called else "ANY-SCP"
        self._max_object_bytes: int | None = positive_cap(
            s.get("max_object_bytes", DEFAULT_MAX_OBJECT_BYTES),
            int,
            knob="max_object_bytes",
            transport="DICOM-SCU destination",
        )
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
                # Not "C-STORE SCU": the log redaction scrubs two adjacent ALL-CAPS tokens, and that
                # label reached the log as "DICOM C-[redacted]".
                cell="DICOM C-STORE client (SCU)",
                description="plaintext DIMSE C-STORE association",
                attested=config.tls_hop_attested,
                attested_reason=config.tls_hop_attested_reason,
                # ADR 0153: `cleartext_accepted` crosses this hop with a loud, audited WARN. Unlike
                # Tcp()/X12() it is TRANSITIONAL here — DICOM() supports tls=true, so the declaration
                # should end when the peer does.
                cleartext_accepted=config.cleartext_accepted,
                cleartext_reason=config.cleartext_reason,
                connection=config.name,
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
        object_bytes = recover_dicom_object_bytes(payload, label="DICOM C-STORE client (SCU)")
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
        surfaces as a deploy ``RuntimeError`` (internal error), not a per-message data ``ERROR``.

        ASVS 5.2.3 (SCU side): a **deflated** Part-10 file-drop passes the File source's DICM-magic-only
        sniff and reaches this ``dcmread`` unparsed, where it would inflate UNBOUNDED — so bound the
        inflate here too, ahead of ``dcmread``. (The network-facing SCP has its own guard over the
        negotiated transfer syntax in ``_on_c_store``.) A deflate bomb is a permanent dead-letter (a retry
        re-sends the identical bad object)."""
        dcmread = load_dcmread()
        # Also outside the try, for the same reason: a pydicom without the readers the guard replays is
        # a deploy error, and the broad except below must not turn it into a per-message bad-object.
        load_header_readers()
        try:
            guard_part10_deflate(object_bytes, force=False, max_bytes=self._max_object_bytes)
        except DicomBombError as exc:
            raise NegativeAckError(
                "DICOM C-STORE client (SCU): outgoing deflated object inflates past the max-object cap "
                "(no retry)",
                code="deflate-bomb",
                permanent=True,
            ) from exc
        except Exception as exc:  # noqa: BLE001 - the guard replays dcmread's header read; same verdict
            raise NegativeAckError(
                "DICOM C-STORE client (SCU): outgoing object is not a parseable DICOM Part-10 object (no retry)",
                code="bad-object",
                permanent=True,
            ) from exc
        try:
            dataset = dcmread(BytesIO(object_bytes))
            transfer_syntax = dataset.file_meta.TransferSyntaxUID
            sop_class = str(dataset.SOPClassUID)
        except Exception as exc:  # noqa: BLE001 - untrusted/forwarded object; never escape as internal
            raise NegativeAckError(
                "DICOM C-STORE client (SCU): outgoing object is not a parseable DICOM Part-10 object (no retry)",
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
                    f"DICOM C-STORE client (SCU): {self._host}:{self._port} accepted no presentation context for "
                    f"SOP class {sop_class} (peer does not support it)",
                    code="no-accepted-context",
                    permanent=True,
                )
            raise DeliveryError(
                f"DICOM C-STORE client (SCU) could not associate with {self._host}:{self._port} "
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
                f"DICOM C-STORE client (SCU) to {self._host}:{self._port} could not send SOP class {sop_class} "
                "(no accepted context or unencodable dataset)",
                code="cstore-unsendable",
                permanent=True,
            ) from exc
        except Exception as exc:  # noqa: BLE001 - a genuine DIMSE/transport error mid-store is transient
            raise DeliveryError(
                f"DICOM C-STORE client (SCU) to {self._host}:{self._port} failed: {safe_exc(exc)}"
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
                f"DICOM C-STORE client (SCU) to {self._host}:{self._port} got no response status "
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
        from pynetdicom.sop_class import (  # type: ignore[attr-defined]
            Verification,  # generated SOP-class const
        )

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

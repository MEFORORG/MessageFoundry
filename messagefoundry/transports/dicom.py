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
association request is read, and the wait itself never drops or refuses; see :meth:`DicomScpSource._pace_association`
for why the unit is an association and not a message) + DICOM-over-TLS, whose inbound handshake is
bounded and runs off the accept loop + a cap and a deadline on connections with no association yet
(see :func:`_admitting_server_class`). A non-loopback
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
    EXPIRY_RELAXED_WAYS_ACROSS,
    RevocationHopGuard,
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
    skips_validity_period,
)
from messagefoundry.keywrap import load_connection_cert_chain
from messagefoundry.netaddr import (
    ALLOWLIST_MIN_PREFIX_V4,
    ALLOWLIST_MIN_PREFIX_V6,
    allowlist_restricts,
)
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
from messagefoundry.tls_handshake_failures import HUNG_UP, HandshakeFailures, handshake_cause
from messagefoundry.transports.admission import (
    REFUSAL_LOG_MAX_PER_WINDOW,
    REFUSAL_LOG_WINDOW_SECONDS,
    RefusalLog,
)
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    count_setting,
    float_setting,
    peer_ip_allowed,
    port_setting,
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
from messagefoundry.transports.receipt import (
    IngressReceipt,
    ReceiptHandler,
    RefusalKind,
    require_receipt,
)

__all__ = [
    "DicomScpSource",
    "DicomScuDestination",
    "DEFAULT_MAX_OBJECT_BYTES",
    "DEFAULT_MAX_ASSOCIATIONS_PER_SECOND",
]

logger = logging.getLogger(__name__)

#: Per-object size cap default: it bounds what is persisted, and what is decoded, because it is charged
#: against the raw received Data Set before decode (see DicomScpSource._raw_over_cap). It does not
#: bound what one received object costs in memory on its own: pynetdicom holds every fragment of an
#: object until its last one arrives, and only then does the cap refuse it. What bounds that memory on
#: the SCP is ``_ReceiptTally``, which ends the association once an object passes twice the SCP's
#: effective cap (owner ruling B462-R3, vault BACKLOG #2712). max_pdu_size is the fragment size the
#: SCP offers, NOT a bound on the object; the SCP refuses a PDU longer than it.
#: Overridable via DICOM(max_object_bytes=...).
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
#: The throttle is the one the socket listeners share (vault BACKLOG #2606), at its defaults.
_REFUSAL_LOG_WINDOW_SECONDS = REFUSAL_LOG_WINDOW_SECONDS

#: How often a pending inbound TLS handshake, and a read of a PDU, look at whether the listener is
#: stopping. It is a poll interval, not a bound. The handshake's bound is
#: ``_TLS_HANDSHAKE_TIMEOUT``, the MLLP listener's constant, imported so the two listeners cannot drift
#: apart. A PDU's is ``timeout_seconds``. pynetdicom polls its own sockets at 0.5 s too.
_STOP_POLL_SECONDS = 0.5

#: Connections that may have no association yet, at once: on one SCP, and from one peer address. A
#: connection counts from accept until its association has started: through the TLS handshake, any
#: association-rate wait, and the read of its association request. All of that runs on the
#: connection's own thread, so these are what bound how many such threads exist. A connection over
#: either is closed before a thread is started. They are the MLLP listener's two shipped connection
#: caps, read from it so the numbers cannot drift apart; its constants say why 256 and why an eighth
#: of it. Here they count a connection only until its association starts, and from then on
#: ``max_associations`` counts it. Constants, not settings, for the reason
#: ``_TLS_HANDSHAKE_TIMEOUT`` gives. An SCU sends its request as soon as it connects, so senders that
#: share one address behind a NAT do not meet the per-address number in normal use.
_MAX_PENDING_CONNECTIONS = DEFAULT_MAX_CONNECTIONS
_MAX_PENDING_CONNECTIONS_PER_HOST = DEFAULT_MAX_CONNECTIONS_PER_HOST

#: The fixed head of every DICOM PDU (PS3.8 section 9.3): type, a reserved byte, a 4-byte length.
_PDU_HEADER_BYTES = 6
#: The PDU type of an A-ASSOCIATE-RQ, the only PDU a peer may open with (PS3.8 section 9.2).
_PDU_TYPE_ASSOCIATE_RQ = 0x01
#: The protocol version bit an A-ASSOCIATE-RQ must set (PS3.8 section 9.3.2). Each bit of the field
#: names one version, and a receiver that implements only version 1 tests only bit 0, so a request
#: that also sets other bits is a version-1 request.
_PROTOCOL_VERSION = 0x0001
#: Where that two-byte field sits in an A-ASSOCIATE-RQ, header included (PS3.8 Table 9-11).
_PROTOCOL_VERSION_OFFSET = 6
#: The PDU type of a P-DATA-TF, the PDU that carries the fragments of a DIMSE message (PS3.8 section
#: 9.3.5). Its declared length is the length of its variable field, which is what ``max_pdu_size``
#: bounds (PS3.8 Annex D.1).
_PDU_TYPE_P_DATA_TF = 0x04
#: The PDU types PS3.8 defines. pynetdicom reads the body of each of these. A PDU of any other type
#: it answers as an invalid PDU without reading its body.
_PDU_TYPES = frozenset(range(0x01, 0x08))

#: The most the SCP reads for one association request. PS3.8 sets no limit, and the PDU's length field
#: can announce 4 GiB. A request names at most 128 presentation contexts, since their IDs are odd
#: numbers in one byte. At 64-byte UIDs and 20 transfer syntaxes each, which is a choice here and not
#: a limit in the standard, that is about 190 KiB, so this leaves room for the user information
#: items. A larger request is legal in the format and is closed. Each connection this reads for is
#: capped, so the memory it can hold is bounded too. This also bounds the decode, which is not cheap:
#: pynetdicom's decoder runs twice on a request that passes, and it logs for each UID it dislikes.
_MAX_ASSOCIATE_RQ_BYTES = 256 * 1024

#: The A-ASSOCIATE-RJ (result, source, diagnostic) the SCP answers a whole request it decoded and
#: refuses before the association starts (PS3.8 section 9.3.4). Both are rejected-permanent, because
#: the same request is refused again. One with the wrong protocol version is the ACSE's "protocol
#: version not supported", the answer pynetdicom's DUL gives it. One the association could not
#: negotiate is the service user's, with no reason given, the answer pynetdicom gives a rejection of
#: its own. A request that does not decode is an invalid PDU, so it gets the A-ABORT the DUL's state
#: table gives one in Sta2 (Evt19, AA-1), with source and reason 0, as pynetdicom sends it.
_RJ_WRONG_PROTOCOL = (0x01, 0x02, 0x02)
_RJ_DOES_NOT_NEGOTIATE = (0x01, 0x01, 0x01)

#: The A-ABORT (source, reason) the SCP sends when it ends a started association itself (PS3.8
#: section 9.3.8). A PDU longer than the SCP takes is the service provider's invalid PDU parameter
#: value. A P-DATA-TF whose items or message pynetdicom would fail on gets what pynetdicom's own
#: AA-8 sends an invalid PDU: the service provider, no reason. An object past twice the object cap,
#: and a command set past its bound, are the SCP's own limits, so the source is the service user,
#: with no reason, as pynetdicom's own ``Association.abort()`` sends.
_ABORT_PDU_TOO_LONG = (0x02, 0x06)
_ABORT_INVALID_MESSAGE = (0x02, 0x00)
_ABORT_OVER_LIMIT = (0x00, 0x00)

#: The most of one DIMSE message's command set the SCP takes. pynetdicom holds a command set's
#: fragments until the message is complete, as it holds a data set's. A real one is a few hundred
#: bytes: it names a SOP class and instance and a few small fields. Past this the association is
#: ended, as an object past twice its cap is.
_MAX_COMMAND_SET_BYTES = 64 * 1024

#: The longest a send of an answer the SCP writes itself may take: an A-ASSOCIATE-RJ or A-ABORT from
#: the connection's thread before an association starts, and an A-ABORT that ends one. Each is under
#: a hundred bytes, which any socket send buffer takes at once, so only a peer that has stopped
#: reading meets this. ``timeout_seconds`` bounds the association's own sends instead, and once one
#: of those notices a stop, it has this long more. A send looks for a stop at least every
#: :data:`_STOP_POLL_SECONDS`, so a stop waits on a send for this plus that, 1.5 seconds, at most.
_ANSWER_SEND_SECONDS = 1.0

#: The least and the most ``max_pdu_size`` the SCP takes. pynetdicom fragments an object into PDVs
#: of six bytes less than the size a peer offers, so a size of six or less breaks its senders, and
#: 4096 is DCMTK's own least. The most bounds what one read holds before the SCP has counted any of
#: it, since a PDU's body is read whole: a 4 GiB size would let a single PDU carry far past twice the
#: object cap. 1 MiB is 64 times the shipped 16 KiB.
_MIN_PDU_SIZE = 4096
_MAX_PDU_SIZE = 1024 * 1024

#: Why the SCP refuses to run, and refuses each connection, while pynetdicom's process-wide
#: ``STORE_RECV_CHUNKED_DATASET`` is set. With it set, pynetdicom writes each object it receives to
#: a temporary file, in plaintext and outside the store and its encryption, and that file is not on
#: any list of where PHI rests (docs/PHI.md).
_CHUNKED_RECEIPT_REFUSAL = (
    "pynetdicom's STORE_RECV_CHUNKED_DATASET is set, which would write each received object to a "
    "plaintext temporary file"
)

#: The least ``timeout_seconds`` the SCP takes. It is a fixed deadline on every read and send, so a
#: tiny one, such as a typo of 0.001, would end nearly every peer while looking like a working value.
#: One second is a floor against that, not a recommendation: the shipped 30 is what a real sender is
#: sized for.
_MIN_TIMEOUT_SECONDS = 1.0

#: The most a closing connection reads and throws away, so that its close is not over unread data.
#: See :func:`_drain_readable`. A peer that has sent more than this gets a reset, as it did before.
_DRAIN_BYTES = 64 * 1024

#: The DUL states (PS3.8 section 9.2) in which ``_AdmittedSocket.ready`` does not read: awaiting the
#: request and awaiting the local answer to it, and closing.
_STATES_BEFORE_THE_ANSWER = frozenset({"Sta2", "Sta3"})
_STATE_CLOSING = "Sta13"

#: The most refusal lines one SCP writes per window over every address together. The per-address
#: bound alone would still let many addresses earn a line each.
_REFUSAL_LOG_MAX_PER_WINDOW = REFUSAL_LOG_MAX_PER_WINDOW


#: Why the allowlist refuses a peer. One wording for the accept gate and for the C-STORE backstop.
_NOT_IN_ALLOWLIST = "peer IP not in source_ip_allowlist"

#: What this blocking handshake leaves uncounted: the same peer acts the MLLP listener leaves
#: uncounted (:data:`HUNG_UP`), as this socket reports them. A peer that closes the socket
#: mid-handshake raises ``SSLEOFError`` here, where the event loop reports that close to MLLP as
#: ``ConnectionResetError`` (measured 2026-10-26, CPython 3.14 for Windows). A close_notify after
#: the ClientHello raises ``SSLZeroReturnError``, which MLLP counts, so it is counted here too.
#: ``ConnectionAbortedError`` (WinError 10053) is left out because a client that closes as soon
#: as its own side of the handshake is done raises it here (measured 2026-10-26 on Windows). It is
#: left out at every stage, so a peer that aborts earlier in the handshake is not counted either.
#: On the MLLP listener it is that listener's own bound, and counted there.
_HUNG_UP = (*HUNG_UP, ssl.SSLEOFError, ConnectionAbortedError)


class _RefusedPeer(Exception):
    """A peer did not deliver an association request the SCP will read. The message is the reason
    the refusal line gives, so it never holds a byte the peer sent."""


def _address_host(client_address: Any) -> str:
    """The host part of a socket peer address, as ``accept()`` returns it. ``"?"`` when there is none."""
    if isinstance(client_address, tuple) and client_address:
        return str(client_address[0])
    return "?"


def _drain_readable(sock: socket.socket) -> None:
    """Read and throw away what the peer has already sent, without waiting for more, before the SCP
    closes the connection.

    A close over unread data resets the connection, and the peer's stack can then drop an answer
    the SCP has just sent, before the peer reads it. Measured on Windows loopback: a request with
    one stray byte behind it got a reset and no A-ASSOCIATE-RJ, 25 times in 25. This stops at the
    end of what has arrived, at the peer's close, at an error, or at :data:`_DRAIN_BYTES`. It never
    waits, so a peer that stalls part way through a PDU cannot hold the closing thread. The socket
    is left non-blocking, which is fine for one that is about to be closed."""
    left = _DRAIN_BYTES
    try:
        sock.settimeout(0.0)
        while left > 0:
            chunk = sock.recv(left)
            if not chunk:
                return
            left -= len(chunk)
    except (BlockingIOError, ssl.SSLWantReadError):  # nothing more has arrived
        return
    except OSError as exc:  # a reset or a TLS error: the close goes ahead regardless
        logger.debug("Draining a closing DICOM connection ended: %s", safe_exc(exc))


#: The DIMSE commands the SCP serves (PS3.7 Annex E): C-STORE-RQ and C-ECHO-RQ. pynetdicom queues
#: each of these for the Association thread, which serves one at a time. It serves some others on a
#: thread of their own, an N-EVENT-REPORT-RQ for one, and so outside the hold ``ready`` puts on a
#: waiting message; and it logs each response it was not waiting for. So any other command ends the
#: association.
_SERVED_COMMANDS = frozenset({0x0001, 0x0030})


def _read_command_set(command_set: bytes) -> tuple[int, bool, bool] | None:
    """A whole command set read as pynetdicom reads it: its ``CommandField``, whether the message is
    complete without a data set, and whether pynetdicom would serve it as a request. ``None`` when
    pynetdicom would fail on it.

    ``DIMSEMessage.decode_msg`` decodes the command set with ``dsutils.decode``, implicit VR little
    endian, looks its ``CommandField`` up in ``_MESSAGE_TYPES``, and compares its
    ``CommandDataSetType`` to 0x0101. Once the message is whole, ``message_to_primitive`` sets each
    element on the command's primitive, whose setters refuse some values, and
    ``Association._serve_request`` serves it only if ``is_valid_request`` holds. These are the same
    steps, on a message built the same way. A raise in the first three happens on the DUL thread
    there and kills it with a traceback, and one in ``message_to_primitive`` is logged at ERROR with
    a traceback, so here either is a reason to end the association instead. A request that is not
    valid gets no response there, only a WARNING, and the association goes on, so a peer could
    stream such requests; the caller ends the association on one.

    Running ``message_to_primitive`` here means pynetdicom's own log lines from it are written here
    first, and then again when pynetdicom runs it on the whole message. At least these: a setter that
    refuses a UID logs it at ERROR before it raises; one that finds a UID non-conformant logs a
    WARNING and does not raise; the Move Originator AE title setter logs an ERROR and does not raise;
    and ``message_to_primitive`` itself logs a WARNING for an element with more than one value. Some
    of those lines name the peer's UID value. They are left as they are."""
    from pynetdicom.dimse_messages import _MESSAGE_TYPES, DIMSEMessage
    from pynetdicom.dsutils import decode

    try:
        command = decode(BytesIO(command_set), True, True)
        message = DIMSEMessage()
        message.command_set = command
        field = int(command.CommandField)
        message.__class__ = _MESSAGE_TYPES[field][1]
        completes = bool(command.CommandDataSetType == 0x0101)
        # C_CANCEL has no is_valid_request; it is not a served command, so the caller ends it as one.
        valid = bool(getattr(message.message_to_primitive(), "is_valid_request", False))
    except Exception as exc:  # noqa: BLE001 - a third-party parser on a peer's bytes
        logger.debug("A DICOM command set did not decode: %s", safe_exc(exc))
        return None
    return field, completes, valid


def _chunked_receipt_on() -> bool:
    """Whether pynetdicom's process-wide ``STORE_RECV_CHUNKED_DATASET`` is set; see
    :data:`_CHUNKED_RECEIPT_REFUSAL`. It is read again at each command, since anything in the
    process could set it while an association is open."""
    from pynetdicom import _config

    return bool(_config.STORE_RECV_CHUNKED_DATASET)


class _ReceiptTally:
    """What one association has received of the DIMSE message in progress, counted as the P-DATA-TF
    PDUs are read and before pynetdicom sees them (owner ruling B462-R3, vault BACKLOG #2712).

    pynetdicom holds every fragment of a message until the message is complete, with no ceiling of
    its own. Its ``max_object_bytes`` check runs only then, so without this a peer could send an
    object of any size, and the SCP would hold it all before refusing it. This counts from the same
    PDUs, in the same order, so it sees what pynetdicom will hold.

    A message is its command set's fragments, then, when the command says one follows, its data
    set's fragments (PS3.8 Annex E.2). The count starts again where pynetdicom starts a new message:
    at a data set's last fragment, and at a command set's last fragment when the command says no
    data set follows. So a run of objects under the cap is never counted together, however long the
    association.

    Each item is split where ``pdu.P_DATA_TF._generate_items`` splits it, and each fragment counts
    what ``DIMSEMessage.decode_msg`` holds of it, all but its control byte. A shape pynetdicom would
    fail on, take out of that order, or serve outside the hold ``ready`` puts on a waiting message,
    ends the association instead of reaching it. At least these: an item too short for its length,
    context and control byte, or longer than the PDU holds; a command set that does not decode, or
    whose values pynetdicom refuses; a command the SCP does not serve; a request that lacks a field
    pynetdicom needs to serve it, which it would answer with nothing; a second command set in one
    message; a data set fragment before its command set is whole; and anything in a PDU after the
    item that completes a message, which pynetdicom drops unread. pynetdicom would log each at ERROR
    with a traceback, or lose its DUL thread to it, or count it apart from what is counted here. The
    fragments are read through a ``memoryview``, so counting one copies nothing."""

    def __init__(self, *, max_data_set_bytes: int) -> None:
        #: Past this the association is ended: twice the SCP's effective ``max_object_bytes``.
        self.max_data_set_bytes = max_data_set_bytes
        #: The data set bytes of the message in progress.
        self.data_set_bytes = 0
        #: The command set of the message in progress, kept whole so that its last fragment can be
        #: read. It is bounded by :data:`_MAX_COMMAND_SET_BYTES`.
        self.command_set = bytearray()
        #: Whether the command set's last fragment has arrived, saying a data set follows.
        self.command_whole = False
        #: Whether an item of the PDU being counted completed a message.
        self.completed = False

    def take(self, body: bytes | bytearray) -> tuple[tuple[int, int], str] | None:
        """Count one P-DATA-TF's variable field. Returns the A-ABORT (source, reason) to end the
        association with, and why, or ``None`` when the PDU may go to pynetdicom."""
        view = memoryview(body)
        offset, size = 0, len(view)
        self.completed = False
        while offset < size:
            if self.completed:
                return _ABORT_INVALID_MESSAGE, "a P-DATA-TF goes on past a message's last fragment"
            start = offset + 5  # the item length and the context ID come first
            end = offset + 4 + int.from_bytes(view[offset : offset + 4], "big")
            if start >= end or end > size:
                return _ABORT_INVALID_MESSAGE, "a P-DATA-TF item does not decode"
            control, fragment = view[start], view[start + 1 : end]
            offset = end
            if control & 0x01:
                ended = self._take_command(fragment, last=bool(control & 0x02))
            else:
                ended = self._take_data(fragment, last=bool(control & 0x02))
            if ended is not None:
                return ended
        return None

    def _take_command(
        self, fragment: memoryview, *, last: bool
    ) -> tuple[tuple[int, int], str] | None:
        if self.command_whole:
            return _ABORT_INVALID_MESSAGE, "a second command set in one message"
        self.command_set += fragment
        if len(self.command_set) > _MAX_COMMAND_SET_BYTES:
            return _ABORT_OVER_LIMIT, f"a command set passed {_MAX_COMMAND_SET_BYTES} bytes"
        if not last:
            return None
        if _chunked_receipt_on():
            return _ABORT_OVER_LIMIT, _CHUNKED_RECEIPT_REFUSAL
        read = _read_command_set(bytes(self.command_set))
        if read is None:
            return _ABORT_INVALID_MESSAGE, "a command set does not decode"
        field, completes, valid = read
        if field not in _SERVED_COMMANDS:
            return _ABORT_INVALID_MESSAGE, "a command the SCP does not serve"
        if not valid:
            return _ABORT_INVALID_MESSAGE, "a request that lacks a field it must carry"
        if completes:
            self._next_message()
        else:
            self.command_whole = True
        return None

    def _take_data(self, fragment: memoryview, *, last: bool) -> tuple[tuple[int, int], str] | None:
        if not self.command_whole:
            return _ABORT_INVALID_MESSAGE, "a data set fragment came before its command set"
        self.data_set_bytes += len(fragment)
        if self.data_set_bytes > self.max_data_set_bytes:
            return _ABORT_OVER_LIMIT, (
                f"an object passed {self.max_data_set_bytes} bytes, twice the SCP's effective "
                "max_object_bytes"
            )
        if last:
            self._next_message()
        return None

    def _next_message(self) -> None:
        self.data_set_bytes = 0
        self.command_set.clear()
        self.command_whole = False
        self.completed = True


def _require_association_seams(handler: type[Any], association_socket: type[Any]) -> None:
    """Refuse a pynetdicom without the private names :func:`_admitting_server_class` builds on.

    An install that got round the pin could bring another release. With these gone the SCP would
    start and then fail every connection, with nothing above stderr to say why, so it does not."""
    own = vars(association_socket)
    present = (
        callable(getattr(handler, "_create_association", None))
        and isinstance(own.get("ready"), property)
        and all(callable(own.get(name)) for name in ("recv", "send", "close", "_shutdown_socket"))
    )
    if not present:
        raise RuntimeError(
            "the installed pynetdicom does not have the association hooks the DICOM server (SCP) "
            "reads a connection's first request through; refusing to start the SCP with it"
        )


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

    **Read against pynetdicom 3.0.4 and CPython's ``socketserver``; re-read both before moving the
    pynetdicom pin in the ``[dicom]`` extra.** ``pyproject.toml`` pins the release this was read
    against, so any other is stopped at install time. The comment above the extra there gives the
    steps to move it. :func:`_require_socketserver_routing` refuses a pynetdicom that left this
    routing, and ``tests/test_dicom_scp_admission.py`` pins the rest.

    * ``AssociationServer.get_request`` accepts a connection and, on a TLS listener, runs the TLS
      handshake in the same call. That call is on the accept loop, and the accepted socket has no
      timeout, so one peer that connects and sends nothing would hold every other sender's handshake
      for as long as it stayed connected. ``get_request`` here only accepts.
    * ``socketserver`` calls ``verify_request`` on the accept loop, straight after ``get_request``
      and before any thread is started, and closes the connection when it returns ``False``. That is
      where the peer address is checked, so a peer outside ``source_ip_allowlist`` is closed before
      an association thread exists for it and before a byte is read from it.
    * ``ThreadingMixIn.process_request`` starts the connection's thread, still on the accept loop.
      The connection takes a slot first, on a cleartext listener as on a TLS one, counted per
      listener and per peer address against :data:`_MAX_PENDING_CONNECTIONS` and
      :data:`_MAX_PENDING_CONNECTIONS_PER_HOST`. One over either is closed with no thread started.
    * ``ThreadedAssociationServer.process_request_thread`` runs on the connection's own thread. The
      handshake runs there, against a deadline of ``_TLS_HANDSHAKE_TIMEOUT`` for the whole handshake.
      A peer that sends nothing, and one that sends its handshake slowly, are both dropped at it.
      The slot is given back in a ``finally`` there, because that thread's work ends when the
      association has started: ``RequestHandler.handle`` returns right after ``assoc.start()``.
    * ``RequestHandler.handle`` is replaced so that the association request is read BEFORE the
      ``Association`` thread starts. pynetdicom reads a connection on the association's DUL thread,
      in a loop of blocking ``recv`` calls on a socket with no timeout. That thread cannot reach
      its own timers while it is blocked, and ``Association.kill()`` then waits on it for good, so
      a peer that sent one byte and stopped would never be ended. Every started ``Association``
      also counts at pynetdicom's ``maximum_associations`` check, so stalled peers could fill it
      and turn a real sender away. Here the connection's own thread reads the first PDU under a
      fixed deadline of ``timeout_seconds``, so a peer that stalls never starts an ``Association``.
      It cannot use up ``max_associations``, and it costs one thread rather than two.
    * That read consumes the PDU, and pynetdicom must still see it. ``_create_association`` names
      ``AssociationSocket`` itself and ``Association.set_socket`` refuses a second socket, so the
      socket it made is turned into an ``_AdmittedSocket``. A wrapper around the ``socket`` would
      lose the ``ssl.SSLSocket`` check in ``AssociationSocket.ready``, and with it ``pending()``.
    * The same socket bounds the DUL thread from there on, so it cannot block for good after the
      association has started either. A later read, and a whole send, each have a fixed deadline.
      It also reads each PDU's body with its header, so that a PDU longer than the SCP offered, and
      an object past twice the object cap, end the association before pynetdicom holds them, and it
      reads nothing while a whole message waits on pynetdicom's queue.
      It also holds off reading while the request is unanswered, so a stray byte behind a whole
      request cannot delay the ``maximum_associations`` check.
    * ``AE.start_server`` cannot start this class: its non-blocking branch names
      ``ThreadedAssociationServer`` itself. ``AE.make_server`` takes ``server_class`` and passes extra
      keywords to its constructor, and ``start_serving`` here does the rest of what that branch does.
    """
    from pynetdicom import _config, evt
    from pynetdicom.pdu import A_ABORT_RQ, A_ASSOCIATE_RJ, A_ASSOCIATE_RQ
    from pynetdicom.pdu_primitives import A_ASSOCIATE, SCP_SCU_RoleSelectionNegotiation
    from pynetdicom.presentation import negotiate_as_acceptor, negotiate_unrestricted
    from pynetdicom.transport import AssociationSocket, RequestHandler, ThreadedAssociationServer
    from pynetdicom.utils import make_target

    _require_socketserver_routing(ThreadedAssociationServer)
    _require_association_seams(RequestHandler, AssociationSocket)

    class _AdmittingAssociationServer(ThreadedAssociationServer):
        def __init__(
            self,
            *args: Any,
            admit: Callable[[Any], bool],
            refused: Callable[[str, str, str], None],
            ended: Callable[[str, str], None],
            handshake_failed: Callable[[str, str], None],
            stopping: threading.Event,
            max_pdu_size: int,
            max_object_bytes: int,
            **kwargs: Any,
        ) -> None:
            #: The longest P-DATA-TF variable field the SCP offers to take, and so takes.
            self.max_pdu_size = max_pdu_size
            #: The SCP's effective object cap. An association whose object passes twice this is
            #: ended (owner ruling B462-R3).
            self.max_object_bytes = max_object_bytes
            self._admit = admit
            self._refused = refused
            #: Called on the DUL thread with the peer address and the reason, when a read of an
            #: association that has started runs out its deadline. It is not a refusal: the SCP
            #: accepted that association and may have taken objects on it.
            self._ended = ended
            #: Called on the connection's thread with the peer address and the cause, for each
            #: handshake :meth:`_handshake` counts as failed (vault BACKLOG #3784).
            self._handshake_failed = handshake_failed
            #: The SCP's own stop signal, set before it calls shutdown(). shutdown() joins every
            #: connection thread, so a thread inside a handshake has to see this to end early.
            self._stopping = stopping
            #: Connections with no association yet, per peer address. Its values sum to the
            #: listener's total.
            self._pending: dict[str, int] = {}
            self._pending_lock = threading.Lock()
            #: When the next admission-check fault may be logged (monotonic). See verify_request.
            self._gate_fault_log_after = 0.0
            kwargs["request_handler"] = _AdmittingRequestHandler
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
            # On the accept loop, for a connection verify_request admitted. It takes its slot here,
            # so one over a cap is closed before a thread exists for it.
            host = _address_host(client_address)
            full = self._take_slot(host)
            if full is not None:
                try:
                    self._refused(host, "a connection", full)
                finally:
                    self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self._release_slot(host)  # no thread was started to give it back
                raise

        def process_request_thread(self, request: Any, client_address: Any) -> None:
            host = _address_host(client_address)
            try:
                context = self.ssl_context
                if context is not None:
                    request = self._handshake(context, request, host)
                    if request is None:
                        return
                # Returns once the association's own thread has started, or the connection has
                # ended. From there pynetdicom's maximum_associations counts it.
                super().process_request_thread(request, client_address)
            finally:
                self._release_slot(host)

        def _take_slot(self, host: str) -> str | None:
            """Count one more connection with no association yet for ``host``. Returns ``None`` when
            the slot is taken, else the reason there is none, and then nothing was counted."""
            with self._pending_lock:
                if sum(self._pending.values()) >= _MAX_PENDING_CONNECTIONS:
                    return (
                        f"{_MAX_PENDING_CONNECTIONS} connections with no association yet are "
                        "already in progress"
                    )
                held = self._pending.get(host, 0)
                if held >= _MAX_PENDING_CONNECTIONS_PER_HOST:
                    return (
                        f"{_MAX_PENDING_CONNECTIONS_PER_HOST} connections from this address with "
                        "no association yet are already in progress"
                    )
                self._pending[host] = held + 1
                return None

        def _release_slot(self, host: str) -> None:
            with self._pending_lock:
                held = self._pending[host] - 1
                if held:
                    self._pending[host] = held
                else:
                    del self._pending[host]  # so the table holds only addresses still pending

        def read_association_request(self, sock: socket.socket, host: str) -> bytes | None:
            """Read the connection's first PDU, on the connection's own thread. Returns it, with the
            socket's own timeout restored, or ``None`` when no association should start.

            A peer that closes, and a stop, are ordinary ends and leave a DEBUG line. A peer that
            runs out the deadline, or opens with anything but an association request the SCP will
            read, is logged as a refusal, throttled per address."""
            try:
                first_pdu = self._read_first_pdu(sock)
                self._check_association_request(sock, first_pdu)
                # A request that sets bit 0 and other version bits as well is a version-1 request,
                # but pynetdicom's AE-6 compares the whole field to 1 and would reject it. So the
                # copy pynetdicom reads names version 1 alone. Nothing else in it changes.
                at = _PROTOCOL_VERSION_OFFSET
                return first_pdu[:at] + _PROTOCOL_VERSION.to_bytes(2, "big") + first_pdu[at + 2 :]
            except _RefusedPeer as exc:
                self._refused(host, "a connection", str(exc))
            except OSError as exc:  # a timeout errno, a reset and an ssl.SSLError are all OSError
                logger.debug("DICOM peer %s sent no association request: %s", host, safe_exc(exc))
            return None

        def _read_first_pdu(self, sock: socket.socket) -> bytes:
            """Read one whole PDU within the deadline, however slowly the peer sends it.

            The bound is a fixed monotonic deadline for the whole PDU, not an idle timer, because a
            byte would restart an idle timer. The first byte is read alone, so a peer that is not
            speaking DICOM is closed at once. It asks for no more than the PDU needs, so nothing
            the association will read next is taken here."""
            restore = sock.gettimeout()  # None: accept() returns a blocking socket
            seconds = cast(float, self.ae.acse_timeout)
            deadline = time.monotonic() + seconds
            expired = _RefusedPeer(f"no complete association request within {seconds:g}s")

            pdu = self._read_exactly(sock, 1, deadline, expired)
            if pdu[0] != _PDU_TYPE_ASSOCIATE_RQ:
                raise _RefusedPeer("its first PDU is not an association request")
            pdu += self._read_exactly(sock, _PDU_HEADER_BYTES - 1, deadline, expired)
            body = int.from_bytes(pdu[2:], "big")
            if _PDU_HEADER_BYTES + body > _MAX_ASSOCIATE_RQ_BYTES:
                raise _RefusedPeer(
                    f"its association request is over {_MAX_ASSOCIATE_RQ_BYTES} bytes"
                )
            pdu += self._read_exactly(sock, body, deadline, expired)
            if self._stopping.is_set():  # finished after the stop began: start no association
                raise OSError("the listener is stopping")
            sock.settimeout(restore)
            return bytes(pdu)

        def read_for_association(self, sock: socket.socket, count: int, host: str) -> bytearray:
            """One read of a started association, within ``timeout_seconds`` however slowly the
            peer sends it. Short where the peer closed, as ``AssociationSocket.recv`` is, and empty
            where the deadline passed, the read failed or the listener is stopping.

            ``_AdmittedSocket._read_pdu`` reads a PDU's header and then its body, so each of those
            has the deadline. The DUL takes a short read as a closed connection, and that ends the
            connection the normal way. A raise would too, but pynetdicom logs each one at ERROR
            with a traceback, and a peer could repeat that as often as it could connect. So the end
            goes through a throttled line of its own instead, apart from the refusals: the SCP
            accepted this association, so it is not a refused connection, and it must not use up an
            address's refusal line. ``_read_pdu`` hands the DUL an empty header for a short body,
            so either short read is silent in the DUL. It is a deadline per read and not per
            object. **A peer that keeps a message incomplete, finishing a small fragment's PDU
            inside each deadline, is not bounded by this, by :class:`_ReceiptTally`, or by
            pynetdicom's timers**: each PDU restarts pynetdicom's idle timer, and the tally ends
            only on size. Such a peer holds a ``max_associations`` slot for as long as it keeps
            sending, and enough of them fill it. No per-message deadline is built here."""
            seconds = cast(float, self.ae.network_timeout)
            expired = _RefusedPeer(f"no complete PDU within {seconds:g}s")
            restore = sock.gettimeout()  # None: pynetdicom reads a blocking socket
            try:
                return self._read_up_to(sock, count, time.monotonic() + seconds, expired)
            except _RefusedPeer as exc:
                self._ended(host, str(exc))
            except OSError as exc:  # a timeout errno, a reset and an ssl.SSLError are all OSError
                logger.debug("A read from DICOM peer %s ended: %s", host, safe_exc(exc))
            finally:
                with contextlib.suppress(OSError):  # the association may have closed it
                    sock.settimeout(restore)
            return bytearray()

        def _read_exactly(
            self, sock: socket.socket, count: int, deadline: float, expired: Exception
        ) -> bytearray:
            """Read ``count`` bytes before ``deadline``, or raise."""
            received = self._read_up_to(sock, count, deadline, expired)
            if len(received) < count:
                raise ConnectionResetError("the peer closed the connection")
            return received

        def _read_up_to(
            self, sock: socket.socket, count: int, deadline: float, expired: Exception
        ) -> bytearray:
            """Read ``count`` bytes before ``deadline``, or fewer if the peer closes first. Raises
            ``expired`` when the deadline passes. A read asks for 4096 bytes at most, as pynetdicom's
            own does."""
            received = bytearray()
            while len(received) < count:
                recv = functools.partial(sock.recv, min(count - len(received), 4096))
                chunk: bytes = self._in_slices(sock, recv, deadline, expired)
                if not chunk:
                    break
                received += chunk
            return received

        def _in_slices(
            self,
            sock: socket.socket,
            step: Callable[[], Any],
            deadline: float,
            expired: Exception,
            *,
            on_stop: Callable[[], float] | None = None,
        ) -> Any:
            """Run one socket ``step`` against ``deadline`` and return what it returns, or raise
            ``expired`` when the deadline passes.

            The step runs in slices of :data:`_STOP_POLL_SECONDS`, so that a stop is noticed without
            closing a socket under the thread that is reading it. A slice that ends with nothing to
            read raises a ``TimeoutError`` that carries no ``errno`` and leaves the socket, and any
            TLS state on it, as it was, so the next slice takes the step up again. A ``TimeoutError``
            that does carry one is the connection itself timing out, and ends the step.

            A stop ends the step at once, or, given ``on_stop``, at the time it returns, if that is
            sooner than ``deadline``.

            The timeout is set only when it changes: at most once per read, and then on each slice
            within the last slice's length of the deadline. Setting it is a system call."""
            while True:
                if self._stopping.is_set():
                    stop_end = time.monotonic() if on_stop is None else on_stop()
                    if time.monotonic() >= stop_end:
                        raise OSError("the listener is stopping")
                    deadline = min(deadline, stop_end)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise expired
                slice_seconds = min(remaining, _STOP_POLL_SECONDS)
                if sock.gettimeout() != slice_seconds:
                    sock.settimeout(slice_seconds)
                try:
                    return step()
                except TimeoutError as exc:
                    if exc.errno is not None:
                        raise

        def _check_association_request(self, sock: socket.socket, first_pdu: bytes) -> None:
            """Refuse a request the association would not be given, or could not negotiate.

            The DUL decodes the PDU, builds its primitive and checks the protocol version, and it
            gives the association nothing unless all three pass. The version check here tests bit
            0 alone, as PS3.8 section 9.3.2 says; the DUL compares the whole field, so
            :meth:`read_association_request` hands it a copy that names version 1. The ``Association`` thread then
            waits out ``timeout_seconds`` with its socket already closed, and it counts against
            ``max_associations`` all that time. Nothing caps that once the association has started,
            so a peer repeating such a request could go round the slots. These are the same three
            steps, so a request that passes here is one the association will be given.

            Then this runs the presentation-context negotiation the association runs, the same
            pynetdicom function on the same contexts and roles, and refuses a request it raises on.
            A raise there kills the ``Association`` thread, and each one writes an unthrottled
            CRITICAL line under ``serve``. At least a context with no transfer syntax, and one with
            no abstract syntax, raise there. Running the step itself, rather than listing the
            shapes it fails on, covers whatever else it reads. The rest of the association's
            negotiation is not run here, so ``_AdmittedSocket.ready`` is what ends a DUL whose
            ``Association`` thread dies some other way.

            Each of these refusals is a whole request read up to its end, so the peer is answered
            before the connection closes. The comment above :data:`_RJ_WRONG_PROTOCOL` says what
            each gets.

            These checks run before ``EVT_REQUESTED``, so a request that fails one gets its answer
            here even where the AE-title checks, or a paused intake, would have refused it too.

            Both ``except Exception`` clauses wrap a third-party step on a peer's bytes, so what
            they catch is the peer's to cause and is logged at DEBUG only, since a peer can repeat
            it as often as it can connect. The refusal itself is the throttled WARNING."""
            pdu = A_ASSOCIATE_RQ()
            try:
                pdu.decode(first_pdu)
                primitive = pdu.to_primitive()
            except Exception as exc:  # noqa: BLE001 - a third-party parser on a peer's bytes
                logger.debug("DICOM association request did not decode: %s", safe_exc(exc))
                abort = A_ABORT_RQ()
                abort.source, abort.reason_diagnostic = 0x00, 0x00
                self._answer(sock, abort.encode())
                raise _RefusedPeer("its association request does not decode") from exc
            if not pdu.protocol_version & _PROTOCOL_VERSION:
                self._reject(sock, _RJ_WRONG_PROTOCOL)
                raise _RefusedPeer("its association request has the wrong protocol")
            negotiate = (
                negotiate_unrestricted
                if _config.UNRESTRICTED_STORAGE_SERVICE
                else negotiate_as_acceptor
            )
            try:
                # The roles as ACSE._negotiate_as_acceptor builds them from the request. Any: the
                # key is a UID there by a cast, and a peer's item may carry none; the step decides.
                roles: dict[Any, tuple[bool | None, bool | None]] = {
                    item.sop_class_uid: (item.scu_role, item.scp_role)
                    for item in primitive.user_information
                    if isinstance(item, SCP_SCU_RoleSelectionNegotiation)
                }
                negotiate(primitive.presentation_context_definition_list, self.contexts, roles)
            except Exception as exc:  # noqa: BLE001 - a third-party step on a peer's request
                logger.debug("DICOM association request did not negotiate: %s", safe_exc(exc))
                self._reject(sock, _RJ_DOES_NOT_NEGOTIATE)
                raise _RefusedPeer("its association request does not negotiate") from exc

        def _reject(self, sock: socket.socket, answer: tuple[int, int, int]) -> None:
            """Answer with an A-ASSOCIATE-RJ of (result, source, diagnostic) ``answer``."""
            primitive = A_ASSOCIATE()
            primitive.result, primitive.result_source, primitive.diagnostic = answer
            self._answer(sock, A_ASSOCIATE_RJ(primitive).encode())

        def _answer(self, sock: socket.socket, pdu: bytes) -> None:
            """Send ``pdu``, best effort, and then read off what the peer sent behind its request,
            so that the close that follows does not reset the connection and lose the answer.

            The drain is here, after an answer, and not in ``shutdown_request``: socketserver
            also calls that on the accept loop for a peer ``source_ip_allowlist`` refuses, and
            such a peer is closed before a byte is read from it.

            This thread holds a slot, and shutdown() joins it, so its one send has the short bound
            :data:`_ANSWER_SEND_SECONDS`, a stop included. A peer that does not take the answer
            in that time gets a closed connection."""
            try:
                self._send_before(sock, pdu, time.monotonic() + _ANSWER_SEND_SECONDS)
            except OSError as exc:  # the bound, a stop, a reset and an ssl.SSLError are all OSError
                logger.debug("DICOM association answer not sent: %s", safe_exc(exc))
                return
            _drain_readable(sock)

        def end_association(
            self, sock: socket.socket, answer: tuple[int, int], host: str, reason: str
        ) -> None:
            """End a started association from the DUL thread: send an A-ABORT of (source, reason)
            ``answer``, best effort, and log the end. The caller then hands the DUL an empty read,
            its silent closed connection, and the DUL closes the socket, reading off what has
            arrived first so that the A-ABORT is not lost to a reset. A peer that has sent more than
            that can still get a reset in its place.

            The line is the one a read deadline gets, :meth:`DicomScpSource._log_ended_association`,
            throttled per address. ``reason`` names the limit, never a byte or a number the peer
            sent."""
            self._ended(host, reason)
            abort = A_ABORT_RQ()
            abort.source, abort.reason_diagnostic = answer
            try:
                self._send_before(sock, abort.encode(), time.monotonic() + _ANSWER_SEND_SECONDS)
            except OSError as exc:
                logger.debug("DICOM A-ABORT to %s not sent: %s", host, safe_exc(exc))

        def send_for_association(self, sock: socket.socket, data: bytes, host: str) -> bool:
            """One send of a started association, whole within ``timeout_seconds`` however slowly
            the peer reads, and within :data:`_ANSWER_SEND_SECONDS` of noticing a stop, which it
            looks for at least every :data:`_STOP_POLL_SECONDS`. Returns
            whether all of ``data`` went.

            A deadline for the whole send, not a timeout per system call: a peer that reads a
            little at a time would let every call finish inside a per-call timeout, and hold the
            DUL thread, and a stop with it, for as long as it liked. The end of a send that ran out
            is logged as an end, the same throttled line a read deadline gets. A socket error, or
            the `ValueError` an ssl socket closed under the send raises, is a closed connection,
            as the stock send takes it to be. Anything else is a fault here, and is left to raise."""
            seconds = cast(float, self.ae.network_timeout)
            restore = sock.gettimeout()  # None: pynetdicom sends on a blocking socket
            try:
                self._send_before(sock, data, time.monotonic() + seconds, seconds=seconds)
                return True
            except _RefusedPeer as exc:
                self._ended(host, str(exc))
            except (OSError, ValueError) as exc:  # ValueError: an ssl socket closed under the send
                logger.debug("A send to DICOM peer %s ended: %s", host, safe_exc(exc))
            finally:
                with contextlib.suppress(OSError):  # the association may have closed it
                    sock.settimeout(restore)
            return False

        def _send_before(
            self, sock: socket.socket, data: bytes, deadline: float, *, seconds: float | None = None
        ) -> None:
            """Send all of ``data`` before ``deadline``, in the slices of :meth:`_in_slices`, or
            raise: a :class:`_RefusedPeer` naming ``seconds`` when that is given and the deadline
            passes, else an ``OSError``. A slice that ends with nothing sent leaves the socket, and
            any TLS state on it, as it was, so the next slice sends the same bytes again, as a TLS
            write that did not finish must be retried."""
            expired: Exception = (
                TimeoutError("the send did not finish within its bound")
                if seconds is None
                else _RefusedPeer(f"a send did not finish within {seconds:g}s")
            )
            stop_seen: list[float] = []

            def end_after_stop() -> float:
                # A send that is moving when the stop begins gets a short while to finish: the
                # C-STORE status for an object committed as the stop began is one, and stop() lets
                # that commit finish. One the peer is not reading cannot hold the stop for longer.
                if not stop_seen:
                    stop_seen.append(time.monotonic() + _ANSWER_SEND_SECONDS)
                return stop_seen[0]

            left = memoryview(data)
            while left:
                send = functools.partial(sock.send, left)
                sent: int = self._in_slices(sock, send, deadline, expired, on_stop=end_after_stop)
                left = left[sent:]

        def _handshake(
            self, context: ssl.SSLContext, plain: socket.socket, host: str
        ) -> ssl.SSLSocket | None:
            """Run the server side of the TLS handshake within the bound. Returns the TLS socket
            with the accepted socket's own timeout restored, or ``None`` after closing the connection.

            The handshake runs through :meth:`_in_slices`. A slice that ends with nothing to read
            leaves the SSL object in the state a non-blocking handshake is resumed from.

            A handshake that fails is logged at DEBUG with its detail, and handed to
            ``handshake_failed`` to be counted (vault BACKLOG #3784), as the MLLP listener counts
            the handshakes it runs itself: a TLS error and the bound count, and so does the
            connection timing out. A peer that closed or reset the socket (:data:`_HUNG_UP`) does
            not, nor does a stop.
            A peer can fail a handshake as often as it can connect, so the SCP's record is the
            throttled WARNING that ``docs/PHI.md`` section 7, row 7 states, never a line each."""
            tls: ssl.SSLSocket | None = None
            try:
                restore = plain.gettimeout()  # None: accept() returns a blocking socket
                # No I/O: without do_handshake_on_connect this only builds the SSL object.
                tls = context.wrap_socket(plain, server_side=True, do_handshake_on_connect=False)
                deadline = time.monotonic() + _TLS_HANDSHAKE_TIMEOUT
                expired = TimeoutError("the handshake did not finish within its bound")
                self._in_slices(tls, tls.do_handshake, deadline, expired)
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
                # A ValueError is a socket this thread could not wrap, not a peer's handshake.
                # A failure the stop caused is dropped by the counter, which stop() closes first.
                if isinstance(exc, OSError) and not isinstance(exc, _HUNG_UP):
                    self._handshake_failed(host, handshake_cause(exc))
            with contextlib.suppress(OSError):
                (plain if tls is None else tls).close()
            return None

    class _AdmittedSocket(AssociationSocket):
        """An admitted connection's association socket. It first serves the PDU the server has
        already read, and after that a read or a send cannot block the DUL thread for good."""

        #: What is left of a PDU already read: first the association request, then each later
        #: PDU's body, which :meth:`_read_pdu` reads with its header. The DUL reads a PDU's header
        #: and then its body, so a read never asks for more than is left.
        replay: bytearray
        server: _AdmittingAssociationServer
        host: str
        tally: _ReceiptTally

        @property
        def ready(self) -> bool:
            """Whether the DUL should read. Not before the request is answered, whatever has
            arrived, not while a whole message waits for the ``Association`` thread, and not in
            Sta13.

            The DUL reads before it takes its next event, so a byte behind the request would have
            it reading while the request itself waits, unanswered, on its queue. The association
            then counts for a whole deadline before ``maximum_associations`` is checked, with its
            slot already given back, so such peers would go round every cap.

            The DUL hands each whole message to pynetdicom's ``dimse.msg_queue``, which has no
            bound, and the ``Association`` thread takes one at a time and serves it, a C-STORE
            for as long as its commit takes. A peer that sent objects without waiting for their
            statuses would have them all held there. So while a whole message waits, the DUL
            reads nothing more, and TCP holds the peer back. An association then holds at most
            the message being served and the next one.

            In Sta13 the DUL closes the connection as soon as this is ``False``, and reads a whole
            PDU while it is ``True``. A PDU read there is thrown away, and a stalled one would hold
            the close for a deadline, so this says ``False`` at once. :meth:`_shutdown_socket`
            reads off what has already arrived, so that the A-ASSOCIATE-RJ or A-ABORT just sent is
            not lost to a reset.

            Holding off relies on the ``Association`` thread to answer, and only that thread reads
            the idle timer, so this is also where a DUL finds it has nobody left. If that thread
            has died, in any state, or was killed with no answer queued, no answer is coming and
            nothing else would ever end the DUL: ``kill()`` itself waits for Sta1. So this closes
            the connection, which puts the DUL's own closed-connection event on its queue. A
            rejection queues its answer before it kills, and that answer still has to go out."""
            if self.replay:
                return True
            assoc = self.assoc
            state = assoc.dul.state_machine.current_state
            if state == _STATE_CLOSING:
                return False
            unanswered = state in _STATES_BEFORE_THE_ANSWER
            killed_unanswered = unanswered and assoc._kill and assoc.dul.to_provider_queue.empty()
            if killed_unanswered or not assoc.is_alive():
                self.close()
                return False
            if unanswered or not assoc.dimse.msg_queue.empty():
                return False
            return super().ready

        def _shutdown_socket(self) -> None:
            """``AssociationSocket._shutdown_socket``, after reading off what the peer has already
            sent, so that the close is not over unread data that would reset the connection and
            lose an answer just sent; see :func:`_drain_readable`.

            ``close()``, the DUL's closing actions AA-4, AA-5 and AR-5, and
            ``Association._abort_blocking`` come through here. Not every close does: at least the
            ``Association`` thread's own close, at the end of ``Association.run``, hands the raw
            socket to the server's ``shutdown_request``, which does not drain."""
            if self.socket is not None:
                _drain_readable(self.socket)
            super()._shutdown_socket()

        def recv(self, nr_bytes: int) -> bytearray:
            if self.replay:
                if nr_bytes >= len(self.replay):  # the whole of it: hand it over uncopied
                    served, self.replay = self.replay, bytearray()
                    return served
                served, self.replay = self.replay[:nr_bytes], self.replay[nr_bytes:]
                return served
            if nr_bytes == _PDU_HEADER_BYTES:
                return self._read_pdu()
            if nr_bytes == 0:
                return bytearray()  # an empty body: nothing to read
            # Every other body is read with its header and served from replay, so a read of any
            # other size is one this was not written for. It would pass both checks in _read_pdu,
            # so the association ends instead.
            sock = cast(socket.socket, self.socket)
            reason = "pynetdicom asked for a read the SCP does not check"
            self.server.end_association(sock, _ABORT_INVALID_MESSAGE, self.host, reason)
            return bytearray()

        def _read_pdu(self) -> bytearray:
            """The DUL's read of a PDU header. It reads the body too, keeps it for the DUL's next
            read, and returns the header, or ends the association and returns nothing.

            The declared length is checked before a byte of the body is read (owner ruling
            B462-R3). A P-DATA-TF may be as long as the ``max_pdu_size`` the SCP offered, and no
            longer: pynetdicom fragments to exactly that, and PS3.8 Annex D.1 bounds that field.
            Any other PDU PS3.8 defines may be as long as an association request, since none is
            longer. Over either, the SCP sends an A-ABORT rather than read what may be 4 GiB.

            A P-DATA-TF's fragments are then counted by :class:`_ReceiptTally` before the DUL sees
            them. An object up to twice ``max_object_bytes`` reaches the C-STORE handler, which
            answers ``0xC010``. One past that ends the association with an A-ABORT, so that what
            the SCP holds of one object stays bounded (owner ruling B462-R3). So does a P-DATA-TF
            pynetdicom would fail on.

            Reading the body here also means a body cut short never reaches the DUL, which would
            log it at ERROR. An empty header read is its silent closed connection, and that is what
            each end above returns. A PDU of a type PS3.8 does not define ends the association with
            its body unread, as the DUL's own AA-8 would, but through the throttled line rather than
            the DUL's unthrottled ERROR."""
            server, host = self.server, self.host
            sock = cast(socket.socket, self.socket)
            header = server.read_for_association(sock, _PDU_HEADER_BYTES, host)
            if len(header) < _PDU_HEADER_BYTES:
                return header  # the DUL's silent closed connection
            if header[0] not in _PDU_TYPES:
                reason = "a PDU of a type PS3.8 does not define"
                server.end_association(sock, _ABORT_INVALID_MESSAGE, host, reason)
                return bytearray()
            declared = int.from_bytes(header[2:], "big")
            if header[0] == _PDU_TYPE_P_DATA_TF:
                limit = server.max_pdu_size
            else:
                limit = _MAX_ASSOCIATE_RQ_BYTES - _PDU_HEADER_BYTES
            if declared > limit:
                reason = f"a PDU declared a length over the {limit} bytes the SCP takes"
                server.end_association(sock, _ABORT_PDU_TOO_LONG, host, reason)
                return bytearray()
            body = server.read_for_association(sock, declared, host)
            if len(body) < declared:
                return bytearray()  # the peer closed, or the read ran out: already logged
            if header[0] == _PDU_TYPE_P_DATA_TF:
                ended = self.tally.take(body)
                if ended is not None:
                    server.end_association(sock, ended[0], host, ended[1])
                    return bytearray()
            self.replay = body
            return header

        def send(self, bytestream: bytes) -> None:
            """``AssociationSocket.send``, whole within ``timeout_seconds``, and within
            :data:`_ANSWER_SEND_SECONDS` of noticing a stop. A peer that never reads, or reads a
            little at a time, would otherwise hold the DUL thread here, and a stop with it. A send
            that does not finish is a closed connection, as the stock ``send`` reports one."""
            sock = self.socket
            if sock is None:
                super().send(bytestream)  # it reports the closed socket
                return
            if self.server.send_for_association(sock, bytestream, self.host):
                evt.trigger(self.assoc, evt.EVT_DATA_SENT, {"data": bytestream})
            else:
                self.event_queue.put("Evt17")  # what the stock send does when its send fails

    class _AdmittingRequestHandler(RequestHandler):
        server: _AdmittingAssociationServer

        def handle(self) -> None:
            """``RequestHandler.handle``, with the association request read before the association
            starts. Runs on the connection's own thread, which holds the connection's slot.

            ``EVT_CONN_OPEN`` still fires before anything is read, so an association-rate wait
            still comes first and does not spend the peer's deadline. A connection that ends here
            never started its ``Association``, so there is no thread to stop and no ``kill()`` to
            wait on. The socket is closed, and ``EVT_CONN_CLOSE`` fires, because pynetdicom pairs
            every ``EVT_CONN_OPEN`` with one when its DUL closes a connection, and a handler that
            counts open connections would otherwise drift up with every refused peer."""
            assoc = self._create_association()
            evt.trigger(assoc, evt.EVT_CONN_OPEN, {"address": self.client_address})
            server = self.server
            host = _address_host(self.client_address)
            first_pdu: bytes | None = None
            if _config.STORE_RECV_CHUNKED_DATASET:  # checked at start too; this is the backstop
                server._refused(host, "a connection", _CHUNKED_RECEIPT_REFUSAL)
            else:
                first_pdu = server.read_association_request(self.request, host)
            if first_pdu is None:
                server.shutdown_request(self.request)
                evt.trigger(assoc, evt.EVT_CONN_CLOSE, {"address": self.client_address})
                return
            sock = cast(_AdmittedSocket, assoc.dul.socket)
            sock.__class__ = _AdmittedSocket  # why not a new socket: _admitting_server_class
            sock.replay = bytearray(first_pdu)
            sock.server = server
            sock.host = host
            sock.tally = _ReceiptTally(max_data_set_bytes=2 * server.max_object_bytes)
            assoc.start()

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
            harden_crl_check(ctx, str(crl), setting=f"inbound connection '{name}' tls_crl_file")
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
    #: handler says which, and why (BACKLOG #1910, #2105). See :attr:`SourceConnector.wants_receipt`.
    wants_receipt: ClassVar[bool] = True

    def __init__(self, config: Source) -> None:
        s = config.settings
        self._ae_title = str(s["ae_title"])
        # The bind interface is injected from [inbound].bind_host (authors never set a host on an
        # inbound); fall back to loopback — never bind all interfaces by accident (DIMSE has no
        # transport auth without the AE/IP allowlists + TLS).
        self._host = str(s.get("host") or "127.0.0.1")
        self._port = port_setting(s.get("port", 104), transport="DICOM-SCP source")
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
        self._max_associations = count_setting(
            s.get("max_associations", 10), knob="max_associations", transport="DICOM-SCP source"
        )
        self._max_pdu_size = count_setting(
            s.get("max_pdu_size", 16384), knob="max_pdu_size", transport="DICOM-SCP source"
        )
        if not _MIN_PDU_SIZE <= self._max_pdu_size <= _MAX_PDU_SIZE:
            raise ValueError(
                f"DICOM-SCP source: max_pdu_size must be from {_MIN_PDU_SIZE} to {_MAX_PDU_SIZE}; "
                "0 would offer a peer no limit on a PDU's length, a smaller size breaks a "
                "pynetdicom sender, and a larger one is read whole before it is counted"
            )
        self._timeout = float_setting(
            s.get("timeout_seconds", 30.0), knob="timeout_seconds", transport="DICOM-SCP source"
        )
        if self._timeout < _MIN_TIMEOUT_SECONDS:  # a hard deadline on every read and send
            raise ValueError(
                f"DICOM-SCP source: timeout_seconds must be at least {_MIN_TIMEOUT_SECONDS:g} "
                "second; it is a deadline on every read and send, so a smaller one would end "
                "nearly every peer"
            )
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
        #: Which refusals earn a line; see _log_refused_peer. The accept loop and the association
        #: threads both reach it, and it carries its own lock. It also counts every refusal since
        #: this SCP was built, logged or not, and each line that is written reports that count.
        self._refusal_log = RefusalLog(
            window_seconds=_REFUSAL_LOG_WINDOW_SECONDS, max_per_window=_REFUSAL_LOG_MAX_PER_WINDOW
        )
        #: The same throttle for associations the SCP ended at a read deadline; see
        #: _log_ended_association. Its own, so those never spend an address's refusal line.
        self._ended_log = RefusalLog(
            window_seconds=_REFUSAL_LOG_WINDOW_SECONDS, max_per_window=_REFUSAL_LOG_MAX_PER_WINDOW
        )
        # Build the TLS context now so a bad cert/key fails at build, not at bind (like MLLP/LDAPS).
        self._ssl = _server_ssl_context(s, name=config.name or "")
        # Failed inbound TLS handshakes and their throttled WARNING (vault BACKLOG #3784). Before,
        # a failed one left no record above DEBUG. A log line rather than a connection event: this
        # SCP emits none, and #3784 adds no event kind. Driven on the loop only; the connection
        # threads hand a failure over through `_note_tls_failure`.
        self._tls_failures = HandshakeFailures(self._log_tls_failures)
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
        #
        # The allow-list is weighed, not counted (vault BACKLOG #2622 item 2): ["0.0.0.0/0"] parses
        # and restricts nobody, so it is held to the same prefix floors as the HTTP intake gate, by
        # the same function (netaddr.allowlist_restricts).
        #
        # NOT BUILT HERE, dated 2026-10-06: mTLS is still counted by presence. tls + tls_ca_file
        # accepts any certificate that CA signed and binds no client subject, which the HTTP gate
        # refuses (intake_client_subjects). The Manager deferred that half of #2622 item 2 to
        # #1182 and #316. Read at vault origin/main the same day, #316 is closed (shipped
        # 2026-07-30, the AE-title half) and #1182 is about backend-hop credentials, so no open row
        # yet names this half; #2622 holds it until one does.
        mtls_on = bool(s.get("tls")) and bool(s.get("tls_ca_file"))
        allowlist_on = allowlist_restricts(self._source_ip_allowlist)
        if self._host not in _LOOPBACK_HOSTS and not (allowlist_on or mtls_on):
            unpaired = (
                " You set calling_ae_allowlist, but an AE Title is asserted by the caller and cannot be"
                " verified, so it no longer satisfies this gate alone (BACKLOG #316) — keep it as a"
                " filter and add one of the two controls above."
                if self._calling_ae_allowlist
                else ""
            )
            too_wide = (
                " You set source_ip_allowlist, but an entry in it is wider than"
                f" /{ALLOWLIST_MIN_PREFIX_V4} (IPv4) or /{ALLOWLIST_MIN_PREFIX_V6} (IPv6), or does"
                " not parse, so it restricts nobody it can be shown to and does not count (vault"
                " BACKLOG #2622). Narrow every entry."
                if self._source_ip_allowlist
                else ""
            )
            raise ValueError(
                f"DICOM C-STORE server (SCP) bound non-loopback host {self._host!r} with no verifiable peer "
                "control: set source_ip_allowlist, or mTLS (tls + tls_ca_file), to fail closed "
                f"(deny-by-default, ADR 0025 §9), or bind 127.0.0.1.{too_wide}{unpaired} Authoring surface: pass "
                'them to inbound(...), e.g. inbound("pacs_in", DICOM(...), '
                'source_ip_allowlist=["10.0.0.0/8"]). That is the ONLY surface for a DICOM server (SCP) — the '
                "[inbound] section of messagefoundry.toml has no source_ip_allowlist key and discards it "
                "silently, and while connections.toml [[inbound]] tables do accept the key, none of "
                "their transports is DICOM."
            )
        #: The runner's receipt handler (``wants_receipt``), never the generic InboundHandler.
        self._handler: ReceiptHandler | None = None
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
        self,
        handler: ReceiptHandler | InboundHandler,
        *,
        leader_gate: Callable[[], bool] | None = None,
    ) -> None:
        # leader_gate is ignored: a listen source binds its own per-node endpoint, so there is no
        # shared-resource double-read to gate (accepted only so the runner's call is uniform).
        # wants_receipt makes the runner pass its receipt handler here (BACKLOG #2105). The parameter
        # keeps the base class's InboundHandler beside it only so the override stays substitutable;
        # require_receipt refuses any other handler here, before a single message is accepted.
        self._handler = require_receipt(handler, source="DICOM SCP source")
        self._stopping.clear()  # a restart must not inherit the previous stop's cut-short signal
        self._tls_failures.open()
        self._loop = asyncio.get_running_loop()  # captured ON the loop, before any off-loop work
        # start_server binds a socket + spawns acceptor threads — do it OFF the loop, then it is live.
        await asyncio.to_thread(self._start_server)

    def _start_server(self) -> None:
        # Imported lazily (the [dicom] extra); a missing extra surfaces as an internal/connection error
        # at start, not a per-message data error — like the FHIR/SQL-Server backends.
        from pynetdicom import AE, StoragePresentationContexts, _config, evt
        from pynetdicom.sop_class import (  # type: ignore[attr-defined]
            Verification,  # generated SOP-class const
        )

        if _config.STORE_RECV_CHUNKED_DATASET:
            raise RuntimeError(f"DICOM server (SCP) not started: {_CHUNKED_RECEIPT_REFUSAL}")

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
            ended=self._log_ended_association,
            handshake_failed=self._note_tls_failure,
            stopping=self._stopping,
            max_pdu_size=self._max_pdu_size,
            max_object_bytes=self._max_object_bytes,
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

    @property
    def tls_handshake_failures(self) -> int:
        """Failed inbound TLS handshakes this SCP has seen since it was built, outside its stop()s
        (vault BACKLOG #3784)."""
        return self._tls_failures.count

    def _note_tls_failure(self, peer_ip: str, cause: str) -> None:
        """Hand a failed handshake from a connection thread to the loop, which owns the counter
        and its timer. Never raises into the connection thread."""
        loop = self._loop
        if loop is None:
            return
        # A closed loop has no stop() left to report to, so the failure goes with it.
        with contextlib.suppress(RuntimeError):
            loop.call_soon_threadsafe(self._tls_failures.note_soon, peer_ip, cause)

    def _log_tls_failures(self, peer_ip: str | None, reason: str) -> None:
        """The SCP's record of failed handshakes: a WARNING, throttled by its counter. It names the
        peer address, a routing-safe identifier, only for a single failure."""
        logger.warning(
            "TLS handshake failed on DICOM server (SCP) %s%s: %s",
            self._ae_title,
            "" if peer_ip is None else f" from {peer_ip}",
            reason,
        )

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
        of live connections per host, and its episode ends when the host has none left. A peer
        refused at accept never holds a connection, so it has no episode to end. The window throttle is
        :class:`~messagefoundry.transports.admission.RefusalLog`, which the socket listeners use for
        their allowlist refusals too (vault BACKLOG #2606).
        """
        self._throttled_warning(
            self._refusal_log, peer_ip, f"refused {what} from {peer_ip}", reason, "refused"
        )

    def _log_ended_association(self, peer_ip: str, reason: str) -> None:
        """Log an association the SCP ended: because a read or a send ran out its deadline, or
        because the peer sent a PDU longer than the SCP takes, or an object past twice its cap.
        The same throttle as :meth:`_log_refused_peer`, but a count and a table of its own.

        It is not a refusal. The SCP accepted the association, and may have taken objects on it,
        so the line says it ended one, and it does not spend the address's refusal line for the
        window. A peer can make one of these as often as it can finish an association request,
        so it is throttled the same way. The line names the address and the deadline or the
        limit, never a byte the peer sent."""
        self._throttled_warning(
            self._ended_log, peer_ip, f"ended an association with {peer_ip}", reason, "ended so"
        )

    def _throttled_warning(
        self, log: RefusalLog, peer_ip: str, event: str, reason: str, counted: str
    ) -> None:
        """One WARNING for ``event``, if ``log`` lets ``peer_ip`` have a line in this window. The
        line carries ``log``'s running count, logged or not, as ``<count> <counted> in all``."""
        total = log.note(peer_ip)
        if total is None:
            return
        logger.warning(
            "DICOM server (SCP) %s %s: %s. An address is logged at most once every %gs. %d %s in "
            "all since this server started.",
            self._ae_title,
            event,
            reason,
            log.window_seconds,
            total,
            counted,
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

        **This wait drops, refuses and answers nothing differently.** The peer is back-pressured by TCP
        while we decline to read, then its association proceeds in full. The delay is bounded by the
        deficit (``associations / rate``) rather than being a hard stop, for the reason
        :class:`~messagefoundry.transports.mllp._MessagePacer` gives: refusing to read at all would pin
        capacity indefinitely.

        **Residual, stated because a knob that hides one is worse than no knob.** The waiting
        connection has no association yet, so it holds one of the slots
        :data:`_MAX_PENDING_CONNECTIONS` and its per-address twin count (vault BACKLOG #2712). A rate
        low enough to make waits long can fill them, and a connection over them is closed, which is
        the cap refusing it, not this wait. A wait that outlasts the SCU's own ACSE timeout becomes an
        abort on the sender's side, which is a refusal this control is otherwise careful never to
        make. That is the DIMSE form of the general residual: a bound that demands a number cannot
        demand a sensible one.
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
        would hold a pending connection slot per sender, and would outlast the sender's own
        association timeout, which then drops the connection with no reason given. The rejection
        says what happened, at once.

        **A peer the association checks would refuse gets that refusal instead.** An unlisted calling
        AE or a wrong called AE is left to pynetdicom, which refuses it permanently right after this
        handler, reading the same ``AE`` settings this does. So the pause neither tells such a peer to
        retry nor reveals to it that intake is paused. ``source_ip_allowlist`` needs no mirror here:
        the SCP applies it when the connection is accepted (:meth:`_admit_connection`), so a peer
        outside it is closed before it can send an association request. A request that does not
        decode, has the wrong protocol version, or does not negotiate is answered before this runs,
        on the connection's own thread, so it gets that answer whatever the pause or its AE titles.

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

        The handler returns a receipt: the committed message id, or a refusal, when it then recorded
        ``ERROR`` and committed no ingress row. A refusal is a DIMSE failure, never Success (BACKLOG
        #1910), mapped in step with the HTTP listener's answer (BACKLOG #2105). A TEMPORARY refusal
        may clear on a re-send, so it answers Out of Resources, as the HTTP listener answers ``503``. A
        permanent or over-size one is Cannot Understand, the status the decode-failure path already
        answers for an object the engine will not take: the same object would be refused again. A
        handler that RAISES, or does not answer in time, has committed nothing for a reason that may
        clear, such as a store that is down, so both answer Out of Resources and the sender re-sends
        (BACKLOG #2103)."""
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
        # The runner's receipt handler is an async def (a Coroutine), but ReceiptHandler is typed as the
        # Awaitable; run_coroutine_threadsafe needs a Coroutine, so narrow it.
        coro = cast("Coroutine[Any, Any, IngressReceipt]", handler(object_bytes))
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
        if receipt.refusal is not None:
            logger.warning(
                "DICOM C-STORE refused by engine ingress from %s (SOP %s): recorded ERROR %s (%s), "
                "returning failure",
                peer_ip,
                sop_instance,
                receipt.message_id,
                receipt.refusal.value,
            )
            if receipt.refusal is RefusalKind.TEMPORARY:
                return _STATUS_OUT_OF_RESOURCES
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
        # In the same loop step, so a failure a connection thread hands over from here on, the
        # ones the stop causes among them, is not counted (vault BACKLOG #3784). A genuine failure
        # that reaches the loop from here on, through the whole of the shutdown below, is dropped
        # with them: the loop cannot tell the two apart.
        self._tls_failures.close()
        # Shut the blocking pynetdicom AE server down OFF the loop (it stops accepting new associations,
        # aborts active ones, and joins its threads) so teardown never stalls the loop. Idempotent.
        server = self._server
        try:
            if server is not None:
                await asyncio.to_thread(server.shutdown)
            # Only once the shutdown returned: one that raised or was cancelled keeps the server,
            # so the next stop() shuts it down again.
            self._server = None
            self._ae = None
        finally:
            # Even when the shutdown raised or was cancelled, report the handshake failures the
            # trailing line still held (vault BACKLOG #3784).
            await self._tls_failures.flush()


def _client_ssl_context(
    s: dict[str, Any], *, trust_anchor_policy: TrustAnchorPolicy | None = None, name: str = ""
) -> ssl.SSLContext | None:
    """Build the SCU's **client** ``SSLContext`` for DICOM-over-TLS dialing a downstream PACS, or
    ``None`` when ``tls`` is off. Built via :func:`ssl.create_default_context` (like MLLP/REST) so it
    verifies the peer's server cert (hostname + chain) and — crucially — loads the **system trust
    store** when ``tls_ca_file`` is unset (a bare ``SSLContext(PROTOCOL_TLS_CLIENT)`` would have an empty
    store and reject every cert). ``tls_ca_file`` pins a private trust anchor instead; ``tls_cert_file``/
    ``tls_key_file`` opt into mTLS. Verification is never disabled (a downstream is a PHI egress). TLS
    1.2+ floor. Built once at construction so a bad cert/key fails at build (dry-run/``check``), not at
    the first delivery — the client mirror of :func:`_server_ssl_context`. ``tls_key_password`` decrypts
    a passphrase-encrypted mTLS client key (``env()``-sourced, mirroring MLLP). ``name`` is the
    connection's, for a refusal of an unreadable ``tls_ca_file`` to name (vault BACKLOG #2370), and
    a suite refusal too (BACKLOG #3096).

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
            connection=name or None,
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
    # BACKLOG #3096: a suite refusal names the connection when the caller passed one, as the runner
    # does, so an operator with several DICOM destinations knows which one to fix.
    connector = f"DICOM destination {name!r}" if name else "DICOM destination"
    # See the SCP listener above: narrow first (ADR 0188), assert second, both visible here.
    apply_connection_tls_ciphers(ctx, s, connector=connector)  # opt-in per-hop suite list
    harden_cipher_suites(ctx, connector=connector)  # assert forward secrecy (ASVS 12.1.2)
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
        self._port = port_setting(s.get("port", 104), transport="DICOM-SCU destination")
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
        self._max_pdu_size = count_setting(
            s.get("max_pdu_size", 16384), knob="max_pdu_size", transport="DICOM-SCU destination"
        )
        self._timeout = float_setting(
            s.get("timeout_seconds", 30.0),
            knob="timeout_seconds",
            transport="DICOM-SCU destination",
        )
        self._connect_timeout = float_setting(
            s.get("connect_timeout", 10.0),
            knob="connect_timeout",
            transport="DICOM-SCU destination",
        )
        # Build the client TLS context now so a bad cert/key fails at construction (check/dry-run), not
        # at the first delivery (like the SCP / MLLP / REST). #190 (ADR 0093): thread the instance [tls]
        # internal-CA trust-anchor policy so an internal hop that names no tls_ca_file of its own verifies
        # against the org internal CA.
        self._ssl = _client_ssl_context(
            s, trust_anchor_policy=config.trust_anchor_policy, name=config.name
        )
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
        # BACKLOG #2193 (ADR 0173): a DICOM-over-TLS association verifies the PACS certificate, but
        # stdlib ssl checks no OCSP or CRL, so a revoked certificate would still be accepted on a hop
        # that carries imaging objects. Taken whenever TLS is on: this connector has no verify-off
        # arm, so a context here always verifies. Handed `self._ssl`, the context the association
        # really dials with, so a [tls].crl_file that reached this hop relaxes the refusal and a hop
        # it never reached keeps it. Disjoint from the cleartext guard above, which is taken only
        # when TLS is off.
        #
        # A context that skips validity-period checks (tls_allow_expired) earns no CRL credit, so it
        # is handed to the guard as no context: see skips_validity_period (vault BACKLOG #2978, ADR
        # 0173 §13). The owner's 2026-10-05 ruling names MLLP; its reach to this hop is the batch 191
        # Manager's reading of "one rule everywhere".
        if self._ssl is not None:
            expiry_relaxed = skips_validity_period(self._ssl)
            RevocationHopGuard.capture(
                host=self._host,
                cell="DICOM C-STORE client (SCU) over TLS",
                description="verified DICOM-over-TLS association (no revocation check)",
                attested=config.tls_revocation_attested,
                attested_reason=config.tls_revocation_attested_reason,
                connection=config.name,
                context=None if expiry_relaxed else self._ssl,
                ways_across=EXPIRY_RELAXED_WAYS_ACROSS if expiry_relaxed else None,
            ).enforce_construction()

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

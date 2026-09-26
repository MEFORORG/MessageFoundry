# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""MLLP (Minimal Lower Layer Protocol) transport + HL7 ACK building.

MLLP wraps each message in a *block*::

    <0x0B> message-bytes <0x1C><0x0D>
     SB                   EB    CR

The single most common place toy engines break is framing: forgetting the trailing CR,
treating the SB/EB bytes as message content, or assuming one message per TCP read. A
real peer may split a message across reads or pack several into one. :class:`MLLPDecoder`
is a stateful, byte-accurate reassembler that handles both.

ACKs are built from the inbound MSH (echoing its encoding characters, swapping
sender/receiver, copying the original control id into MSA-2). ``ack_mode`` selects the
MSA-1 code family: ``original`` → AA/AE/AR, ``enhanced`` → CA/CE/CR.

The framing and ACK builder are defined in the client-importable leaf
:mod:`messagefoundry.mllpcodec` (BACKLOG #1697) and re-exported here; this module adds the
connectors, their TLS and their resource caps.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import hl7
from hl7.containers import Component, Field, Repetition

from messagefoundry.auth.trust_anchors import inbound_ca_cadata, refuse_an_unread_ca_pin
from messagefoundry.config.models import ConnectorType, ContentType, Destination, Source
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    weakened_tls_escape_permitted_here,
)
from messagefoundry.config.tls_policy import (
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    TrustAnchorPolicy,
    apply_connection_tls_ciphers,
    build_verifying_client_context,
    cleartext_acceptance_audit_sink,
    current_hop_posture,
    enforce_insecure_hop,
    harden_cipher_suites,
    harden_crl_check,
    harden_kex_groups,
    harden_verify_flags,
    insecure_hop_disposition,
    is_loopback_hop_host,
    relax_verify_expiry,
    resolve_trust_anchor,
)
from messagefoundry.mllpcodec import (
    _CODES,
    CR,
    DEFAULT_MAX_FRAME_BYTES,
    EB,
    SB,
    AckMode,
    MLLPDecoder,
    MLLPFrameError,
    build_ack,
    frame,
)
from messagefoundry.parsing.message import emit_raw_separators
from messagefoundry.parsing.peek import HL7PeekError, Peek, normalize
from messagefoundry.redaction import clamp_untrusted, safe_exc
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    peer_ip_allowed,
    probe_tcp_reachable,
    register_destination,
    register_source,
)

__all__ = [
    "SB",
    "EB",
    "CR",
    "DEFAULT_MAX_FRAME_BYTES",
    "DEFAULT_MAX_FRAME_SECONDS",
    "DEFAULT_MAX_CONNECTIONS",
    "DEFAULT_MAX_CONNECTIONS_PER_HOST",
    "DEFAULT_RECEIVE_TIMEOUT",
    "frame",
    "MLLPDecoder",
    "MLLPFrameError",
    "build_ack",
    "EncodingCharacters",
    "parse_encoding_characters",
    "reencode_delimiters",
    "MLLPDestination",
    "MLLPSource",
    "InsecureHopGuard",
]

logger = logging.getLogger(__name__)

# SB/EB/CR, DEFAULT_MAX_FRAME_BYTES, frame(), MLLPDecoder, MLLPFrameError and build_ack() live in the
# client-importable leaf `messagefoundry.mllpcodec` (BACKLOG #1697) and are re-exported here, so
# engine callers and tests that import them from this module keep working.

# Resource caps (DoS guards). All are overridable per connection via MLLP() settings; see
# docs/CONNECTIONS.md. A falsy value (None/0) in settings disables the cap explicitly. The frame
# cap, DEFAULT_MAX_FRAME_BYTES, is defined in `messagefoundry.mllpcodec` beside the decoder.
DEFAULT_MAX_CONNECTIONS = 256  # bound concurrent inbound clients (connection-flood guard)
DEFAULT_RECEIVE_TIMEOUT = 60.0  # seconds — close inbound sockets idle this long (slowloris guard)

#: Seconds one frame may take from its START byte to its END byte (BACKLOG #1725).
#:
#: :data:`DEFAULT_RECEIVE_TIMEOUT` bounds SILENCE between reads and resets on every byte received, so
#: a peer trickling one byte at a time INSIDE A FRAME is never idle: it would hold its slot — and up
#: to ``max_frame_bytes`` of decoder buffer — for as long as it liked, without ever completing a
#: message. This bounds the frame itself, so the two answer different questions and **both apply**.
#: They are deliberately kept apart: dropping the per-read timeout would lose the idle-socket bound,
#: which is a separate property and still wanted (a peer that opens a socket and says nothing at all
#: never opens a frame, so no frame deadline would ever fire on it).
#:
#: **The clock runs from a START byte, and a peer that never sends one is outside it.** Inter-frame
#: noise is discarded by the decoder without opening a frame, so a peer trickling bytes that are not
#: an MLLP frame is neither idle nor in-frame and holds its slot. It buffers nothing, so the memory
#: half of the threat is absent, and ``max_connections_per_host`` bounds how many slots one address
#: can hold that way — but it is not bounded by THIS key, and reading it as "no peer can hold a slot
#: without sending a message" would be wrong. Closing that needs a bound on a different unit
#: (connected time without a completed message), which is a separate decision from this one.
#:
#: 60 s matches the idle bound, so the shipped posture reads as "a frame gets about as long to arrive
#: as a quiet socket gets to stay open". ``None``/``0`` disables it, like every cap here.
#:
#: **It does not derive from** :data:`DEFAULT_MAX_FRAME_BYTES`, **and the pair is only satisfiable
#: above a certain link speed.** Delivering the 16 MiB the byte cap permits inside 60 s needs roughly
#: 2.2 Mbps sustained on that one socket. A connection carrying large embedded documents — a base64
#: PDF spliced into OBX-5.5, ADR 0105 — over a slower WAN link will hit the deadline mid-document on
#: every message. **Raise this key whenever you raise** ``max_frame_bytes``: the two are one bound on
#: a frame expressed in two units, and setting only the byte half is how a feed that was working
#: starts being dropped. Nothing warns about the combination at start today; wiring that check is
#: left unbuilt rather than guessed at, since the honest threshold is a link speed the engine cannot
#: see.
DEFAULT_MAX_FRAME_SECONDS = 60.0

#: Concurrent inbound clients allowed from ONE peer address (BACKLOG #1725).
#:
#: :data:`DEFAULT_MAX_CONNECTIONS` counts sockets, not hosts, so one peer can take every slot a
#: listener has; ``source_ip_allowlist`` ships off, so on a default listener there is no other
#: peer-scoped term at all. 32 is an eighth of the global cap, and that ratio is the point of the
#: number — a per-host cap set near the global one bounds nothing, while at an eighth it takes at
#: least eight distinct source addresses to fill a default listener. It is still far above what a
#: real partner needs: MLLP is request/response over one socket per sending channel, so a partner
#: holding thirty-two simultaneous connections into one listener port is already unusual.
#:
#: **What it does NOT bound, stated because the cap is easy to over-read.** It keys on the source
#: address, so an attacker holding eight addresses — an IPv6 /64 hands out far more — gets a fresh
#: budget per address and is bounded by :data:`DEFAULT_MAX_CONNECTIONS` alone. This raises the floor
#: on the single-address case the row measured; it does not make a listener safe against a
#: distributed peer, and nothing here should be read as claiming it does.
#:
#: This is a CONNECTION cap, not a rate cap, which is why it does not simply contradict
#: :class:`_MessagePacer`'s "never scoped per PEER". That rule is about a per-IP MESSAGE budget,
#: where NAT makes two feeds behind one egress address throttle each other. A slot cap refuses
#: pre-ingress at accept, exactly like the ``max_connections`` refusal, so nothing was received to
#: drop and the peer reconnects as soon as one of its own connections ends.
#:
#: **The NAT objection does still land on one topology, and it ships ON, so say so plainly.** Behind
#: a source-NAT load balancer or proxy that does not preserve the client address, EVERY partner
#: arrives as one peer and this becomes the effective listener capacity — 32 rather than 256, while
#: the operator is reading ``max_connections`` in their config. That is a real way to lose a go-live.
#: Two things make it survivable rather than a trap: the refusal names itself (a
#: ``max_connections_per_host`` reason on the ``at_capacity`` event, and one warning per episode), so
#: the diagnosis is the log line rather than an investigation; and ``None``/``0`` turns it off, which
#: is the documented setting for exactly that topology. A proxied listener has a single upstream
#: address it trusts, so it is the deployment with the least to gain from a per-host term anyway.
DEFAULT_MAX_CONNECTIONS_PER_HOST = 32

#: Message-rate pacing ships OFF, and that is a DELIBERATE DEVIATION from this module's
#: "key absent -> secure default" convention, ruled 2026-08-11 (ASVS 2.4.1 / 15.2.2). A rate limit
#: on a clinical interface is only safe at a number derived from a real feed profile, and this
#: project has no site data to derive one from — shipping a guessed default would throttle real
#: traffic, which is a worse failure than the unbounded intake it would be guarding. So the
#: mechanism exists and an operator opts in with their own number. The cell stays `partial` on the
#: shipped default and the record says why; that is the honest outcome, not a disappointing one.
DEFAULT_MAX_MESSAGES_PER_SECOND: float | None = None

#: Seconds between operator-facing pacing reports on ONE pacer (BACKLOG #290). Pacing is silent by
#: construction — it never drops, NAKs or errors — so without a report an operator cannot tell a
#: paced interface from a slow one. A pacer in deficit is consulted on every read, so the report is
#: throttled to this window; see :meth:`_MessagePacer._note_paced`.
_PACING_REPORT_SECONDS = 60.0
# On stop()/reload, established clients are closed and their handlers given this long to finish an
# in-flight commit before the connection tasks are cancelled — bounds shutdown so a peer holding a
# connection open can't hang it (review H-2).
_CLIENT_SHUTDOWN_GRACE = 5.0

# Seconds one ACK gets to drain to the sender before the connection is dropped (BACKLOG #1617).
# `receive_timeout` bounds the READ and nothing bounded the WRITE, so a peer that stops consuming —
# its receive window full, the connection still open — would pin the client task and the
# `max_connections` slot it holds for as long as it liked: the slow-READER half of the slow-loris the
# read bound exists to stop. Deliberately the shutdown grace rather than a new per-connection knob.
# An MLLP ACK is engine-generated and receipt-sized (`InboundHandler` returns a `str`, never a
# partner-sized body), so there is nothing to size an operator budget against; and reusing
# `receive_timeout` would be worse than useless, since its documented `None`/`0` = "no timeout" would
# restore the unbounded drain through a supported setting. The HTTP listener bounds its
# `202`-on-receipt write by this same constant for the same reason (`http_listener._drain_budget`).
# Named apart from the grace it equals because the two answer different questions — how long one ACK
# may take to leave, versus how long teardown waits for in-flight handlers — and a test that bounds
# one must not silently shrink the other.
_ACK_DRAIN_GRACE = _CLIENT_SHUTDOWN_GRACE

# Seconds a TLS listener waits for a new connection to finish its handshake (BACKLOG #1606).
# `_on_client` runs only after the handshake, so until then a socket is outside `_clients` and the
# `max_connections` count, and asyncio's own default of 60 s was the only bound on it. A peer that
# opened sockets and never sent a ClientHello could hold each one that long, uncounted. A handshake
# is a few round trips of engine-fixed work, so 10 s is generous even across a slow WAN hop.
# A constant rather than a per-connection setting, for the reason `_ACK_DRAIN_GRACE` gives: there is
# no feed-shaped traffic to size it against, and a setting would carry the `None`/`0` = "off" spelling
# every cap here accepts, which would restore the unbounded window through a supported value.
# **This bounds how LONG an unhandshaken socket lives, not how MANY there are.** A peer that keeps
# opening them still holds about its connect rate times this window, outside `max_connections`,
# `max_connections_per_host` and `source_ip_allowlist`, which all act only in `_on_client`. When it
# fires, asyncio aborts the socket and logs that only in debug mode, so nothing reaches the log.
_TLS_HANDSHAKE_TIMEOUT = 10.0

# Seconds a closed TLS connection waits for the peer's close_notify before the socket is dropped
# (BACKLOG #1606). asyncio's default is 30 s, and it runs AFTER the handler has freed the connection's
# `max_connections` slot, so a peer that never answered held each socket that long uncounted. Equal
# to the shutdown grace, and named apart from it for the reason `_ACK_DRAIN_GRACE` gives: shortening
# teardown in a test must not silently shorten this too. stop() does not wait for it; see stop().
_TLS_SHUTDOWN_TIMEOUT = _CLIENT_SHUTDOWN_GRACE

#: Characters of a negative acknowledgment's MSA-3 that reach the :class:`NegativeAckError` message
#: (BACKLOG #1576). MSA-3 is *Text Message* — a human-readable reason for the rejection — and the
#: consumers of it are a log line, a dead-letter row's ``last_error`` and an alert, each of which
#: redacts and then truncates to :data:`~messagefoundry.redaction._DEFAULT_LIMIT` (200) anyway. Five
#: times that is room for a peer to name the offending segment and then some. MSA-1 and MSA-2 share
#: the bound through :func:`_bounded_ack_field`; MSA-3 is the field it was sized for.
#:
#: **The bound belongs here rather than only downstream because the length is the PEER's to choose.**
#: ``receive_max_bytes`` caps the ACK frame, not this field inside it, so MSA-3 arrives sized to the
#: frame cap — 16 MiB by default — and redaction is a linear event-loop scan that would be charged all
#: of it. Bounding at the read keeps the peer's string out of the exception text, the store write and
#: the log, not merely out of the scan.
_MAX_NAK_DETAIL_CHARS = 1024

#: MSA-3 of the NAK an MLLP listener sends when its inbound handler faults (BACKLOG #1619). Fixed and
#: value-free: it names no exception, because the fault's text can carry message content.
_HANDLER_FAILURE_NAK_TEXT = "message not accepted: internal error, retry later"

#: How much of a faulted frame is read to find the MSH segment its NAK echoes (BACKLOG #1619). A
#: header longer than this is not echoed; the NAK then carries the header defaults.
_NAK_HEADER_SCAN_BYTES = 64 * 1024


def _bounded_ack_field(value: str | None) -> str:
    """A peer-chosen ACK field, bounded for the exception message it is about to be written into
    (BACKLOG #1576, #1847).

    One helper for every peer-sized field that reaches a raise (MSA-1, MSA-2 and MSA-3 today), so
    they cannot drift: adding the bound to MSA-3 and leaving MSA-2 beside it is the shape #1576
    arrived in, and MSA-1 was the one left after that (#1847).
    ``clamp_untrusted`` and not a slice -- cutting at an arbitrary offset strands a fragment under the
    redactor's thresholds and walks the identifier into the log downstream."""
    return clamp_untrusted(value or "", window=_MAX_NAK_DETAIL_CHARS)


# --- posture-keyed cleartext-hop refusal (#200, ADR 0092) --------------------------------------
#
# The raw-TCP / DIMSE / plain-FTP outbound transports carry PHI over a hop with NO TLS (mllp/dicom when
# tls is off) or no TLS option at all (tcp/x12/anonymous-ftp). Off-loopback that is cleartext PHI on the
# wire, and it was UNGUARDED before #200. `InsecureHopGuard` consumes the ONE pure authority
# (`config.tls_policy.insecure_hop_disposition`) so every raw transport decides identically — refuse a
# production-PHI cleartext hop, warn on a non-production PHI hop, allow a loopback / synthetic /
# per-connection-attested hop. It lives here (the raw-TCP hub tcp.py/x12.py already import from) and is
# imported by dicom.py/remotefile.py too, so the gradient is applied in exactly one place, never re-forked.


@dataclass(frozen=True, slots=True)
class InsecureHopGuard:
    """A captured cleartext-hop refusal decision for one outbound connector (#200, ADR 0092).

    Built once at connector construction via :meth:`capture`, which snapshots the active hop posture
    (:func:`~messagefoundry.config.tls_policy.current_hop_posture`). :meth:`enforce_construction` is the
    ENFORCED gate — it fires inside ``build_check`` (``messagefoundry check`` / dry-run / reload / the
    serve pre-flight), where the derived posture IS stamped, and refuses a production-PHI cleartext hop
    there. :meth:`assert_send` is the zero-I/O send-time backstop at the byte crossing. Both **no-op when
    the posture is unstamped** (``None`` — a live serve build after the pre-flight, or a direct
    test/embedding): the enforced gate has already validated the config, so fail-closing here would
    wrongly refuse a legitimate non-prod cleartext lane that ``build_check`` allowed (and would break
    every live serve of such a lane, since the live-build sites are deliberately not re-gated)."""

    host: str
    port: int
    cell: str
    description: str
    attested: bool
    attested_reason: str | None
    posture: HopPosture | None
    # ADR 0153 decision 2: the operator's declaration that THIS hop is cleartext, is not secure, and
    # that is accepted. Distinct from `attested` above, which claims the opposite (the hop IS secure by
    # means the engine cannot see) — never fuse the two, the audit trail exists to tell them apart.
    cleartext_accepted: bool = False
    cleartext_reason: str | None = None
    # The DECLARING connection's name. It is what makes the acceptance audit record actionable: `cell`
    # is a static family label, so with two outbounds to the same host an auditor could otherwise not
    # tell which declaration produced the crossing.
    connection: str | None = None

    @classmethod
    def capture(
        cls,
        *,
        host: str,
        port: int,
        cell: str,
        description: str,
        attested: bool,
        attested_reason: str | None,
        cleartext_accepted: bool = False,
        cleartext_reason: str | None = None,
        connection: str | None = None,
    ) -> InsecureHopGuard:
        """Snapshot the decision inputs + the active hop posture for a cleartext outbound hop. ``cell`` is
        a short PHI-free label of the crossing; ``description`` explains the hop (scheme only — never a
        credential or a body)."""
        return cls(
            host=host,
            port=port,
            cell=cell,
            description=description,
            attested=attested,
            attested_reason=attested_reason,
            cleartext_accepted=cleartext_accepted,
            cleartext_reason=cleartext_reason,
            connection=connection,
            posture=current_hop_posture(),
        )

    def _disposition(self, posture: HopPosture) -> HopDisposition:
        return insecure_hop_disposition(
            enforcing=posture.enforcing,
            is_loopback_hop=is_loopback_hop_host(self.host),
            hop_attested=self.attested,
            # ADR 0153: the data label is gone, and with it the blunt global MEFOR_ALLOW_INSECURE_TLS
            # escape — a cleartext hop is now crossed only on-box, on an attestation, on a per-connection
            # acceptance, or under a non-enforcing dial.
            cleartext_accepted=self.cleartext_accepted,
        )

    def _detail(self) -> str:
        return f"{self.description} to {self.host}:{self.port} (no verified TLS on the hop)"

    def enforce_construction(self) -> None:
        """The ENFORCED construction gate: raise
        :class:`~messagefoundry.config.tls_policy.InsecureHopRefused` on an unattested, unaccepted
        enforcing cleartext hop, loud-log (+ audit the attestation / the acceptance) on a warned hop,
        allow the rest. No-op when the posture is unstamped (``None``) — the build_check gate is the
        authority; see the class docstring."""
        posture = self.posture
        if posture is None:
            return
        disposition = self._disposition(posture)
        # Audit an attestation that SUPPRESSED a would-be enforcing refusal (ADR 0092 decision 3): the
        # disposition is ALLOW only because `tls_hop_attested` fired before the REFUSE arm. The
        # `posture.is_phi` conjunct this branch used to carry went with ADR 0153 — the authority no
        # longer reads the label, so gating the audit on it would silence the record for exactly the
        # hops that newly depend on the attestation.
        if (
            disposition is HopDisposition.ALLOW
            and self.attested
            and posture.enforcing
            and not is_loopback_hop_host(self.host)
        ):
            logger.warning(
                "insecure hop crossed on operator attestation — %s: %s (tls_hop_attested; reason: %s)",
                self.cell,
                self._detail(),
                self.attested_reason or "(none provided)",
            )
        enforce_insecure_hop(
            disposition,
            message=self._detail(),
            cell=self.cell,
            # ADR 0153 decision 2: an ACCEPTED cleartext hop is recorded at EVERY construction, not just
            # warned — an accepted risk that stops being visible has stopped being accepted. Only wired
            # when the acceptance is what produced the WARN, so a merely non-enforcing instance does not
            # manufacture acceptance records for hops nobody declared.
            audit_sink=(
                cleartext_acceptance_audit_sink(self.cleartext_reason, connection=self.connection)
                if disposition is HopDisposition.WARN and self.cleartext_accepted
                else None
            ),
        )

    def assert_send(self) -> None:
        """Zero-I/O send-time backstop: re-assert the captured decision at the byte crossing (defense in
        depth against a reload / per-message routing PHI around the construction-only gate). Raises
        :class:`~messagefoundry.config.tls_policy.InsecureHopRefused` on REFUSE; silent otherwise (the
        construction gate already logged any WARN, so re-warning per message would flood the log). No-op
        when the posture is unstamped (``None``)."""
        posture = self.posture
        if posture is None:
            return
        if self._disposition(posture) is HopDisposition.REFUSE:
            raise InsecureHopRefused(f"{self.cell}: {self._detail()}")


def _set_tcp_nodelay(writer: asyncio.StreamWriter) -> None:
    """Disable Nagle's algorithm on the underlying TCP socket.

    MLLP is a small-frame request-response protocol (write one framed message, drain, block on the
    ACK). With Nagle on, a small write that has no unacked data outstanding is held until the peer's
    delayed-ACK timer fires, so the request-response round-trip eats a ~tens-of-ms stall per exchange
    — crippling on the ADR 0067 persistent path where every delivery is one tiny frame each way. This
    also covers the underlying TCP socket under TLS (the option lives on the raw socket). Best-effort:
    a missing socket or an OS that rejects the option is harmless (framing correctness is unaffected).
    """
    sock = writer.get_extra_info("socket")
    if sock is not None:
        with contextlib.suppress(OSError):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


# --- per-outbound encoding-character override (Corepoint -override parity) ----

#: The five MSH delimiter characters, in MSH order: MSH-1 (field separator) then the four MSH-2
#: characters (component, repetition, escape, subcomponent). A target set for an outbound re-encode.
EncodingCharacters = tuple[str, str, str, str, str]

#: The number of characters an ``encoding_characters`` override must carry (MSH-1 + 4 MSH-2 chars).
_ENCODING_CHARS_LEN = 5


def parse_encoding_characters(value: str) -> EncodingCharacters:
    """Validate an ``encoding_characters`` override and split it into its five MSH delimiters.

    ``value`` is the MSH-1 field separator followed by the four MSH-2 characters
    (component, repetition, escape, subcomponent) — e.g. the HL7 default ``"|^~\\&"``. Fails **loud**
    (``ValueError``) on a bad value rather than silently shipping a malformed header: it must be exactly
    five characters and all five must be distinct (HL7 forbids reusing a delimiter for two roles — a
    collision would make the message ambiguous to the receiver). Called once at connector build so a bad
    config is caught at dry-run / ``check`` time, not per delivery."""
    if not isinstance(value, str) or len(value) != _ENCODING_CHARS_LEN:
        raise ValueError(
            f"encoding_characters must be exactly {_ENCODING_CHARS_LEN} characters "
            "(MSH-1 field separator + the 4 MSH-2 chars: component, repetition, escape, subcomponent), "
            f"got {value!r}"
        )
    if len(set(value)) != _ENCODING_CHARS_LEN:
        raise ValueError(
            f"encoding_characters {value!r} reuses a delimiter — all five (field, component, "
            "repetition, escape, subcomponent) must be distinct"
        )
    # Index explicitly rather than unpack the str (mypy disallows str-unpacking) — the five characters
    # are MSH-1 then the four MSH-2 chars, in order.
    return value[0], value[1], value[2], value[3], value[4]


def reencode_delimiters(payload: str, target: EncodingCharacters) -> str:
    """Re-serialize ``payload`` (an HL7 v2 message) with the ``target`` MSH delimiters.

    The message is parsed with its **own** current delimiters (read from its MSH-1/MSH-2, never assumed
    to be ``|^~\\&``), then re-joined with the target field/component/repetition/subcomponent separators
    and a rewritten MSH-1/MSH-2 — so a downstream re-parse sees the same logical fields under the new
    delimiters. This is the "parse → set new MSH-1/MSH-2 → re-encode" contract, done by re-joining the
    parse tree rather than by string-slicing the raw bytes.

    Leaf values are carried through **verbatim except for the escape character**: structural delimiters
    never appear literally inside a leaf (they are escaped), and HL7's named escapes (``\\F\\``,
    ``\\S\\`` …) are delimiter-agnostic — only their surrounding escape character changes when the
    escape character does. Crucially we do **not** round-trip leaves through python-hl7's
    ``unescape``/``escape`` (which corrupt code points above U+007F — accented/CJK names — and would
    silently mangle PHI; the same quirk :class:`~messagefoundry.parsing.message.Message` avoids). When
    the source already uses the target escape character, leaves are byte-identical.

    Raises :class:`ValueError` if ``payload`` is not parseable HL7 (no MSH / malformed header), so the
    caller can fail the delivery loud instead of framing a corrupted message."""
    field_sep, comp, rep, esc, sub = target
    try:
        message = hl7.parse(normalize(payload))
        seg_sep: str = message.separator  # segment separator (CR) is not part of the override
        src_esc: str = message.esc  # the source message's own escape character
    except (hl7.HL7Exception, IndexError, ValueError, AssertionError) as exc:
        # IndexError covers a header so truncated python-hl7 can't read MSH-2 (e.g. "MSH"); ValueError
        # is defensive. AssertionError is python-hl7's own header check, which a header with no field
        # separator before its first segment break trips ("MSH\rPID|1", "MSH|\rPID|1"; BACKLOG
        # #1601). A non-HL7 body simply cannot be delimiter-rewritten — surface it, don't corrupt.
        # safe_exc names the type: python-hl7's AssertionError carries no message of its own.
        raise ValueError(
            f"cannot re-encode delimiters: payload is not parseable HL7 ({safe_exc(exc)})"
        ) from exc

    def leaf_text(node: object) -> str:
        # Only the escape character can legitimately change inside a leaf; every other byte (incl.
        # non-ASCII) is preserved exactly. If the escape char is unchanged this is a no-op copy.
        text = str(node)
        return text if src_esc == esc else text.replace(src_esc, esc)

    def join_component(node: object) -> str:
        if isinstance(node, Component):
            return sub.join(leaf_text(child) for child in node)
        return leaf_text(node)

    def join_repetition(node: object) -> str:
        if isinstance(node, Repetition):
            return comp.join(join_component(child) for child in node)
        return join_component(node)

    def join_field(node: object) -> str:
        if isinstance(node, Field):
            return rep.join(join_repetition(child) for child in node)
        return join_repetition(node)

    out_segments: list[str] = []
    for segment in message:
        seg_id = str(segment[0])
        if seg_id == "MSH":
            # python-hl7 indexes MSH as: [0]="MSH", [1]=MSH-1 (the field sep itself), [2]=MSH-2; MSH-1
            # is implied by the field join and MSH-2 is rewritten to advertise the new delimiters, so
            # the real fields start at index 3.
            parts = ["MSH", comp + rep + esc + sub]
            tail = list(segment)[3:]
        else:
            parts = [seg_id]
            tail = list(segment)[1:]
        parts.extend(join_field(node) for node in tail)
        out_segments.append(field_sep.join(parts))
    return seg_sep.join(out_segments) + seg_sep


# --- destination -------------------------------------------------------------


def _mllp_ssl_context(
    s: Mapping[str, Any],
    *,
    server: bool,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
    name: str = "",
) -> ssl.SSLContext | None:
    """Build the per-connection MLLP ``SSLContext`` (WP-13b, ADR 0002), or ``None`` when ``tls`` is off.

    Built once in the connector ``__init__`` (a bad cert/key fails at build, like LDAPS). TLS 1.2+ floor.
    **Inbound** (``server=True``): present ``tls_cert_file``/``tls_key_file`` as the server identity;
    ``tls_ca_file`` opts into mTLS (require + verify a client cert). **Outbound** (``server=False``):
    verify the peer's cert against ``tls_ca_file`` (or the system trust store) with hostname checking,
    and optionally present ``tls_cert_file`` for mTLS. ``tls_verify=False`` (outbound) is MITM-able and
    refused unless ``insecure_tls_allowed()``, with a loud warning — exactly as LDAPS / SQL Server.

    ``trust_anchor_policy`` (#190, ADR 0093, OUTBOUND verify path only) supplies the instance ``[tls]``
    internal-CA fallback: when the connection names no ``tls_ca_file`` of its own, an internal hop
    verifies against the org internal CA per the resolved anchor (``system``/``augment``/``pinned``).
    ``None`` (a direct test build) keeps the historical ``create_default_context(cafile=…)`` behaviour,
    byte-identical. It only chooses WHICH roots verify the peer — it never touches the ``tls_verify=false``
    refusal below — so the internal CA can never bypass verification.

    ``tls_key_password`` decrypts a passphrase-encrypted private key (``env()``-sourced, mirroring the
    API listener's ``MEFOR_API_TLS_KEY_PASSWORD``); ``None`` (the default) loads an unencrypted key
    exactly as before.

    ``name`` is the connection's, for the inbound CA's messages and audit label (BACKLOG #1142)."""
    refuse_an_unread_ca_pin(
        s, inbound=server, connector="MLLP listener" if server else "MLLP destination"
    )
    if not s.get("tls"):
        return None
    cert, key, ca = s.get("tls_cert_file"), s.get("tls_key_file"), s.get("tls_ca_file")
    # Passphrase for an encrypted private key (both directions). None => unencrypted key, the prior behavior.
    # An encrypted key with NO passphrase must fail deterministically, not fall back to OpenSSL's blocking
    # TTY prompt — there is no TTY under a service account / in a container. The empty-bytes callback is
    # never invoked for an unencrypted key (prior behavior preserved) and yields a clear ssl.SSLError
    # at build time (surfaced by dry-run / `check`) for an encrypted key that was given no passphrase.
    key_password = s.get("tls_key_password")
    pw_arg = key_password if key_password is not None else (lambda: b"")
    if server:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if not cert:
            raise ValueError("MLLP inbound tls=true requires tls_cert_file (the server identity)")
        ctx.load_cert_chain(certfile=cert, keyfile=key, password=pw_arg)
        if ca:  # opt-in mTLS: require + verify a client cert against this trust anchor
            # BACKLOG #1142, slice 3: the CA's pin, ACL, path and PEM checks, then load the bytes
            # they read. cafile= would open the file again, and a file swapped between the two
            # reads would admit a forged client certificate. Outside the construction gate (no
            # posture stamped) the check enforces, as every posture-keyed cell here fails closed.
            posture = current_hop_posture()
            cadata = inbound_ca_cadata(name, s, enforcing=posture is None or posture.enforcing)
            ctx.load_verify_locations(cadata=cadata)
            ctx.verify_mode = ssl.CERT_REQUIRED
            # Opt-in revocation (#1005). AFTER the CA load, because the CRL goes into the same
            # trust store. Only meaningful under mTLS -- with no client cert required there is
            # nothing to revoke. Covers the inbound HTTP listener too: it calls this builder
            # (http_listener.py), so one wiring serves two listeners.
            if crl := s.get("tls_crl_file"):
                harden_crl_check(ctx, str(crl))
        harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
        # Narrow first, assert last, both spelled here -- do NOT fold them into one call; see
        # apply_connection_tls_ciphers. Unset (the default) narrows to the approved AEAD suites
        # (BACKLOG #300, the ADR 0188 amendment); set, to the operator's validated string.
        apply_connection_tls_ciphers(ctx, s, connector="MLLP listener")  # opt-in per-hop suite list
        harden_cipher_suites(ctx, connector="MLLP listener")  # assert forward secrecy (ASVS 12.1.2)
        harden_verify_flags(ctx)  # strict RFC 5280 validation of any mTLS client cert (ASVS 12.1.4)
        return ctx
    # Outbound (client): verify the server cert unless explicitly — and loudly — disabled. #200 (ADR
    # 0092 decision 2): the escape is CLAMPED to non production-PHI (weakened_tls_escape_permitted_here),
    # so tls_verify=false can no longer be silenced by MEFOR_ALLOW_INSECURE_TLS on a prod-PHI instance —
    # matching the plaintext-MLLP InsecureHopGuard. Byte-identical off the construction gate (unstamped).
    verify = bool(s.get("tls_verify", True))
    if not verify and not weakened_tls_escape_permitted_here():
        raise ValueError(
            "MLLP tls_verify=false disables server-certificate verification (MITM risk). Use a trusted "
            f"CA (tls_ca_file), or set {INSECURE_TLS_ESCAPE_ENV}=1 to allow it on a trusted-network bind "
            "(refused on a production-PHI instance even with the escape, #200)."
        )
    # #190 (ADR 0093): resolve the trust anchor — the connection's own tls_ca_file wins verbatim, else an
    # internal hop may anchor on the [tls] internal CA. Only the VERIFY path uses it; the tls_verify=false
    # branch below stays CERT_NONE and is already refused above, so the internal CA never bypasses a refusal.
    if verify and trust_anchor_policy is not None:
        anchor = resolve_trust_anchor(
            connection_ca_file=str(ca) if ca else None,
            host=str(s.get("host", "127.0.0.1")),
            policy=trust_anchor_policy,
        )
        ctx = build_verifying_client_context(anchor)
    else:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify:
        ctx.check_hostname = bool(s.get("tls_check_hostname", True))
    else:
        logger.warning(
            "MLLP TLS certificate verification is DISABLED (tls_verify=false, permitted by %s).",
            INSECURE_TLS_ESCAPE_ENV,
        )
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cert:  # optional client identity for mTLS
        ctx.load_cert_chain(certfile=cert, keyfile=key, password=pw_arg)
    harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
    # See the listener above: narrow first (ADR 0188), assert second, both visible here. The pair runs
    # on the tls_verify=false path too -- a hop that skips certificate verification still negotiates a
    # suite, and an operator who narrowed this connection meant that hop as much as any other.
    apply_connection_tls_ciphers(ctx, s, connector="MLLP destination")  # opt-in per-hop suite list
    harden_cipher_suites(ctx, connector="MLLP destination")  # assert forward secrecy (ASVS 12.1.2)
    if verify:  # skip the tls_verify=false / CERT_NONE path — nothing to validate (ASVS 12.1.4)
        harden_verify_flags(ctx)  # strict RFC 5280 validation of the server cert
        # #129 (ADR 0094): granular expiry-only relaxation — honour a partner cert whose notAfter has
        # passed while STILL validating chain + hostname. Opt-in per connection (default False = byte-
        # identical); applied on the verify path only, so it composes with (never bypasses) the
        # tls_verify=false refusal above and the #200 cleartext/verify-off hop refusals.
        if s.get("tls_allow_expired"):
            relax_verify_expiry(ctx, host=str(s.get("host", "127.0.0.1")))
    return ctx


class MLLPDestination(DestinationConnector):
    """Send a payload to an MLLP receiver and require a positive ACK.

    Connect-per-message is the shipped default this release (``persistent=false`` — today's proven
    posture, BACKLOG #82.1 "stays off by default"): each delivery dials a fresh connection, sends its
    frame, reads one ACK, and closes (two intentional hardening deltas — see :meth:`_send_once`).

    ``persistent=true`` is the documented **opt-in** (ADR 0067): one lazily-established TCP connection
    is **reused across deliveries** — the delivery worker is the lane's single serial sender, so a
    single cached connection (not a pool) removes the per-message TCP/TLS handshake and its
    ``TIME_WAIT`` (the fix for the bench-measured ephemeral-port exhaustion at 1,500-lane rates).
    Before reusing, a cheap no-I/O liveness check (``is_closing``/buffered unsolicited bytes/
    ``at_eof``/idle/age) closes a stale socket and dials fresh **before any payload byte is
    written** — the one sanctioned internal reconnect, never charged to the message. The default flips
    to ``persistent=true`` in a subsequent release once the ADR 0067 §8 trigger is met.
    A negative ACK (MSA-1 not in the accept family) or any I/O/timeout raises
    :class:`DeliveryError`, so the pipeline retries.

    Note (at-least-once): if the payload is sent but the ACK is lost (peer closes / times
    out after receiving), the retry re-delivers — the receiver may see a duplicate. This is
    the documented at-least-once trade-off; outbound receivers must be idempotent. Enabling
    connection reuse (``persistent=true``) makes that window *more frequent*, not new (a write onto
    a dead cached connection can "succeed" into the TCP buffer and only fail at drain/ACK-read) —
    the reuse-time check and ``idle_timeout_seconds`` bound it, and there is **no internal resend
    loop** in either mode.
    """

    def __init__(self, config: Destination) -> None:
        s = config.settings
        # Refuse a missing/blank host rather than invent one, for the reason spelled out in full on
        # TcpDestination.__init__: a defaulted peer would dial THIS machine, and where the same engine
        # runs a listener on that port the delivery would succeed into its own intake rather than
        # failing. `_mllp_ssl_context` below carries its own `s.get("host", "127.0.0.1")` defaults;
        # this refusal runs first, so those become unreachable through the destination path.
        host = s.get("host")
        if not isinstance(host, str) or not host:
            raise ValueError("MLLP destination requires a 'host' setting (the downstream peer)")
        self.host: str = host
        self.port: int = int(s["port"])
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.connect_timeout: float = float(s.get("connect_timeout", 10.0))
        self.encoding: str = s.get("encoding", "utf-8")
        # Per-outbound frame cap. This bounds ONLY the ACK-read decoder (the reply we read back); the
        # OUTGOING frame written by send() is deliberately UNCAPPED (frame() never truncates), so a
        # re-attached very-large document (#149, ADR 0105 Phase 1b — a base64 PDF spliced back into
        # OBX-5.5 for an inline MDM) or a Handler-built large MDM streams inline to a receiver that does
        # not cap the frame (Epic). Raise/lower it per outbound only to bound a partner's ACK size; a
        # falsy value disables the ACK cap entirely (`max_frame_bytes=0`).
        mf = s.get("max_frame_bytes", DEFAULT_MAX_FRAME_BYTES)
        self.max_frame_bytes: int | None = int(mf) if mf else None
        # ADR 0067: persistent outbound connection. Shipped OPT-IN this release (default OFF): the
        # adjudicated default is connect-per-message (today's proven posture, BACKLOG #82.1 "stays off
        # by default"); persistent=true is the documented opt-in that removes the per-message
        # TIME_WAIT port pressure, with the default flip planned once the §8 trigger is met. Key absent
        # → off; the two freshness knobs follow the receive_timeout convention: present-but-falsy
        # (None/0) = disabled.
        self.persistent: bool = bool(s.get("persistent", False))
        it = s.get("idle_timeout_seconds", 60.0)
        self.idle_timeout_seconds: float | None = float(it) if it else None
        ma = s.get("max_connection_age_seconds")
        self.max_connection_age_seconds: float | None = float(ma) if ma else None
        # BACKLOG #117 (ADR 0124): fire-and-forward. When True, send() writes + drains and finalizes
        # the delivery on the successful TCP write — it reads NO ACK and validates NO MSA-1
        # (at-most-once-confirmation; there is no NAK-/timeout-driven retry). Default False = today's
        # ACK-waiting behavior, byte-identical. Composes with persistent (the no-ack persistent path
        # is SIMPLER — no reply frame to read, no desync guard). Mutually exclusive with
        # capture_response/reingress_to (nothing to capture) and MLLP-only — both rejected at wiring.
        self.no_ack: bool = bool(s.get("no_ack", False))
        # The cached connection + freshness stamps (monotonic clock — a wall-clock jump must not
        # expire a healthy socket). Cached only after a FULLY successful transaction (including a
        # NAK — a complete request/response on a healthy transport); any transport failure discards
        # it so a socket in an unknown framing state can never bleed a late ACK into the next send.
        self._conn: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        self._last_used = 0.0
        self._established_at = 0.0
        # Fail-loud invariant guard (no lock — a lock would silently mask the violation): the
        # delivery worker is the lane's single serial sender, so concurrent send() is a pipeline bug.
        self._sending = False
        self._closed = False
        #: Reconnects observed (stale-detect, post-error discard, desync guard) — log-only in v1.
        self.reconnects: int = 0
        # #136 (ADR 0065 amendment): the cosmetic "Waiting for Reply" side-band marker + its pre-display
        # delay. `_waiting_since` (monotonic) is stamped around the ACK read and cleared when it resolves;
        # `waiting_for_reply(now)` reports True only once `waiting_display_delay` has elapsed. DISPLAY ONLY
        # — no delivery-path effect, and stamped ONLY around an ACK read that actually happens (so a
        # future no-ack mode, #117, never sets it). The delay is independent of `timeout_seconds`/pacing.
        self.waiting_display_delay: float = config.waiting_display_delay
        self._waiting_since: float | None = None
        # Per-outbound delimiter override (Corepoint -override parity): None = ship the payload as-is
        # (byte-identical, the default). A set value is validated NOW (at build) so a malformed override
        # fails at dry-run / `check`, not per delivery; it is applied in send() before framing.
        chars = s.get("encoding_characters")
        self.encoding_characters: EncodingCharacters | None = (
            parse_encoding_characters(chars) if chars is not None else None
        )
        # BACKLOG #107: per-outbound escape-hatch — emit reserved HL7 structural separators as RAW bytes
        # instead of \F\ \S\ \R\ \T\ escapes for a partner that cannot decode escapes. Read from the typed
        # Destination field (assembled by _dest_config from the outbound's hl7_raw_separators setting).
        # False (default) = ship the payload as-is (byte-identical); applied in send() before framing.
        self.hl7_raw_separators: bool = config.hl7_raw_separators
        # ADR 0013: when True, send() returns a DeliveryResponse carrying the application ACK (the
        # MSA/ERR the partner returned) for the delivery worker to capture. Default False → returns None,
        # byte-identical. A *read* failure (peer-close, frame-size) is never captured — it stays a
        # retryable DeliveryError; only a read-but-unparseable ACK becomes outcome='unparseable'.
        self.capture_response: bool = bool(s.get("capture_response", False))
        # BACKLOG #82: when True, a positive ACK (MSA-1 AA/CA) is accepted only if its MSA-2 echoes the
        # sent message's MSH-10 — a mismatched control id is a correlation failure (retryable). Default
        # False → no correlation, byte-identical (the sent control id is never threaded to _check_ack).
        # The sent MSH-10 is read defensively in send() (a non-HL7 / unreadable payload → skip, deliver
        # as before); MSA-2 is read separator-aware via Peek, never hardcoded delimiters.
        self.verify_ack_control_id: bool = bool(s.get("verify_ack_control_id", False))
        # WP-13b: per-connection outbound TLS (verify the peer). Built once here so a bad cert/CA fails
        # at build (dry-run/check), not per delivery. None when tls is off → plaintext, byte-identical.
        # #190 (ADR 0093): thread the instance [tls] internal-CA trust-anchor policy so an internal hop
        # that names no tls_ca_file of its own can verify against the org internal CA.
        self._ssl: ssl.SSLContext | None = _mllp_ssl_context(
            s, server=False, trust_anchor_policy=config.trust_anchor_policy
        )
        # #200 (ADR 0092): a plaintext MLLP egress (tls off) is a cleartext PHI hop — guard it on the
        # posture gradient (a production-PHI hop off-loopback is refused at the enforced construction
        # gate). None when TLS is on: a verified hop needs no cleartext guard, and the verify-off case is
        # already refused separately in _mllp_ssl_context. tls_hop_attested opts a legitimately-secure
        # hop (proxy-terminated / trusted segment) back in per-connection.
        self._hop_guard: InsecureHopGuard | None = (
            InsecureHopGuard.capture(
                host=self.host,
                port=self.port,
                cell="MLLP outbound",
                description="cleartext MLLP egress",
                attested=config.tls_hop_attested,
                attested_reason=config.tls_hop_attested_reason,
                # ADR 0153: `cleartext_accepted` crosses this hop with a loud, audited WARN. TRANSITIONAL
                # here — MLLP() supports tls=true, so the declaration should end when the peer does.
                cleartext_accepted=config.cleartext_accepted,
                cleartext_reason=config.cleartext_reason,
                connection=config.name,
            )
            if self._ssl is None
            else None
        )
        if self._hop_guard is not None:
            self._hop_guard.enforce_construction()
        # #201 (ADR 0078 amendment): a VERIFYING MLLP-over-TLS egress validates the peer cert but does no
        # OCSP/CRL revocation (stdlib ssl has none). Guard the VERIFY path only — the tls_verify=false /
        # CERT_NONE case is already refused by _mllp_ssl_context / #200, and the plaintext case by the
        # cleartext _hop_guard above — so the two gates never double-refuse one hop. A production-PHI hop
        # off-loopback is refused at the enforced construction gate unless tls_revocation_attested / the
        # blanket env opts in; loopback / synthetic / non-prod / attested stay byte-identical.
        self._revocation_guard: RevocationHopGuard | None = (
            RevocationHopGuard.capture(
                host=self.host,
                cell="MLLP outbound",
                description="verified MLLP-over-TLS egress (no revocation check)",
                attested=config.tls_revocation_attested,
                attested_reason=config.tls_revocation_attested_reason,
                connection=config.name,
                # BACKLOG #299: the context this hop will actually hand to wrap_socket. A CRL that
                # reached it (via [tls].crl_file through the resolved anchor) sets
                # VERIFY_CRL_CHECK_LEAF, and the guard reads that flag rather than the setting -- so a
                # sibling hop the same CRL never reached keeps its refusal.
                context=self._ssl,
            )
            if self._ssl is not None and self._ssl.verify_mode is not ssl.CERT_NONE
            else None
        )
        if self._revocation_guard is not None:
            self._revocation_guard.enforce_construction()

    @staticmethod
    def _describe_error(exc: BaseException) -> str:
        """Render a transport exception with its OS-level detail. ``str(exc)`` alone is empty or
        bland exactly where it matters most (``asyncio.TimeoutError`` is ``''``; a proactor
        ``OSError`` may carry only ``winerror``) — the WS-C bench dead-lettered ~18.6k deliveries
        whose ``last_error`` ended at "failed:" while the actual cause (ephemeral-port exhaustion,
        WinError 10055-class) was invisible. Always name the type; append errno/winerror/strerror
        when they aren't already in the text, so a dead-letter is diagnosable from its own message."""
        text = str(exc)
        extras: list[str] = []
        for attr in ("winerror", "errno"):
            val = getattr(exc, attr, None)
            if val is not None and str(val) not in text:
                extras.append(f"{attr}={val}")
        strerror = getattr(exc, "strerror", None)
        if strerror and str(strerror) not in text:
            extras.append(str(strerror))
        if text:
            extras.append(text)
        name = type(exc).__name__
        return f"{name}: {' '.join(extras)}" if extras else name

    def waiting_for_reply(self, now: float) -> bool:
        """#136 (ADR 0065 amendment): whether this outbound is currently AWAITING an MLLP ACK and at
        least ``waiting_display_delay`` has elapsed since the send began. DISPLAY ONLY — read off the
        event loop by the API's connections view via ``RegistryRunner.outbound_waiting_for_reply``.
        ``now`` is a monotonic clock (the same clock ``_waiting_since`` was stamped with). False whenever
        no ACK read is in flight (including a future no-ack mode that never stamps the marker)."""
        since = self._waiting_since
        return since is not None and (now - since) >= self.waiting_display_delay

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        # ADR 0067 §2.5: the worker-per-lane structure already serializes send(); ASSERT it rather
        # than trust it. A re-entrant/concurrent send() on one instance would interleave two frames
        # on one socket — a pipeline-invariant bug that must fail loud (it lands in the delivery
        # worker's internal-error path), not be silently serialized by a lock.
        if self._sending:
            raise RuntimeError(
                "MLLPDestination.send() called concurrently on one instance — the delivery worker "
                "must be the lane's single serial sender (per-lane FIFO invariant, ADR 0067)"
            )
        self._sending = True
        try:
            if self._hop_guard is not None:
                # Zero-I/O byte-crossing backstop (#200): assert the cleartext hop is still permitted
                # before any payload byte leaves the box (defense in depth against a reload routing PHI
                # around the construction-only gate).
                self._hop_guard.assert_send()
            if self.encoding_characters is not None:
                # Re-encode the body with this destination's delimiters before framing. A non-HL7/
                # garbled payload can't be rewritten — surface it as a DeliveryError (the message
                # reached neither the wire nor the peer) rather than framing a corrupted message; the
                # pipeline records the ERROR.
                try:
                    payload = reencode_delimiters(payload, self.encoding_characters)
                except ValueError as exc:
                    raise DeliveryError(f"MLLP encoding-character override failed: {exc}") from exc
            if self.hl7_raw_separators:
                # BACKLOG #107: re-serialize emitting the reserved structural separators as raw bytes
                # (composes after any delimiter rewrite above). A non-HL7 / unparseable payload can't be
                # rewritten — surface a DeliveryError (the message reached neither wire nor peer) rather
                # than framing a corrupted message; the pipeline records the ERROR.
                try:
                    payload = emit_raw_separators(payload)
                except (hl7.HL7Exception, ValueError, IndexError, AssertionError) as exc:
                    # IndexError and AssertionError: the same truncated-header shapes that
                    # reencode_delimiters maps to ValueError above (BACKLOG #1601).
                    raise DeliveryError(
                        "MLLP hl7_raw_separators emit failed (payload not parseable HL7): "
                        f"{safe_exc(exc)}"
                    ) from exc
            if self.no_ack:
                # BACKLOG #117 (ADR 0124): fire-and-forward — write + drain, no ACK read, deliver on
                # the successful TCP write. Composes with persistent (reuse the cached connection).
                # Deliberately BEFORE the #82 peek below: with no ACK to read there is no MSA-2 to
                # correlate, so the outgoing-MSH-10 read would be pure waste (the two knobs are also
                # rejected together at wiring — see build_outbound_connection).
                if not self.persistent:
                    return await self._send_once_no_ack(payload)
                return await self._send_persistent_no_ack(payload)
            # BACKLOG #82: read the OUTGOING control id (MSH-10) once, off the final on-wire payload
            # (after any delimiter/raw-separator rewrite), so _check_ack can correlate it to the reply's
            # MSA-2. Off → None → no correlation (byte-identical). Defensive: a non-HL7 / unparseable
            # payload has no MSH-10 to correlate, so we skip (deliver as before) rather than fail.
            sent_control_id: str | None = None
            if self.verify_ack_control_id:
                try:
                    sent_control_id = Peek.parse(payload).control_id
                except HL7PeekError:
                    sent_control_id = None
            if not self.persistent:
                return await self._send_once(payload, sent_control_id)
            return await self._send_persistent(payload, sent_control_id)
        finally:
            self._sending = False

    async def _dial(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """One connection attempt (TCP + optional TLS handshake through the prebuilt context). A
        failure is a **charged** :class:`DeliveryError` carrying ``_describe_error`` detail — there is
        exactly one dial per send in every mode, never an internal connect-retry loop."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.host,
                    self.port,
                    ssl=self._ssl,
                    # SNI + (when verifying) hostname check against the configured peer host. The
                    # context is built once at __init__ and reused, so every reconnect performs a
                    # full handshake with the same CA/hostname/mTLS posture (ADR 0067 §2.7).
                    server_hostname=self.host if self._ssl else None,
                ),
                self.connect_timeout,
            )
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(
                f"MLLP connect to {self.host}:{self.port} failed: {self._describe_error(exc)}"
            ) from exc
        # Kill Nagle/delayed-ACK on the request-response round-trip (see _set_tcp_nodelay). Set here on
        # every dial so both the connect-per-send (_send_once) and persistent (_send_persistent, ADR
        # 0067) paths — and every reconnect — get it.
        _set_tcp_nodelay(writer)
        return reader, writer

    async def _send_once(
        self, payload: str, sent_control_id: str | None = None
    ) -> DeliveryResponse | None:
        """The historical connect-per-send path (``persistent=false``) — one connection per delivery,
        closed in a finally, error text unchanged. Two deliberate deltas from the pre-ADR-0067 code,
        both hardening (ADR 0067 §2.1/AC-2): the close is *bounded* (the #55 Proactor-wedge pattern —
        legacy awaited ``wait_closed()`` forever) and the fail-loud serial-``send()`` assert in
        :meth:`send` applies to both modes."""
        reader, writer = await self._dial()
        try:
            writer.write(frame(payload, self.encoding))
            await asyncio.wait_for(writer.drain(), self.timeout)
            # #136: stamp the side-band "waiting for reply" marker around the ACK read only (cleared in
            # the finally). Purely observational — the read itself is unchanged.
            self._waiting_since = time.monotonic()
            try:
                ack_bytes = await asyncio.wait_for(self._read_ack(reader), self.timeout)
            finally:
                self._waiting_since = None
        except TimeoutError as exc:
            raise DeliveryError("MLLP timed out waiting for ACK") from exc
        except OSError as exc:
            raise DeliveryError(f"MLLP I/O error: {self._describe_error(exc)}") from exc
        finally:
            await self._close_bounded(writer)
        return self._check_ack(ack_bytes, sent_control_id)

    async def _send_once_no_ack(self, payload: str) -> DeliveryResponse | None:
        """Connect-per-send fire-and-forward (``no_ack`` + ``persistent=false``, BACKLOG #117 / ADR
        0124): dial → write → drain → bounded close, with **no ACK read** and no MSA-1 validation. The
        delivery is confirmed on the successful TCP write (at-most-once-confirmation). A connect/drain
        failure is still a charged :class:`DeliveryError` (at-least-once for the write; the retry may
        duplicate — receivers stay idempotent). Returns ``None`` — there is no ACK to capture
        (``capture_response`` is rejected at wiring for a no-ack outbound)."""
        _reader, writer = await self._dial()
        try:
            writer.write(frame(payload, self.encoding))
            await asyncio.wait_for(writer.drain(), self.timeout)
        except TimeoutError as exc:
            raise DeliveryError("MLLP timed out draining the write (no-ack)") from exc
        except OSError as exc:
            raise DeliveryError(f"MLLP I/O error (no-ack): {self._describe_error(exc)}") from exc
        finally:
            await self._close_bounded(writer)
        return None

    async def _send_persistent(
        self, payload: str, sent_control_id: str | None = None
    ) -> DeliveryResponse | None:
        """One delivery over the cached connection (ADR 0067): reuse-time liveness check →
        reconnect-before-first-byte (uncharged) → write/drain/ACK-read (any failure after ``write()``
        is charged, names its phase, and discards the connection) → re-cache on a fully-successful
        transaction (including a NAK) unless the peer left extra bytes behind (desync guard)."""
        if self._closed:
            # aclose() already ran (engine stop / reload swap) — never re-establish a socket the
            # lifecycle can no longer close. Fail loud; the retry lands on the replacement connector.
            raise DeliveryError(
                f"MLLP destination {self.host}:{self.port} is closed (stop/reload); "
                "delivery retries on the replacement connector"
            )
        conn = self._conn
        if conn is not None:
            reason = self._stale_reason(*conn)
            if reason is not None:
                # Reconnect-before-first-byte: zero payload bytes ever touched this socket during
                # THIS send, so a fresh dial provably cannot duplicate — not charged to the message
                # (no attempts consumed, no lane-health flip). Exactly one dial follows; if it fails,
                # _dial raises the normal charged DeliveryError.
                self._conn = None
                self.reconnects += 1
                logger.info(
                    "MLLP %s:%d persistent connection not reused (%s); reconnecting",
                    self.host,
                    self.port,
                    reason,
                )
                await self._close_bounded(conn[1])
                conn = None
        if conn is None:
            conn = await self._dial()
            self._established_at = time.monotonic()
        reader, writer = conn
        # Keep the in-flight connection visible in the cache slot so a concurrent aclose() (the
        # documented reload race) closes it under us — this send then fails loud and is retried.
        self._conn = conn
        try:
            try:
                writer.write(frame(payload, self.encoding))
                await asyncio.wait_for(writer.drain(), self.timeout)
            except (TimeoutError, OSError) as exc:
                # Payload bytes were (at least partially) written: the peer may have processed the
                # message even though we saw no ACK — the documented at-least-once duplicate window.
                # Name the phase so an operator can distinguish it from a pre-write failure.
                raise DeliveryError(
                    "MLLP send failed in the drain phase (payload written — delivery "
                    f"indeterminate): {self._describe_error(exc)}"
                ) from exc
            # #136: stamp the side-band "waiting for reply" marker around the ACK read only (cleared in
            # the finally). Purely observational — the read itself is unchanged.
            self._waiting_since = time.monotonic()
            try:
                ack_bytes, leftover = await asyncio.wait_for(
                    self._read_ack_reuse(reader), self.timeout
                )
            except TimeoutError as exc:
                raise DeliveryError(
                    "MLLP timed out waiting for ACK (ACK-read phase — delivery indeterminate)"
                ) from exc
            except OSError as exc:
                raise DeliveryError(
                    "MLLP I/O error in the ACK-read phase (delivery indeterminate): "
                    f"{self._describe_error(exc)}"
                ) from exc
            finally:
                self._waiting_since = None
        except DeliveryError as exc:
            # ANY failed transaction discards the connection — a socket in an unknown framing state
            # must never bleed a late/partial ACK into the next send. Charged; the next send re-dials.
            self._conn = None
            self.reconnects += 1
            logger.warning(
                "MLLP %s:%d persistent connection discarded after delivery failure: %s",
                self.host,
                self.port,
                exc,  # transport/OS metadata only (_describe_error) — never payload bytes
            )
            await self._close_bounded(writer)
            raise
        except BaseException:
            # Cancellation (or any non-DeliveryError escape) mid-transaction is still a failed
            # transaction — the same "ANY failed transaction discards" invariant, or the peer's ACK
            # for the abandoned send would later be read as the NEXT send's reply. Synchronous
            # transport close only: never await inside cancellation (no wait_closed here).
            self._conn = None
            self.reconnects += 1
            writer.close()
            raise
        # Transaction complete: one ACK frame read and parsed below — including a NAK, which is a
        # complete request/response on a healthy transport, so the connection stays cached (AC-10).
        # The reuse decision happens BEFORE _check_ack so a NegativeAckError can't discard it.
        if leftover:
            # Desync guard (ADR 0067 §2.2): the peer packed extra bytes after its ACK frame —
            # reusing would corrupt the next transaction's framing. Conservative: costs a reconnect.
            self._conn = None
            self.reconnects += 1
            logger.warning(
                "MLLP %s:%d peer sent extra bytes after its ACK; closing instead of reusing "
                "(desync guard)",
                self.host,
                self.port,
            )
            await self._close_bounded(writer)
        elif self._closed:
            # aclose() raced this send after the ACK was read — don't cache a socket past the
            # connector's death (the delivery itself succeeded).
            self._conn = None
            await self._close_bounded(writer)
        else:
            self._last_used = time.monotonic()
        try:
            response = self._check_ack(ack_bytes, sent_control_id)
        except NegativeAckError:
            raise  # complete transaction on a healthy transport — the connection stays cached
        except DeliveryError:
            # An unparseable ACK (non-capturing) means the transaction was NOT fully successful
            # ("one ACK read *and parsed*", ADR 0067 §2.2) — discard like any other DeliveryError
            # rather than trust a peer that talks garbage to keep its framing aligned.
            await self._discard_unparseable(conn, writer)
            raise
        if response is not None and response.outcome == "unparseable":
            # capture_response turns the unparseable ACK into a captured outcome instead of a raise
            # (ADR 0013), but the wire behavior is identical garbage — the §2.2 cache condition
            # ("one ACK read *and parsed*") fails the same way in both modes.
            await self._discard_unparseable(conn, writer)
        return response

    async def _send_persistent_no_ack(self, payload: str) -> DeliveryResponse | None:
        """One fire-and-forward delivery over the cached connection (``no_ack`` + ``persistent=true``,
        BACKLOG #117 / ADR 0124). Simpler than :meth:`_send_persistent`: **no ACK frame is read** and
        **no desync/leftover guard runs** — no reply is expected, so any bytes a misbehaving peer
        sends are caught as "unsolicited bytes" by the reuse-time :meth:`_stale_reason` veto (a
        reconnect, never a mis-parse). Reuse-time liveness → reconnect-before-first-byte (uncharged) →
        write/drain → re-cache on drain success; any failure after ``write()`` discards the connection
        (charged; the next send re-dials)."""
        if self._closed:
            # aclose() already ran (engine stop / reload swap) — never re-establish a socket the
            # lifecycle can no longer close. Fail loud; the retry lands on the replacement connector.
            raise DeliveryError(
                f"MLLP destination {self.host}:{self.port} is closed (stop/reload); "
                "delivery retries on the replacement connector"
            )
        conn = self._conn
        if conn is not None:
            reason = self._stale_reason(*conn)
            if reason is not None:
                # Reconnect-before-first-byte: zero payload bytes touched this socket during THIS send,
                # so a fresh dial provably cannot duplicate — not charged (no attempts consumed). Exactly
                # one dial follows; if it fails, _dial raises the normal charged DeliveryError.
                self._conn = None
                self.reconnects += 1
                logger.info(
                    "MLLP %s:%d persistent connection not reused (%s); reconnecting",
                    self.host,
                    self.port,
                    reason,
                )
                await self._close_bounded(conn[1])
                conn = None
        if conn is None:
            conn = await self._dial()
            self._established_at = time.monotonic()
        _reader, writer = conn
        # Keep the in-flight connection visible so a concurrent aclose() (the documented reload race)
        # closes it under us — this send then fails loud and is retried.
        self._conn = conn
        try:
            writer.write(frame(payload, self.encoding))
            await asyncio.wait_for(writer.drain(), self.timeout)
        except (TimeoutError, OSError) as exc:
            # Payload bytes were (at least partially) written: the peer may have processed the message
            # even though there is no ACK to confirm it — the documented at-least-once duplicate window.
            # ANY failed transaction discards the connection (a socket in an unknown state must never be
            # reused); charged, the next send re-dials.
            self._conn = None
            self.reconnects += 1
            logger.warning(
                "MLLP %s:%d persistent connection discarded after no-ack delivery failure: %s",
                self.host,
                self.port,
                self._describe_error(exc),  # transport/OS metadata only — never payload bytes
            )
            await self._close_bounded(writer)
            raise DeliveryError(
                "MLLP no-ack send failed in the drain phase (payload written — delivery "
                f"indeterminate): {self._describe_error(exc)}"
            ) from exc
        except BaseException:
            # Cancellation (or any non-DeliveryError escape) mid-transaction is still a failed
            # transaction — discard synchronously (never await inside cancellation).
            self._conn = None
            self.reconnects += 1
            writer.close()
            raise
        # Write drained: the transaction is complete (no ACK expected). Re-cache unless aclose() raced.
        if self._closed:
            # aclose() raced this send after the write drained — don't cache past the connector's death
            # (the delivery itself succeeded on the write).
            self._conn = None
            await self._close_bounded(writer)
        else:
            self._last_used = time.monotonic()
        return None

    async def _discard_unparseable(
        self,
        conn: tuple[asyncio.StreamReader, asyncio.StreamWriter],
        writer: asyncio.StreamWriter,
    ) -> None:
        """Discard the cached connection after a read-but-unparseable ACK (both the raising
        non-capturing path and the captured ``outcome='unparseable'`` path). Fixed reason only in
        the log: the parse error's text can embed a reply fragment (#120)."""
        if self._conn is conn:
            self._conn = None
            self.reconnects += 1
            logger.warning(
                "MLLP %s:%d persistent connection discarded after delivery failure: "
                "unparseable ACK",
                self.host,
                self.port,
            )
            await self._close_bounded(writer)

    def _stale_reason(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> str | None:
        """Why the cached connection must not be reused, or ``None`` when it looks live. Cheap —
        no I/O round-trip. ``at_eof`` is sound for MLLP: a peer sends nothing unsolicited between
        transactions, so a readable EOF while idle means the peer closed (the expected idle-close)."""
        if writer.is_closing():
            return "socket is closing/closed"
        # Desync guard, reuse-time half (ADR 0067 §2.2): a late/duplicate frame the peer sent AFTER
        # the ACK read completed (a separate segment, or while the connection sat idle) lands in the
        # StreamReader buffer, where the in-transaction ``leftover`` flag can never see it — and it
        # also masks a subsequent FIN from ``at_eof()`` (``_eof and not _buffer``). Reusing would
        # parse that stale frame as the NEXT send's ACK, misattributing dispositions. asyncio has no
        # public buffered-data probe (a raw-socket MSG_PEEK is wrong under TLS), so peek the private
        # buffer, guarded: attribute absent ⇒ falsy ⇒ no reuse veto, same as before this check.
        if getattr(reader, "_buffer", b""):
            return "unsolicited bytes received while idle"
        if reader.at_eof():
            return "peer closed while idle (EOF)"
        now = time.monotonic()
        if self.idle_timeout_seconds is not None:
            idle = now - self._last_used
            if idle > self.idle_timeout_seconds:
                return f"idle {idle:.1f}s > idle_timeout_seconds={self.idle_timeout_seconds:g}"
        if self.max_connection_age_seconds is not None:
            age = now - self._established_at
            if age > self.max_connection_age_seconds:
                return f"age {age:.1f}s > max_connection_age_seconds={self.max_connection_age_seconds:g}"
        return None

    @staticmethod
    async def _close_bounded(writer: asyncio.StreamWriter) -> None:
        """Close with a bounded ``wait_closed`` — the #55 pattern the inbound side uses: on the
        Windows Proactor an unbounded ``wait_closed()`` can never return on a pending overlapped op,
        which would wedge the delivery worker/aclose forever. Abandoning after the grace is safe
        (the socket is already closed)."""
        writer.close()
        try:  # noqa: SIM105
            await asyncio.wait_for(writer.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
        except (TimeoutError, OSError):
            pass

    async def aclose(self) -> None:
        """Close the cached persistent connection (engine stop / reload swap — the runner calls this
        for every replaced/removed connector). Idempotent; bounded; safe concurrently with an
        in-flight send: closing the socket under it makes that send fail loud → charged → retried,
        exactly the documented reload race semantics."""
        self._closed = True
        conn = self._conn
        self._conn = None
        if conn is not None:
            await self._close_bounded(conn[1])

    async def test_connection(self) -> None:
        # Reachability only: open + close a connection (no frame, no ACK) so a test never delivers.
        # Always a fresh probe socket — never the cached persistent connection (a probe must not
        # disturb, consume from, or be confused with live delivery traffic).
        #
        # #1178: the probe carries the SAME prebuilt context the delivery dial uses, so a tls=true
        # hop is tested over TLS instead of over a plaintext socket the operator never configured.
        # Without it the engine fell back to an unencrypted protocol on a hop its own configuration
        # says is encrypted (ASVS 12.3.1), and — the half an operator feels — a broken certificate,
        # CA or hostname passed a green connection test and then failed every delivery. The DICOM
        # SCU already works this way, associating its C-ECHO through the same tls_args as a C-STORE;
        # TCP and X12 pass nothing because neither can speak TLS in any configuration.
        await probe_tcp_reachable(
            self.host, self.port, self.connect_timeout, "MLLP", ssl_context=self._ssl
        )

    async def _read_ack(self, reader: asyncio.StreamReader) -> bytes:
        decoder = MLLPDecoder(max_frame_bytes=self.max_frame_bytes)
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                raise DeliveryError("MLLP peer closed before sending an ACK")
            try:
                for message in decoder.feed(chunk):
                    return message
            except MLLPFrameError as exc:
                raise DeliveryError(f"ACK exceeded max frame size: {exc}") from exc

    async def _read_ack_reuse(self, reader: asyncio.StreamReader) -> tuple[bytes, bool]:
        """Read one ACK frame for the persistent path: the frame plus a ``leftover`` flag — ``True``
        when the peer packed more than the one expected reply into the same read (a second complete
        frame, or an opened partial one) past the ACK. Inter-frame noise (the CR trailer, stray
        keep-alive bytes) is discarded by the decoder as always and does NOT count as leftover; a
        further frame would desync the next transaction, so the caller closes instead of reusing."""
        decoder = MLLPDecoder(max_frame_bytes=self.max_frame_bytes)
        while True:
            chunk = await reader.read(4096)
            if not chunk:
                raise DeliveryError("MLLP peer closed before sending an ACK")
            try:
                messages = list(decoder.feed(chunk))
            except MLLPFrameError as exc:
                raise DeliveryError(f"ACK exceeded max frame size: {exc}") from exc
            if messages:
                return messages[0], len(messages) > 1 or decoder.in_frame

    def _check_ack(
        self, ack_bytes: bytes, sent_control_id: str | None = None
    ) -> DeliveryResponse | None:
        # ``sent_control_id`` (BACKLOG #82) is the outgoing MSH-10 threaded by send() when
        # verify_ack_control_id is on; None (the default, and whenever the flag is off or our own MSH-10
        # was unreadable) → no correlation, byte-identical to the pre-#82 behaviour.
        try:
            ack = Peek.parse(ack_bytes)
        except HL7PeekError as exc:
            # A reply frame WAS received (the read above succeeded) but its MSA won't parse. For a
            # capturing outbound this is a captured outcome='unparseable' — a reply arrived; we just
            # can't read it — NOT "no reply". For a non-capturing outbound it stays byte-identical:
            # a transport-level problem retried like any I/O failure (plain DeliveryError).
            if self.capture_response:
                return DeliveryResponse(
                    body=ack_bytes.decode(self.encoding, errors="replace"),
                    outcome="unparseable",
                    detail=f"unparseable ACK: {safe_exc(exc)}",  # scrub: a bad ACK can embed a reply fragment (#120)
                )
            raise DeliveryError(f"unparseable ACK: {exc}") from exc
        msa1 = ack.field("MSA-1")
        if msa1 in ("AA", "CA"):
            if sent_control_id:
                # BACKLOG #82: correlate the reply to the send. A positive ACK whose MSA-2 does not echo
                # the sent MSH-10 is NOT a valid accept for THIS message (a stale/mis-framed reply, or a
                # peer that answered a different send) — raise a retryable DeliveryError so the pipeline
                # retries per the at-least-once path (on the persistent lane this also discards the cached
                # connection via _discard_unparseable, correct since a mis-correlated reply implies socket
                # desync). Control ids only in the exception text — never a full payload, never a raised
                # log level. Read separator-aware via Peek. Note: the `if sent_control_id` guard means an
                # unreadable OWN MSH-10 skips correlation (nothing to correlate), per the design decision.
                ack_control_id = ack.field("MSA-2")
                if ack_control_id != sent_control_id:
                    # BACKLOG #1576, same defect as MSA-3 below: MSA-2 is peer-chosen and frame-cap
                    # sized too, and it is interpolated into this raise. Clamped HERE and not at the
                    # read above, because the comparison must see the field the peer actually sent --
                    # bounding first would silently correlate a long control id against its own prefix.
                    raise DeliveryError(
                        f"ACK control-id mismatch: "
                        f"MSA-2={_bounded_ack_field(ack_control_id)!r} "
                        f"!= sent MSH-10={sent_control_id!r}"
                    )
            if self.capture_response:
                # Unbounded on purpose: this branch runs only when msa1 is exactly AA or CA, so the
                # peer cannot size it here (BACKLOG #1847 bounds the one that can, below).
                return DeliveryResponse(
                    body=ack_bytes.decode(self.encoding, errors="replace"),
                    outcome="accepted",
                    detail=f"MSA-1={msa1}",
                )
            return None
        # BACKLOG #1576: the peer sizes MSA-3, and it reached the frame cap unbounded. Every consumer
        # downstream redacts this text, and redaction is a linear scan on the event loop, so an
        # unbounded field here is an unbounded stall there — measured, 0.29 s to 0.78 s per negative
        # acknowledgment at a 16 MiB cap depending on shape. Bound it at READ time, where it is still a
        # field and not yet an exception message half the engine will re-render: the 16 MiB string is
        # never copied into the raise, the dead-letter row, or the alert.
        #
        # _MAX_NAK_DETAIL_CHARS, not the redaction module's own window, because this is not a
        # traceback: MSA-3 is a human-readable reason and a peer that answers with a megabyte is
        # echoing our payload back at us, not explaining anything. Clamped rather than sliced --
        # slicing at an arbitrary offset strands a fragment under the redactor's thresholds and walks
        # the identifier straight into the log, which is the whole defect #1576 was filed on.
        detail = _bounded_ack_field(ack.field("MSA-3"))
        # A negative ACK is a *partner rejection*, not a transport failure: the message reached the
        # peer, which said no. It is NOT captured — it routes through the existing NegativeAckError
        # failure policy (dead-letter on a permanent reject / retry on a transient error), unchanged by
        # capture. AR/CR (reject) is permanent (fail-fast); AE/CE (error) and any unrecognized negative
        # code are treated as transient (retry), the conservative choice when the intent is unclear.
        code, permanent = ("AR", True) if msa1 in ("AR", "CR") else ("AE", False)
        # BACKLOG #1847, the sibling of MSA-2 and MSA-3 above: every code that is not AA/CA lands
        # here, so the peer sizes MSA-1 in this message too. Bounded for the TEXT only, after the
        # comparisons: they must see the code the peer actually sent, or a clamp that rewrote it could
        # move a reply from one branch to another. str() keeps an absent MSA-1 rendering as "None",
        # as it did before, where the helper alone would print it as an empty field.
        raise NegativeAckError(
            f"negative ACK (MSA-1={_bounded_ack_field(str(msa1))}): {detail}".rstrip(": "),
            code=code,
            permanent=permanent,
        )


# --- source ------------------------------------------------------------------


def _peer_host(writer: asyncio.StreamWriter) -> str | None:
    """The peer IP from the socket for a connection-event row (#46) — socket metadata, never payload.
    ``None`` for a UNIX/unresolved peer."""
    peer = writer.get_extra_info("peername")
    if isinstance(peer, tuple) and peer and isinstance(peer[0], str):
        return peer[0]
    return None


class _MessagePacer:
    """Message-rate pacing for the inbound data plane (ASVS 2.4.1, and the availability
    bound of 15.2.2 — one control, because building them apart yields two halves that interact).

    Charges one token per DECODED message and answers ONE question: how long to wait before
    consuming more from the socket.

    Built for MLLP and shared verbatim by the raw-TCP, X12 and HTTP intakes (BACKLOG #1114), which
    import it from here rather than growing a second implementation that could drift.

    **It never drops, never NAKs and never refuses, and that is the whole design.** The count-and-log
    invariant forbids accept-and-drop, so a limiter that discards is not available. NAKing would mean
    refusing clinical messages the engine is able to process. Closing the connection moves the loss
    outside our boundary, where we cannot count it. Pacing the READ is the only option that satisfies
    the invariant *by construction*: the excess is never framed, so it never becomes a received
    message that the invariant would then oblige us to account for. Back-pressure is applied by TCP
    itself once we stop consuming.

    **Why a bounded delay rather than a hard stop.** Refusing to read at all holds the connection open
    and keeps consuming a ``max_connections`` slot, so a flood of paced peers could exhaust the slot
    budget and *become* the denial of service this exists to prevent. A delay bounded by the deficit
    paces the peer without pinning capacity.

    **Never scoped per PEER, on any intake.** These peers are unauthenticated and identified only by
    address, so a per-IP budget collapses under NAT or a shared integration host — it would throttle
    unrelated feeds that happen to share an egress address. A budget is honest about what it bounds
    or it is not worth having; a peer opening more connections is bounded by ``max_connections``.

    **Beyond that, the consumer picks its scope by which pair of methods it calls.** A STREAM intake
    reads many messages down one connection, so it holds a pacer per connection and drives it with
    :meth:`pace` / :meth:`settle`. A listener whose connections carry a single message each has no
    next read on the same connection to settle against, so it holds ONE pacer for the whole listener
    and drives it with :meth:`deficit` / :meth:`charge`. There is no flag and no branch in here.
    """

    __slots__ = (
        "_capacity",
        "_last",
        "_name",
        "_paced_count",
        "_paced_seconds",
        "_pending_wait",
        "_rate",
        "_report_at",
        "_tokens",
    )

    def __init__(self, rate: float, burst: float, *, now: float, name: str = "") -> None:
        self._rate = rate
        self._capacity = max(burst, 1.0)
        self._tokens = self._capacity
        self._last = now
        #: Debt owed before the next read, in seconds. PRIVATE, and settled only through pace() —
        #: a consult-then-clear a caller performs by hand is an invariant restated once per loop.
        self._pending_wait = 0.0
        #: The declaring inbound's name, carried only so a pacing report can NAME the connection an
        #: operator has to go and look at (the :attr:`Source.name` precedent). "" when unwired.
        self._name = name
        #: Applied-delay tally since the last report, reset by each report.
        self._paced_count = 0
        self._paced_seconds = 0.0
        #: Next monotonic stamp a report may be emitted at. Starts at ``now`` so the FIRST time
        #: pacing engages is reported immediately — that transition is the event an operator most
        #: needs, and holding it back for a window would hide it behind the throttle.
        self._report_at = now

    def charge(self, messages: int, *, now: float) -> float:
        """Charge ``messages`` and return the seconds to wait before reading again (0.0 if none).

        The returned delay is exactly the time for the bucket to return to non-negative, so it is
        bounded by ``messages / rate`` and cannot grow without limit.
        """
        self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._rate)
        self._last = now
        self._tokens -= messages
        return 0.0 if self._tokens >= 0 else -self._tokens / self._rate

    async def pace(self) -> None:
        """Wait off whatever is owed BEFORE the next read, then clear the debt — the stream pair.

        ASVS 2.4.1 / 15.2.2. The wait belongs before the read and never around the handler: stopping
        consumption lets TCP back-pressure the sender, so the excess is never framed and never
        becomes a received message. Delaying anything AFTER decode would pace a message the
        count-and-log invariant has already obliged us to account for — the same control with none
        of the property.
        """
        if (wait := self._pending_wait) > 0.0:
            self._pending_wait = 0.0
            self._note_paced(wait)
            await asyncio.sleep(wait)

    def settle(self, messages: int) -> None:
        """Charge ``messages`` and hold the debt for the next :meth:`pace` — the stream pair.

        Called once a chunk's messages are fully handled, so the debt is paid before the NEXT read
        and never by withholding a reply the sender is already owed.
        """
        if messages:
            self._pending_wait = self.charge(messages, now=time.monotonic())

    def deficit(self, *, now: float) -> float:
        """Seconds still owed before the next read, charging NOTHING — the listener-scoped read.

        A stream intake caches its debt at charge time; a listener-wide bucket shared by concurrent
        connections has to recompute it at read time instead. Delegates to :meth:`charge` rather
        than re-deriving the arithmetic, so the two can never disagree.
        """
        owed = self.charge(0, now=now)
        if owed > 0.0:
            self._note_paced(owed, now=now)
        return owed

    def _note_paced(self, seconds: float, *, now: float | None = None) -> None:
        """Tally one APPLIED read delay and report it to the operator, throttled.

        Called from the two places a wait is actually acted on — :meth:`pace` for the stream pair and
        :meth:`deficit` for the listener pair — never from :meth:`charge`, which both of those route
        through and which ``deficit`` consults on every read. Counting in ``charge`` would tally the
        same outstanding debt once per consult and report a number that is not a count of anything.

        **Why pacing needs a voice at all.** The control is otherwise entirely invisible: it never
        drops, NAKs, refuses or errors, so a paced interface looks to the operator exactly like a
        slow one, and nothing is written anywhere. The 2026-08-11 ruling ships
        :data:`DEFAULT_MAX_MESSAGES_PER_SECOND` OFF *because* a safe number can only come from a
        site's own feed profile — and a site cannot tune a number it has no way to watch engage.
        Reporting is the half that makes the opt-in posture usable; it changes no default and paces
        nothing differently.

        Throttled to one line per :data:`_PACING_REPORT_SECONDS` because a pacer that is in deficit
        is consulted on every read, and an unthrottled line would restate one fact thousands of
        times. WARNING rather than INFO: a clinical interface being held back is an operator-facing
        condition, not routine chatter.

        **Metadata only.** The connection name, a count, a duration and the configured rate — never a
        frame, a peer address, or a byte of the body being paced (PHI.md; CLAUDE.md section 9).
        """
        self._paced_count += 1
        self._paced_seconds += seconds
        stamp = time.monotonic() if now is None else now
        if stamp < self._report_at:
            return
        logger.warning(
            "inbound message pacing engaged on %s: %d read delay(s) totalling %.3fs "
            "(max_messages_per_second=%g). The sender is being held back, not refused — no message "
            "is dropped. Raise the rate if this feed is legitimate.",
            self._name or "<unnamed inbound>",
            self._paced_count,
            self._paced_seconds,
            self._rate,
        )
        self._paced_count = 0
        self._paced_seconds = 0.0
        self._report_at = stamp + _PACING_REPORT_SECONDS

    @classmethod
    def for_rate(cls, rate: float | None, burst: float, *, name: str = "") -> _MessagePacer | None:
        """Build a pacer, or ``None`` when no rate is configured — the shipped default.

        The single place the off-default is honoured, so the four intakes that pace cannot drift
        apart on what "unset" means. See :data:`DEFAULT_MAX_MESSAGES_PER_SECOND` for why off.
        """
        return cls(rate, burst, now=time.monotonic(), name=name) if rate else None


def _pacing_settings(settings: Mapping[str, Any]) -> tuple[float | None, float]:
    """Read ``(max_messages_per_second, message_burst)`` from one connection's settings.

    Shared by every intake that paces, so a rename, a default change or a coercion fix lands once
    instead of in four places that must agree. Absent rate -> OFF, deliberately against this
    module's "key absent -> secure default" convention; see :data:`DEFAULT_MAX_MESSAGES_PER_SECOND`.
    Burst defaults to one second's worth, so a peer that sends in bursts is not paced until it
    exceeds the SUSTAINED rate; it is meaningless when pacing is off.
    """
    mps = settings.get("max_messages_per_second", DEFAULT_MAX_MESSAGES_PER_SECOND)
    rate = float(mps) if mps else None
    return rate, float(settings.get("message_burst") or rate or 0.0)


def _cap_setting[NumT: (int, float)](value: Any, convert: Callable[[Any], NumT]) -> NumT | None:
    """Read one inbound cap: a number, or ``None`` for the documented ``None``/``0`` disable.

    **Decide "off" on the NUMBER, not on Python truthiness.** The older idiom ``int(v) if v else
    None`` tests the RAW settings value, and a raw ``"0"`` is a non-empty string — truthy — so it
    survives that test and becomes a live cap of zero. That spelling is reachable rather than
    contrived: a
    ``connections.toml`` ``env()`` reference without a ``cast`` hands the connector the environment's
    TEXT (``docs/CONNECTIONS.md``), so an operator disabling a cap through the environment writes
    ``"0"`` and gets the opposite of what they asked for — a listener that refuses every connection,
    rejects every frame, or closes every socket the instant it opens, depending on which cap it was.

    ``None`` and ``""`` short-circuit before either conversion, and both are needed: a key may be
    absent, and ``resolve_env_settings`` tests membership rather than truthiness, so an env var that
    is SET but empty arrives as ``""`` — which ``int()``/``float()`` would raise on.

    **The zero test reads a ``float`` view, and the cap is built with the caller's own ``convert``.**
    Testing the CONVERTED value instead would read anything that truncates to zero as "off": with
    ``convert=int``, a ``max_connections_per_host`` of ``-0.5`` would silently disable a security cap
    that the guard below is supposed to refuse at build. A float view answers "did the operator write
    zero", which is the actual question, and leaves every sub-1 value to the caller's own guard.

    A negative value is therefore returned as-is, for the callers that refuse one at build with a
    message naming their own key. It is a different mistake with a different answer, and folding it
    into "off" here would swallow the typo this connector exists to reject.
    """
    if value is None or value == "":
        return None
    if float(value) == 0:  # at least 0, 0.0, -0.0, False, "0", "0.0" and " 0 " reach this as off
        return None
    return convert(value)


class MLLPSource(SourceConnector):
    """Listen for inbound MLLP connections, hand each message to the pipeline handler,
    and frame whatever the handler returns back to the sender as the ACK.

    **The inbound resource caps are separate on purpose: each bounds a unit the others do not, so a
    peer can sit inside all of them but one.** ``max_connections`` counts sockets on this listener
    and ``max_connections_per_host`` counts sockets from one peer address; ``receive_timeout`` bounds
    SILENCE between reads and ``max_frame_seconds`` bounds one frame's life; ``max_frame_bytes``
    bounds that frame's size. Each takes ``None``/``0`` to disable it.

    The two caps BACKLOG #1725 added are documented once, on :data:`DEFAULT_MAX_CONNECTIONS_PER_HOST`
    and :data:`DEFAULT_MAX_FRAME_SECONDS` above — what each bounds, why the default is the number it
    is, and what it does NOT cover. Read those rather than a summary here; this docstring deliberately
    does not restate them, and does not count the caps either, because a closed count is a claim that
    goes stale the next time a cap is added.
    """

    def __init__(self, config: Source) -> None:
        s = config.settings
        # The bind interface is injected from the service's [inbound].bind_host (authors never set a
        # host on an inbound). Fall back to loopback for a missing/None value — never bind all
        # interfaces (0.0.0.0) by accident, since MLLP has no transport auth. See docs/CONNECTIONS.md.
        self.host: str = s.get("host") or "127.0.0.1"
        self.port: int = int(s["port"])
        self.encoding: str = s.get("encoding", "utf-8")
        # The inbound's ack mode, read only to NAK a frame the handler faulted on (BACKLOG #1619).
        # The runner builds every other ACK itself.
        self.ack_mode: AckMode = config.ack_mode
        # Every cap on THIS listener: key absent → secure default; None/0 → disabled, in whichever
        # spelling arrives. `_cap_setting` is what makes that last clause true — see it for why
        # deciding "off" before the conversion read a string `"0"` as a live cap of zero. All five go
        # through it, so there is one rule here rather than a per-key convention to look up. The
        # raw-TCP, X12 and HTTP listeners still read their own caps the older way, so this is a
        # property of this connector and not yet of the transport layer.
        self.max_connections: int | None = _cap_setting(
            s.get("max_connections", DEFAULT_MAX_CONNECTIONS), int
        )
        self.max_connections_per_host: int | None = _cap_setting(
            s.get("max_connections_per_host", DEFAULT_MAX_CONNECTIONS_PER_HOST), int
        )
        if self.max_connections_per_host is not None and self.max_connections_per_host < 1:
            # Only a NEGATIVE value reaches here: `_cap_setting` passes one through on purpose, and
            # it would be a cap that refuses every peer, including one holding zero connections,
            # since `0 >= -1`. Nothing is admitted, so `_release` never runs and
            # `_host_capacity_warned` grows one attacker-chosen key per address with nothing to clear
            # it: the unbounded table this control is not allowed to contain. Refuse at build, where
            # dry-run and `check` surface it, rather than at the first connection.
            raise ValueError(
                "MLLP max_connections_per_host must be at least 1 (use None or 0 to disable the "
                f"per-host cap), got {self.max_connections_per_host}"
            )
        self.receive_timeout: float | None = _cap_setting(
            s.get("receive_timeout", DEFAULT_RECEIVE_TIMEOUT), float
        )
        self.max_frame_bytes: int | None = _cap_setting(
            s.get("max_frame_bytes", DEFAULT_MAX_FRAME_BYTES), int
        )
        self.max_frame_seconds: float | None = _cap_setting(
            s.get("max_frame_seconds", DEFAULT_MAX_FRAME_SECONDS), float
        )
        if self.max_frame_seconds is not None and not self.max_frame_seconds >= 0:
            # Negative reaches here too, and would expire every frame the instant one opened — a
            # listener that drops every sender, configured from a value the author meant as "off".
            # Written `not >= 0` rather than `< 0` so NaN is refused as well: TOML can spell `nan`,
            # `_cap_setting` cannot recognise it (`nan != 0`), and every comparison with it is false
            # — so `min()` against the idle bound would silently drop the deadline and a bare
            # `wait_for(..., nan)` would fire at once.
            raise ValueError(
                "MLLP max_frame_seconds must be a number of seconds, zero or more (use None or 0 to "
                f"disable the frame deadline), got {self.max_frame_seconds}"
            )
        # Message-rate pacing. Absent -> OFF, unlike the caps above; see _pacing_settings and
        # DEFAULT_MAX_MESSAGES_PER_SECOND for why that deviation is deliberate and ruled.
        self.max_messages_per_second, self.message_burst = _pacing_settings(s)
        # Carried only so a pacing report can name this connection (BACKLOG #290).
        self._pacing_name = config.name or ""
        # Per-connection peer-IP allowlist (Tier 4 operability): when set, a connecting peer whose IP
        # is not listed is refused when its connection reaches `_on_client` -- with TLS on, that is
        # after the handshake (see _TLS_HANDSHAKE_TIMEOUT). Absent/empty = no restriction.
        sa = s.get("source_ip_allowlist")
        self.source_ip_allowlist: list[str] | None = [str(x) for x in sa] if sa else None
        # WP-13b: per-connection inbound TLS (present a server cert; opt-in mTLS via tls_ca_file). Built
        # once here so a bad cert/key fails at build. None when tls is off → plaintext, byte-identical.
        self._ssl: ssl.SSLContext | None = _mllp_ssl_context(s, server=True, name=config.name or "")
        self._server: asyncio.Server | None = None
        self._handler: InboundHandler | None = None
        self._active = 0
        #: Live connections per peer address, for `max_connections_per_host`. Keyed by IP string; a
        #: peer whose address the socket cannot report (`_peer_host` -> None) is never counted and
        #: never refused by that cap.
        #:
        #: A host is DROPPED at zero rather than left sitting at 0. This table is keyed by an
        #: attacker-chosen value, so a peer cycling source addresses would otherwise grow it without
        #: bound — the table would become a memory leak inside a control whose whole subject is
        #: bounded resources. Dropping at zero holds it to the live connections, which
        #: `max_connections` already bounds. **That is a bound on the TABLE, not a claim about the
        #: cap:** a peer with many source addresses gets a fresh per-host budget for each one and is
        #: bounded by `max_connections` alone. See DEFAULT_MAX_CONNECTIONS_PER_HOST.
        self._per_host: dict[str, int] = {}
        #: Hosts already warned about their per-host cap this episode, cleared with the count above.
        #: See `_log_host_capacity_once` for why the refusal is not logged per attempt.
        self._host_capacity_warned: set[str] = set()
        # Live client writers + their handler tasks, so stop()/reload can actively close established
        # connections (a peer may hold one open for weeks) and bound the wait — server.wait_closed()
        # alone hangs on a still-connected sender on py3.12.1+ and is a no-op quiesce on 3.11 (H-2).
        self._clients: set[asyncio.StreamWriter] = set()
        self._client_tasks: set[asyncio.Task[None]] = set()

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        # leader_gate is ignored: a listen source runs on every node (each binds its own endpoint;
        # a load balancer / per-node ports distribute inbound connections), so there is no
        # shared-resource double-read to gate. Accepted only so the runner's call is uniform.
        self._handler = handler
        # Bound both ends of a TLS socket's life outside `_on_client` (BACKLOG #1606): the handshake
        # before it, and the close_notify exchange after writer.close(), which otherwise holds the
        # socket open for asyncio's default of 30 s after its slot is freed. Only when there is TLS,
        # because asyncio refuses both arguments without `ssl`. Read at start() so a test can shorten
        # them.
        tls = self._ssl is not None
        self._server = await asyncio.start_server(
            self._on_client,
            self.host,
            self.port,
            ssl=self._ssl,
            ssl_handshake_timeout=_TLS_HANDSHAKE_TIMEOUT if tls else None,
            ssl_shutdown_timeout=_TLS_SHUTDOWN_TIMEOUT if tls else None,
        )

    @property
    def sockport(self) -> int:
        """The actual bound port (useful when configured with port 0 in tests)."""
        assert self._server is not None
        port: int = self._server.sockets[0].getsockname()[1]
        return port

    async def stop(self) -> None:
        # Stop accepting NEW connections (this alone does not close established ones).
        if self._server is not None:
            self._server.close()
        # Close established client connections BEFORE awaiting the server — otherwise
        # server.wait_closed() hangs on py3.12.1+ waiting for in-flight handlers of a peer that
        # holds its connection open. Closing the writer makes each read loop return EOF; a message
        # mid-handler still finishes its commit (the body is durably stored before any ACK, so
        # at-least-once holds — only a not-yet-sent ACK is lost, which the sender retries). Then
        # await the connection tasks with a bounded grace and cancel any stragglers (review H-2).
        for writer in list(self._clients):
            writer.close()
        # Then close every transport the SERVER tracks, a wider set than `_clients` (BACKLOG #1606).
        # A TLS socket still in its handshake never reached `_on_client`, so the loop above cannot see
        # it, and wait_closed() below waits for it -- so stop() spent its whole grace there and left
        # the socket open behind it. This comes BEFORE the task wait: during that wait such a socket
        # could otherwise finish its handshake, reach `_on_client` and have a message handled
        # mid-stop. For an established client this closes the raw socket under the writer just
        # closed; its close_notify is already queued, and close() sends what is queued before it
        # closes, so stop() does not wait out `_TLS_SHUTDOWN_TIMEOUT`. A handler mid-commit is
        # untouched, as with writer.close(). It awaits nothing, so it cannot wedge on the Proactor
        # (#55).
        if self._server is not None:
            self._server.close_clients()
        # One loop turn, so a client task created but not yet started (its handshake completed in
        # the same turn stop() began) registers itself in `_client_tasks` and joins the wait below,
        # rather than first running after stop() has returned. That narrows the window to asyncio's
        # own scheduling; it does not claim to close every interleaving.
        await asyncio.sleep(0)
        pending = [task for task in self._client_tasks if not task.done()]
        if pending:
            _done, still_running = await asyncio.wait(pending, timeout=_CLIENT_SHUTDOWN_GRACE)
            for task in still_running:
                task.cancel()
            if still_running:
                await asyncio.gather(*still_running, return_exceptions=True)
        self._clients.clear()
        self._client_tasks.clear()
        # Clear the per-host tables with them. A client task cancelled past its grace above, or one
        # the runner ABANDONS when a stop() overruns (wiring_runner's demotion path leaves the drain
        # running and reuses this same instance at the next promotion), never runs its `finally` —
        # so a stale count would survive into the restarted listener, and `_release`'s own docstring
        # names what that costs: "a per-host count left behind by a missed release locks that peer
        # out permanently". A straggler that does run later decrements a missing key, which
        # `_release` already treats as a no-op. `_active` keeps its existing behaviour: it is read
        # by the global cap that predates this row, and resetting it here would be a separate change.
        self._per_host.clear()
        self._host_capacity_warned.clear()
        # Now that no client handlers are in flight, this should complete promptly — but on the Windows
        # ProactorEventLoop a still-pending overlapped accept/read can make wait_closed() never return,
        # which (on the suite's single shared session loop) wedges every subsequent test with no output
        # until the CI job cap cancels it (#55, same class as the #17 Windows teardown hang). Bound it:
        # the listener is already .close()'d and every client task is done/cancelled, so a wait_closed()
        # that hasn't returned within the grace is the OS-level overlapped-op wedge, not work in flight —
        # abandoning it is safe (the socket is closed) and converts an infinite teardown into a bounded one.
        if self._server is not None:
            try:
                await asyncio.wait_for(self._server.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
            except TimeoutError:
                logger.warning("MLLP server.wait_closed() exceeded shutdown grace; abandoning")
            self._server = None

    async def _emit_event(
        self, kind: str, *, peer_host: str | None = None, reason: str | None = None
    ) -> None:
        """Fire one connection event (Corepoint-style log, #46) to the injected sink, **fail-soft**: a
        capture/store hiccup must NEVER raise into the per-client loop or block accept (pure observer).
        No-op when the sink is unset (capture off → byte-identical)."""
        sink = self.on_connection_event
        if sink is None:
            return
        try:
            await sink(kind, peer_host, reason)
        except Exception as exc:  # swallow + log; a capture bug can't drop an MLLP client
            logger.warning("MLLP connection-event emit failed: %s", safe_exc(exc))

    async def _drain_ack(self, writer: asyncio.StreamWriter) -> None:
        """Flush one already-written ACK to the sender under :data:`_ACK_DRAIN_GRACE` (BACKLOG #1617).

        Re-raises the ``TimeoutError`` rather than handling it here. That is deliberate: a
        ``TimeoutError`` IS an ``OSError``, so a peer that stopped reading is released down the
        **same** path a real reset already takes — ``_on_client``'s outer ``OSError`` arm frees the
        ``max_connections`` slot, emits ``peer_reset`` and closes the socket. A second release path
        beside that one is how a slot leaks. Only the warning is added here, where the peer is still
        in hand and the outer arm's redacted ``peer_reset`` alone would not say which bound fired.
        """
        try:
            await asyncio.wait_for(writer.drain(), _ACK_DRAIN_GRACE)
        except TimeoutError:
            logger.warning(
                "MLLP ACK to %s not drained within %.1fs; dropping the connection",
                writer.get_extra_info("peername"),
                _ACK_DRAIN_GRACE,
            )
            raise

    def _owes_handler_failure_reply(self) -> bool:
        """Whether this inbound answers each frame in HL7, so a handler fault owes the sender a NAK.

        Mirrors the runner, which replies only on an HL7 inbound with acknowledgements on.
        ``content_type`` is injected by the runner; ``None`` (a direct build, as in tests) reads as
        HL7, the MLLP default.
        """
        return self.ack_mode is not AckMode.NONE and self.content_type in (
            None,
            ContentType.HL7V2,
        )

    def _handler_failure_nak(self, message: bytes) -> bytes | None:
        """The framed ``AE`` NAK (``CE`` in enhanced mode) for a frame the inbound handler faulted
        on, or ``None`` if none can be framed. Call it only when a reply is owed.

        **Why AE.** It is this engine's code for "not accepted, and not because of what the message
        says". The runner answers ``AE`` for its own transient conditions (a strict-validation
        timeout, a streaming-detach budget) and ``AR`` only for a body it could not read. The
        engine's own MLLP destination reads the same split: it retries ``AE`` and dead-letters
        ``AR`` at once. An ``AR`` here would dead-letter an engine-to-engine hop on a store blip.

        Built defensively, because the fault may have come from reading this very message. Only a
        bounded prefix up to the first segment break is decoded and parsed, so a large frame costs
        nothing extra on the event loop. A header that cannot be read, or a ``build_ack`` that
        faults on it, falls back to the header defaults. The text is fixed and names no exception,
        so nothing from the message or the fault reaches the sender.
        """
        header: Peek | str = ""
        try:
            prefix = message[:_NAK_HEADER_SCAN_BYTES].lstrip()
            breaks = [i for i in (prefix.find(b"\r"), prefix.find(b"\n")) if i >= 0]
            first_segment = prefix[: min(breaks, default=len(prefix))]
            header = Peek.parse(normalize(first_segment, encoding=self.encoding))
        except Exception as exc:  # noqa: BLE001 -- an unreadable header: the NAK uses the defaults
            logger.warning("MLLP NAK cannot echo the message header: %s", safe_exc(exc))
        for inbound in (header, ""):
            try:
                nak = build_ack(
                    inbound, code="AE", text=_HANDLER_FAILURE_NAK_TEXT, ack_mode=self.ack_mode
                )
                return frame(nak, self.encoding)
            except Exception as exc:  # noqa: BLE001 -- fall back to the defaults, then give up
                logger.warning("MLLP NAK for a handler fault could not be built: %s", safe_exc(exc))
        return None

    async def _answer_handler_failure(
        self, message: bytes, exc: Exception, peer: object, peer_host: str | None
    ) -> tuple[bool, bytes | None]:
        """Log and record a handler fault. Returns whether a reply is owed, and the framed NAK.

        BACKLOG #1619. The runner lets a store exception at the ingress commit propagate, so a
        store outage used to reach the listener's last-resort catch. That catch dropped the
        connection with no reply and recorded ``framing_error``, so the sender saw a reset and the
        event log blamed framing.

        Now the event is ``handler_error``. A sender that expects replies gets a NAK, and then the
        connection closes, as before. Closing keeps two things the old drop gave for free. Frames
        the sender pipelined behind this one go unanswered, so it resends them after this one and
        order holds. And a sender pinned to a node whose store is down reconnects, which lets a
        load balancer move it. A sender that expects no reply keeps its socket instead: it never
        resends, so closing would only lose the frames it already sent behind this one.

        Nothing is ACKed here, so the ACK-after-commit rule holds. A fault that came after a
        commit does mean the resend commits another copy, which at-least-once delivery allows.
        """
        reason = safe_exc(exc)
        owed = self._owes_handler_failure_reply()
        nak = self._handler_failure_nak(message) if owed else None
        if nak is not None:
            outcome = f"answering MSA-1 {_CODES[self.ack_mode]['AE']}, then closing the connection"
        elif owed:
            outcome = "no reply could be framed; closing the connection"
        else:
            outcome = "this inbound sends no reply; keeping the connection"
        logger.error(
            "MLLP message from %s failed unexpectedly in the inbound handler: %s (%s)",
            peer,
            reason,
            outcome,
        )
        await self._emit_event("handler_error", peer_host=peer_host, reason=reason)
        return owed, nak

    def _at_host_capacity(self, peer_host: str | None) -> bool:
        """Whether this peer address already holds every connection ``max_connections_per_host``
        allows it (BACKLOG #1725). Always ``False`` when the cap is off or the socket could not
        report an address — a cap that cannot name its subject must not refuse anybody."""
        if self.max_connections_per_host is None or peer_host is None:
            return False
        return self._per_host.get(peer_host, 0) >= self.max_connections_per_host

    def _log_host_capacity_once(self, writer: asyncio.StreamWriter, peer_host: str) -> None:
        """Warn the FIRST time a host hits its cap, then stay quiet until it has no connections left.

        Clearing at zero rather than the moment the host drops back under the cap is deliberate: a
        peer oscillating on the boundary — close one, open two — would otherwise earn a line per
        cycle, which is connection churn and unbounded. Requiring a full disconnect makes one line
        per episode a real bound rather than a slower leak.

        A peer that loops ``connect()`` against a budget it has already filled is refused as fast as
        it can open sockets, so a line per refusal would let an unauthenticated peer fill the log
        volume — the service's stdout is captured to files under NSSM. That turns the defense into an
        amplifier for the very flood it exists to stop. The global ``max_connections`` refusal logs
        nothing at all for the same reason; one line per episode is the middle ground, and the
        `at_capacity` event still records every individual refusal for anyone counting them.

        The warned set is keyed and cleared exactly like :attr:`_per_host`, so it inherits that
        table's bound and adds no second population to leak.
        """
        if peer_host in self._host_capacity_warned:
            return
        self._host_capacity_warned.add(peer_host)
        logger.warning(
            "MLLP connections from %s refused: %s holds max_connections_per_host (%d). Further "
            "refusals for this host are not logged until it has no connections left.",
            writer.get_extra_info("peername"),
            peer_host,
            self.max_connections_per_host,
        )

    def _admit(self, peer_host: str | None) -> None:
        """Take one connection slot, globally and (when the peer has an address) for that host."""
        self._active += 1
        if peer_host is not None:
            self._per_host[peer_host] = self._per_host.get(peer_host, 0) + 1

    def _release(self, peer_host: str | None) -> None:
        """Give both slots back. Paired with :meth:`_admit` in one place so the two counters cannot
        drift — a per-host count left behind by a missed release locks that peer out permanently."""
        self._active -= 1
        if peer_host is None:
            return
        remaining = self._per_host.get(peer_host, 0) - 1
        if remaining > 0:
            self._per_host[peer_host] = remaining
        else:
            self._per_host.pop(peer_host, None)
            # Dropped together with the count, so the next episode for this host warns again and
            # neither table outlives the connections it describes.
            self._host_capacity_warned.discard(peer_host)

    def _log_frame_deadline(self, writer: asyncio.StreamWriter) -> None:
        """Say which bound dropped the connection (BACKLOG #1725). The `closed` event's reason says
        `frame_deadline`, but only when connection-event capture is on; this line lands either way,
        and an operator reading `idle_timeout` for a peer that was never idle would look in the wrong
        place. Socket metadata only — no frame bytes, which is the whole point of the partial frame
        this drops.

        Unthrottled, unlike :meth:`_log_host_capacity_once`, and the difference is the rate rather
        than a difference of opinion. A refused connection is free to the peer, so that path could be
        driven as fast as it could call ``connect()``. Reaching this one costs a connection held for
        ``max_frame_seconds``, so the caps already bound it: at the defaults, 32 lines per minute per
        address. That is the same shape as the existing `frame_oversize` warning beside it, which is
        also one line per dropped connection."""
        logger.warning(
            "MLLP frame from %s did not complete within max_frame_seconds (%.1fs); "
            "dropping the connection",
            writer.get_extra_info("peername"),
            self.max_frame_seconds,
        )

    def _frame_seconds_left(self, frame_opened_at: float | None) -> float | None:
        """Seconds left on the open frame's deadline, or ``None`` when no deadline is running.

        ``None`` means "this bound has nothing to say" — either ``max_frame_seconds`` is off or no
        frame is open. The result may be NEGATIVE, and the sign is the answer: at or below zero the
        frame has outlived its budget, which is what both callers test.
        """
        if frame_opened_at is None or self.max_frame_seconds is None:
            return None
        return self.max_frame_seconds - (time.monotonic() - frame_opened_at)

    def _read_budget(self, frame_left: float | None) -> float | None:
        """How long the next read may block: the idle bound, the open frame's remaining life, or the
        smaller of the two. ``None`` only when neither bound is configured (an unbounded read).

        There is no clamp on the result. ``frame_left`` cannot be negative here — the caller has
        already broken out of the loop on a spent one — and ``receive_timeout`` is ``None`` rather
        than falsy when it is off, so neither ordinary input can produce one. An earlier draft
        carried ``max(0.0, ...)`` and it was dead on those inputs, which is a claim nobody can check.

        **One input CAN still be negative, and it is not defended here.** Unlike
        ``max_frame_seconds``, ``receive_timeout`` has no build-time guard refusing a negative, so a
        configured ``-1`` reaches this function and closes every peer at once as ``idle_timeout``.
        That predates the frame deadline and is unchanged by it; the fix is a guard beside the other
        two in ``__init__``, not a clamp here, because a clamp would turn a typo into a silent bound.
        """
        if frame_left is None:
            return self.receive_timeout
        if self.receive_timeout is None:
            return frame_left
        return min(self.receive_timeout, frame_left)

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert self._handler is not None
        # Register before anything else so stop() can always find + close this connection — no race
        # with a client that connects just as we're stopping (review H-2).
        task = asyncio.current_task()
        self._clients.add(writer)
        if task is not None:
            self._client_tasks.add(task)
        # Kill Nagle/delayed-ACK so our framed ACK reply is not held back on the request-response
        # round-trip with the sender (see _set_tcp_nodelay). Applies to the accepted client socket.
        _set_tcp_nodelay(writer)
        peer_host = _peer_host(writer)
        established = False  # paired with a single `closed` event on a clean/idle end
        failed = False  # an error close is covered by its specific failure kind — don't double-emit
        close_reason = "eof"
        try:
            if self.source_ip_allowlist is not None:
                peer = writer.get_extra_info("peername")
                if not peer_ip_allowed(peer, self.source_ip_allowlist):
                    logger.warning(
                        "MLLP connection from %s refused: not in source_ip_allowlist", peer
                    )
                    await self._emit_event("peer_not_allowlisted", peer_host=peer_host)
                    return  # not allowlisted — refuse (closed in the outer finally; _active untouched)
            if self.max_connections is not None and self._active >= self.max_connections:
                await self._emit_event("at_capacity", peer_host=peer_host)
                return  # at capacity — refuse the new client (closed in the outer finally)
            if peer_host is not None and self._at_host_capacity(peer_host):
                # Same refusal, a different budget: this peer address already holds its share
                # (BACKLOG #1725). Deliberately the SAME `at_capacity` kind rather than a new one —
                # the connection event vocabulary is asserted against the emit sites and mirrored in
                # the web console filter, and what an operator needs here is WHICH cap refused them,
                # which the reason carries. The counter is not incremented, as above.
                self._log_host_capacity_once(writer, peer_host)
                await self._emit_event(
                    "at_capacity", peer_host=peer_host, reason="max_connections_per_host"
                )
                return  # at per-host capacity — refuse (closed in the outer finally)
            self._admit(peer_host)
            established = True
            # The `established` emit sits INSIDE the try whose finally releases the slot. It is
            # fail-soft against `Exception` but not against `CancelledError`, and stop() cancels
            # straggling client tasks — so a cancellation delivered here used to escape past
            # `_release`. That leaked an `_active` count before; with a per-host table it would leak
            # an entry nothing ever decrements, locking that address out until restart.
            try:
                await self._emit_event("established", peer_host=peer_host)
                decoder = MLLPDecoder(max_frame_bytes=self.max_frame_bytes)
                pacer = _MessagePacer.for_rate(
                    self.max_messages_per_second, self.message_burst, name=self._pacing_name
                )
                # Monotonic stamp of the read that carried the CURRENT frame's first byte, or None
                # when no frame is open (BACKLOG #1725). A wall clock would let a DST jump either
                # expire a healthy frame or reprieve a stalled one.
                frame_opened_at: float | None = None
                while True:
                    # ASVS 2.4.1 / 15.2.2 — the wait is BEFORE the read, never around the handler.
                    if pacer is not None:
                        paced_from = time.monotonic()
                        await pacer.pace()
                        if frame_opened_at is not None:
                            # Deliberate back-pressure is the ENGINE declining to read, not the peer
                            # being slow, so it must not spend the peer's frame budget. Push the
                            # frame's start stamp forward by exactly what we withheld.
                            # `_MessagePacer` promises it "never drops, never NAKs and never
                            # refuses"; without this line a paced connection with a partial frame
                            # buffered could be closed BY the pacing, which is that promise broken
                            # and a partial frame discarded outside the count-and-log boundary.
                            frame_opened_at += time.monotonic() - paced_from
                    frame_left = self._frame_seconds_left(frame_opened_at)
                    if frame_left is not None and frame_left <= 0.0:
                        # The budget went while we were NOT waiting on the socket — bytes arrived at
                        # or past the deadline, so the read below returned instead of timing out.
                        # The trickle case is caught by the TimeoutError arm, not here: the read is
                        # armed with the frame's remaining life whenever that is the smaller bound.
                        self._log_frame_deadline(writer)
                        close_reason = "frame_deadline"
                        break
                    read_budget = self._read_budget(frame_left)
                    # WHICH bound armed the wait, decided here rather than re-measured in the
                    # handler below. Re-measuring loses at the boundary: when the two budgets are
                    # close, or wait_for fires a hair early, the frame's remaining life reads as a
                    # small POSITIVE number and a peer that was never idle is closed as
                    # `idle_timeout` — the exact misdiagnosis this reason exists to prevent.
                    armed_by_frame = frame_left is not None and frame_left == read_budget
                    if read_budget is not None:
                        try:
                            chunk = await asyncio.wait_for(reader.read(4096), read_budget)
                        except TimeoutError:
                            # One wait_for serves both bounds, so name whichever armed it.
                            if armed_by_frame:
                                self._log_frame_deadline(writer)
                                close_reason = "frame_deadline"
                            else:
                                close_reason = "idle_timeout"
                            break  # past one of the two read bounds — close the connection
                    else:
                        chunk = await reader.read(4096)
                    if not chunk:
                        break
                    try:
                        decoded = 0
                        handler_dropped = False
                        for message in decoder.feed(chunk):
                            decoded += 1
                            try:
                                reply = await self._handler(message)
                            except Exception as exc:  # noqa: BLE001 -- see _answer_handler_failure
                                # BACKLOG #1619: the handler faulted on a frame the decoder read
                                # cleanly, which is not a framing fault. A store outage at the
                                # ingress commit is one reachable case. NAK it, then close.
                                owed, nak = await self._answer_handler_failure(
                                    message, exc, writer.get_extra_info("peername"), peer_host
                                )
                                if not owed:
                                    continue  # no reply on this inbound: handle what follows
                                if nak is not None:
                                    writer.write(nak)
                                    await self._drain_ack(writer)
                                handler_dropped = True
                                break
                            if reply is not None:
                                writer.write(frame(reply, self.encoding))
                                await self._drain_ack(writer)
                        if handler_dropped:
                            failed = True  # handler_error already names why this closes
                            break
                        # Charge AFTER the messages in this chunk are fully handled and ACKed.
                        if pacer is not None:
                            pacer.settle(decoded)
                    except MLLPFrameError as exc:
                        peer = writer.get_extra_info("peername")
                        logger.warning(
                            "MLLP frame from %s over cap; closing connection: %s", peer, exc
                        )
                        failed = True
                        await self._emit_event(
                            "frame_oversize", peer_host=peer_host, reason=safe_exc(exc)
                        )
                        break  # drop the connection rather than buffer without bound
                    except OSError:
                        raise  # peer reset / write failure → handled by the outer OSError catch (quiet)
                    except Exception as exc:
                        # Last-resort (ASVS 16.5.4): an unexpected codec error must not let the
                        # per-connection task die silently or leak detail. Log redacted; drop the conn.
                        # A HANDLER fault no longer lands here: the inner arm above answers it
                        # (BACKLOG #1619). What still does includes a reply the listener's
                        # encoding cannot carry.
                        peer = writer.get_extra_info("peername")
                        logger.error(
                            "MLLP connection from %s failed unexpectedly: %s", peer, safe_exc(exc)
                        )
                        failed = True
                        await self._emit_event(
                            "framing_error", peer_host=peer_host, reason=safe_exc(exc)
                        )
                        break
                    # Run the frame clock off the DECODER, after it has consumed this read — it is
                    # the only thing that knows whether a start byte arrived without its end byte.
                    # Reached on the success path alone (every arm above breaks), so a connection
                    # already being dropped never re-stamps.
                    #
                    # `decoded` is what makes this PER FRAME rather than per connection, and getting
                    # it wrong is not a small error. A pipelined sender's reads almost never end on a
                    # frame boundary, so `in_frame` stays True read after read across DIFFERENT
                    # frames; stamping only when `frame_opened_at is None` would therefore measure
                    # every later frame from the FIRST one's start byte and reset a perfectly healthy
                    # feed once per `max_frame_seconds`, forever. Any frame that was being timed is
                    # finished once this read completed one, so an open frame after that is a new one
                    # and its clock starts here.
                    if not decoder.in_frame:
                        frame_opened_at = None  # the frame closed, or none was ever open
                    elif decoded or frame_opened_at is None:
                        frame_opened_at = time.monotonic()  # this read carried a frame's first byte
            except OSError as exc:
                failed = True  # peer reset; nothing to do but drop the connection
                await self._emit_event("peer_reset", peer_host=peer_host, reason=safe_exc(exc))
            finally:
                self._release(peer_host)
        finally:
            self._clients.discard(writer)
            if task is not None:
                self._client_tasks.discard(task)
            writer.close()
            try:  # noqa: SIM105
                # Bound the close (see stop()): an unbounded writer.wait_closed() on the Windows
                # Proactor can never complete on a pending overlapped op, and the per-client task then
                # never finishes — so stop()'s `asyncio.wait(pending, ...)` grace never sees it done and
                # the whole shutdown wedges. Bounding it here makes the task always terminate (#55).
                await asyncio.wait_for(writer.wait_closed(), timeout=_CLIENT_SHUTDOWN_GRACE)
            except (TimeoutError, OSError):
                pass
            # Pair every `established` with one `closed` (clean EOF / idle). Emitted last (after the
            # socket is closed) so a cancel during shutdown can't skip the writer cleanup.
            if established and not failed:
                await self._emit_event("closed", peer_host=peer_host, reason=close_reason)


register_destination(ConnectorType.MLLP, MLLPDestination)
register_source(ConnectorType.MLLP, MLLPSource)

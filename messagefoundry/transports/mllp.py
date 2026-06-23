# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

import hl7
from hl7.containers import Component, Field, Repetition

from messagefoundry.config.models import AckMode, ConnectorType, Destination, Source
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.config.tls_policy import harden_kex_groups, harden_verify_flags
from messagefoundry.parsing.peek import HL7PeekError, Peek, normalize
from messagefoundry.redaction import safe_exc
from messagefoundry.transports.framing import MLLP_CODEC, FrameDecoder, FrameError
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
    "DEFAULT_MAX_CONNECTIONS",
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
]

logger = logging.getLogger(__name__)

# MLLP framing is the VT/FS+CR preset of the shared, configurable codec (transports.framing); these
# names + frame()/MLLPDecoder are kept as the MLLP-specific surface so existing imports + tests hold.
SB = 0x0B  # start block  (VT)
EB = 0x1C  # end block    (FS)
CR = 0x0D  # carriage return

# Resource caps (DoS guards). All are overridable per connection via MLLP() settings; see
# docs/CONNECTIONS.md. A falsy value (None/0) in settings disables the cap explicitly.
DEFAULT_MAX_FRAME_BYTES = 16 * 1024 * 1024  # 16 MiB — fits embedded base64 docs, bounds OOM
DEFAULT_MAX_CONNECTIONS = 256  # bound concurrent inbound clients (connection-flood guard)
DEFAULT_RECEIVE_TIMEOUT = 60.0  # seconds — close inbound sockets idle this long (slowloris guard)
# On stop()/reload, established clients are closed and their handlers given this long to finish an
# in-flight commit before the connection tasks are cancelled — bounds shutdown so a peer holding a
# connection open can't hang it (review H-2).
_CLIENT_SHUTDOWN_GRACE = 5.0


# MLLP's frame-too-large error is the shared codec error under its historical name (subclassing keeps
# `except MLLPFrameError` working while the codec raises the generic FrameError internally).
class MLLPFrameError(FrameError):
    """Raised when an MLLP frame exceeds its configured byte cap before end-of-block.

    Signals the caller to drop the connection rather than buffer an unbounded frame.
    """


def frame(payload: str | bytes, encoding: str = "utf-8") -> bytes:
    """Wrap a message in an MLLP block: ``SB payload EB CR`` (the VT/FS+CR codec preset)."""
    return MLLP_CODEC.frame(payload, encoding)


class MLLPDecoder(FrameDecoder):
    """Stateful MLLP frame reassembler — the :class:`~messagefoundry.transports.framing.FrameDecoder`
    bound to the MLLP (VT/FS+CR) codec.

    Feed it whatever bytes arrive; it yields complete message payloads (framing bytes
    stripped) as they complete. Bytes outside a frame — including a stray CR after EB or
    junk before the next SB — are discarded, matching tolerant real-world receivers. A frame
    over ``max_frame_bytes`` raises :class:`MLLPFrameError`.
    """

    error_class = MLLPFrameError

    def __init__(self, max_frame_bytes: int | None = None) -> None:
        super().__init__(MLLP_CODEC, max_frame_bytes=max_frame_bytes)


# --- ACK building ------------------------------------------------------------

# MSH-1 default field separator and MSH-2 default encoding characters.
_DEFAULT_FIELD_SEP = "|"
_DEFAULT_ENC = "^~\\&"


def _no_seg_sep(value: str) -> str:
    """Strip CR/LF from an echoed ACK value so an attacker-controlled inbound field can't inject a
    new segment into the ACK we send back (HL7-3)."""
    return value.replace("\r", " ").replace("\n", " ")


def _escape_ack_text(text: str, *, field_sep: str, enc: str) -> str:
    """Sanitize free-text MSA-3: drop CR/LF and escape the escape char + field separator so the
    text can't introduce extra fields/segments (the inbound-derived NACK reason is untrusted)."""
    esc = enc[2] if len(enc) > 2 else "\\"
    text = _no_seg_sep(text)
    # Escape the escape char first (so the substitution below stays reversible), then the field sep.
    return text.replace(esc, f"{esc}E{esc}").replace(field_sep, f"{esc}F{esc}")


_CODES = {
    AckMode.ORIGINAL: {"AA": "AA", "AE": "AE", "AR": "AR"},
    AckMode.ENHANCED: {"AA": "CA", "AE": "CE", "AR": "CR"},
}


def build_ack(
    inbound: str | bytes | Peek,
    *,
    code: str = "AA",
    text: str | None = None,
    ack_mode: AckMode = AckMode.ORIGINAL,
    control_id: str | None = None,
    timestamp: str = "",
) -> str:
    """Build an HL7 acknowledgement for ``inbound``.

    ``code`` is the logical outcome — ``"AA"`` (accept), ``"AE"`` (error) or ``"AR"``
    (reject) — mapped to the MSA-1 value appropriate for ``ack_mode``. ``text`` becomes
    MSA-3 (e.g. a NACK reason). ``control_id`` is the ACK's own MSH-10 (defaults to
    echoing the inbound control id). ``timestamp`` is MSH-7; pass one to pin it (tests),
    otherwise it defaults to the current HL7 DTM so strict senders that reject an empty
    MSH-7 don't NAK-loop and re-send (review low-6).
    """
    if code not in _CODES[AckMode.ORIGINAL]:
        raise ValueError(f"unknown ack code {code!r} (expected AA, AE or AR)")
    timestamp = timestamp or datetime.now().strftime("%Y%m%d%H%M%S")
    msa1 = _CODES[ack_mode if ack_mode is not AckMode.NONE else AckMode.ORIGINAL][code]

    try:
        peek = inbound if isinstance(inbound, Peek) else Peek.parse(inbound)
    except HL7PeekError:
        peek = None

    field_sep = (peek.field("MSH-1") if peek else None) or _DEFAULT_FIELD_SEP
    enc = (peek.field("MSH-2") if peek else None) or _DEFAULT_ENC
    # Every value below is echoed from the (untrusted) inbound message, so strip CR/LF to prevent
    # segment injection into the ACK; MSA-3 free text is additionally escaped (HL7-3).
    sending_app = _no_seg_sep((peek.sending_app if peek else None) or "")
    sending_fac = _no_seg_sep((peek.sending_facility if peek else None) or "")
    receiving_app = _no_seg_sep((peek.receiving_app if peek else None) or "")
    receiving_fac = _no_seg_sep((peek.receiving_facility if peek else None) or "")
    version = _no_seg_sep((peek.version if peek else None) or "2.5.1")
    original_control = _no_seg_sep((peek.control_id if peek else None) or "")
    ack_control = _no_seg_sep(control_id if control_id is not None else original_control)

    # Swap sender/receiver: the ACK goes back the way it came.
    msh_fields = [
        "MSH",
        _no_seg_sep(enc),
        receiving_app,
        receiving_fac,
        sending_app,
        sending_fac,
        timestamp,
        "",
        "ACK",
        ack_control,
        "P",
        version,
    ]
    msh = field_sep.join(msh_fields)
    msa_fields = ["MSA", msa1, original_control]
    if text:
        msa_fields.append(_escape_ack_text(text, field_sep=field_sep, enc=enc))
    msa = field_sep.join(msa_fields)
    return msh + "\r" + msa + "\r"


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
    except (hl7.HL7Exception, IndexError, ValueError) as exc:
        # IndexError covers a header so truncated python-hl7 can't read MSH-2 (e.g. "MSH|"); ValueError
        # is defensive. A non-HL7 body simply cannot be delimiter-rewritten — surface it, don't corrupt.
        raise ValueError(
            f"cannot re-encode delimiters: payload is not parseable HL7 ({exc})"
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


def _mllp_ssl_context(s: Mapping[str, Any], *, server: bool) -> ssl.SSLContext | None:
    """Build the per-connection MLLP ``SSLContext`` (WP-13b, ADR 0002), or ``None`` when ``tls`` is off.

    Built once in the connector ``__init__`` (a bad cert/key fails at build, like LDAPS). TLS 1.2+ floor.
    **Inbound** (``server=True``): present ``tls_cert_file``/``tls_key_file`` as the server identity;
    ``tls_ca_file`` opts into mTLS (require + verify a client cert). **Outbound** (``server=False``):
    verify the peer's cert against ``tls_ca_file`` (or the system trust store) with hostname checking,
    and optionally present ``tls_cert_file`` for mTLS. ``tls_verify=False`` (outbound) is MITM-able and
    refused unless ``insecure_tls_allowed()``, with a loud warning — exactly as LDAPS / SQL Server.

    ``tls_key_password`` decrypts a passphrase-encrypted private key (``env()``-sourced, mirroring the
    API listener's ``MEFOR_API_TLS_KEY_PASSWORD``); ``None`` (the default) loads an unencrypted key
    exactly as before."""
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
            ctx.load_verify_locations(cafile=ca)
            ctx.verify_mode = ssl.CERT_REQUIRED
        harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
        harden_verify_flags(ctx)  # strict RFC 5280 validation of any mTLS client cert (ASVS 12.1.4)
        return ctx
    # Outbound (client): verify the server cert unless explicitly — and loudly — disabled.
    verify = bool(s.get("tls_verify", True))
    if not verify and not insecure_tls_allowed():
        raise ValueError(
            "MLLP tls_verify=false disables server-certificate verification (MITM risk). Use a trusted "
            f"CA (tls_ca_file), or set {INSECURE_TLS_ESCAPE_ENV}=1 to allow it on a trusted-network bind."
        )
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
    if verify:  # skip the tls_verify=false / CERT_NONE path — nothing to validate (ASVS 12.1.4)
        harden_verify_flags(ctx)  # strict RFC 5280 validation of the server cert
    return ctx


class MLLPDestination(DestinationConnector):
    """Send a payload to an MLLP receiver and require a positive ACK.

    Phase 1 opens a fresh connection per delivery — simple and robust to flaky peers; a
    persistent/pooled connection can come later. A negative ACK (MSA-1 not in the accept
    family) or any I/O/timeout raises :class:`DeliveryError`, so the pipeline retries.

    Note (at-least-once): if the payload is sent but the ACK is lost (peer closes / times
    out after receiving), the retry re-delivers — the receiver may see a duplicate. This is
    the documented at-least-once trade-off; outbound receivers must be idempotent.
    """

    def __init__(self, config: Destination) -> None:
        s = config.settings
        self.host: str = s.get("host", "127.0.0.1")
        self.port: int = int(s["port"])
        self.timeout: float = float(s.get("timeout_seconds", 30.0))
        self.connect_timeout: float = float(s.get("connect_timeout", 10.0))
        self.encoding: str = s.get("encoding", "utf-8")
        mf = s.get("max_frame_bytes", DEFAULT_MAX_FRAME_BYTES)
        self.max_frame_bytes: int | None = int(mf) if mf else None
        # Per-outbound delimiter override (Corepoint -override parity): None = ship the payload as-is
        # (byte-identical, the default). A set value is validated NOW (at build) so a malformed override
        # fails at dry-run / `check`, not per delivery; it is applied in send() before framing.
        chars = s.get("encoding_characters")
        self.encoding_characters: EncodingCharacters | None = (
            parse_encoding_characters(chars) if chars is not None else None
        )
        # ADR 0013: when True, send() returns a DeliveryResponse carrying the application ACK (the
        # MSA/ERR the partner returned) for the delivery worker to capture. Default False → returns None,
        # byte-identical. A *read* failure (peer-close, frame-size) is never captured — it stays a
        # retryable DeliveryError; only a read-but-unparseable ACK becomes outcome='unparseable'.
        self.capture_response: bool = bool(s.get("capture_response", False))
        # WP-13b: per-connection outbound TLS (verify the peer). Built once here so a bad cert/CA fails
        # at build (dry-run/check), not per delivery. None when tls is off → plaintext, byte-identical.
        self._ssl: ssl.SSLContext | None = _mllp_ssl_context(s, server=False)

    async def send(self, payload: str) -> DeliveryResponse | None:
        if self.encoding_characters is not None:
            # Re-encode the body with this destination's delimiters before framing. A non-HL7/garbled
            # payload can't be rewritten — surface it as a DeliveryError (the message reached neither the
            # wire nor the peer) rather than framing a corrupted message; the pipeline records the ERROR.
            try:
                payload = reencode_delimiters(payload, self.encoding_characters)
            except ValueError as exc:
                raise DeliveryError(f"MLLP encoding-character override failed: {exc}") from exc
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.host,
                    self.port,
                    ssl=self._ssl,
                    # SNI + (when verifying) hostname check against the configured peer host.
                    server_hostname=self.host if self._ssl else None,
                ),
                self.connect_timeout,
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise DeliveryError(f"MLLP connect to {self.host}:{self.port} failed: {exc}") from exc
        try:
            writer.write(frame(payload, self.encoding))
            await asyncio.wait_for(writer.drain(), self.timeout)
            ack_bytes = await asyncio.wait_for(self._read_ack(reader), self.timeout)
        except asyncio.TimeoutError as exc:
            raise DeliveryError("MLLP timed out waiting for ACK") from exc
        except OSError as exc:
            raise DeliveryError(f"MLLP I/O error: {exc}") from exc
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        return self._check_ack(ack_bytes)

    async def test_connection(self) -> None:
        # Reachability only: open + close a connection (no frame, no ACK) so a test never delivers.
        await probe_tcp_reachable(self.host, self.port, self.connect_timeout, "MLLP")

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

    def _check_ack(self, ack_bytes: bytes) -> DeliveryResponse | None:
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
            if self.capture_response:
                return DeliveryResponse(
                    body=ack_bytes.decode(self.encoding, errors="replace"),
                    outcome="accepted",
                    detail=f"MSA-1={msa1}",
                )
            return None
        detail = ack.field("MSA-3") or ""
        # A negative ACK is a *partner rejection*, not a transport failure: the message reached the
        # peer, which said no. It is NOT captured — it routes through the existing NegativeAckError
        # failure policy (dead-letter on a permanent reject / retry on a transient error), unchanged by
        # capture. AR/CR (reject) is permanent (fail-fast); AE/CE (error) and any unrecognized negative
        # code are treated as transient (retry), the conservative choice when the intent is unclear.
        code, permanent = ("AR", True) if msa1 in ("AR", "CR") else ("AE", False)
        raise NegativeAckError(
            f"negative ACK (MSA-1={msa1}): {detail}".rstrip(": "), code=code, permanent=permanent
        )


# --- source ------------------------------------------------------------------


class MLLPSource(SourceConnector):
    """Listen for inbound MLLP connections, hand each message to the pipeline handler,
    and frame whatever the handler returns back to the sender as the ACK."""

    def __init__(self, config: Source) -> None:
        s = config.settings
        # The bind interface is injected from the service's [inbound].bind_host (authors never set a
        # host on an inbound). Fall back to loopback for a missing/None value — never bind all
        # interfaces (0.0.0.0) by accident, since MLLP has no transport auth. See docs/CONNECTIONS.md.
        self.host: str = s.get("host") or "127.0.0.1"
        self.port: int = int(s["port"])
        self.encoding: str = s.get("encoding", "utf-8")
        # Caps below: key absent → secure default; present-but-falsy (None/0) → disabled.
        mc = s.get("max_connections", DEFAULT_MAX_CONNECTIONS)
        self.max_connections: int | None = int(mc) if mc else None
        rt = s.get("receive_timeout", DEFAULT_RECEIVE_TIMEOUT)
        self.receive_timeout: float | None = float(rt) if rt else None
        mf = s.get("max_frame_bytes", DEFAULT_MAX_FRAME_BYTES)
        self.max_frame_bytes: int | None = int(mf) if mf else None
        # Per-connection peer-IP allowlist (Tier 4 operability): when set, a connecting peer whose IP
        # is not listed is refused at accept time. Absent/empty = no restriction.
        sa = s.get("source_ip_allowlist")
        self.source_ip_allowlist: list[str] | None = [str(x) for x in sa] if sa else None
        # WP-13b: per-connection inbound TLS (present a server cert; opt-in mTLS via tls_ca_file). Built
        # once here so a bad cert/key fails at build. None when tls is off → plaintext, byte-identical.
        self._ssl: ssl.SSLContext | None = _mllp_ssl_context(s, server=True)
        self._server: asyncio.Server | None = None
        self._handler: InboundHandler | None = None
        self._active = 0
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
        self._server = await asyncio.start_server(
            self._on_client, self.host, self.port, ssl=self._ssl
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
        pending = [task for task in self._client_tasks if not task.done()]
        if pending:
            _done, still_running = await asyncio.wait(pending, timeout=_CLIENT_SHUTDOWN_GRACE)
            for task in still_running:
                task.cancel()
            if still_running:
                await asyncio.gather(*still_running, return_exceptions=True)
        self._clients.clear()
        self._client_tasks.clear()
        # Now that no client handlers are in flight, this completes promptly instead of hanging.
        if self._server is not None:
            await self._server.wait_closed()
            self._server = None

    async def _on_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert self._handler is not None
        # Register before anything else so stop() can always find + close this connection — no race
        # with a client that connects just as we're stopping (review H-2).
        task = asyncio.current_task()
        self._clients.add(writer)
        if task is not None:
            self._client_tasks.add(task)
        try:
            if self.source_ip_allowlist is not None:
                peer = writer.get_extra_info("peername")
                if not peer_ip_allowed(peer, self.source_ip_allowlist):
                    logger.warning(
                        "MLLP connection from %s refused: not in source_ip_allowlist", peer
                    )
                    return  # not allowlisted — refuse (closed in the outer finally; _active untouched)
            if self.max_connections is not None and self._active >= self.max_connections:
                return  # at capacity — refuse the new client (closed in the outer finally)
            self._active += 1
            try:
                decoder = MLLPDecoder(max_frame_bytes=self.max_frame_bytes)
                while True:
                    if self.receive_timeout:
                        try:
                            chunk = await asyncio.wait_for(reader.read(4096), self.receive_timeout)
                        except asyncio.TimeoutError:
                            break  # idle past receive_timeout — close the connection
                    else:
                        chunk = await reader.read(4096)
                    if not chunk:
                        break
                    try:
                        for message in decoder.feed(chunk):
                            reply = await self._handler(message)
                            if reply is not None:
                                writer.write(frame(reply, self.encoding))
                                await writer.drain()
                    except MLLPFrameError as exc:
                        peer = writer.get_extra_info("peername")
                        logger.warning(
                            "MLLP frame from %s over cap; closing connection: %s", peer, exc
                        )
                        break  # drop the connection rather than buffer without bound
                    except OSError:
                        raise  # peer reset / write failure → handled by the outer OSError catch (quiet)
                    except Exception as exc:
                        # Last-resort (ASVS 16.5.4): an unexpected handler/codec error must not let the
                        # per-connection task die silently or leak detail. Log redacted; drop the conn.
                        peer = writer.get_extra_info("peername")
                        logger.error(
                            "MLLP connection from %s failed unexpectedly: %s", peer, safe_exc(exc)
                        )
                        break
            except OSError:
                pass  # peer reset; nothing to do but drop the connection
            finally:
                self._active -= 1
        finally:
            self._clients.discard(writer)
            if task is not None:
                self._client_tasks.discard(task)
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


register_destination(ConnectorType.MLLP, MLLPDestination)
register_source(ConnectorType.MLLP, MLLPSource)

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Remote-file transport: SFTP / FTP / FTPS — directory destination + directory-polling source.

A single connector type (``REMOTEFILE``) with a ``protocol`` setting selecting the wire protocol:

- ``sftp`` — SSH file transfer (paramiko, the ``[sftp]`` extra — lazily imported, so installs that
  never use SFTP skip it). **Host-key verification is ON by default**; an unknown key is refused
  unless the explicit dev escape ``MEFOR_ALLOW_INSECURE_TLS`` is set (and logged loudly when it is),
  mirroring the SQL Server backend's weakened-TLS posture.
- ``ftp`` — plain FTP (stdlib ``ftplib``). Cleartext: credentials over plain ``ftp`` are **refused**
  outright, with no escape (use ``ftps``/``sftp``; vault BACKLOG #2636).
- ``ftps`` — FTP over explicit TLS (``ftplib.FTP_TLS`` + ``PROT P``), credentials encrypted. **The
  server certificate and hostname are verified by default** (a verifying :class:`ssl.SSLContext`, not
  ftplib's no-verify stdlib fallback); ``tls_verify=false`` drops verification only when the explicit
  escape ``MEFOR_ALLOW_INSECURE_TLS`` is set (and is logged loudly), mirroring the MLLP outbound posture,
  and only on an anonymous hop: with a credential it is refused outright (vault BACKLOG #2636).

**Destination** uploads each payload to ``remote_dir``/``filename`` (``{HL7-path}`` placeholders
resolved via :func:`render_filename`). The write goes to a temp name then a **rename** to the final
name, so a poller on the far side never sees a partial file. A name collision is uniquified (never a
silent clobber), and with ``overwrite`` off the rename itself refuses a name taken since the
listing (:meth:`_RemoteClient.publish` and its overrides say how far that holds per protocol). A
transient failure (connect/timeout/transient FTP error) → :class:`DeliveryError` (retried); a
permanent server refusal (auth failure, no-such-dir, a 5xx-class permanent FTP error) →
:class:`NegativeAckError` (``permanent=True``), which dead-letters. With ``overwrite`` off, the
upload first lists the directory to find a free name; :meth:`RemoteFileDestination._unique` states
what a failed listing does.

**Source** polls ``remote_dir`` for ``pattern`` files, hands each to the pipeline handler, then — only
after the handler returns — moves the file to ``processed_subdir`` (or deletes it per ``after_read``).
A handler failure leaves the file in place to re-emit (at-least-once); an over-``max_file_bytes`` file
is moved to ``error_subdir`` before it's retrieved (a transport-level reject, like the File source).
A file is read only once it lists at the same size on two polls in a row (the settle gate, BACKLOG
#2071; :meth:`RemoteFileSource._settled`), so every file waits at least one poll.

**``max_file_bytes`` is charged TWICE, and the second charge is the one that binds** (BACKLOG #1191).
The pre-retrieve gate compares the size the server reported in its own directory listing, so it is
only as honest as the partner share. The retrieve itself then reads in ``RETRIEVE_CHUNK_BYTES``
chunks and refuses at the first byte past the same budget — counting **bytes actually read** — so a
share that lists a small file and then delivers an arbitrarily large body is cut off mid-transfer
rather than buffered whole. That matters here more than on any other intake: this transport consumes
the body *before* an ingress row exists, so no admission bound further down the pipeline can see it.
The refusal is a content refusal, not a transient one — the file is quarantined to ``error_subdir``
and logged, exactly as an over-listed-size or content-sniff reject is. ``max_file_bytes=0`` disables
both charges (unbounded), which is the operator's explicit choice.

**Idempotency.** Delivery is at-least-once (an upload may re-send) and a poll may re-emit a file that
was handled but not yet marked, so downstream consumers **must** tolerate duplicates.

The client is opened **per operation** (no shared mutable client held across an ``await``), mirroring
the MLLP destination's fresh-connection-per-delivery — simplest and safest under the staged pipeline's
concurrent workers. All blocking client I/O runs via :func:`asyncio.to_thread`.
"""

from __future__ import annotations

import abc
import asyncio
import contextlib
import ftplib  # nosec B402 — plain FTP is gated: cleartext credentials are refused (see _validate_common); FTPS/SFTP are the encrypted defaults
import hashlib
import io
import itertools
import logging
import posixpath
import re
import ssl
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Iterator, Mapping, Sequence
from typing import Any, TypeVar

from messagefoundry.config.models import (
    ConnectorType,
    ContentType,
    Destination,
    Source,
    remote_file_protocol,
)
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    weakened_tls_escape_permitted_here,
)
from messagefoundry.config.tls_policy import (
    RevocationHopGuard,
    TrustAnchorPolicy,
    build_verifying_client_context,
    harden_cipher_suites,
    harden_kex_groups,
    harden_verify_flags,
    hop_name_prefix,
    narrow_to_approved_suites,
    relax_verify_expiry,
    resolve_trust_anchor,
    warn_hostname_check_off,
)
from messagefoundry.connection_names import inbound_record_name
from messagefoundry.controlchars import has_control_char
from messagefoundry.keywrap import load_connection_cert_chain, ssh_key_encrypted
from messagefoundry.parsing.split import split_batch_bytes
from messagefoundry.redaction import safe_exc, safe_name
from messagefoundry.transports.base import (
    DEFAULT_MAX_ITEMS_PER_POLL,
    DeliveryError,
    DestinationConnector,
    DestinationStartupError,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    SourceStartupError,
    encode_wire_body,
    intake_open,
    positive_cap,
    register_destination,
    register_source,
    resolve_poll_ceiling,
)
from messagefoundry.transports.file import (
    _FALLBACK_NAME,
    DEFAULT_MAX_FILE_BYTES,
    FILENAME_MAX_BYTES,
    LEAVE_SEEN_CACHE_MAX,
    SETTLE_MISS_LIMIT,
    SETTLE_SEEN_MAX,
    ScanRejected,
    _check_template_fits,
    _content_matches_declared,
    render_filename,
    scan_inbound_file,
)
from messagefoundry.transports.mllp import InsecureHopGuard

__all__ = ["RemoteFileDestination", "RemoteFileSource"]

logger = logging.getLogger(__name__)

_PROTOCOLS = ("sftp", "ftp", "ftps")

_T = TypeVar("_T")

#: Bytes pulled per chunk while retrieving a remote file. Only the granularity of the budget check —
#: it does not change how much of the file ends up in memory on a healthy retrieve, and a body is
#: refused at most this far past ``max_file_bytes``.
RETRIEVE_CHUNK_BYTES = 1024 * 1024  # 1 MiB

#: Wall-clock bound on a single read from an established SFTP channel (BACKLOG #1195, ASVS 15.4.4).
#:
#: paramiko's ``connect(timeout=...)`` bounds the TCP connect and the handshake only. Once the
#: transport is up the channel reverts to a blocking socket, so a peer that accepts the connection
#: and then stops sending would park the calling thread for as long as it stayed silent. Every
#: REMOTEFILE operation runs on a worker thread, so a first deployment polling a hung share would
#: lose one thread per stuck operation and, with enough of them, would delay unrelated work sharing
#: the same pool.
#:
#: This bounds each individual read, not the whole transfer. A slow but live transfer keeps resetting
#: it, so a large file over a thin link is unaffected; only a peer that goes silent for this long is
#: cut off. The refusal is transient -- the caller retries it.
#:
#: The same value bounds opening the SFTP session, before the first read (BACKLOG #1936; see
#: :func:`_open_sftp_within`).
SFTP_CHANNEL_READ_TIMEOUT_SECONDS = 120.0

#: Most names one upload tries to publish under, with ``overwrite`` off (BACKLOG #2553). Each try
#: that finds its name taken moves on to the next free name in the listing. A partner filling those
#: names as fast as the upload tries them could otherwise hold it in that loop for good, so past this
#: many the delivery fails transient, and its retry lists the directory again.
PUBLISH_NAME_ATTEMPTS = 8


def _is_contained_name(name: object) -> bool:
    """True if ``name`` is a single, safe path component — a listing entry we may join onto the
    configured remote directory (BACKLOG #1238, ASVS 5.3.2).

    The name comes from a **remote server's own directory listing**, so it is chosen by a party we do
    not control: a malicious or compromised partner could return ``../../etc/passwd.hl7``, and the
    default ``pattern`` of ``*.hl7`` matches it (``fnmatch``'s ``*`` spans ``/``, unlike ``glob``).

    **Reject, never rewrite.** ``posixpath.basename`` is the obvious fix and is actively harmful:
    it MUTATES rather than refuses, so ``../../etc/adt_20260812.hl7`` becomes ``adt_20260812.hl7``,
    which rejoins to a *real* file in the poll directory — handing a hostile server a retrieve /
    move / delete primitive against the partner's own drop directory. It is also a no-op on the
    Windows-separator form (``posixpath`` tokenizes only ``/``), and because its output can never
    contain ``/`` any containment check placed after it is unreachable and always passes. For a
    healthcare feed, refusing one file is strictly better than silently reading the wrong one, and
    mutation cannot give that property.

    Refused: a non-``str``; empty; ``.`` and ``..``; any ``/`` or ``\\``; a control character; and the
    drive-relative form (``C:x.hl7``), which carries no separator at all and so slips a
    separator-only check."""
    if not isinstance(name, str) or not name or name in (".", ".."):
        return False
    if "/" in name or "\\" in name:
        return False
    if has_control_char(name):
        return False
    # A drive-relative path ("C:x.hl7") resolves against the drive's CWD on Windows and contains no
    # separator, so the checks above cannot see it. Two chars, ASCII letter, then a colon.
    return not (len(name) >= 2 and name[0].isascii() and name[0].isalpha() and name[1] == ":")


def _redact(host: str, path: str) -> str:
    """``host:path`` only — never credentials, for a log line."""
    return f"{host}:{path}"


# --- client abstraction ------------------------------------------------------


class _RemoteError(Exception):
    """A remote-file operation failed. ``permanent`` distinguishes a server refusal that a retry can't
    fix (auth failure, no-such-dir, a permanent FTP 5xx) from a transient connect/IO/timeout failure.

    ``credential_fault`` (BACKLOG #109, ADR 0095) narrows a permanent failure to specifically a
    **bad credential / authentication rejection** (would lock out the partner account on a retry
    storm), as distinct from a content/path permanent failure (no-such-dir, no-perm on one operation).
    Only auth-refusal sites set it; it is threaded onto the :class:`NegativeAckError` so the delivery
    worker can STOP-and-retain rather than dead-letter the backlog.

    ``config_fault`` (BACKLOG #2083) marks a permanent refusal of the connection's configuration
    while the FTP session opens: see :func:`_ftp_connect_refusal`. It is threaded the same way, and
    the worker stops the lane on it too, because every queued row would meet the same refusal.

    The connector maps a transient error to :class:`DeliveryError` (retry) and a permanent one to
    :class:`NegativeAckError` (dead-letter, or a STOP on either marker), so the client layer stays
    transport-detail-only."""

    def __init__(
        self,
        message: str,
        *,
        permanent: bool,
        credential_fault: bool = False,
        config_fault: bool = False,
    ) -> None:
        super().__init__(message)
        self.permanent = permanent
        self.credential_fault = credential_fault
        self.config_fault = config_fault

    @property
    def connection_fault(self) -> bool:
        """True for a credential or a configuration fault: a fault of the connection, which every
        row meets alike, rather than of one message or one path."""
        return self.credential_fault or self.config_fault

    def as_delivery_error(self) -> DeliveryError:
        """The pipeline error for this failure: a transient one retries, a permanent one is a
        :class:`NegativeAckError` carrying both markers."""
        if not self.permanent:
            return DeliveryError(str(self))
        return NegativeAckError(
            str(self),
            code="remotefile",
            permanent=True,
            credential_fault=self.credential_fault,
            config_fault=self.config_fault,
        )


class _RemoteOversize(Exception):
    """A retrieve read more bytes than ``max_file_bytes`` allows, and was cut off mid-transfer.

    **Deliberately NOT a** :class:`_RemoteError`. A ``_RemoteError`` on the retrieve path means
    "transient, leave the file and try again next poll", which is the one disposition an oversize
    body must never get: the next poll would pull the same oversized body again, forever. This is a
    content refusal, so the source quarantines the file to its error dir exactly as the listing-size
    gate and the content-sniff gate do — logged with a disposition, never accepted-and-dropped."""

    def __init__(self, *, limit: int) -> None:
        super().__init__(f"remote file exceeds max_file_bytes ({limit}) as actually read")
        self.limit = limit


class _RemoteChanged(Exception):
    """The file's size moved while it was being retrieved (BACKLOG #116): a partner is still writing
    it in place, so the bytes read may be a cut-off message.

    **Deliberately NOT a** :class:`_RemoteError`, like :class:`_RemoteOversize`, so the source can say
    in its log what happened. The disposition is the transient one: the file is left where it is and
    the next poll reads it again. ``None`` is a size the server could not report."""

    def __init__(self, *, before: int | None, read: int, after: int | None) -> None:
        super().__init__(
            f"remote file changed during the retrieve ({before} bytes before, {read} read, "
            f"{after} after)"
        )
        self.before = before
        self.read = read
        self.after = after


def _differs(reported: int | None, actual: int) -> bool:
    """True when the server reported a size and it is not ``actual``. A size the server could not
    report is no evidence either way, so on its own it never holds a file back (#116)."""
    return reported is not None and reported != actual


def _raise_if_changed(before: int | None, read: int, after: int | None) -> None:
    """Raise :class:`_RemoteChanged` unless each size the server reported matches the bytes read."""
    if _differs(before, read) or _differs(after, read):
        raise _RemoteChanged(before=before, read=read, after=after)


def _sftp_size(attrs: Any) -> int | None:
    """``st_size`` from paramiko ``SFTPAttributes``, which leaves it ``None`` when the server omits it."""
    size = attrs.st_size
    return None if size is None else int(size)


def _sftp_exists(sftp: Any, path: str) -> bool:
    """True when ``lstat`` shows an entry of any type at ``path``; a symlink counts as itself,
    whatever it points at. Some servers answer a missing path with a failure other than "no such
    file", or refuse ``lstat`` to an account that may still write. Either reads as False: a check
    before a rename then leaves the decision to the ``RENAME``'s own refusal, and a check after
    one confirms nothing, so the refusal raises. A timeout raises, for ``_op`` to map."""
    try:
        sftp.lstat(path)
    except TimeoutError:
        raise
    except OSError:
        return False
    return True


def _sftp_refused(sftp: Any, exc: Exception, src: str) -> bool:
    """True when a failed SFTP ``RENAME`` was the server refusing and nothing moved (BACKLOG
    #2553). paramiko raises a refusal status as an ``OSError``; SFTP version 3 has no "already
    exists" code, so a refused existing target arrives as a plain failure with no errno. Not a
    refusal: a timeout, where the server may still have renamed; "no such file", which keeps its
    permanent class; or any failure after which the temp is gone."""
    if isinstance(exc, (TimeoutError, FileNotFoundError)):
        return False
    return _sftp_exists(sftp, src)


def _publish_first(
    candidates: Sequence[str],
    *,
    taken: Callable[[str, bool], bool],
    rename: Callable[[str], object],
    refusals: tuple[type[Exception], ...],
    refused: Callable[[Exception], bool],
) -> str | None:
    """The loop every client's :meth:`_RemoteClient.publish` runs on its one connection, so the
    collision rule lives in one place (BACKLOG #2553).

    For each candidate: skip it when ``taken(dst, False)`` says something holds it; else
    ``rename`` onto it. A rename failing with one of ``refusals`` is a collision only when
    ``refused(exc)`` says the server refused and moved nothing, and ``taken(dst, True)`` then
    finds the name held
    (``True`` asks for a fresh answer where a client caches one). Anything else re-raises
    unchanged for the client to classify, as it was before #2553. A rename the server may have
    carried out, such as one whose reply timed out, must never count as a refusal: the loop would
    skip a name holding this very message and fail on the next. Returns the name published, or
    ``None`` when every candidate was taken."""
    for dst in candidates:
        if taken(dst, False):
            continue
        try:
            rename(dst)
        except refusals as exc:
            if refused(exc) and taken(dst, True):
                continue
            raise
        return dst
    return None


def _ftp_size(ftp: ftplib.FTP, path: str) -> int | None:
    """The file's size from ``SIZE`` (RFC 3659), or ``None`` when the server will not say.

    A #116 caller sends ``TYPE I`` first on its session: several common servers refuse ``SIZE`` in
    ASCII mode, and the binary size is the one ``retrbinary`` reads. A transient reply still raises,
    for ``_op`` to map."""
    try:
        return ftp.size(path)
    except (ftplib.error_perm, ftplib.error_proto):
        return None


class _BoundedSink:
    """Accumulates retrieved chunks and refuses at the first byte past ``limit``.

    **The budget is charged against bytes ACTUALLY READ, and that asymmetry is the whole point.**
    The source's pre-retrieve gate compares the size the SERVER reported in its directory listing,
    which a hostile or malfunctioning partner share simply lies about; this one counts what arrives.
    ``limit=None`` (the operator set ``max_file_bytes=0``, explicitly disabling the cap) never
    refuses, so the disabled posture stays byte-identical to the unbounded read this replaced."""

    __slots__ = ("_buf", "_limit", "_total")

    def __init__(self, limit: int | None) -> None:
        self._buf = io.BytesIO()
        self._limit = limit
        self._total = 0

    def write(self, chunk: bytes) -> None:
        """Append ``chunk``, raising :class:`_RemoteOversize` the moment the budget is passed. Shaped
        as a ``write(bytes) -> None`` callback so ``ftplib.retrbinary`` can call it directly."""
        self._total += len(chunk)
        if self._limit is not None and self._total > self._limit:
            raise _RemoteOversize(limit=self._limit)
        self._buf.write(chunk)

    def value(self) -> bytes:
        return self._buf.getvalue()


class _RemoteClient(abc.ABC):
    """Connect-per-operation remote-file client. Implementations are **synchronous** (blocking I/O);
    the connector calls them via :func:`asyncio.to_thread`. Each method opens its own connection, does
    the operation, and closes — nothing is held across calls."""

    @property
    def tls_context(self) -> ssl.SSLContext | None:
        """The TLS context this client dials with, or ``None`` for a client that uses none (SFTP,
        plain FTP). The destination's revocation guard reads it (BACKLOG #2193), so a client that
        gains TLS must return its context here to be guarded."""
        return None

    @abc.abstractmethod
    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        """``(name, size)`` for each regular file directly in ``remote_dir`` (no recursion)."""

    def list_names(self, remote_dir: str) -> set[str]:
        """The name of EVERY entry directly in ``remote_dir``, whatever its type: a directory, a
        symlink or anything else a server lists, as well as a regular file (BACKLOG #2082).

        The upload's collision check reads this, not :meth:`list_dir`. A same-named symlink or
        directory is a collision too: the rename that publishes the upload would replace the link,
        or fail on the directory. The SFTP and FTP clients override this; the default, for a client
        that can list only regular files, is exactly as wide as :meth:`list_dir`."""
        return {name for name, _ in self.list_dir(remote_dir)}

    def ensure_dir_and_list_names(self, remote_dir: str) -> tuple[bool, set[str]]:
        """:meth:`ensure_dir`, then :meth:`list_names`, on ONE connection where the client can
        (BACKLOG #2082). The connection probe runs both, and two connect bounds in a row can outlast
        the API's own cap on the probe. The default makes two calls."""
        return self.ensure_dir(remote_dir), self.list_names(remote_dir)

    @abc.abstractmethod
    def retrieve(self, path: str, *, max_bytes: int | None = None) -> bytes:
        """The full bytes of the file at ``path``, read in bounded chunks.

        ``max_bytes`` bounds what is pulled into memory. An implementation reads incrementally and
        raises :class:`_RemoteOversize` as soon as the bytes it has actually read pass the budget,
        so it never buffers a whole hostile body first. ``None`` = unbounded (the operator set
        ``max_file_bytes=0``).

        It also reads the file's size on the same connection before and after the transfer, and
        raises :class:`_RemoteChanged` when either differs from the bytes read (BACKLOG #116)."""

    @abc.abstractmethod
    def store(self, path: str, data: bytes) -> None:
        """Write ``data`` to ``path`` (overwriting if it exists)."""

    @abc.abstractmethod
    def rename(self, src: str, dst: str) -> None:
        """Rename ``src`` to ``dst``, replacing anything there: the ``overwrite = true`` publish and
        the source's moves."""

    @abc.abstractmethod
    def publish(self, src: str, candidates: Sequence[str]) -> str | None:
        """Rename ``src`` to the first of ``candidates`` that nothing holds, never replacing an
        entry of any type (BACKLOG #2553). Every try shares one connection.

        Returns the candidate, exactly as given, that ``src`` was published under, or ``None``
        when every candidate was taken, leaving ``src`` in place. Any other failure raises, classified as for :meth:`rename`.
        Abstract so that each client states how far its refusal is atomic; a check-then-rename
        default would let a new client inherit the race silently."""

    @abc.abstractmethod
    def remove(self, path: str) -> None:
        """Delete the file at ``path``."""

    @abc.abstractmethod
    def dispose_unless_changed(self, path: str, expected_size: int, dest: str | None) -> int | None:
        """Rename ``path`` to ``dest``, or delete it when ``dest`` is ``None``, unless its size is no
        longer ``expected_size`` (BACKLOG #116).

        Returns ``None`` once the file is disposed of. Returns the size it has now when that differs,
        and leaves the file in place. A size the server cannot report does not block the disposal. The
        check and the rename or delete share one connection, so the gap between them stays small."""

    @abc.abstractmethod
    def ensure_dir(self, remote_dir: str) -> bool:
        """Best-effort create ``remote_dir`` (ignore "already exists"). Returns **True only when THIS
        call created it** (#114) — the destination logs that, so a delivery landing in a directory the
        engine just invented is distinguishable from a normal one. A best-effort failure (no permission,
        a racing creator) returns False: nothing was created here."""


def _ftps_ssl_context(
    settings: dict[str, Any],
    *,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
    name: str = "",
) -> ssl.SSLContext:
    """Build a verifying TLS context for an FTPS control+data channel, mirroring the MLLP outbound arm
    (mllp.py ``_mllp_ssl_context``). Without this, ``ftplib.FTP_TLS()`` falls back to a no-verify stdlib
    context (``check_hostname=False`` / ``CERT_NONE``) — any certificate, including an attacker's, is
    silently accepted, so the encrypted FTPS channel is MITM-able. We verify the server certificate and
    hostname by default and only drop verification behind the explicit, loudly-logged dev escape.

    Fail-fast (build time): ``tls_verify=false`` without ``MEFOR_ALLOW_INSECURE_TLS`` raises, exactly
    like the MLLP path, so a misconfiguration is refused at construction rather than silently insecure.
    Optional mTLS via ``tls_cert_file``/``tls_key_file`` (passphrase ``tls_key_password``).

    ``trust_anchor_policy`` (#190, ADR 0093) supplies the instance ``[tls]`` internal-CA fallback when
    the connection names no ``tls_ca_file`` of its own (the verify path only; ``None`` = the historical
    ``create_default_context(cafile=…)`` behaviour, byte-identical). It never disables verification, so
    the internal CA never bypasses the ``tls_verify=false`` refusal above.

    ``name`` is the connection's, for the ``tls_check_hostname=false`` warning (ASVS 12.3.2). ``Ftp()``
    does not take that key, so ``connections.toml`` cannot set it either, but a hand-built
    ``ConnectionSpec`` can, and this context honours it, so the warning lives here.

    With a ``username`` or ``password`` set, both ``tls_verify=false`` and ``tls_check_hostname=false``
    are refused outright, with no escape (vault BACKLOG #2636, mirroring the SMTP credential arms of
    #323 and #1314). The escape governs only an anonymous hop."""
    verify = bool(settings.get("tls_verify", True))
    # Vault BACKLOG #2636: the FTPS twin of the two SMTP credential arms (#323 and #1314, in email.py
    # and direct.py). ABSOLUTE and keyed on no escape: the escape below may govern the BODY posture
    # of an anonymous hop, never the CREDENTIAL, because login() hands the credential to whichever
    # peer the session reached. Keyed on either half, as the plain-ftp credential guard is. Checked
    # BEFORE the escape arm, unlike SMTP, so a credentialed hop is never told to set an escape that
    # cannot unlock it.
    has_credential = bool(settings.get("username") or settings.get("password"))
    if not verify and has_credential:
        # No chain and no name: an on-path peer presenting any certificate captures the login.
        raise ValueError(
            f"{hop_name_prefix(name)}REMOTEFILE ftps sends FTP login credentials over an unverified "
            "TLS session (tls_verify=false); refused -- credentials require a verified TLS session. "
            "Leave tls_verify on (the default) with a trusted CA (tls_ca_file), or use sftp."
        )
    check_hostname = bool(settings.get("tls_check_hostname", True))
    if not check_hostname and has_credential:
        # The chain IS verified (the arm above refused the rest), but with the name check off any
        # certificate chaining to the anchor is accepted whatever host it names -- on the system
        # trust store, any certificate any public CA issued to anyone. The credential-less hop keeps
        # the warning below.
        raise ValueError(
            f"{hop_name_prefix(name)}REMOTEFILE ftps sends FTP login credentials over a TLS session "
            "whose peer NAME is unverified (tls_check_hostname=false); refused -- credentials "
            "require a session bound to the host, not merely to the trust anchor. Leave "
            "tls_check_hostname on (the default) and have the partner's certificate name the host "
            "you dial, or use sftp."
        )
    # #200 (ADR 0092 decision 2): the escape is CLAMPED to non production-PHI, so tls_verify=false can no
    # longer be silenced by MEFOR_ALLOW_INSECURE_TLS on a prod-PHI instance (mirrors the MLLP verify-off
    # arm). Off the construction gate (posture unstamped) the escape is refused since vault BACKLOG
    # #2354; it used to be honoured there unclamped. Only an anonymous hop reaches here.
    if not verify and not weakened_tls_escape_permitted_here():
        raise ValueError(
            "REMOTEFILE ftps tls_verify=false disables server-certificate verification (MITM risk). "
            f"Use a trusted CA (tls_ca_file), or set {INSECURE_TLS_ESCAPE_ENV}=1 on an instance at "
            "[security].enforcement = warn to allow it on a trusted-network bind (the escape has no "
            "effect while enforcing, the default, or with no posture)."
        )
    ca = settings.get("tls_ca_file")
    if verify and trust_anchor_policy is not None:
        # #190 (ADR 0093): the connection's own tls_ca_file wins verbatim, else the internal-CA anchor
        # for an internal hop. Only the VERIFY path uses it; the CERT_NONE branch is refused above.
        anchor = resolve_trust_anchor(
            connection_ca_file=str(ca) if ca else None,
            host=str(settings.get("host", "")),
            policy=trust_anchor_policy,
            connection=name or None,
        )
        ctx = build_verifying_client_context(anchor)
    else:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify:
        ctx.check_hostname = check_hostname
        if not check_hostname:  # ASVS 12.3.2: a recorded loosening, never a silent one
            warn_hostname_check_off(
                connector="remote-file (FTPS) connection",
                name=name,
                host=str(settings.get("host", "")),
            )
    else:
        logger.warning(
            "REMOTEFILE ftps TLS certificate verification is DISABLED (tls_verify=false, permitted "
            "by %s at [security].enforcement = warn) — MITM-able; for a trusted-network dev/test "
            "bind only.",
            INSECURE_TLS_ESCAPE_ENV,
        )
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    cert = settings.get("tls_cert_file")
    if cert:  # optional client identity for mTLS
        # The wrap is checked first (BACKLOG #1352, #1171), so a weak wrap or an encrypted key with NO
        # passphrase is refused rather than blocking on a TTY prompt (there is none under a service
        # account); the empty-bytes callback stays behind the check -- same as the MLLP path.
        load_connection_cert_chain(
            ctx, cert, settings.get("tls_key_file"), settings.get("tls_key_password")
        )
    harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
    narrow_to_approved_suites(ctx)  # approved AEAD default (BACKLOG #300)
    harden_cipher_suites(
        ctx, connector="remote-file (FTPS) connection"
    )  # assert forward secrecy (ASVS 12.1.2)
    if verify:  # nothing to strict-validate on the CERT_NONE path (ASVS 12.1.4)
        harden_verify_flags(ctx)
        # #129 (ADR 0094): opt-in granular expiry-only relaxation — accept an expired server cert while
        # STILL validating the chain, and the hostname unless tls_check_hostname=false (verify path
        # only; default off = byte-identical).
        if settings.get("tls_allow_expired"):
            relax_verify_expiry(ctx, host=str(settings.get("host", "")))
    return ctx


#: The steps of opening an FTP session, named so a 5xx reply can be classified by the step it answers.
_FTP_GREETING = "the greeting"
_FTP_AUTH_TLS = "AUTH TLS"
_FTP_LOGIN = "the login"
_FTP_PROT_P = "PBSZ/PROT P"

#: A reply line that names a connection limit as a whole phrase: ProFTPD's "530 Sorry, the maximum
#: number of clients (5) for this user are already connected.", Serv-U's "530 Sorry, no more than 10
#: users allowed", "Too many connections" or "too many users" from several others, and "Connection
#: limit reached". A "maximum ... clients" must go on to say they are already connected, or that the
#: limit is reached or exceeded; the word "maximum" and a noun alone are not enough. A full stop
#: ends the phrase, except one inside a token ("192.0.2.10", "ftp.example.com") or after "max". The
#: nouns are clients, connections, users and sessions only. "Login" is left out on purpose: "530
#: Maximum login attempts exceeded" is a credential refusal, not a limit.
_FTP_CONNECTION_LIMIT = re.compile(
    r"\bmax(?:imum)?\b\.?(?:[^.\n]|\.(?=\w)){0,60}?\b(?:clients?|connections?|users?|sessions?)\b"
    r"(?:[^.\n]|\.(?=\w)){0,40}?\b(?:already\s+(?:connected|logged\s+in)|reached|exceeded)\b"
    r"|\btoo\s+many\s+(?:\w+\s+){0,2}?(?:clients?|connections?|users?|sessions?)\b"
    r"|\bno\s+more\s+than\s+\d+\s+(?:\w+\s+){0,2}?(?:clients?|connections?|users?|sessions?)\b"
    r"|\b(?:client|connection|user|session)s?\s+limit\s+(?:reached|exceeded)\b",
    re.IGNORECASE,
)

#: Words that mark a login reply as being about the credential or the account, even when it also
#: names a limit or a TLS demand. A login reply carrying one anywhere keeps the credential-fault
#: class. An underscore counts as a space (see :func:`_names_credential`), so "LOGIN_FAILED" and
#: "USER_NOT_FOUND" are read as words.
#:
#: Most stems match inside a word, so "blocked", "Unauthorized", "loginfailed" and "badpassword"
#: count (BACKLOG #2083, fix round 3). "tries" and "retries" are anchored at both ends, so "entries"
#: is not "tries".
#:
#: Two busy-server words are left out on purpose: "retry" ("please retry later") and "permitted"
#: ("no more than 10 users permitted"); "not permitted" is in. Others a busy server also says stay
#: in: "denied", "rejected", "refused", "not allowed", and a banner's "Unauthorized access". Such a
#: reply stops the lane, the cheaper of the two errors; see :func:`_names_connection_limit`.
_FTP_CREDENTIAL_WORDS = re.compile(
    r"lock|auth|passw|fail|invalid|incorrect|wrong|mismatch|unknown|unsuccess|cred|revo[kc]"
    r"|deactivat|forbid|reject|refus|disabl|disallow|prohibit|inactiv|expir|suspend|terminat"
    r"|blacklist|\bbad|\bpwd\b|\battempt|\btries\b|\bretries\b|\bden(?:y|ies|ied|ying|ial)"
    r"|\bbann?ed\b|\bfrozen\b|\bon\s+hold\b|\bclosed\b"
    r"|\bnot\s+(?:allowed|permitted|found|accepted|recogni[sz]ed|logged\s+in)\b"
    r"|\bno\s+such\s+user\b|\bdoes\s+not\s+exist\b",
    re.IGNORECASE,
)

#: TLS vocabulary taken out before the credential words are looked for, in a TLS demand only: the
#: ``AUTH TLS`` command ("must use AUTH TLS first"), and "authenticate" ("You must authenticate over
#: TLS"). There neither is about the credential. "Authentication failed" still counts, by "failed".
#: Beside a connection limit they stay credential words: "530 Not authenticated; too many
#: connections" is a refused login, and retrying it would move a partner lockout counter.
_FTP_TLS_VOCABULARY = re.compile(r"\bAUTH\s+(?:TLS|SSL)\b|\bauthenticat\w*", re.IGNORECASE)

#: A TLS name as a whole token: "SSL", "TLS", "TLSv1.2", "FTPS", or a word starting "encrypt". Not
#: "SSL-VPN", "ftps-users", "sslhome", "the SSL VPN", "/srv/tls" or "encrypted_users", which name an
#: account's group or path: a name joined to "-", "_" or "/" is part of a longer token.
_TLS_NAME_PATTERN = (
    # "/" joins a path, except between two TLS names, as in ProFTPD's "SSL/TLS required".
    r"(?:(?<!_)(?:(?<!/)|(?<=ssl/)|(?<=tls/))\b(?:ssl|tls|ftps)(?:v?[\d.]*\d)?\b"
    r"(?![-_])(?!/(?!(?:ssl|tls)\b))(?!\W{1,3}vpn\b)"
    r"|(?<![/_])\bencrypt[a-z]*\b(?![-_/]))"
)

#: A reply line that demands TLS as one phrase: a TLS name then "required" or "mandatory" within
#: three words, or "must", "have to" or "requires" then a TLS name within four. vsftpd's "530
#: Non-anonymous sessions must use encryption.", ProFTPD's "550 SSL/TLS required on the control
#: channel", FileZilla's "You have to use FTP over TLS" and IIS's "534 Policy requires SSL." all
#: match. "only" is left out: "530 Login for SSL-VPN users only" refuses an account.
_FTP_TLS_DEMAND = re.compile(
    rf"{_TLS_NAME_PATTERN}\W+(?:\w+\W+){{0,3}}?(?:requir\w*|mandatory)\b"
    rf"|\b(?:must|have\s+to|requir\w*)\W+(?:\w+\W+){{0,4}}?{_TLS_NAME_PATTERN}",
    re.IGNORECASE,
)


def _last_reply_line(reply: str) -> str:
    """The last non-blank line of a reply, the one that carries the final code."""
    lines = [line for line in reply.strip().splitlines() if line.strip()]
    return lines[-1] if lines else ""


def _names_credential(reply: str, *, in_tls_demand: bool = False) -> bool:
    """True when a reply carries a credential or account word anywhere (``_FTP_CREDENTIAL_WORDS``).
    An underscore is read as a space. With ``in_tls_demand``, TLS vocabulary
    (``_FTP_TLS_VOCABULARY``) is taken out first."""
    text = reply.replace("_", " ")
    if in_tls_demand:
        text = _FTP_TLS_VOCABULARY.sub(" ", text)
    return bool(_FTP_CREDENTIAL_WORDS.search(text))


def _names_connection_limit(reply: str, *, at_login: bool) -> bool:
    """True when an FTP reply names a connection limit, and, at the login, says nothing about the
    credential.

    **An unclear login refusal is a credential fault (BACKLOG #2083).** RFC 959 gives 530 for "not
    logged in", whatever the reason. So only the text can tell a busy server from a wrong password,
    and servers word it freely. This function is the narrow test that lets a 5xx login refusal be
    read as a busy server. :func:`_demands_tls` is another, and there may be more: a 4xx is
    classified in :meth:`_FtpClient._connect`. A 5xx login refusal that passes neither is a
    credential fault, which stops the lane under the default policy (ADR 0095).

    The two errors do not cost the same. Reading a busy server as a bad password stops one lane on
    this engine, with every message kept, until an operator resumes it. Reading a bad password as a
    busy server retries the login on every delivery. A partner that locks an account after a few
    failures would lock it, on its own system, where no operator here can undo it.

    So the test is narrow on purpose. The limit phrase must be on the reply's last line, which
    carries the final code; earlier lines are often a banner. At the login, no credential word may
    appear anywhere in the reply. Before the login no credential has been sent, so the words are
    not looked for there."""
    if not _FTP_CONNECTION_LIMIT.search(_last_reply_line(reply)):
        return False
    return not (at_login and _names_credential(reply))


def _demands_tls(reply: str) -> bool:
    """True when a login refusal demands TLS as one phrase, and says nothing about the credential.

    Such a server refuses a plain session's login whatever the credential, so the fault is the
    connection's TLS setting (BACKLOG #2083, fix round 3). The caller asks only for a plain session;
    an FTPS control channel is already TLS. The demand must be one phrase on the last line
    (``_FTP_TLS_DEMAND``), and a credential word anywhere keeps the credential-fault class."""
    return bool(_FTP_TLS_DEMAND.search(_last_reply_line(reply))) and not _names_credential(
        reply, in_tls_demand=True
    )


def _ftp_connect_refusal(step: str, exc: ftplib.error_perm, *, tls: bool) -> _RemoteError:
    """Classify a 5xx reply received while opening an FTP session (BACKLOG #2083).

    - A reply naming a connection limit is **transient**: the server is busy, and a later attempt
      gets in. See :func:`_names_connection_limit` for how an ambiguous login reply falls.
    - A refusal of ``AUTH TLS`` or ``PBSZ``/``PROT P`` is a **configuration** fault: permanent, and
      not a credential fault. The server does not offer the TLS this connection asks for, so no
      retry helps and no credential was at fault.
    - On a plain session, a login refusal that says the server requires TLS is the same
      configuration fault; see :func:`_demands_tls`.
    - A refusal of the greeting, before any credential is sent, is permanent and not a credential
      fault either.
    - Any other refusal at the login is a **credential** fault (#109, ADR 0095), so the delivery
      worker stops the lane rather than retrying into an account lockout.

    These are the 5xx rules. A 4xx is transient, except a 4xx at the login that names the credential
    ("430 Invalid username or password"): :meth:`_FtpClient._connect` makes that a credential fault.

    The configuration faults carry ``config_fault`` (fix round 4). Every queued row would meet the
    same refusal, so on the delivery path the worker stops the lane and keeps the queue, as it does
    for a credential fault, rather than dead-letter each row in turn. Both follow
    ``credential_fault_policy``; ``"dead_letter"`` dead-letters instead. :meth:`_list_or_retry`
    passes both markers through unchanged.
    """
    reply = str(exc)
    if _names_connection_limit(reply, at_login=step == _FTP_LOGIN):
        return _RemoteError(
            f"FTP server refused {step} at its connection limit (retried): {reply}",
            permanent=False,
        )
    if step in (_FTP_AUTH_TLS, _FTP_PROT_P):
        return _RemoteError(
            f"FTPS server refused {step}, a TLS configuration fault, not a credential fault: {reply}",
            permanent=True,
            config_fault=True,
        )
    if step == _FTP_LOGIN and not tls and _demands_tls(reply):
        return _RemoteError(
            f"FTP server requires TLS at {step}, a TLS configuration fault, not a credential "
            f"fault: {reply}",
            permanent=True,
            config_fault=True,
        )
    if step == _FTP_GREETING:
        return _RemoteError(
            f"FTP server refused the connection, a configuration fault: {reply}",
            permanent=True,
            config_fault=True,
        )
    return _RemoteError(f"FTP login refused: {reply}", permanent=True, credential_fault=True)


class _FtpClient(_RemoteClient):
    """FTP / FTPS client over the stdlib ``ftplib``. ``tls`` selects ``FTP_TLS`` (explicit TLS, with
    ``PROT P`` so the data channel is encrypted too) over plain ``FTP``. For FTPS a verifying
    :class:`ssl.SSLContext` is built at construction (fail-fast) so the server certificate and hostname
    are validated — ftplib's default no-verify stdlib context is never used."""

    def __init__(
        self,
        settings: dict[str, Any],
        *,
        tls: bool,
        trust_anchor_policy: TrustAnchorPolicy | None = None,
        name: str = "",
    ) -> None:
        self._host = str(settings["host"])
        self._port = int(settings.get("port", 21))
        self._user = settings.get("username")
        self._password = settings.get("password")
        self._tls = tls
        self._timeout = float(settings.get("connect_timeout", 30.0))
        # Build the verifying TLS context once, fail-fast (build_check) — mirrors the SFTP host-key
        # posture: a verify-disabled ftps without the escape is refused here, not silently insecure.
        # #190 (ADR 0093): thread the instance [tls] internal-CA trust-anchor policy (verify path only).
        self._context: ssl.SSLContext | None = (
            _ftps_ssl_context(settings, trust_anchor_policy=trust_anchor_policy, name=name)
            if tls
            else None
        )

    @property
    def tls_context(self) -> ssl.SSLContext | None:
        return self._context

    def _connect(self) -> ftplib.FTP:
        """Connect, secure the control channel (FTPS), log in and secure the data channel (FTPS), or
        raise a classified :class:`_RemoteError`. Each step is named, because the step a 5xx reply
        answers decides its class (BACKLOG #2083); see :func:`_ftp_connect_refusal`. The connection
        is closed on every failure."""
        # B321: plain FTP only when explicitly selected, and only anonymously: credentials over it
        # are refused outright (see _validate_common). FTPS/SFTP are the encrypted defaults.
        if self._tls:
            ftp: ftplib.FTP = ftplib.FTP_TLS(context=self._context, timeout=self._timeout)
        else:
            ftp = ftplib.FTP(timeout=self._timeout)  # nosec B321
        step = _FTP_GREETING
        try:
            ftp.connect(self._host, self._port)
            if isinstance(ftp, ftplib.FTP_TLS):
                # Explicit here rather than left to login(), so a refusal is known to answer AUTH TLS
                # and not the credential. login() skips its own AUTH once the socket is TLS.
                step = _FTP_AUTH_TLS
                ftp.auth()
            step = _FTP_LOGIN
            ftp.login(user=str(self._user or ""), passwd=str(self._password or ""))
            if isinstance(ftp, ftplib.FTP_TLS):
                step = _FTP_PROT_P
                ftp.prot_p()  # encrypt the data channel, not just the control channel
        except ftplib.error_perm as exc:
            ftp.close()
            raise _ftp_connect_refusal(step, exc, tls=self._tls) from exc
        except ftplib.error_temp as exc:
            ftp.close()
            if step == _FTP_LOGIN and _names_credential(str(exc)):
                # A 4xx that names the credential ("430 Invalid username or password") is a refused
                # login too: retried, it would lock the partner account (BACKLOG #2083, fix round 3).
                # A credential word wins over a limit phrase here as it does at a 5xx, so "421 Too
                # many connections; account locked" stops the lane. The word list is broad, so some
                # busy or closing 4xx replies ("blocked", "terminated") stop it too: the cheaper
                # error, as :func:`_names_connection_limit` explains (fix round 4 review 2).
                raise _RemoteError(
                    f"FTP login refused: {exc}", permanent=True, credential_fault=True
                ) from exc
            raise _RemoteError(f"FTP connect failed: {exc}", permanent=False) from exc
        except ftplib.all_errors as exc:  # connect/timeout/4xx/protocol/OSError -- transient
            ftp.close()
            raise _RemoteError(f"FTP connect failed: {exc}", permanent=False) from exc
        except BaseException:
            ftp.close()
            raise
        return ftp

    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        return self._op(lambda ftp: self._list(ftp, remote_dir))

    @staticmethod
    def _list(ftp: ftplib.FTP, remote_dir: str) -> list[tuple[str, int]]:
        out: list[tuple[str, int]] = []
        # MLSD gives a reliable type + size; fall back to NLST + SIZE where the server lacks it.
        try:
            for name, facts in ftp.mlsd(remote_dir):
                if name in (".", "..") or facts.get("type") != "file":
                    continue
                out.append((name, int(facts.get("size", 0))))
            return out
        except (ftplib.error_perm, ftplib.error_proto):
            pass
        for name in ftp.nlst(remote_dir):
            base = posixpath.basename(name)
            if base in (".", ".."):
                continue
            # A directory or an un-sizable entry lists as 0 (the oversize check skips it).
            size = _ftp_size(ftp, posixpath.join(remote_dir, base)) or 0
            out.append((base, int(size)))
        return out

    def list_names(self, remote_dir: str) -> set[str]:
        return self._op(lambda ftp: self._names(ftp, remote_dir))

    def ensure_dir_and_list_names(self, remote_dir: str) -> tuple[bool, set[str]]:
        return self._op(lambda ftp: (self._mkd(ftp, remote_dir), self._names(ftp, remote_dir)))

    @staticmethod
    def _names(ftp: ftplib.FTP, remote_dir: str) -> set[str]:
        """Every entry's name, of any type (see :meth:`_RemoteClient.list_names`). ``MLSD`` names
        the directory itself and its parent as ``cdir`` and ``pdir``; those are left out, and so
        are ``.`` and ``..``. ``NLST`` already names every entry."""
        try:
            return {
                name
                for name, facts in ftp.mlsd(remote_dir)
                if name not in (".", "..") and facts.get("type", "").lower() not in ("cdir", "pdir")
            }
        except (ftplib.error_perm, ftplib.error_proto):
            pass
        names = {posixpath.basename(name) for name in ftp.nlst(remote_dir)}
        return names - {".", ".."}

    def retrieve(self, path: str, *, max_bytes: int | None = None) -> bytes:
        def run(ftp: ftplib.FTP) -> bytes:
            # retrbinary already streams; the sink is what makes the stream BOUNDED — it raises out
            # of the callback the moment the bytes read pass the budget, which aborts the transfer
            # instead of buffering the rest of a hostile body. _op's finally still closes the
            # connection (its quit() is bounded by the socket timeout set at connect).
            sink = _BoundedSink(max_bytes)
            ftp.voidcmd("TYPE I")  # before SIZE: see _ftp_size
            before = _ftp_size(ftp, path)
            ftp.retrbinary(f"RETR {path}", sink.write, blocksize=RETRIEVE_CHUNK_BYTES)
            body = sink.value()
            _raise_if_changed(before, len(body), _ftp_size(ftp, path))
            return body

        return self._op(run)

    def store(self, path: str, data: bytes) -> None:
        self._op(lambda ftp: ftp.storbinary(f"STOR {path}", io.BytesIO(data)))

    def rename(self, src: str, dst: str) -> None:
        self._op(lambda ftp: ftp.rename(src, dst))

    def publish(self, src: str, candidates: Sequence[str]) -> str | None:
        """See :meth:`_RemoteClient.publish`. **Not atomic on FTP.** RFC 959 does not say what
        ``RNTO`` does to an existing name: some servers refuse it and some replace it. So this lists
        the directory, then sends ``RNFR`` and ``RNTO``, all on one connection. On a server that
        replaces, a partner file written after the listing and before ``RNTO`` is still replaced:
        a gap of a few round trips, where it used to span the whole upload.

        The candidates share one directory, as :meth:`RemoteFileDestination._unique` builds them.
        Its listing is reused for each and taken again only after ``RNTO`` is refused. Only a
        refused ``RNTO`` can count as a collision: a refused ``RNFR`` means the temp is gone. That
        fresh listing compares case-blind, since a case-insensitive server refuses a case variant
        too; if it fails, it confirms nothing and the refusal raises as it was. The first listing
        failing is transient, as every send-path listing is (the #1936 rule in
        :meth:`RemoteFileDestination._unique`)."""

        def run(ftp: ftplib.FTP) -> str | None:
            listing: set[str] | None = None
            rnto_sent = False

            def taken(dst: str, fresh: bool) -> bool:
                nonlocal listing
                directory, name = posixpath.split(dst)
                if fresh:
                    try:
                        listing = self._names(ftp, directory)
                    except ftplib.error_perm as exc:
                        logger.warning(
                            "REMOTEFILE could not list the upload directory to confirm a refused "
                            "RNTO, so the refusal stands: %s",
                            exc,
                        )
                        return False
                    return name.casefold() in {n.casefold() for n in listing}
                if listing is None:
                    try:
                        listing = self._names(ftp, directory)
                    except ftplib.error_perm as exc:
                        raise _RemoteError(
                            f"FTP could not list the upload directory to check a name: {exc}",
                            permanent=False,
                        ) from exc
                return name in listing

            def rename(dst: str) -> None:
                # ftplib.FTP.rename's two commands, split so a refusal is known to answer RNTO.
                nonlocal rnto_sent
                rnto_sent = False
                reply = ftp.sendcmd(f"RNFR {src}")
                if not reply.startswith("3"):
                    raise ftplib.error_reply(reply)
                rnto_sent = True
                ftp.voidcmd(f"RNTO {dst}")

            return _publish_first(
                candidates,
                taken=taken,
                rename=rename,
                refusals=(ftplib.error_perm, ftplib.error_temp),
                refused=lambda exc: rnto_sent,
            )

        return self._op(run)

    def remove(self, path: str) -> None:
        self._op(lambda ftp: ftp.delete(path))

    def dispose_unless_changed(self, path: str, expected_size: int, dest: str | None) -> int | None:
        def run(ftp: ftplib.FTP) -> int | None:
            ftp.voidcmd("TYPE I")  # before SIZE: see _ftp_size
            current = _ftp_size(ftp, path)
            if _differs(current, expected_size):
                return current
            if dest is None:
                ftp.delete(path)
            else:
                ftp.rename(path, dest)
            return None

        return self._op(run)

    def ensure_dir(self, remote_dir: str) -> bool:
        return self._op(lambda ftp: self._mkd(ftp, remote_dir))

    @staticmethod
    def _mkd(ftp: ftplib.FTP, remote_dir: str) -> bool:
        try:
            ftp.mkd(remote_dir)
        except ftplib.error_perm:
            # already exists (or no permission) — best-effort, like File's mkdir(exist_ok); either
            # way THIS call did not create it, so the caller must not report a creation.
            return False
        return True

    def _op(self, fn: Callable[[ftplib.FTP], _T]) -> _T:
        """Connect, run ``fn(ftp)``, always close. A connect fault arrives already classified from
        :meth:`_connect`. An operation fault is mapped here: a permanent reply (``error_perm`` --
        no-such-file, no-perm) is permanent; a connect/IO/timeout/protocol error is transient."""
        ftp = self._connect()
        try:
            return fn(ftp)
        except ftplib.error_perm as exc:
            raise _RemoteError(f"FTP rejected the operation: {exc}", permanent=True) from exc
        except ftplib.all_errors as exc:
            raise _RemoteError(f"FTP operation failed: {exc}", permanent=False) from exc
        finally:
            try:
                ftp.quit()
            except ftplib.all_errors:
                ftp.close()


#: SSH MAC algorithms this connector will PROPOSE (BACKLOG #1171, ASVS 11.4.1). Appendix C of the
#: ASVS V11 chapter marks HMAC-MD5 **D** (disallowed) and SHA-1 **L** (restricted: "not suitable for
#: HMAC"), and paramiko's own preferred list carries `hmac-md5`, `hmac-sha1` and their -96 truncations.
#: With no restriction the shipped connector OFFERS them, and a server that selects one gets it -- on
#: a use case this requirement names by name, in a clause with no default-off escape.
#:
#: STATED AS AN ALLOW-LIST, DELIBERATELY. paramiko's API takes a DENY list (``disabled_algorithms``),
#: so :func:`_disabled_sftp_macs` derives that deny list by subtracting this set from whatever the
#: installed paramiko offers. A deny list would have to be edited every time the library adds an
#: algorithm, and the failure mode of forgetting is that the new algorithm is PROPOSED. Here the
#: failure mode of forgetting is that it is excluded -- wrong in the safe direction, by construction.
#:
#: ENCRYPT-THEN-MAC ONLY. Encrypt-then-MAC is the composition order ASVS 11.3.5 asks about, and the
#: plain ``hmac-sha2-256`` / ``hmac-sha2-512`` names are SSH's original Encrypt-and-MAC: the tag is
#: computed over the PLAINTEXT, so a receiver has to decrypt attacker-chosen ciphertext before it can
#: authenticate it. The ``-etm@openssh.com`` names authenticate the ciphertext instead, so a forgery
#: is rejected without ever being decrypted. The hash is the same SHA-2 either way; the ORDER is the
#: control, which is why the two Encrypt-and-MAC names are not approved despite a sound hash.
_APPROVED_SFTP_MACS = frozenset(
    {
        "hmac-sha2-256-etm@openssh.com",
        "hmac-sha2-512-etm@openssh.com",
    }
)

#: SSH ciphers this connector will PROPOSE. Same shape and same reasoning as :data:`_APPROVED_SFTP_MACS`
#: above: an allow-list, subtracted by :func:`_disabled_sftp_ciphers` from whatever the installed
#: paramiko offers, so forgetting to add a newly-shipped algorithm EXCLUDES it rather than proposing it.
#:
#: MEASURED against paramiko 5.0.0 (the version ``constraints.lock`` pins), whose ``_preferred_ciphers``
#: offers nine names. ONE is approved here: ``aes256-gcm@openssh.com``, an AEAD cipher -- it
#: authenticates its own ciphertext. paramiko 5.0.0 still negotiates a MAC beside it, though, so a
#: server must ALSO offer a name from the MAC allow-list above or the handshake fails on "no
#: acceptable macs". The eight left out, and why each:
#:   - ``aes128-cbc``, ``aes192-cbc``, ``aes256-cbc`` -- CBC. SSH's CBC mode is what the
#:     chosen-ciphertext plaintext-recovery attack of CVE-2008-5161 targets, and CBC is also the half
#:     of the composition that makes a plaintext MAC (above) dangerous.
#:   - ``3des-cbc`` -- CBC as above, and under the 128-bit floor twice over: a 64-bit block (the
#:     Sweet32 birthday attack, CVE-2016-2183) and roughly 112 bits of effective key strength.
#:   - ``aes128-ctr``, ``aes192-ctr``, ``aes256-ctr`` -- CTR. ASVS Appendix C gives CTR status D
#:     (disallowed), whatever the key size (BACKLOG #2041).
#:   - ``aes128-gcm@openssh.com`` -- a 128-bit AES key. Owner ruling R4 of 2026-09-26 (BACKLOG #2042)
#:     withdrew AES-128 here and on Vault Transit; this row is BACKLOG #2044.
#: So a server that offers none of the approved names fails the handshake. OpenSSH added
#: ``aes256-gcm@openssh.com`` in 6.2 (2013); a server or appliance that speaks only CTR fails.
#:
#: EXCLUDING AN ALGORITHM THE LIBRARY DOES NOT OFFER IS HARMLESS. The subtraction only ever names
#: something paramiko actually proposed, so an algorithm a future release drops simply stops
#: appearing in the deny list, and one it adds -- ``chacha20-poly1305@openssh.com``, say -- stays out
#: until someone approves it here. That second case costs a good cipher, never proposes a weak one.
_APPROVED_SFTP_CIPHERS = frozenset(
    {
        "aes256-gcm@openssh.com",
    }
)


def _not_approved(paramiko: Any, attribute: str, approved: frozenset[str]) -> list[str]:
    """Every algorithm the installed paramiko offers under ``attribute`` that is NOT in ``approved``.

    Reads the library's own preferred list rather than a hardcoded one, so the subtraction stays
    correct across paramiko versions. If that attribute ever disappears the result is an EMPTY deny
    list, which would silently restore the weak proposals -- so the negotiation tests in
    ``tests/test_remotefile_transport.py`` assert the derived deny list is NON-EMPTY, for each arm,
    rather than trusting this to have found something.

    One body serves both arms (MAC and cipher) deliberately: a second copy would drift, and the copy
    that drifted would be the one asserting safety.
    """
    offered = getattr(paramiko.Transport, attribute, None)
    return [name for name in (offered or ()) if name not in approved]


def _disabled_sftp_macs(paramiko: Any) -> list[str]:
    """Every MAC the installed paramiko would offer that is NOT in :data:`_APPROVED_SFTP_MACS`."""
    return _not_approved(paramiko, "_preferred_macs", _APPROVED_SFTP_MACS)


def _disabled_sftp_ciphers(paramiko: Any) -> list[str]:
    """Every cipher the installed paramiko would offer that is NOT in :data:`_APPROVED_SFTP_CIPHERS`."""
    return _not_approved(paramiko, "_preferred_ciphers", _APPROVED_SFTP_CIPHERS)


def _import_paramiko() -> Any:
    """Import the optional ``paramiko`` SSH library, raising a clear install hint if the ``[sftp]``
    extra isn't present — so installs that never use SFTP never touch it (mirrors ``_import_aioodbc``)."""
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise RuntimeError(
            "REMOTEFILE sftp protocol requires the 'sftp' extra: pip install 'messagefoundry[sftp]'"
        ) from exc
    return paramiko


def _bound_sftp_channel_reads(sftp: Any) -> None:
    """Put :data:`SFTP_CHANNEL_READ_TIMEOUT_SECONDS` on the SFTP channel's socket.

    Every read the client makes on this channel then raises :class:`TimeoutError` once the server has
    sent nothing for that long, instead of blocking the worker thread forever (BACKLOG #1195).

    ``get_channel`` is documented to return ``None`` for a client not backed by a channel, and the
    test doubles this module is exercised with do not always provide one, so an absent channel is a
    no-op rather than an error: the caller's work is still correct without the bound, and refusing a
    transfer over a missing test-double attribute would be a worse failure than the one being fixed.
    """
    channel = getattr(sftp, "get_channel", None)
    if channel is None:
        return
    sock = channel()
    if sock is None:
        return
    sock.settimeout(SFTP_CHANNEL_READ_TIMEOUT_SECONDS)


def _start_helper(target: Callable[[], None], name: str) -> None:
    """Start ``target`` on a daemon thread, or raise a transient :class:`_RemoteError`.

    ``Thread.start`` raises :class:`RuntimeError` when the process cannot make another thread. That
    is this engine short of a resource, not a fault in the server or the message, so it is transient
    and the operation is retried (BACKLOG #2082). Left unclassified it escaped ``_op`` raw."""
    try:
        threading.Thread(target=target, name=name, daemon=True).start()
    except RuntimeError as exc:
        raise _RemoteError(
            f"SFTP could not start its {name} helper thread: {exc}", permanent=False
        ) from exc


#: Wall-clock bound on an SFTP upload that makes no progress (BACKLOG #2082, ASVS 15.4.4). The same
#: value as :data:`SFTP_CHANNEL_READ_TIMEOUT_SECONDS`, and like it, it bounds each step, not the
#: whole transfer. See :class:`_WriteWatchdog`.
SFTP_WRITE_STALL_SECONDS = 120.0

#: Bytes per step of an SFTP upload: paramiko 5.0.0's ``SFTPFile.MAX_REQUEST_SIZE``, the size of the
#: write requests it sends anyway, so writing in these steps changes nothing on the wire.
SFTP_WRITE_CHUNK_BYTES = 32768


class _WriteWatchdog:
    """Closes the SSH transport when an upload stops making progress (BACKLOG #2082, ASVS 15.4.4).

    THIS DOCSTRING IS THE ONE PLACE THE PARAMIKO FACT BELOW IS STATED. Read against paramiko 5.0.0.

    ``Packetizer.write_all`` retries a socket send that timed out, without limit, and gives up only
    once the packetizer is closed. The channel timeout :func:`_bound_sftp_channel_reads` sets bounds
    a wait for window space and a wait for the server's reply, but not that loop. So a server that
    stops reading, and keeps its TCP window shut, would park the worker thread for good.

    The upload writes in :data:`SFTP_WRITE_CHUNK_BYTES` steps and calls :meth:`progress` after each.
    A helper thread closes the transport once :data:`SFTP_WRITE_STALL_SECONDS` pass with no progress.
    ``Transport.close`` closes the packetizer, so ``write_all`` raises ``EOFError`` on its next turn,
    and ``_op`` reports the upload as stalled, which is transient. A slow upload that keeps moving
    resets the bound at every step, so only a stall is cut off."""

    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self._last = time.monotonic()
        self._done = threading.Event()
        self.fired = False

    def progress(self) -> None:
        self._last = time.monotonic()

    @contextlib.contextmanager
    def watching(self, client: Any) -> Iterator[None]:
        """Watch ``client`` for the length of the ``with`` block."""
        self._last = time.monotonic()
        _start_helper(lambda: self._watch(client), "mefor-sftp-write-watch")
        try:
            yield
        finally:
            self._done.set()

    def _watch(self, client: Any) -> None:
        while True:
            remaining = self._last + self.seconds - time.monotonic()
            if remaining <= 0:
                break
            if self._done.wait(remaining):
                return
        if self._done.is_set():
            return
        self.fired = True
        # The transport, not the client: ``SSHClient.close`` reads and then clears its transport
        # with no lock, and ``_session`` closes the client in its own ``finally``, so two threads
        # closing it could race. ``Transport.close`` is safe to call twice.
        transport = client.get_transport()
        if transport is not None:
            transport.close()


def _open_sftp_within(client: Any, seconds: float) -> Any:
    """``client.open_sftp()``, refused as a transient :class:`_RemoteError` if it takes longer than
    ``seconds`` (BACKLOG #1936, ASVS 15.4.4).

    THIS DOCSTRING IS THE ONE PLACE THE PARAMIKO FACTS BELOW ARE STATED; the tests and
    ``docs/CONNECTIONS.md`` point here rather than restating them. Read against paramiko 5.0.0.

    Opening the session waits on the server at least three times after authentication.
    ``Transport.open_channel`` waits for the channel open for ``channel_timeout``, an hour by
    default. ``Channel.invoke_subsystem`` then waits on a bare ``threading.Event.wait()`` for the
    reply to the ``sftp`` subsystem request. Last, ``SFTPClient.__init__`` reads the server's VERSION
    packet from a channel with no socket timeout yet, because :func:`_bound_sftp_channel_reads` can
    only run once this call returns. Without this bound, a peer that authenticates and then goes
    silent would park the calling worker thread on first deployment, for good at either of the last
    two waits.

    Those waits take no timeout, so the open runs on a helper thread and the caller waits for it
    with one. Past ``seconds`` the caller closes the whole client and raises. ``Transport.close``
    marks the transport inactive and closes every channel. That sets the event the subsystem wait is
    parked on and closes the buffer the VERSION read is parked on, so the helper normally returns
    promptly with an error nobody reads. ``_op`` closes the client in its own ``finally`` anyway, so
    closing it early loses nothing.

    **The caller returns once the bound passes and the close completes; the helper almost always
    does too.** One narrow race
    is paramiko's: ``invoke_subsystem`` checks the channel is open and only then clears its event, so
    a close landing between those two steps is erased and nothing wakes the wait after it. A helper
    caught in that window of a few bytecodes stays parked on a closed transport. It is a daemon
    thread outside the shared pool, which is why the open runs on one rather than on the caller.
    """
    done = threading.Event()
    outcome: list[Any] = []
    failure: list[BaseException] = []

    def _open() -> None:
        try:
            outcome.append(client.open_sftp())
        except BaseException as exc:  # handed to the caller below, never lost
            failure.append(exc)
        finally:
            done.set()

    _start_helper(_open, "mefor-sftp-open")
    if not done.wait(seconds):
        client.close()
        raise _RemoteError(
            f"SFTP session open timed out after {seconds:g}s: the server authenticated and then did "
            "not finish the channel open, the sftp subsystem request or the SFTP version exchange",
            permanent=False,
        )
    if failure:
        raise failure[0]
    return outcome[0]


_PARAMIKO_AUTH_TIMEOUT = "Authentication timeout."
_PARAMIKO_NO_SESSION = "No existing session"
_PARAMIKO_BANNER_ERROR = "Error reading SSH protocol banner"
_KEX_TIMED_OUT = "the banner and key exchange timed out"


def _transport_io_fault(exc: BaseException | None) -> BaseException | None:
    """The socket or EOF fault the transport thread hit before the key exchange, or ``None``.

    That is ``exc`` itself when the thread raised a bare one, or the cause of paramiko's banner-read
    wrapper. ``__context__`` is trusted ONLY on that wrapper: on any other exception it may be
    whatever the calling thread happened to be handling, which says nothing about the peer."""
    if isinstance(exc, (OSError, EOFError)):
        return exc
    if exc is not None and str(exc).startswith(_PARAMIKO_BANNER_ERROR):
        cause = exc.__context__
        if isinstance(cause, (OSError, EOFError)):
            return cause
    return None


def _sftp_slow_peer(
    paramiko: Any, exc: BaseException, client: Any, *, waited_full_bound: bool
) -> tuple[str | None, BaseException | None]:
    """Decide whether a failed ``SSHClient.connect`` came from a slow or dropped peer rather than a
    refusal (BACKLOG #1999). Returns the reason to report, or ``None`` for a refusal, and the
    exception the transport thread left behind, if this read one, so the caller can report it.
    ``waited_full_bound`` says whether the connect ran for at least the connect timeout.

    THIS DOCSTRING IS THE ONE PLACE THE PARAMIKO FACTS BELOW ARE STATED. Read against paramiko 5.0.0.

    **Authentication.** ``AuthHandler.wait_for_response`` raises
    ``AuthenticationException("Authentication timeout.")`` once ``auth_timeout`` passes with no reply.
    A refusal is the same class, ``"Authentication failed."``, with no subclass, attribute or chained
    cause between them, so the message is the only discriminator. Matching it exactly fails safe: if
    paramiko rewords it, the timeout goes back to being a credential fault, which stops the lane
    rather than retrying into a lockout. A transport that dies mid-authentication raises
    ``"Authentication failed: transport shut down or saw EOF"``; that is left a credential fault,
    because a server that refuses and then disconnects produces it too.

    **Banner and key exchange.** ``SSHClient.connect`` passes one ``timeout`` to both the TCP connect
    and ``Transport.start_client``, and this connector sets ``banner_timeout`` to the same value.
    ``start_client`` does not raise when its own wait runs out; it returns, and the next call,
    ``get_remote_server_key``, raises ``SSHException("No existing session")`` with nothing chained.
    That is what a silent peer produces here, measured on every run against a peer that accepts the
    connection and never sends a banner. The transport is then still active. That is the
    discriminator: every call that raises "No existing session" does so only on an inactive
    transport or one whose first key exchange is not done, and the transport thread can finish that
    exchange between the raise and this read, so an active transport is enough on its own.

    The transport thread's own banner read wraps any failure as ``SSHException("Error reading SSH
    protocol banner")``, implicitly chained from what it caught: ``TimeoutError`` for a silent peer,
    ``EOFError`` or a reset for one that dropped the connection. That exception reaches the caller
    when the thread dies before ``start_client`` returns, or it is left on the transport, read here
    by ``get_exception``, when the thread dies in between. A dropped connection is transient for the
    same reason a dropped TCP connect is. A key-exchange mismatch dies with no socket fault chained,
    so it stays permanent, and so does everything after the exchange, host-key rejection included.

    **A banner-read timeout counts only after the full bound.** The read waits ``banner_timeout``
    for the first line but only 2 s for each line after it. So a non-SSH service on the port, one
    that sends a line of its own and then waits, fails the same way about 2 s in. That is a
    misconfiguration, not a slow peer, and it stays permanent.

    paramiko also waits at most ``Transport.handshake_timeout``, 15 s, for the server's first
    key-exchange message. ``SSHClient.connect`` has no keyword for it; only a custom
    ``transport_factory`` could change it, and this connector passes none. Past it the thread
    raises a bare ``EOFError``, which is transient as a dropped connection.
    """
    if isinstance(exc, paramiko.AuthenticationException):
        return ("authentication timed out" if str(exc) == _PARAMIKO_AUTH_TIMEOUT else None), None
    transport = client.get_transport()
    if transport is None:
        return None, None
    # Read with a default so that a paramiko which renamed the attribute falls back to the
    # pre-#1999 permanent classification rather than raising out of the connector.
    kex_done = getattr(transport, "initial_kex_done", True)
    if transport.is_active() and (not kex_done or str(exc) == _PARAMIKO_NO_SESSION):
        return _KEX_TIMED_OUT, None
    if kex_done:
        return None, None
    late = transport.get_exception()
    fault = _transport_io_fault(exc) or _transport_io_fault(late)
    if isinstance(fault, TimeoutError):
        return (_KEX_TIMED_OUT if waited_full_bound else None), late
    if fault is not None:
        return "the server dropped the connection during the banner and key exchange", late
    return None, late


#: Smallest RSA modulus the SFTP connector authenticates with (BACKLOG #1352). 2048, matching owner
#: rulings R2 and R6 for keys that face a counterparty; not the 3072 the JWS signer uses.
_SFTP_MIN_RSA_BITS = 2048


def _refuse_sftp_key_wrap(private_key: object, key_password: object) -> None:
    """Refuse a passphrase, or an encrypted key, for the SFTP client key (BACKLOG #1352, #1171).

    paramiko opens an encrypted key only through MD5 (legacy PEM) or bcrypt_pbkdf (OpenSSH format),
    and neither is an approved key derivation (ASVS 11.4.4, the 11.4.4 cell's SFTP clause). So the
    SFTP key must be unencrypted, protected by where its ``env()`` value is kept. An RSA key under
    the 2048-bit floor is refused here too. Refused at construction, so ``check`` reports it. The
    message names the setting, never the key."""
    if key_password:
        raise ValueError(
            "REMOTEFILE sftp key_password is refused: paramiko can open an encrypted key only "
            "through MD5 or bcrypt_pbkdf, neither an approved key derivation (ASVS 11.4.4). Supply "
            "private_key unencrypted through env(), for example: ssh-keygen -p -N '' -f <key>"
        )
    if private_key and ssh_key_encrypted(str(private_key).encode("utf-8", "replace")):
        raise ValueError(
            "REMOTEFILE sftp private_key is encrypted, which is refused: paramiko can open it only "
            "through MD5 or bcrypt_pbkdf (ASVS 11.4.4). Supply it unencrypted through env(), for "
            "example: ssh-keygen -p -N '' -f <key>"
        )
    bits = _sftp_rsa_bits(private_key) if private_key else None
    if bits is not None and bits < _SFTP_MIN_RSA_BITS:
        raise ValueError(
            f"REMOTEFILE sftp private_key is RSA-{bits}, below the {_SFTP_MIN_RSA_BITS}-bit floor; "
            f"generate a key of at least {_SFTP_MIN_RSA_BITS} bits (BACKLOG #1352)"
        )


def _sftp_rsa_bits(private_key: object) -> int | None:
    """The RSA modulus size of an unencrypted SFTP key, or ``None`` when it is not RSA or this
    cannot read it. ``None`` defers to the load-time floor in ``_load_key``, so a shape this misses
    is still refused at connect; it never passes a key."""
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import (
        load_pem_private_key,
        load_ssh_private_key,
    )

    data = str(private_key).encode("utf-8", "replace")
    try:
        if b"BEGIN OPENSSH PRIVATE" in data:
            key: object = load_ssh_private_key(data, password=None)
        else:
            key = load_pem_private_key(data, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return None
    return key.key_size if isinstance(key, rsa.RSAPrivateKey) else None


class _SftpClient(_RemoteClient):
    """SFTP client over paramiko. Host-key verification is ON by default (system known_hosts + an
    optional ``known_hosts`` file, paramiko ``RejectPolicy``); an unknown key is refused unless the
    explicit dev escape is set, in which case ``AutoAddPolicy`` is used and a warning is logged."""

    def __init__(self, settings: dict[str, Any]) -> None:
        self._host = str(settings["host"])
        self._port = int(settings.get("port", 22))
        self._user = settings.get("username")
        self._password = settings.get("password")
        self._private_key = settings.get("private_key")
        self._key_password = settings.get("key_password")
        _refuse_sftp_key_wrap(self._private_key, self._key_password)
        self._known_hosts = settings.get("known_hosts")
        self._timeout = float(settings.get("connect_timeout", 30.0))
        # Fail fast at construction (build_check time): an unknown-host-key posture without the escape
        # must never silently weaken to auto-accept. #329: read the escape through the ADR-0092 clamp
        # (weakened_tls_escape_permitted_here consults the active construction posture, exactly like the
        # FTPS tls_verify=false sibling at :176 that this class is built alongside), so under an
        # enforcing-PHI posture the escape is INERT — the accept-unknown policy then stays RejectPolicy
        # and an unknown host key is refused at connect (:392-394), as today. Off the construction gate
        # (posture unstamped) the escape is refused since vault BACKLOG #2354 (it used to be unclamped).
        self._accept_unknown = weakened_tls_escape_permitted_here()
        if self._accept_unknown:
            logger.warning(
                "REMOTEFILE sftp %s accepts UNKNOWN host keys (AutoAddPolicy) because %s is set "
                "on an instance at [security].enforcement = warn — MITM-able; for a trusted-network "
                "dev/test bind only",
                self._host,
                INSECURE_TLS_ESCAPE_ENV,
            )

    def _connect(self) -> Any:
        """Connect and authenticate, or raise. The connect arms live here, so ``_op`` has none.

        At least these are mapped to a :class:`_RemoteError`: a host-key rejection is permanent (the
        operator must add the key; a retry cannot fix it), an authentication refusal is a permanent
        credential fault, and a TCP/IO failure is transient, as is a banner, key-exchange or
        authentication timeout (BACKLOG #1999). Whatever else is raised propagates unmapped. The
        client is closed on every failure."""
        paramiko = _import_paramiko()
        client = paramiko.SSHClient()
        started = time.monotonic()
        try:
            self._dial(paramiko, client)
        except paramiko.SSHException as exc:
            # Classify before closing: the close ends the transport state that is read. The close
            # matters most on the timeout path, where the transport thread is still waiting on the
            # peer and would otherwise hold the socket past this call.
            try:
                reason, late = _sftp_slow_peer(
                    paramiko,
                    exc,
                    client,
                    waited_full_bound=time.monotonic() - started >= self._timeout,
                )
            finally:
                client.close()
            detail = str(exc) if late is None else f"{exc} (the transport saw {late!r})"
            if reason is not None:
                # A slow peer, not a refusing one: transient, so the caller retries. As a permanent
                # error it would dead-letter on first deployment, and an authentication timeout
                # would stop the lane as a credential fault (ADR 0095) that no credential caused.
                raise _RemoteError(
                    f"SFTP connect failed, {reason} (connect_timeout {self._timeout:g}s): {detail}",
                    permanent=False,
                ) from exc
            if isinstance(exc, paramiko.AuthenticationException):
                # #109 (ADR 0095): auth rejection is a CREDENTIAL fault (account-lockout risk), so
                # the delivery worker STOP-and-retains instead of dead-lettering and re-authing the
                # backlog.
                raise _RemoteError(
                    f"SFTP authentication failed: {detail}", permanent=True, credential_fault=True
                ) from exc
            # SSHException covers an unknown/rejected host key (RejectPolicy): a security stop the
            # operator must resolve, so it's permanent, not a retry.
            raise _RemoteError(f"SFTP connection rejected: {detail}", permanent=True) from exc
        except (OSError, EOFError) as exc:
            client.close()
            # A bare EOFError has no text, which would leave the operator a message ending in ": ".
            raise _RemoteError(
                f"SFTP connect failed: {str(exc) or type(exc).__name__}", permanent=False
            ) from exc
        except BaseException:
            client.close()
            raise
        return client

    def _dial(self, paramiko: Any, client: Any) -> None:
        """Load host keys, pick the host-key policy, and ``connect`` ``client``. Unclassified: every
        exception is :meth:`_connect`'s to map."""
        client.load_system_host_keys()
        if self._known_hosts:
            client.load_host_keys(str(self._known_hosts))
        # RejectPolicy (default-secure): an unknown host key raises rather than being trusted. Only
        # fall back to AutoAddPolicy behind the explicit insecure escape (set in __init__, logged).
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if self._accept_unknown else paramiko.RejectPolicy()
        )
        pkey = self._load_key(paramiko)
        # Constrain the MAC proposal to the approved set (BACKLOG #1171), and the cipher proposal to
        # its own approved set. Both are passed on every connect, not behind a setting: a control an
        # operator has to switch on is not a control.
        # THE KEYS ARE PLURAL AND THAT IS THE WHOLE CONTROL. paramiko's
        # ``Transport._filter_algorithm`` does ``self.disabled_algorithms.get(type_, [])`` and is
        # called with "ciphers", "macs", "keys", "pubkeys", "kex" and "compression". A SINGULAR key
        # matches nothing, ``.get`` returns the empty default, and every weak algorithm stays on the
        # wire -- silently, because paramiko neither validates the keys nor warns about an unknown
        # one. This shipped as ``{"mac": ...}`` and was therefore INERT from the day it landed: a
        # real handshake against a server pinned to 3des-cbc and hmac-md5 COMPLETED through it.
        # Do not "tidy" these to the singular names that read more naturally beside the helpers.
        disabled = {
            "macs": _disabled_sftp_macs(paramiko),
            "ciphers": _disabled_sftp_ciphers(paramiko),
        }
        client.connect(
            disabled_algorithms=disabled,
            hostname=self._host,
            port=self._port,
            username=str(self._user) if self._user else None,
            password=str(self._password) if self._password else None,
            pkey=pkey,
            timeout=self._timeout,
            # ``timeout`` covers the TCP connect. It does NOT cover the banner exchange or the
            # authentication round trips: paramiko bounds those with their own keywords, so a peer
            # that completes the TCP handshake and then stalls would hold the worker thread well
            # past ``timeout``. Pinned here rather than left to paramiko's defaults so all three
            # bounds are readable at the one call that makes the socket (BACKLOG #1195).
            banner_timeout=self._timeout,
            auth_timeout=self._timeout,
            allow_agent=False,
            look_for_keys=False,
        )

    def _load_key(self, paramiko: Any) -> Any:
        if not self._private_key:
            return None
        # Construction already refused a passphrase, an encrypted key and an RSA key it could size
        # under the floor (_refuse_sftp_key_wrap), so this loads an unencrypted key and never
        # derives one from a password. The floor below is the backstop for a key it could not size.
        key = paramiko.RSAKey.from_private_key(io.StringIO(str(self._private_key)), password=None)
        bits = int(key.get_bits())
        if bits < _SFTP_MIN_RSA_BITS:
            raise _RemoteError(
                f"SFTP private_key is RSA-{bits}, below the {_SFTP_MIN_RSA_BITS}-bit floor; generate "
                f"a key of at least {_SFTP_MIN_RSA_BITS} bits (BACKLOG #1352)",
                permanent=True,
            )
        return key

    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        import stat as _stat

        def run(sftp: Any) -> list[tuple[str, int]]:
            out: list[tuple[str, int]] = []
            for entry in sftp.listdir_attr(remote_dir):
                mode = getattr(entry, "st_mode", 0) or 0
                if _stat.S_ISREG(mode):
                    out.append((entry.filename, int(getattr(entry, "st_size", 0) or 0)))
            return out

        return self._op(run)

    def retrieve(self, path: str, *, max_bytes: int | None = None) -> bytes:
        def run(sftp: Any) -> bytes:
            sink = _BoundedSink(max_bytes)
            with sftp.open(path, "rb") as fh:
                before = _sftp_size(fh.stat())
                while True:
                    chunk: bytes = fh.read(RETRIEVE_CHUNK_BYTES)
                    if not chunk:
                        break
                    sink.write(chunk)  # raises _RemoteOversize past the budget, closing the handle
                after = _sftp_size(fh.stat())
            body = sink.value()
            _raise_if_changed(before, len(body), after)
            return body

        return self._op(run)

    def list_names(self, remote_dir: str) -> set[str]:
        return self._op(lambda sftp: set(sftp.listdir(remote_dir)))

    def ensure_dir_and_list_names(self, remote_dir: str) -> tuple[bool, set[str]]:
        return self._op(
            lambda sftp: (self._ensure(sftp, remote_dir), set(sftp.listdir(remote_dir)))
        )

    def store(self, path: str, data: bytes) -> None:
        watchdog = _WriteWatchdog(SFTP_WRITE_STALL_SECONDS)

        def run(sftp: Any) -> None:
            with sftp.open(path, "wb") as fh:
                for start in range(0, len(data), SFTP_WRITE_CHUNK_BYTES):
                    fh.write(data[start : start + SFTP_WRITE_CHUNK_BYTES])
                    watchdog.progress()

        self._op(run, watchdog=watchdog)

    def rename(self, src: str, dst: str) -> None:
        self._op(lambda sftp: sftp.posix_rename(src, dst))

    def publish(self, src: str, candidates: Sequence[str]) -> str | None:
        """See :meth:`_RemoteClient.publish`. Publishes with the plain SFTP ``RENAME``
        (``sftp.rename``), never ``posix_rename``.

        The SFTP version 3 draft says ``RENAME`` fails when the target exists, and paramiko's own
        docstring for ``SFTPClient.rename`` says the new name "must not exist already". OpenSSH's
        sftp-server meets that with ``link`` then ``unlink``, which refuses an existing name
        atomically. On a filesystem without hard links it falls back to a ``stat`` then a
        ``rename``, which is not atomic. ``posix_rename`` is a plain ``rename(2)`` there, which
        replaces. A server that implements ``RENAME`` as a replace gets no refusal from it.

        So this also checks with ``lstat`` first, on the same connection, which narrows the gap on
        such a server to one round trip. What counts as a refused ``RENAME`` is
        :func:`_sftp_refused`'s to say.

        Two costs of the plain ``RENAME``, against the ``posix_rename`` it replaced. On OpenSSH the
        final name appears by a hard link, not a move, so a far-side watcher waiting for a move
        event (inotify ``IN_MOVED_TO``) does not see it. And a server that refuses ``RENAME``
        outright fails every delivery, transient until the retry cap; nothing falls back to
        ``posix_rename``, since that would bring back the replace. Either site sets ``overwrite =
        true`` with a per-message filename."""

        def run(sftp: Any) -> str | None:
            return _publish_first(
                candidates,
                taken=lambda dst, fresh: _sftp_exists(sftp, dst),
                rename=lambda dst: sftp.rename(src, dst),
                refusals=(OSError,),
                refused=lambda exc: _sftp_refused(sftp, exc, src),
            )

        return self._op(run)

    def remove(self, path: str) -> None:
        self._op(lambda sftp: sftp.remove(path))

    def dispose_unless_changed(self, path: str, expected_size: int, dest: str | None) -> int | None:
        def run(sftp: Any) -> int | None:
            current = _sftp_size(sftp.stat(path))
            if _differs(current, expected_size):
                return current
            if dest is None:
                sftp.remove(path)
            else:
                sftp.posix_rename(path, dest)
            return None

        return self._op(run)

    def ensure_dir(self, remote_dir: str) -> bool:
        return self._op(lambda sftp: self._ensure(sftp, remote_dir))

    @staticmethod
    def _ensure(sftp: Any, remote_dir: str) -> bool:
        try:
            sftp.stat(remote_dir)
        except FileNotFoundError:
            try:
                sftp.mkdir(remote_dir)
            except OSError:
                return False  # racing creator / no permission — best-effort
            return True
        return False  # already there — nothing created

    def _op(self, fn: Callable[[Any], _T], *, watchdog: _WriteWatchdog | None = None) -> _T:
        """Connect, open an SFTP channel, run ``fn(sftp)``, always close. ``watchdog``, when given,
        watches the work for a stall (:class:`_WriteWatchdog`); a failure after it fired is
        reported as a stalled upload, transient, whatever paramiko raised once the transport
        closed."""
        try:
            return self._session(fn, watchdog)
        except _RemoteError as exc:
            if watchdog is None or not watchdog.fired:
                raise
            raise _RemoteError(
                f"SFTP upload stalled: the server accepted no data for {watchdog.seconds:g}s, "
                f"so the connection was closed ({exc})",
                permanent=False,
            ) from exc

    def _session(self, fn: Callable[[Any], _T], watchdog: _WriteWatchdog | None) -> _T:
        """:meth:`_op`'s body. A connect fault arrives already classified from :meth:`_connect`.
        Everything raised after it is mapped below, at least these (BACKLOG #2082 for the last
        three rows):

        - a missing path is permanent;
        - an SSH, socket or timeout fault is transient, as a dropped connection is;
        - ``EOFError`` is transient: the server or the transport closed the channel;
        - ``paramiko.SFTPError`` is permanent. paramiko raises it when the server's SFTP replies
          make no sense to it: an unsupported protocol version at the open ("Incompatible sftp
          protocol"), bytes that are not SFTP ("Garbage packet received", as a login script that
          prints text produces), or a reply of the wrong type. The same server gives the same
          answer on a retry;
        - a helper thread that cannot start is transient (:func:`_start_helper`)."""
        paramiko = _import_paramiko()
        client = self._connect()
        try:
            sftp = _open_sftp_within(client, SFTP_CHANNEL_READ_TIMEOUT_SECONDS)
            _bound_sftp_channel_reads(sftp)
            with watchdog.watching(client) if watchdog is not None else contextlib.nullcontext():
                try:
                    return fn(sftp)
                finally:
                    sftp.close()
        except (_RemoteError, _RemoteOversize, _RemoteChanged):
            raise  # already classified, or a content refusal the source handles itself
        except FileNotFoundError as exc:
            raise _RemoteError(f"SFTP path not found: {exc}", permanent=True) from exc
        except paramiko.SFTPError as exc:
            raise _RemoteError(f"SFTP protocol error: {exc}", permanent=True) from exc
        except EOFError as exc:
            # A bare EOFError has no text, which would leave the operator a message ending in ": ".
            raise _RemoteError(
                f"SFTP connection closed: {str(exc) or type(exc).__name__}", permanent=False
            ) from exc
        except paramiko.SSHException as exc:
            raise _RemoteError(f"SFTP operation failed: {exc}", permanent=False) from exc
        except TimeoutError as exc:
            # A silent peer, not a broken one: the channel bound fired (BACKLOG #1195). Transient, so
            # the caller retries. Named before the OSError arm below only to say so in the message --
            # TimeoutError is an OSError subclass and would otherwise be classified identically.
            raise _RemoteError(
                f"SFTP read timed out after {SFTP_CHANNEL_READ_TIMEOUT_SECONDS:g}s "
                f"with no data from the server: {exc}",
                permanent=False,
            ) from exc
        except OSError as exc:
            raise _RemoteError(f"SFTP operation failed: {exc}", permanent=False) from exc
        finally:
            client.close()


def _make_client(
    settings: dict[str, Any],
    *,
    trust_anchor_policy: TrustAnchorPolicy | None = None,
    name: str = "",
) -> _RemoteClient:
    """Build the protocol-appropriate client. Tests monkeypatch this (or the client classes) so no
    real server/SSH is needed; both connectors call it per operation-batch. ``trust_anchor_policy``
    (#190, ADR 0093) is the FTPS verify-path internal-CA fallback. Both connectors pass their
    config's policy (the source since vault BACKLOG #2370); SFTP/plain-FTP ignore it (no server-cert
    verify)."""
    protocol = remote_file_protocol(settings)
    if protocol == "sftp":
        return _SftpClient(settings)
    if protocol == "ftp":
        return _FtpClient(settings, tls=False)
    if protocol == "ftps":
        return _FtpClient(settings, tls=True, trust_anchor_policy=trust_anchor_policy, name=name)
    raise ValueError(f"REMOTEFILE protocol must be one of {_PROTOCOLS}, got {protocol!r}")


def _anon_ftp_guard(
    s: dict[str, Any],
    *,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
    connection: str | None,
) -> InsecureHopGuard | None:
    """An :class:`~messagefoundry.transports.mllp.InsecureHopGuard` for an ANONYMOUS plain-``ftp`` hop
    (protocol ``ftp`` with no credentials), or ``None`` for any other protocol / a credentialed ftp.

    Credentialed plain-ftp is already refused by :func:`_validate_common` (it puts the credential itself
    on the wire in the clear); ``ftps``/``sftp`` are encrypted. The remaining gap #200 closes is an
    ANONYMOUS plain-ftp hop — no credential, but the message BODY is still PHI over a cleartext channel.
    Keyed on the shared gradient off-loopback: loopback / per-connection-attested ALLOW, an ADR 0153
    ``cleartext_accepted`` declaration WARNs (loudly, audited), everything else REFUSES under ENFORCE.

    The acceptance pair arrives as arguments rather than out of ``s``: it is a top-level OUTBOUND key,
    not a transport setting, and it is **Destination-only** (ADR 0153 decision 2), so the inbound
    ``RemoteFileSource`` path leaves it at its default."""
    if remote_file_protocol(s) != "ftp":
        return None
    if s.get("username") or s.get("password"):
        return None  # credentialed ftp — covered by _validate_common's cleartext-credential refusal
    reason = s.get("tls_hop_attested_reason")
    return InsecureHopGuard.capture(
        host=str(s["host"]),
        port=int(s.get("port", 21)),
        cell="REMOTEFILE ftp",
        description="cleartext anonymous FTP egress",
        attested=bool(s.get("tls_hop_attested", False)),
        attested_reason=None if reason is None else str(reason),
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
        connection=connection,
    )


def _validate_common(
    s: dict[str, Any],
    *,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
    connection: str | None,
) -> str:
    """Shared construction-time validation: required ``host``/``remote_dir``, a known ``protocol``, and
    the cleartext-FTP credential guard. Returns the normalized protocol.

    The ADR 0153 acceptance pair is threaded through to the anonymous-ftp hop guard below — it must
    reach the ENFORCED gate that runs here, not just the destination's send-time backstop, or a declared
    acceptance would be refused at construction and never take effect. Defaults off, so the inbound
    ``RemoteFileSource`` path (which has no such field — Destination-only) is byte-identical."""
    for req in ("host", "remote_dir"):
        if not s.get(req):
            raise ValueError(f"REMOTEFILE connector requires a {req!r} setting")
    protocol = remote_file_protocol(s)
    if protocol not in _PROTOCOLS:
        raise ValueError(f"REMOTEFILE protocol must be one of {_PROTOCOLS}, got {protocol!r}")
    if protocol == "ftp" and (s.get("username") or s.get("password")):
        # Plain FTP puts the credential itself on the wire in the clear. Vault BACKLOG #2636: ABSOLUTE,
        # keyed on no escape and no posture, as the SMTP cleartext-credential arm is (email.py,
        # direct.py) and as the two FTPS credential arms in _ftps_ssl_context are. This was clamped
        # (#200, ADR 0092 decision 2) and the escape released it on a non-enforcing instance, which
        # left the cleartext rung weaker than the verify-off FTPS rung above it. Keyed on either half.
        # The anonymous plain-ftp hop is governed by the hop guard below and is unchanged.
        raise ValueError(
            f"{hop_name_prefix(connection)}REMOTEFILE plain ftp transmits credentials in CLEARTEXT; "
            "refused -- credentials require an encrypted, verified session. Use ftps (tls=True) or "
            "sftp."
        )
    # #200 (ADR 0092): an ANONYMOUS plain-ftp hop carries no credential but still ships the PHI body over
    # cleartext. Refuse a production-PHI hop off-loopback at the ENFORCED construction gate (the
    # credentialed case above is the orthogonal credential-on-the-wire guard). No-op for ftps/sftp/
    # credentialed-ftp, and byte-identical off the enforced gate (posture unstamped).
    guard = _anon_ftp_guard(
        s,
        cleartext_accepted=cleartext_accepted,
        cleartext_reason=cleartext_reason,
        connection=connection,
    )
    if guard is not None:
        guard.enforce_construction()
    return protocol


class RemoteFileDestination(DestinationConnector):
    """Upload each payload to ``remote_dir``/``filename`` over SFTP/FTP/FTPS (temp-then-rename)."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        _validate_common(
            s,
            cleartext_accepted=config.cleartext_accepted,
            cleartext_reason=config.cleartext_reason,
            connection=config.name,
        )
        # #200 send-time backstop for an anonymous plain-ftp hop (the enforced refusal already fired in
        # _validate_common at the construction gate). None for ftps/sftp/credentialed-ftp.
        self._hop_guard = _anon_ftp_guard(
            s,
            cleartext_accepted=config.cleartext_accepted,
            cleartext_reason=config.cleartext_reason,
            connection=config.name,
        )
        # Constructing the SFTP client validates the host-key escape posture fail-fast (build_check).
        # #190 (ADR 0093): pass the instance [tls] internal-CA trust-anchor policy so an FTPS hop that
        # names no tls_ca_file of its own verifies against the org internal CA.
        self._client = _make_client(
            s, trust_anchor_policy=config.trust_anchor_policy, name=config.name
        )
        # BACKLOG #2193 (ADR 0173): a verifying FTPS upload validates the server certificate, but
        # stdlib ssl checks no OCSP or CRL, so a revoked certificate would still be accepted on a hop
        # that carries message files and the FTP login. Taken AFTER the client is built and handed
        # the context that client will really dial with, so a [tls].crl_file that reached this hop
        # relaxes the refusal and a hop it never reached keeps it. Keyed on the context, as MLLP's
        # is: sftp and plain ftp build none, and a tls_verify=false context verifies nothing, so
        # the refusals that own those hops stay the only gate on them.
        ftps_context = self._client.tls_context
        if ftps_context is not None and ftps_context.verify_mode is not ssl.CERT_NONE:
            RevocationHopGuard.capture(
                host=str(s["host"]),
                cell="REMOTEFILE ftps destination",
                description="verified FTPS upload (no revocation check)",
                attested=config.tls_revocation_attested,
                attested_reason=config.tls_revocation_attested_reason,
                connection=config.name,
                context=ftps_context,
            ).enforce_construction()
        self._settings = s
        self._host = str(s["host"])
        self._remote_dir = str(s["remote_dir"])
        self._filename_template = str(s.get("filename", "{MSH-10}.hl7"))
        # ADR 0204: a template whose fixed text alone is over the cap would name every upload by
        # the fallback, so it is refused here.
        _check_template_fits(self._filename_template, "", FILENAME_MAX_BYTES)
        self._overwrite = bool(s.get("overwrite", False))
        self._encoding: str = s.get("encoding", "utf-8")
        # Opt-in at-start directory validation (#114, ADR 0031 amendment). Default off = the historical
        # run-time deferral (ensure_dir creates the upload dir on the first send). When on, remote_dir
        # must be listable at start AND _upload never creates it.
        self._validate_directory: bool = bool(s.get("validate_directory", False))

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> None:  # metadata (#68): unused — no per-message header knob here
        if self._hop_guard is not None:
            # Zero-I/O byte-crossing backstop (#200) before the upload (defense in depth against a reload
            # routing PHI around the construction gate).
            self._hop_guard.assert_send()
        try:
            await asyncio.to_thread(self._upload, payload)
        except _RemoteError as exc:
            raise exc.as_delivery_error() from exc

    async def validate_startup(self) -> None:
        """Opt-in at-start directory validation (#114) — the outbound mirror of
        :meth:`RemoteFileSource.validate_startup`. No-op unless ``validate_directory`` is set; then
        ``remote_dir`` must be reachable and listable now. A listing is the only **no-create** probe
        this client contract has (``ensure_dir`` creates, which is exactly what must not happen here),
        so a no-such-dir / connect / auth failure raises :class:`DestinationStartupError` and the runner
        isolates the lane as ADR-0031 ``failed``. Listing proves reachability and existence, not
        writability — a share that lists but refuses a write still fails at the first delivery, where it
        is retried and never dropped."""
        if not self._validate_directory:
            return
        try:
            await asyncio.to_thread(self._client.list_dir, self._remote_dir)
        except _RemoteError as exc:
            raise DestinationStartupError(
                f"REMOTEFILE destination directory {_redact(self._host, self._remote_dir)} failed "
                f"startup validation: {exc}"
            ) from exc

    def _prepare_remote_dir(self) -> None:
        """Make ``remote_dir`` usable for this upload — and make a CREATION observable (#114).

        Default (``validate_directory`` off): the unchanged ``ensure_dir`` create-if-missing, except
        that a directory this call actually created now logs a WARNING. That silence is the defect: a
        typo'd ``remote_dir`` would otherwise be created on the partner's server and every message
        counted and logged as delivered — because it was — into a path nobody is watching.

        ``validate_directory`` on: never create. The directory was validated at start, so a LIST is the
        pre-flight check and its failure is re-raised as **transient**, which ``send`` maps to a
        retryable :class:`DeliveryError`. The reclassification is the point: an SFTP/FTP no-such-dir is
        a **permanent** error, so letting the upload fail on its own would dead-letter live traffic over
        a share that is merely unmounted. It costs one extra round trip per delivery, on the opt-in
        path only. A credential or configuration fault is not reclassified; see
        :meth:`_list_or_retry`."""
        if self._validate_directory:
            self._list_or_retry(
                self._client.list_dir,
                "is not available, and validate_directory is on so it is never created on send",
            )
            return
        if self._client.ensure_dir(self._remote_dir):
            logger.warning(
                "REMOTEFILE destination CREATED missing directory %s — this delivery is landing in a "
                "directory the engine just made; verify the configured remote_dir is the intended one",
                _redact(self._host, self._remote_dir),
            )

    def _list_or_retry(self, lister: Callable[[str], _T], why: str) -> _T:
        """List ``remote_dir`` with ``lister`` on the send path, re-raising a failure as **transient**
        so the row retries under its retry policy rather than dead-lettering on a no-such-dir or a 550.

        A connection fault is the exception and is re-raised unchanged, keeping its marker, so the
        delivery worker STOPs and retains. A credential fault would otherwise retry into an account
        lockout (ADR 0095). A configuration fault, such as a refused ``AUTH TLS``, would otherwise
        reconnect into the same refusal on every row until each row's retry cap dead-lettered it
        (BACKLOG #2083, fix round 4). This retry is for a directory that is merely not there yet,
        which neither fault is. An FTP server at its connection limit carries neither marker
        (:func:`_ftp_connect_refusal`), so it is retried here and never stops the lane."""
        try:
            return lister(self._remote_dir)
        except _RemoteError as exc:
            if exc.connection_fault:
                raise
            raise _RemoteError(
                f"REMOTEFILE upload directory {_redact(self._host, self._remote_dir)} {why}: {exc}",
                permanent=False,
            ) from exc

    def _upload(self, payload: str) -> None:
        # The default byte cap applies (ADR 0204): a long field falls back rather than reaching the
        # server. The remote path limit is the partner's and is not known here, so there is no
        # directory budget; a server refusal is classified by its own reply.
        name = render_filename(self._filename_template, payload, fallback=_FALLBACK_NAME)
        # The shared helper, not a bare .encode(): a UnicodeEncodeError names a character of the
        # message and carries the WHOLE payload on `.object`. The helper raises a permanent,
        # content-free NegativeAckError with the chain severed (#1920), before any I/O. It is not a
        # _RemoteError, so send() lets it through unchanged and the row dead-letters.
        data = encode_wire_body(
            payload,
            self._encoding,
            transport=f"REMOTEFILE upload to {_redact(self._host, self._remote_dir)}",
        )
        self._prepare_remote_dir()
        # With overwrite off, list for free names BEFORE anything is written (the #1936 rule).
        candidates = [] if self._overwrite else self._unique(name)
        # Write to a unique temp name then rename, so a poller on the far side never sees a partial
        # file. The temp suffix is unguessable so two concurrent uploads never collide on it.
        tmp = posixpath.join(self._remote_dir, f".{name}.{uuid.uuid4().hex}.part")
        try:
            self._client.store(tmp, data)
        except _RemoteError as exc:
            # A store cut off part-way, by the stall bound (#2082) or a dropped connection, can leave
            # a partial temp behind, one more on every retry. Not after a credential fault: another
            # login would be one more refused attempt against the partner account. Nor after a
            # configuration fault: it refuses the session open, so no temp was written and another
            # connect would meet the same refusal (#2083). A store that failed before it connected
            # for any other reason left no temp, so this costs one more connect and a warning there;
            # _prepare_remote_dir connected just before, so that case is rare.
            if not exc.connection_fault:
                self._remove_temp(tmp, name, "store")
            raise
        try:
            if self._overwrite:  # replacing is what it asks for
                self._client.rename(tmp, posixpath.join(self._remote_dir, name))
            else:
                self._publish_new(tmp, name, candidates)
        except _RemoteError:
            # Publish failed — don't leave the temp behind. Best-effort cleanup, then re-raise so the
            # delivery is classified (retry/dead-letter) by send(). Unlike the store branch, this
            # tries even after a connection fault: the store succeeded, so a whole message sits in
            # the temp, and the lane stops right after, so it costs one more login at most.
            self._remove_temp(tmp, name, "rename")
            raise

    def _publish_new(self, tmp: str, name: str, candidates: list[str]) -> None:
        """Publish ``tmp`` under the first of ``candidates`` still free when the client tries it,
        never replacing an entry (BACKLOG #2553). The listing ran before the store, so a partner can
        take a name in between; the client's :meth:`_RemoteClient.publish` refuses that name and
        moves on to the next. When all are taken it raises transient, and the retry lists again.
        ``name`` is logged only through ``safe_name``, and the names taken never are."""
        published = self._client.publish(tmp, candidates)
        if published is None:
            raise _RemoteError(
                f"REMOTEFILE upload to {_redact(self._host, self._remote_dir)} found all "
                f"{len(candidates)} names it tried taken after the listing, and overwrite is off, "
                "so it published nothing; the retry lists again",
                permanent=False,
            )
        if published != candidates[0]:
            logger.warning(
                "REMOTEFILE upload for %s: %d chosen name(s) were taken after the listing, "
                "so it published under the next free one",
                safe_name(name),
                candidates.index(published),
            )

    def _remove_temp(self, tmp: str, name: str, after: str) -> None:
        """Best-effort removal of an upload's temp file after a failed ``after`` step. The temp name
        carries the rendered filename, which can hold an identifier, so it is logged only through
        ``safe_name`` (BACKLOG #2082; this line logged it raw before)."""
        try:
            self._client.remove(tmp)
        except _RemoteError:
            logger.warning(
                "REMOTEFILE could not remove the temp for %s after a failed %s",
                safe_name(name),
                after,
            )

    def _unique(self, name: str) -> list[str]:
        """List ``remote_dir``, and return the first :data:`PUBLISH_NAME_ATTEMPTS` paths the
        listing shows free, in order: ``name`` itself, then ``name-1.ext``, ``name-2.ext``, …
        skipping each one listed. Never clobbers an existing entry silently. Unlike the File
        destination, which splits at the last dot, the suffix goes before the first. The listing is
        only a first guess: :meth:`_publish_new` lets the publish refuse a name taken since
        (BACKLOG #2553).

        **THIS IS THE ONE STATEMENT OF THE RULE (BACKLOG #1936); everything else points here.** With
        ``overwrite`` off, a listing that fails is never read as "nothing to collide with": it is
        raised through :meth:`_list_or_retry`, which makes it transient unless it is a credential or
        configuration fault, and nothing is written first. Returning the unsuffixed name there would
        let the store and rename replace a partner file.

        Every entry counts, not only a regular file (BACKLOG #2082): the rename would replace a
        same-named symlink, or fail on a same-named directory. So this reads
        :meth:`_RemoteClient.list_names`.

        A missing directory earns no exception. ``_upload`` runs :meth:`_prepare_remote_dir` first,
        which lists it or tries to create it. ``ensure_dir`` is best-effort, so the directory can
        still be missing here, but then the store into it would fail too, so the upload never
        delivered that message. What changes is the disposition: the row now retries at this
        listing instead of dead-lettering at the store."""
        existing = self._list_or_retry(
            self._client.list_names,
            "could not be listed to check the upload name for a collision, and overwrite is "
            "off, so nothing was written",
        )
        stem, dot, ext = name.partition(".")
        names = (name if n == 0 else f"{stem}-{n}{dot}{ext}" for n in itertools.count())
        free = (posixpath.join(self._remote_dir, n) for n in names if n not in existing)
        return list(itertools.islice(free, PUBLISH_NAME_ATTEMPTS))

    async def test_connection(self) -> None:
        # Connect + authenticate + ensure the upload dir (the destination's normal first step) — no
        # message data written. A failure is mapped like send()'s. Under validate_directory the probe
        # LISTS instead of ensuring: "never invent this path" has to hold for the on-demand probe too,
        # or POST /connections/{name}/test would silently repair the typo the toggle exists to catch.
        # With overwrite off it also lists, as every such delivery does (see _unique), and on the
        # same connection as the ensure, so one connect bound fits the API's cap on the probe (#2082).
        try:
            if self._validate_directory:
                await asyncio.to_thread(self._client.list_dir, self._remote_dir)
            elif self._overwrite:
                await asyncio.to_thread(self._client.ensure_dir, self._remote_dir)
            else:
                await asyncio.to_thread(self._client.ensure_dir_and_list_names, self._remote_dir)
        except _RemoteError as exc:
            raise exc.as_delivery_error() from exc

    async def aclose(self) -> None:
        return None  # connect-per-operation — nothing held open


class RemoteFileSource(SourceConnector):
    """Poll ``remote_dir`` for ``pattern`` files and feed each to the pipeline handler."""

    polls_shared_resource = True  # a remote dir is a shared external resource — leader-gate it

    def __init__(self, config: Source) -> None:
        s = config.settings
        _validate_common(
            s, connection=None if config.name is None else inbound_record_name(config.name)
        )
        # Vault BACKLOG #2370: the poller verifies its FTPS server under [tls], as the outbound does,
        # and its warnings and refusals spell it inbound:<name>, as _validate_common above does.
        self._client = _make_client(
            s,
            trust_anchor_policy=config.trust_anchor_policy,
            name="" if config.name is None else inbound_record_name(config.name),
        )
        self._host = str(s["host"])
        self._remote_dir = str(s["remote_dir"])
        self._pattern: str = s.get("pattern", "*.hl7")
        # The declared charset, resolved as ingress_guards.ingress_encoding resolves it (an absent or
        # None setting is utf-8): the batch split decodes with it to find the MSH boundaries (ADR
        # 0206 rule 5). A name the codec registry lacks makes the split hand the file over whole.
        self._encoding: str = s.get("encoding") or "utf-8"
        self._poll_seconds: float = float(s.get("poll_seconds", 5.0))
        self._after_read: str = s.get("after_read", "move")  # "move" | "delete" | "leave" (#142)
        if self._after_read not in ("move", "delete", "leave"):
            raise ValueError(
                f"REMOTEFILE after_read must be 'move', 'delete', or 'leave', got {self._after_read!r}"
            )
        # #142 leave-in-place: HASHED file_keys this connection ingested — a BOUNDED LRU fast-path (cap
        # LEAVE_SEEN_CACHE_MAX) in front of the authoritative durable ledger, so it can't outgrow the
        # ledger's own count cap. A miss falls through to ledger.is_processed(); eviction never causes a
        # false re-ingest. Never a cleartext filename; never logged at INFO+.
        self._processed_seen: OrderedDict[str, None] = OrderedDict()
        # BACKLOG #2071 settle gate: the listed size each not-yet-admitted file showed at the poll that
        # last saw it, and how many polls in a row have since failed to list it, keyed by name. In
        # memory only and never logged. See _settled.
        self._settle_seen: dict[str, tuple[int, int]] = {}
        # Opt-in at-start directory validation (#114, ADR 0031 amendment). Default off = the historical
        # run-time deferral (an unreachable remote dir is logged-and-retried each poll, never fails start).
        self._validate_directory: bool = bool(s.get("validate_directory", False))
        self._max_file_bytes: int | None = positive_cap(
            s.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES),
            int,
            knob="max_file_bytes",
            transport="REMOTEFILE source",
        )
        # Per-tick intake ceiling, SHIPPED ON (DEFAULT_MAX_ITEMS_PER_POLL — the number and the reason a
        # poll source may default this on are stated once, in transports/base.py). Caps how many files
        # ONE poll disposes of; the rest stay on the remote share and the next poll takes them.
        # None/0 (in any spelling) disables the cap, matching max_file_bytes above.
        self._poll_max_files: int | None = resolve_poll_ceiling(
            s.get("poll_max_files", DEFAULT_MAX_ITEMS_PER_POLL),
            knob="poll_max_files",
            transport="REMOTEFILE source",
        )
        self._processed_dir = posixpath.join(
            self._remote_dir, s.get("processed_subdir", ".processed")
        )
        self._error_dir = posixpath.join(self._remote_dir, s.get("error_subdir", ".error"))
        self._handler: InboundHandler | None = None
        # Leader-gate (Track B Step 4b): when set, the remote dir (a shared external resource) is
        # listed/downloaded/moved only while the gate returns True, so in a cluster exactly one node
        # ingests its files. None = always poll (single-node / direct callers / tests) — identical.
        self._leader_gate: Callable[[], bool] | None = None
        self._skipping = False  # whether the last tick was gated out (for a single transition log)
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        self._handler = handler
        self._leader_gate = leader_gate
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            # return_exceptions: a faulted poll task must not re-raise here — stop() runs during reload
            # quiesce, outside its rollback (mirrors the File / DATABASE sources).
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def test_connection(self) -> None:
        # Connect + authenticate + list the poll dir (read-only — what the source actually does), no
        # files moved or deleted. A failure is mapped like the delivery path's.
        try:
            await asyncio.to_thread(self._client.list_dir, self._remote_dir)
        except _RemoteError as exc:
            raise exc.as_delivery_error() from exc

    async def validate_startup(self) -> None:
        """Opt-in at-start directory validation (#114). No-op unless ``validate_directory`` is set; then
        the remote poll dir must be reachable and listable now — a listing failure (no-such-dir,
        connect/auth) raises :class:`SourceStartupError` so the runner isolates the connection as
        ADR-0031 ``failed`` rather than logging-and-retrying every poll. Listing is the read-only probe
        the source does anyway; it never creates the directory."""
        if not self._validate_directory:
            return
        try:
            await asyncio.to_thread(self._client.list_dir, self._remote_dir)
        except _RemoteError as exc:
            raise SourceStartupError(
                f"REMOTEFILE source directory {_redact(self._host, self._remote_dir)} failed startup "
                f"validation: {exc}"
            ) from exc

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                # BACKLOG #290 slice 2: a paused engine skips the whole tick, so no remote file is
                # listed, retrieved, moved or deleted; it stays on the share for the next open tick.
                if intake_open(self.intake_gate) and self._may_poll():
                    await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A poll error (connection drop, a bad pattern, a retrieve/move failure) must NOT kill
                # the poller — it would silently stop the connection from receiving while it still
                # reports running. Log and retry next interval (mirrors the File / DATABASE sources).
                logger.exception(
                    "REMOTEFILE source poll failed for %s; retrying next interval",
                    _redact(self._host, self._remote_dir),
                )
            try:  # noqa: SIM105
                await asyncio.wait_for(self._stop.wait(), self._poll_seconds)
            except TimeoutError:
                pass  # poll interval elapsed; poll again

    def _may_poll(self) -> bool:
        """Whether this tick may list/retrieve/move the remote dir. False on a follower (leader-
        gated, Step 4b): a non-leader must NOT list, download, or move/delete remote files, since
        the dir is shared and two nodes ingesting it would duplicate intake. The loop still ticks,
        so a node that becomes leader polls on its next tick (reactive-by-polling, no restart). When
        the gate is None or True, behaves exactly as before. Logged once on each transition (never
        per skipped tick — that would spam a follower's log every poll interval)."""
        if self._leader_gate is None or self._leader_gate():
            if self._skipping:
                self._skipping = False
                logger.debug(
                    "REMOTEFILE source resuming polling of %s (now leader)",
                    _redact(self._host, self._remote_dir),
                )
            return True
        if not self._skipping:
            self._skipping = True
            logger.debug(
                "REMOTEFILE source skipping polling of %s (not leader; another node ingests it)",
                _redact(self._host, self._remote_dir),
            )
        return False

    async def _poll_once(self) -> None:
        import fnmatch

        assert self._handler is not None
        await asyncio.to_thread(self._client.ensure_dir, self._processed_dir)
        await asyncio.to_thread(self._client.ensure_dir, self._error_dir)
        entries = await asyncio.to_thread(self._client.list_dir, self._remote_dir)
        newly_recorded = 0  # #142: files marked processed THIS poll — gates one end-of-poll prune
        listing = sorted(entries)
        self._prune_settle(listing)
        disposed = 0  # files this poll finished with — the per-tick ceiling's budget (_at_ceiling)
        for position, (name, size) in enumerate(listing):
            if self._stop.is_set():
                break  # shutting down — leave the rest for the next start (at-least-once)
            if self._at_ceiling(disposed, len(listing) - position):
                break
            if not _is_contained_name(name):
                # #1238 (ASVS 5.3.2): the server chose this name. Refuse it HERE — at the source,
                # before the pattern filter — because the raw name reaches at least four consumers
                # (the retrieve path, the error/oversize move, the after_read disposition, and the
                # leave-mode dedup key), and a per-consumer check would keep missing one: the
                # consumer set grew at every measurement pass and never shrank.
                # NOT quarantined: moving it would join the hostile name onto a directory, which is
                # the very operation being refused. Left in place and logged, so an operator sees it
                # every poll rather than once. No name is logged: this arm has refused the name as an
                # unsafe path component, so it is the one place that must not hand it to `safe_name`
                # either — the host:dir and the fact of a refusal are the signal.
                #
                # This comment used to justify that by asserting "names are not logged at INFO+
                # elsewhere in this source". Nine WARNING sites below falsified it (BACKLOG #1748),
                # which made a real control rest on a false premise (CLAUDE.md §11, SDS-3.7). Those
                # sites now route through `safe_name`, so the claim would be true today — it is gone
                # anyway, because this arm's reason never depended on what the others do.
                logger.warning(
                    "REMOTEFILE %s: a listing entry was refused as an unsafe path component "
                    "(not a single safe name); left in place, not retrieved",
                    _redact(self._host, self._remote_dir),
                )
                continue
            if not fnmatch.fnmatch(name, self._pattern):
                continue
            path = posixpath.join(self._remote_dir, name)
            # #142 leave-in-place dedup: skip a file this connection already ingested (in-process set,
            # then the durable ledger). Keyed on a HASHED id (name+size — a remote listing carries no
            # mtime) — never a cleartext filename, never logged at INFO+.
            file_key = self._file_key(name, size) if self._after_read == "leave" else None
            if file_key is not None and await self._leave_already_ingested(file_key):
                continue
            if not self._settled(name, size):
                # BACKLOG #2071: first sighting, or the listed size changed since the last poll.
                # Nothing is read, moved or charged against the per-tick budget.
                continue
            if self._max_file_bytes is not None and size > self._max_file_bytes:
                # Transport-level reject *before* any bytes are read — parallels the File source's
                # oversize guard. It never became a "received message", so there's no store
                # disposition; move it to the error dir and log it (never a silent drop).
                # THIS GATE TRUSTS THE SERVER. `size` came out of the remote directory listing, so a
                # hostile or malfunctioning share passes it by under-reporting; the same budget is
                # therefore charged again below against the bytes actually read.
                logger.warning(
                    "REMOTEFILE file %s (listed at %s bytes) exceeds max_file_bytes (%s); routing "
                    "to error dir",
                    safe_name(name),
                    size,
                    self._max_file_bytes,
                )
                await self._move(path, self._error_dir, name)
                disposed += 1
                continue
            try:
                raw = await asyncio.to_thread(
                    self._client.retrieve, path, max_bytes=self._max_file_bytes
                )
            except _RemoteOversize:
                # The share DELIVERED more than it listed. Same disposition as the listing-size gate
                # above — quarantine + log, never a silent drop — and deliberately NOT the transient
                # arm below: leaving it in place would re-pull the same oversized body every poll.
                # The body is already discarded; nothing partial reaches the pipeline.
                logger.warning(
                    "REMOTEFILE file %s delivered more than max_file_bytes (%s) despite a smaller "
                    "listed size; routing to error dir",
                    safe_name(name),
                    self._max_file_bytes,
                )
                await self._move(path, self._error_dir, name)
                disposed += 1
                continue
            except _RemoteChanged as exc:
                # BACKLOG #116: a partner is still writing this file in place, so what was read may be
                # a cut-off message. Leave it for the next poll; not charged, since it did not move.
                logger.warning(
                    "REMOTEFILE %s: %s changed while it was retrieved (%s bytes before, %d read, %s "
                    "after); not emitted, left in place for the next poll",
                    _redact(self._host, self._remote_dir),
                    safe_name(name),
                    exc.before,
                    exc.read,
                    exc.after,
                )
                # Still moving, so it must settle again from its latest size (#2071).
                self._remember_size(name, exc.read if exc.after is None else exc.after)
                continue
            except _RemoteError as exc:
                # Transient (locked / vanished mid-poll): leave it in place to retry next poll rather
                # than quarantine a healthy file. Logged, never silently swallowed.
                logger.warning(
                    "REMOTEFILE could not retrieve %s (will retry next poll): %s",
                    safe_name(name),
                    safe_exc(exc, file_name=name),
                )
                continue
            # Content-vs-type magic-byte check (ASVS 5.2.2), mirroring the local File source's
            # _content_matches_declared dispatch (hl7v2→MSH/FHS/BHS, x12→ISA, dicom→preamble+DICM,
            # json/fhir→{/[, xml→<; binary/text unchecked). The remote dir is a less-trusted source, so a
            # drop whose leading bytes contradict its declared content_type is quarantined before its bytes
            # reach the pipeline. The former None-skips-sniff carve-out was REMOVED (ASVS 5.2.2): the check
            # now ALWAYS runs, converging onto the local source's semantics — the helper's None arm already
            # means hl7v2, so a content_type=None drop is sniffed as HL7 (a binary drop is quarantined to
            # .error, not delivered raw).
            if not _content_matches_declared(self.content_type, raw):
                # Like the oversize / scan-reject cases it never became a "received message", so there
                # is no store disposition; preserve it in .error and log it (never a silent drop).
                logger.warning(
                    "REMOTEFILE file %s does not match its declared content type %r "
                    "(no matching magic bytes); routing to error dir",
                    safe_name(name),
                    (self.content_type or ContentType.HL7V2).value,
                )
                await self._move(path, self._error_dir, name)
                disposed += 1
                continue
            try:
                await asyncio.to_thread(scan_inbound_file, raw, name)
            except ScanRejected as exc:
                # A configured pre-ingest scanner (AV/ICAP/plugin) rejected the content before it
                # entered the pipeline (ASVS 5.4.3) — the control that matters most for a remote /
                # less-trusted drop source. Quarantine + log; like the oversize reject above it never
                # became a "received message", so there's no store disposition.
                logger.warning(
                    "REMOTEFILE file %s rejected by the pre-ingest scan hook (%s); routing to error dir",
                    safe_name(name),
                    safe_exc(exc, file_name=name),
                )
                await self._move(path, self._error_dir, name)
                disposed += 1
                continue
            except Exception as exc:  # noqa: BLE001 - operator scan hook: any failure fails closed
                # The scan hook MALFUNCTIONED (AV/ICAP unreachable, a plugin bug) — NOT a content
                # rejection. Fail closed (ASVS 5.4.3): never emit unscanned content from a less-trusted
                # remote source. Unlike a ScanRejected we don't quarantine a possibly-healthy file on a
                # scanner outage — leave it in place so the next poll re-runs the scan once the scanner
                # recovers (at-least-once, mirroring the transient-retrieve path). Logged, never a silent
                # pass-through, and scoped to THIS file so a hiccup can't abort the poll's remaining files.
                logger.warning(
                    "REMOTEFILE file %s: pre-ingest scan hook errored (%s); leaving in place, will retry",
                    safe_name(name),
                    safe_exc(exc, file_name=name),
                )
                continue
            try:
                stopped = await self._hand_off(raw)
            except Exception as exc:
                # The handler records every message-level outcome itself and returns, so an exception
                # escaping here is an infrastructure failure (the durable store write failed). Leave the
                # file in place so the next poll retries (at-least-once) — moving it would drop a
                # received-but-unrecorded message (mirrors the File source's M-15).
                logger.warning(
                    "REMOTEFILE handler failed for %s (will retry next poll): %s",
                    safe_name(name),
                    safe_exc(exc, file_name=name),
                )
                continue
            if stopped:
                # A stop arrived before the file's last message: the whole file stays, and the next
                # start hands it over again (at-least-once, as the File source does). Break, not
                # return, so the prune below still bounds what this poll recorded.
                break
            await self._after_processing(path, name, len(raw))
            disposed += 1
            if file_key is not None:
                # Record AFTER emit success (the FILE — not each split message — is the dedup unit).
                await self._leave_record(file_key)
                newly_recorded += 1
        if newly_recorded and self.processed_ledger is not None:
            await (
                self.processed_ledger.prune()
            )  # bound growth (age + count), only when something new

    async def _hand_off(self, raw: bytes) -> bool:
        """Hand one retrieved file to the pipeline, one message at a time; return True when a stop
        arrived before every message was handed over.

        An ``hl7v2`` file is split on ``MSH`` boundaries first, as the File source splits one (ADR
        0206 rule 5): a batch file, with or without an ``FHS``/``BHS`` envelope, becomes one hand-off
        and one disposition per message, in file order. The listener refuses a body holding a second
        ``MSH``, so a whole batch handed over unsplit would be one ``ERROR``. An undecodable file is
        handed over as its original bytes, and so is a single-message file, unless a byte order mark
        or an ``FHS``/``BHS`` header the parser refuses leads it (:func:`split_batch_bytes`). Any
        other content type is handed over verbatim, never decoded.

        The split runs in a worker thread, so a cancellation at that await hands nothing over and
        leaves the file for the next poll. The stop is checked before every hand-off, the first
        included: a stop set while the file was retrieved or scanned hands nothing over, so the next
        start does not ingest a message twice."""
        assert self._handler is not None
        if self.content_type is not None and self.content_type is not ContentType.HL7V2:
            messages = [raw]
        else:
            # Off the event loop, as every other blocking step of a poll is: a large batch file is a
            # decode, a regex split and a re-encode per message.
            messages = await asyncio.to_thread(split_batch_bytes, raw, self._encoding)
        for message in messages:
            if self._stop.is_set():
                return True
            await self._handler(message)
        return False

    def _at_ceiling(self, disposed: int, remaining: int) -> bool:
        """True when this poll has spent its per-tick budget (``poll_max_files``) and must stop, leaving
        ``remaining`` listing entries for the next poll.

        **Nothing is dropped.** A file this poll does not reach is still on the share, so the next poll
        takes it — the same at-least-once deferral a transient retrieve failure already produces. No
        message was received, so there is no disposition to record.

        **What charges the budget.** Only a file this poll FINISHED with: one handed to the pipeline, or
        one quarantined to ``error_subdir`` (over the listed size, over the retrieved size, a
        content-vs-type mismatch, a scanner rejection). Those leave the poll directory, so the next poll
        starts on new work. The arms that leave a file **in place** for a later retry — a refused unsafe
        listing name, a file not yet settled (#2071), a transient retrieve failure, a malfunctioning
        scan hook, a handler failure — do
        NOT charge, because a stuck file that sorts early would otherwise eat the whole budget every
        poll and starve the healthy files behind it. This mirrors
        :meth:`~messagefoundry.transports.file.FileSource._at_ceiling`, which states the rule in full.

        PHI-safe: the log names the redacted host/dir and two counts, never a filename."""
        if self._poll_max_files is None or disposed < self._poll_max_files:
            return False
        logger.info(
            "REMOTEFILE source %s reached poll_max_files (%s) this poll; %d listing entr(ies) left for "
            "the next poll (deferred, not dropped)",
            _redact(self._host, self._remote_dir),
            self._poll_max_files,
            remaining,
        )
        return True

    def _settled(self, name: str, size: int) -> bool:
        """True when ``name`` lists at the same size it listed at the last poll that looked at it,
        which admits it for reading (BACKLOG #2071). Otherwise remember ``size`` and return False, so
        the file waits for a later poll.

        This is the local File source's settle gate (#1811) ported here, and
        :meth:`~messagefoundry.transports.file.FileSource._settled` states the rule in full: why it
        exists beside #116, why it is always on with no setting, and why ``poll_seconds`` is its
        window. It shares that source's memory bounds, ``SETTLE_SEEN_MAX`` and ``SETTLE_MISS_LIMIT``.

        **Where it differs.** A remote listing carries no reliable modification time, so the signal
        is the listed size alone, the one :meth:`_file_key` already uses. So besides what the local
        gate cannot see, this one also misses a same-size rewrite, and a server that lists every
        file at the same size, or at 0, as an FTP server without ``MLSD`` or ``SIZE`` does. On such
        a server every file waits one poll and nothing more. The key is the name, since every
        listed file sits in the one ``remote_dir``."""
        seen = self._settle_seen.get(name)
        if seen is not None and seen[0] == size:
            del self._settle_seen[name]
            return True
        recorded = self._remember_size(name, size)
        # safe_name hashes the name, so skip it when nobody reads the line.
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "REMOTEFILE %s: %s not yet settled (listed at %d bytes); %s",
                _redact(self._host, self._remote_dir),
                safe_name(name),
                size,
                "waiting for the next poll to agree"
                if recorded
                else f"settle memory is full ({SETTLE_SEEN_MAX}), so it waits for room",
            )
        return False

    def _remember_size(self, name: str, size: int) -> bool:
        """Record ``size`` as this poll's sighting of ``name`` and return True. At ``SETTLE_SEEN_MAX``
        a name not already recorded is left out and this returns False, so it waits for room; the
        local source's constant says why that is not eviction."""
        if name in self._settle_seen or len(self._settle_seen) < SETTLE_SEEN_MAX:
            self._settle_seen[name] = (size, 0)
            return True
        return False

    def _prune_settle(self, listing: list[tuple[str, int]]) -> None:
        """Forget a file once ``SETTLE_MISS_LIMIT`` polls in a row have not listed it (moved, deleted,
        renamed away), so the settle map is bounded by the poll directory. A file listed again has its
        count reset. A failed listing raises before this runs, so it never counts as a miss."""
        if not self._settle_seen:
            return
        listed = {name for name, _ in listing}
        for name, (size, missed) in list(self._settle_seen.items()):
            if name in listed:
                if missed:
                    self._settle_seen[name] = (size, 0)
            elif missed + 1 >= SETTLE_MISS_LIMIT:
                del self._settle_seen[name]
            else:
                self._settle_seen[name] = (size, missed + 1)

    def _file_key(self, name: str, size: int) -> str:
        """A stable, HASHED identity for a remote source file, for the leave-in-place dedup ledger
        (#142). SHA-256 over the file's FULL REMOTE PATH (``remote_dir``/``name``) + size — folding the
        full path, not just the basename, keeps two same-named files that live under different bases (or
        a re-pointed ``remote_dir``) DISTINCT so both are ingested (never one silently deduped away — the
        count-and-log invariant). A remote directory listing carries no reliable mtime, so size is the
        change signal (a same-path file whose SIZE changes is re-ingested); on a read-only share (the
        target use case) files are stable. The path — which, like a filename, can embed an MRN — is never
        stored or logged in the clear (the ledger holds this derived id only; never log the path)."""
        full = posixpath.join(self._remote_dir, name)
        return hashlib.sha256(f"{full}\x00{size}".encode("utf-8", "surrogatepass")).hexdigest()

    def _seen_touch(self, file_key: str) -> bool:
        """True if ``file_key`` is in the bounded in-memory fast-path (and refresh its LRU recency)."""
        if file_key in self._processed_seen:
            self._processed_seen.move_to_end(file_key)
            return True
        return False

    def _seen_add(self, file_key: str) -> None:
        """Add ``file_key`` to the bounded LRU, evicting the oldest on overflow. Eviction is safe: a
        later miss falls through to the authoritative durable ``ledger.is_processed()`` read."""
        self._processed_seen[file_key] = None
        self._processed_seen.move_to_end(file_key)
        while len(self._processed_seen) > LEAVE_SEEN_CACHE_MAX:
            self._processed_seen.popitem(last=False)

    async def _leave_already_ingested(self, file_key: str) -> bool:
        """True if this leave-in-place file was already ingested — the bounded in-process cache first (no
        I/O), then, on a miss, the AUTHORITATIVE durable ledger (covers a restart / a fresh process / a
        cache eviction). A durable hit is re-cached, so eviction never causes a false re-ingest."""
        if self._seen_touch(file_key):
            return True
        ledger = self.processed_ledger
        if ledger is not None and await ledger.is_processed(file_key):
            self._seen_add(file_key)
            return True
        return False

    async def _leave_record(self, file_key: str) -> None:
        """Mark a leave-in-place file ingested: the durable ledger (a HASHED key) + the bounded cache."""
        self._seen_add(file_key)
        if self.processed_ledger is not None:
            await self.processed_ledger.mark_processed(file_key)

    async def _after_processing(self, path: str, name: str, read_size: int) -> None:
        if self._after_read == "leave":
            # #142 process-in-place: never move/delete — the durable dedup ledger (recorded by
            # _poll_once AFTER this returns) is what stops it being re-ingested next poll.
            # No #116 size check here: it would cost a connection per file, and the dedup key folds
            # the listed size, so a file that grew after this read gets a new key and is re-read.
            return
        dest = None if self._after_read == "delete" else posixpath.join(self._processed_dir, name)
        try:
            # #116: the size check and the rename or delete share one connection, so a file that
            # changed after it was read is left in place rather than archived with its unread tail.
            now = await asyncio.to_thread(
                self._client.dispose_unless_changed, path, read_size, dest
            )
        except _RemoteError as exc:
            # A processed file we can't move or delete will be re-read (a duplicate); surface it.
            logger.warning(
                "REMOTEFILE could not %s %s%s: %s",
                "delete processed file" if dest is None else "move",
                safe_name(name),
                "" if dest is None else f" to {self._processed_dir}",
                safe_exc(exc, file_name=name),
            )
            return
        if now is not None:
            logger.warning(
                "REMOTEFILE %s: %s changed after it was read (%d bytes read, %d now); the message "
                "emitted from it may be incomplete, so the file is left in place for the next poll to "
                "read whole",
                _redact(self._host, self._remote_dir),
                safe_name(name),
                read_size,
                now,
            )

    async def _move(self, path: str, dest_dir: str, name: str) -> None:
        dst = posixpath.join(dest_dir, name)
        try:
            await asyncio.to_thread(self._client.rename, path, dst)
        except _RemoteError as exc:
            # A stuck file (locked / dest unwritable) stays and is re-read; log it.
            logger.warning(
                "REMOTEFILE could not move %s to %s: %s",
                safe_name(name),
                dest_dir,
                safe_exc(exc, file_name=name),
            )


register_destination(ConnectorType.REMOTEFILE, RemoteFileDestination)
register_source(ConnectorType.REMOTEFILE, RemoteFileSource)

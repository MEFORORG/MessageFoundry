# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Remote-file transport: SFTP / FTP / FTPS — directory destination + directory-polling source.

A single connector type (``REMOTEFILE``) with a ``protocol`` setting selecting the wire protocol:

- ``sftp`` — SSH file transfer (paramiko, the ``[sftp]`` extra — lazily imported, so installs that
  never use SFTP skip it). **Host-key verification is ON by default**; an unknown key is refused
  unless the explicit dev escape ``MEFOR_ALLOW_INSECURE_TLS`` is set (and logged loudly when it is),
  mirroring the SQL Server backend's weakened-TLS posture. The negotiated key exchange, cipher and
  MAC are held to the same floor the TLS hops assert on their contexts — see
  :mod:`messagefoundry.config.ssh_policy`, which is where that floor is defined and justified.
- ``ftp`` — plain FTP (stdlib ``ftplib``). Cleartext: credentials over plain ``ftp`` are **refused**
  unless the escape is set (use ``ftps``/``sftp``), mirroring :func:`refuse_cleartext_credentials`.
- ``ftps`` — FTP over explicit TLS (``ftplib.FTP_TLS`` + ``PROT P``), credentials encrypted. **The
  server certificate and hostname are verified by default** (a verifying :class:`ssl.SSLContext`, not
  ftplib's no-verify stdlib fallback); ``tls_verify=false`` drops verification only when the explicit
  escape ``MEFOR_ALLOW_INSECURE_TLS`` is set (and is logged loudly), mirroring the MLLP outbound posture.

**Destination** uploads each payload to ``remote_dir``/``filename`` (``{HL7-path}`` placeholders
resolved via :func:`render_filename`). The write goes to a temp name then a **rename** to the final
name, so a poller on the far side never sees a partial file. A name collision is uniquified (never a
silent clobber). A transient failure (connect/timeout/transient FTP error) → :class:`DeliveryError`
(retried); a permanent server refusal (auth failure, no-such-dir, a 5xx-class permanent FTP error) →
:class:`NegativeAckError` (``permanent=True``) → dead-letter.

**Source** polls ``remote_dir`` for ``pattern`` files, hands each to the pipeline handler, then — only
after the handler returns — moves the file to ``processed_subdir`` (or deletes it per ``after_read``).
A handler failure leaves the file in place to re-emit (at-least-once); an over-``max_file_bytes`` file
is moved to ``error_subdir`` before it's retrieved (a transport-level reject, like the File source).

**Idempotency.** Delivery is at-least-once (an upload may re-send) and a poll may re-emit a file that
was handled but not yet marked, so downstream consumers **must** tolerate duplicates.

The client is opened **per operation** (no shared mutable client held across an ``await``), mirroring
the MLLP destination's fresh-connection-per-delivery — simplest and safest under the staged pipeline's
concurrent workers. All blocking client I/O runs via :func:`asyncio.to_thread`.
"""

from __future__ import annotations

import abc
import asyncio
import ftplib  # nosec B402 — plain FTP is gated: cleartext credentials are refused (see _validate_common); FTPS/SFTP are the encrypted defaults
import hashlib
import io
import logging
import posixpath
import ssl
import uuid
from collections import OrderedDict
from collections.abc import Callable, Mapping
from typing import Any, TypeVar

from messagefoundry.config.models import ConnectorType, ContentType, Destination, Source
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    weakened_tls_escape_permitted_here,
)
from messagefoundry.config.ssh_policy import (
    ssh_disabled_algorithms,
    ssh_floor_refusal,
)
from messagefoundry.config.tls_policy import (
    TrustAnchorPolicy,
    build_verifying_client_context,
    harden_cipher_suites,
    harden_kex_groups,
    harden_verify_flags,
    relax_verify_expiry,
    resolve_trust_anchor,
)
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    SourceStartupError,
    register_destination,
    register_source,
)
from messagefoundry.transports.file import (
    DEFAULT_MAX_FILE_BYTES,
    LEAVE_SEEN_CACHE_MAX,
    ScanRejected,
    _content_matches_declared,
    render_filename,
    scan_inbound_file,
)
from messagefoundry.transports.mllp import InsecureHopGuard

__all__ = ["RemoteFileDestination", "RemoteFileSource"]

logger = logging.getLogger(__name__)

_PROTOCOLS = ("sftp", "ftp", "ftps")

_T = TypeVar("_T")


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

    The connector maps a transient error to :class:`DeliveryError` (retry) and a permanent one to
    :class:`NegativeAckError` (dead-letter / credential-STOP), so the client layer stays
    transport-detail-only."""

    def __init__(self, message: str, *, permanent: bool, credential_fault: bool = False) -> None:
        super().__init__(message)
        self.permanent = permanent
        self.credential_fault = credential_fault


class _RemoteClient(abc.ABC):
    """Connect-per-operation remote-file client. Implementations are **synchronous** (blocking I/O);
    the connector calls them via :func:`asyncio.to_thread`. Each method opens its own connection, does
    the operation, and closes — nothing is held across calls."""

    @abc.abstractmethod
    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        """``(name, size)`` for each regular file directly in ``remote_dir`` (no recursion)."""

    @abc.abstractmethod
    def retrieve(self, path: str) -> bytes:
        """The full bytes of the file at ``path``."""

    @abc.abstractmethod
    def store(self, path: str, data: bytes) -> None:
        """Write ``data`` to ``path`` (overwriting if it exists)."""

    @abc.abstractmethod
    def rename(self, src: str, dst: str) -> None:
        """Rename ``src`` to ``dst`` (atomic publish / move-to-processed)."""

    @abc.abstractmethod
    def remove(self, path: str) -> None:
        """Delete the file at ``path``."""

    @abc.abstractmethod
    def ensure_dir(self, remote_dir: str) -> None:
        """Best-effort create ``remote_dir`` (ignore "already exists")."""


def _ftps_ssl_context(
    settings: dict[str, Any], *, trust_anchor_policy: TrustAnchorPolicy | None = None
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
    the internal CA never bypasses the ``tls_verify=false`` refusal above."""
    # #200 (ADR 0092 decision 2): the escape is CLAMPED to non production-PHI, so tls_verify=false can no
    # longer be silenced by MEFOR_ALLOW_INSECURE_TLS on a prod-PHI instance (mirrors the MLLP verify-off
    # arm). Byte-identical off the construction gate (posture unstamped → unclamped escape).
    verify = bool(settings.get("tls_verify", True))
    if not verify and not weakened_tls_escape_permitted_here():
        raise ValueError(
            "REMOTEFILE ftps tls_verify=false disables server-certificate verification (MITM risk). "
            f"Use a trusted CA (tls_ca_file), or set {INSECURE_TLS_ESCAPE_ENV}=1 to allow it on a "
            "trusted-network bind (refused on a production-PHI instance even with the escape, #200)."
        )
    ca = settings.get("tls_ca_file")
    if verify and trust_anchor_policy is not None:
        # #190 (ADR 0093): the connection's own tls_ca_file wins verbatim, else the internal-CA anchor
        # for an internal hop. Only the VERIFY path uses it; the CERT_NONE branch is refused above.
        anchor = resolve_trust_anchor(
            connection_ca_file=str(ca) if ca else None,
            host=str(settings.get("host", "")),
            policy=trust_anchor_policy,
        )
        ctx = build_verifying_client_context(anchor)
    else:
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if verify:
        ctx.check_hostname = bool(settings.get("tls_check_hostname", True))
    else:
        logger.warning(
            "REMOTEFILE ftps TLS certificate verification is DISABLED (tls_verify=false, permitted "
            "by %s) — MITM-able; for a trusted-network dev/test bind only.",
            INSECURE_TLS_ESCAPE_ENV,
        )
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    cert = settings.get("tls_cert_file")
    if cert:  # optional client identity for mTLS
        key = settings.get("tls_key_file")
        key_password = settings.get("tls_key_password")
        # An encrypted key with NO passphrase must fail deterministically, not block on a TTY prompt
        # (there is none under a service account) — same empty-bytes callback guard as the MLLP path.
        pw_arg = key_password if key_password is not None else (lambda: b"")
        ctx.load_cert_chain(certfile=cert, keyfile=key, password=pw_arg)
    harden_kex_groups(ctx)  # pin approved ECDHE groups where supported (ASVS 11.6.2)
    harden_cipher_suites(
        ctx, connector="remote-file (FTPS) connection"
    )  # assert forward secrecy (ASVS 12.1.2)
    if verify:  # nothing to strict-validate on the CERT_NONE path (ASVS 12.1.4)
        harden_verify_flags(ctx)
        # #129 (ADR 0094): opt-in granular expiry-only relaxation — accept an expired server cert while
        # STILL validating chain + hostname (verify path only; default off = byte-identical).
        if settings.get("tls_allow_expired"):
            relax_verify_expiry(ctx, host=str(settings.get("host", "")))
    return ctx


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
            _ftps_ssl_context(settings, trust_anchor_policy=trust_anchor_policy) if tls else None
        )

    def _connect(self) -> ftplib.FTP:
        # B321: plain FTP only when explicitly selected; credentials over it are refused unless
        # MEFOR_ALLOW_INSECURE_TLS is set (see _validate_common). FTPS/SFTP are the encrypted defaults.
        if self._tls:
            ftp: ftplib.FTP = ftplib.FTP_TLS(context=self._context, timeout=self._timeout)
        else:
            ftp = ftplib.FTP(timeout=self._timeout)  # nosec B321
        ftp.connect(self._host, self._port)
        ftp.login(user=str(self._user or ""), passwd=str(self._password or ""))
        if isinstance(ftp, ftplib.FTP_TLS):
            ftp.prot_p()  # encrypt the data channel, not just the control channel
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
            try:
                size = ftp.size(posixpath.join(remote_dir, base)) or 0
            except (ftplib.error_perm, ftplib.error_proto):
                size = 0  # a directory or an un-sizable entry; treat as 0 (oversize check skips it)
            out.append((base, int(size)))
        return out

    def retrieve(self, path: str) -> bytes:
        def run(ftp: ftplib.FTP) -> bytes:
            buf = io.BytesIO()
            ftp.retrbinary(f"RETR {path}", buf.write)
            return buf.getvalue()

        return self._op(run)

    def store(self, path: str, data: bytes) -> None:
        self._op(lambda ftp: ftp.storbinary(f"STOR {path}", io.BytesIO(data)))

    def rename(self, src: str, dst: str) -> None:
        self._op(lambda ftp: ftp.rename(src, dst))

    def remove(self, path: str) -> None:
        self._op(lambda ftp: ftp.delete(path))

    def ensure_dir(self, remote_dir: str) -> None:
        def run(ftp: ftplib.FTP) -> None:
            try:  # noqa: SIM105
                ftp.mkd(remote_dir)
            except ftplib.error_perm:
                pass  # already exists (or no permission) — best-effort, like File's mkdir(exist_ok)

        self._op(run)

    def _op(self, fn: Callable[[ftplib.FTP], _T]) -> _T:
        """Connect, run ``fn(ftp)``, always close. Maps ``ftplib`` failures to :class:`_RemoteError`:
        a permanent reply (``error_perm`` — auth/no-such-file/no-perm) is permanent; a connect/IO/
        timeout/protocol error is transient."""
        try:
            ftp = self._connect()
        except (
            ftplib.error_perm
        ) as exc:  # login refused — a permanent credential/permission problem
            # #109 (ADR 0095): login refusal is a CREDENTIAL fault (account-lockout risk on a retry
            # storm) — distinct from an operation-level error_perm below (a content/path problem).
            raise _RemoteError(
                f"FTP login refused: {exc}", permanent=True, credential_fault=True
            ) from exc
        except ftplib.all_errors as exc:  # connect/timeout/protocol/OSError — transient
            raise _RemoteError(f"FTP connect failed: {exc}", permanent=False) from exc
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
        self._known_hosts = settings.get("known_hosts")
        self._timeout = float(settings.get("connect_timeout", 30.0))
        # Fail fast at construction (build_check time): an unknown-host-key posture without the escape
        # must never silently weaken to auto-accept. #329: read the escape through the ADR-0092 clamp
        # (weakened_tls_escape_permitted_here consults the active construction posture, exactly like the
        # FTPS tls_verify=false sibling at :176 that this class is built alongside), so under an
        # enforcing-PHI posture the escape is INERT — the accept-unknown policy then stays RejectPolicy
        # and an unknown host key is refused at connect (:392-394), as today. Off the construction gate
        # (posture unstamped) the escape is unclamped, byte-identical to the pre-#329 bare read.
        self._accept_unknown = weakened_tls_escape_permitted_here()
        if self._accept_unknown:
            logger.warning(
                "REMOTEFILE sftp %s accepts UNKNOWN host keys (AutoAddPolicy) because %s is set "
                "— MITM-able; for a trusted-network dev/test bind only",
                self._host,
                INSECURE_TLS_ESCAPE_ENV,
            )

    @property
    def _connector(self) -> str:
        """The label the algorithm-floor errors identify this hop by, matching the log-line style."""
        return f"REMOTEFILE sftp {self._host}"

    def _algorithm_offer(self, paramiko: Any) -> dict[str, list[str]]:
        """The key-exchange / cipher / MAC names the SSH library would propose (#178).

        The only thing this reads from paramiko; the policy applied to it lives in
        ``config/ssh_policy.py``, which is also where the floor is justified. Read through
        ``getattr`` so a library that stops exposing one of the lists leaves that category ABSENT,
        which makes :func:`ssh_disabled_algorithms` refuse rather than leaving it silently
        unfloored. Recomputed per connect rather than cached: it is an attribute read next to a TCP
        connect and a key exchange, and a cache keyed on nothing would outlive a test's fake
        library."""
        transport = getattr(paramiko, "Transport", None)
        raw = {
            "kex": getattr(transport, "_preferred_kex", None),
            "ciphers": getattr(transport, "_preferred_ciphers", None),
            "macs": getattr(transport, "_preferred_macs", None),
        }
        return {category: list(names) for category, names in raw.items() if names is not None}

    def _floor_refusal(self, paramiko: Any, exc: Exception) -> str | None:
        """The operator-actionable text for a negotiation failure the floor caused, else ``None``.

        Recomputes the floor rather than carrying it on the instance: this runs on an error path, and
        state stashed during a connect would be stale (or absent) for a connect that never got that
        far. A derivation failure here yields ``None`` so the caller reports the ORIGINAL negotiation
        error -- an error path must not raise a second, unrelated exception over the first."""
        try:
            offer = self._algorithm_offer(paramiko)
            disabled = ssh_disabled_algorithms(offer, connector=self._connector)
        except ValueError:
            return None
        return ssh_floor_refusal(
            str(exc),
            connector=self._connector,
            host=self._host,
            port=self._port,
            disabled=disabled,
            offered=offer,
        )

    def _connect(self) -> Any:
        paramiko = _import_paramiko()
        # Applied here rather than passed in, so there is no parameter a caller could omit: an
        # algorithm floor that one code path can skip is not a floor.
        disabled = ssh_disabled_algorithms(
            self._algorithm_offer(paramiko), connector=self._connector
        )
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if self._known_hosts:
            client.load_host_keys(str(self._known_hosts))
        # RejectPolicy (default-secure): an unknown host key raises rather than being trusted. Only
        # fall back to AutoAddPolicy behind the explicit insecure escape (set in __init__, logged).
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if self._accept_unknown else paramiko.RejectPolicy()
        )
        pkey = self._load_key(paramiko)
        client.connect(
            hostname=self._host,
            port=self._port,
            username=str(self._user) if self._user else None,
            password=str(self._password) if self._password else None,
            pkey=pkey,
            timeout=self._timeout,
            allow_agent=False,
            look_for_keys=False,
            disabled_algorithms=disabled,
        )
        return client

    def _load_key(self, paramiko: Any) -> Any:
        if not self._private_key:
            return None
        passphrase = str(self._key_password) if self._key_password else None
        return paramiko.RSAKey.from_private_key(
            io.StringIO(str(self._private_key)), password=passphrase
        )

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

    def retrieve(self, path: str) -> bytes:
        def run(sftp: Any) -> bytes:
            with sftp.open(path, "rb") as fh:
                data: bytes = fh.read()
                return data

        return self._op(run)

    def store(self, path: str, data: bytes) -> None:
        def run(sftp: Any) -> None:
            with sftp.open(path, "wb") as fh:
                fh.write(data)

        self._op(run)

    def rename(self, src: str, dst: str) -> None:
        self._op(lambda sftp: sftp.posix_rename(src, dst))

    def remove(self, path: str) -> None:
        self._op(lambda sftp: sftp.remove(path))

    def ensure_dir(self, remote_dir: str) -> None:
        def run(sftp: Any) -> None:
            try:
                sftp.stat(remote_dir)
            except FileNotFoundError:
                try:  # noqa: SIM105
                    sftp.mkdir(remote_dir)
                except OSError:
                    pass  # racing creator / no permission — best-effort

        self._op(run)

    def _op(self, fn: Callable[[Any], _T]) -> _T:
        """Connect, open an SFTP channel, run ``fn(sftp)``, always close. Maps a host-key rejection
        to a permanent error (the operator must add the key — a retry can't fix it) and authentication
        failure to permanent; connect/IO/timeout to transient."""
        paramiko = _import_paramiko()
        try:
            client = self._connect()
        except paramiko.AuthenticationException as exc:
            # #109 (ADR 0095): auth rejection = a CREDENTIAL fault (account-lockout risk) — the delivery
            # worker STOP-and-retains instead of dead-lettering + re-authing the whole backlog.
            raise _RemoteError(
                f"SFTP authentication failed: {exc}", permanent=True, credential_fault=True
            ) from exc
        except paramiko.SSHException as exc:
            # SSHException covers an unknown/rejected host key (RejectPolicy) — a security stop the
            # operator must resolve, so it's permanent, not a retry. It ALSO covers a peer that offers
            # nothing above the algorithm floor; that refusal gets its own message naming what was
            # refused and what the server could enable instead, because "SFTP connection rejected:
            # Incompatible ssh server (no acceptable macs)" reads like a partner defect and gives an
            # operator nothing to act on. `ssh_floor_refusal` returns None for every incompatibility
            # the floor did not cause, so the generic message still covers those.
            raise _RemoteError(
                self._floor_refusal(paramiko, exc) or f"SFTP connection rejected: {exc}",
                permanent=True,
            ) from exc
        except ValueError as exc:
            # The floor derivation itself refused (an unclassified algorithm, or a library exposing no
            # preferred list) — or a malformed private key. Both are operator-fixable configuration,
            # never transient, so retrying the backlog against them would be pure noise.
            raise _RemoteError(f"SFTP connect refused: {exc}", permanent=True) from exc
        except (OSError, EOFError) as exc:
            raise _RemoteError(f"SFTP connect failed: {exc}", permanent=False) from exc
        try:
            sftp = client.open_sftp()
            try:
                return fn(sftp)
            finally:
                sftp.close()
        except FileNotFoundError as exc:
            raise _RemoteError(f"SFTP path not found: {exc}", permanent=True) from exc
        except paramiko.SSHException as exc:
            raise _RemoteError(f"SFTP operation failed: {exc}", permanent=False) from exc
        except OSError as exc:
            raise _RemoteError(f"SFTP operation failed: {exc}", permanent=False) from exc
        finally:
            client.close()


def _make_client(
    settings: dict[str, Any], *, trust_anchor_policy: TrustAnchorPolicy | None = None
) -> _RemoteClient:
    """Build the protocol-appropriate client. Tests monkeypatch this (or the client classes) so no
    real server/SSH is needed; both connectors call it per operation-batch. ``trust_anchor_policy``
    (#190, ADR 0093) is the outbound FTPS verify-path internal-CA fallback; the source passes ``None``
    (byte-identical) and SFTP/plain-FTP ignore it (no server-cert verify)."""
    protocol = str(settings.get("protocol", "sftp")).lower()
    if protocol == "sftp":
        return _SftpClient(settings)
    if protocol == "ftp":
        return _FtpClient(settings, tls=False)
    if protocol == "ftps":
        return _FtpClient(settings, tls=True, trust_anchor_policy=trust_anchor_policy)
    raise ValueError(f"REMOTEFILE protocol must be one of {_PROTOCOLS}, got {protocol!r}")


def _anon_ftp_guard(
    s: dict[str, Any],
    *,
    cleartext_accepted: bool = False,
    cleartext_reason: str | None = None,
    connection: str | None = None,
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
    if str(s.get("protocol", "sftp")).lower() != "ftp":
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
    connection: str | None = None,
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
    protocol = str(s.get("protocol", "sftp")).lower()
    if protocol not in _PROTOCOLS:
        raise ValueError(f"REMOTEFILE protocol must be one of {_PROTOCOLS}, got {protocol!r}")
    if protocol == "ftp" and (s.get("username") or s.get("password")):
        # Plain FTP sends the credential in cleartext (and the body is PHI). Refuse unless the explicit
        # dev/trusted-network escape is set, mirroring refuse_cleartext_credentials. #200 (ADR 0092
        # decision 2): the escape is CLAMPED to non production-PHI — the credential-on-the-wire hop (the
        # strictly-worse case) now gets the same clamp the sibling anonymous-ftp guard already applies, so
        # MEFOR_ALLOW_INSECURE_TLS can no longer cross a prod-PHI credentialed-ftp hop.
        if not weakened_tls_escape_permitted_here():
            raise ValueError(
                "REMOTEFILE plain ftp transmits credentials in CLEARTEXT; refused unless "
                f"{INSECURE_TLS_ESCAPE_ENV} is set — use ftps (tls=True) or sftp (refused on a "
                "production-PHI instance even with the escape, #200)"
            )
        logger.warning(
            "REMOTEFILE %s sends credentials over CLEARTEXT ftp (no TLS)",
            _redact(str(s["host"]), str(s.get("remote_dir", ""))),
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
        self._client = _make_client(s, trust_anchor_policy=config.trust_anchor_policy)
        self._settings = s
        self._host = str(s["host"])
        self._remote_dir = str(s["remote_dir"])
        self._filename_template = str(s.get("filename", "{MSH-10}.hl7"))
        self._overwrite = bool(s.get("overwrite", False))
        self._encoding: str = s.get("encoding", "utf-8")

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
            if exc.permanent:
                raise NegativeAckError(
                    str(exc),
                    code="remotefile",
                    permanent=True,
                    credential_fault=exc.credential_fault,
                ) from exc
            raise DeliveryError(str(exc)) from exc

    def _upload(self, payload: str) -> None:
        name = render_filename(self._filename_template, payload, fallback="message.hl7")
        data = payload.encode(self._encoding)
        self._client.ensure_dir(self._remote_dir)
        final = posixpath.join(self._remote_dir, name)
        if not self._overwrite:
            final = self._unique(final)
        # Write to a unique temp name then rename, so a poller on the far side never sees a partial
        # file. The temp suffix is unguessable so two concurrent uploads never collide on it.
        tmp = posixpath.join(self._remote_dir, f".{name}.{uuid.uuid4().hex}.part")
        self._client.store(tmp, data)
        try:
            self._client.rename(tmp, final)
        except _RemoteError:
            # Publish failed — don't leave the temp behind. Best-effort cleanup, then re-raise so the
            # delivery is classified (retry/dead-letter) by send().
            try:
                self._client.remove(tmp)
            except _RemoteError:
                logger.warning("REMOTEFILE could not remove temp %s after a failed rename", tmp)
            raise

    def _unique(self, final: str) -> str:
        """Return ``final`` or, if a file already exists there, ``name-1.ext``, ``name-2.ext``, …
        Never clobbers an existing file silently (mirrors the File destination)."""
        try:
            existing = {n for n, _ in self._client.list_dir(self._remote_dir)}
        except _RemoteError:
            return final  # can't list (e.g. dir not yet created) → nothing to collide with
        base = posixpath.basename(final)
        if base not in existing:
            return final
        stem, dot, ext = base.partition(".")
        n = 1
        while True:
            candidate = f"{stem}-{n}{dot}{ext}"
            if candidate not in existing:
                return posixpath.join(self._remote_dir, candidate)
            n += 1

    async def test_connection(self) -> None:
        # Connect + authenticate + ensure the upload dir (the destination's normal first step) — no
        # message data written. A failure is mapped like send()'s.
        try:
            await asyncio.to_thread(self._client.ensure_dir, self._remote_dir)
        except _RemoteError as exc:
            if exc.permanent:
                raise NegativeAckError(
                    str(exc),
                    code="remotefile",
                    permanent=True,
                    credential_fault=exc.credential_fault,
                ) from exc
            raise DeliveryError(str(exc)) from exc

    async def aclose(self) -> None:
        return None  # connect-per-operation — nothing held open


class RemoteFileSource(SourceConnector):
    """Poll ``remote_dir`` for ``pattern`` files and feed each to the pipeline handler."""

    polls_shared_resource = True  # a remote dir is a shared external resource — leader-gate it

    def __init__(self, config: Source) -> None:
        s = config.settings
        _validate_common(s)
        self._client = _make_client(s)
        self._host = str(s["host"])
        self._remote_dir = str(s["remote_dir"])
        self._pattern: str = s.get("pattern", "*.hl7")
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
        # Opt-in at-start directory validation (#114, ADR 0031 amendment). Default off = the historical
        # run-time deferral (an unreachable remote dir is logged-and-retried each poll, never fails start).
        self._validate_directory: bool = bool(s.get("validate_directory", False))
        mfb = s.get("max_file_bytes", DEFAULT_MAX_FILE_BYTES)
        self._max_file_bytes: int | None = int(mfb) if mfb else None
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
            if exc.permanent:
                raise NegativeAckError(
                    str(exc),
                    code="remotefile",
                    permanent=True,
                    credential_fault=exc.credential_fault,
                ) from exc
            raise DeliveryError(str(exc)) from exc

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
                if self._may_poll():
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
        for name, size in sorted(entries):
            if self._stop.is_set():
                break  # shutting down — leave the rest for the next start (at-least-once)
            if not fnmatch.fnmatch(name, self._pattern):
                continue
            path = posixpath.join(self._remote_dir, name)
            # #142 leave-in-place dedup: skip a file this connection already ingested (in-process set,
            # then the durable ledger). Keyed on a HASHED id (name+size — a remote listing carries no
            # mtime) — never a cleartext filename, never logged at INFO+.
            file_key = self._file_key(name, size) if self._after_read == "leave" else None
            if file_key is not None and await self._leave_already_ingested(file_key):
                continue
            if self._max_file_bytes is not None and size > self._max_file_bytes:
                # Transport-level reject *before* any bytes are read — parallels the File source's
                # oversize guard. It never became a "received message", so there's no store
                # disposition; move it to the error dir and log it (never a silent drop).
                logger.warning(
                    "REMOTEFILE file %s exceeds max_file_bytes (%s); routing to error dir",
                    name,
                    self._max_file_bytes,
                )
                await self._move(path, self._error_dir, name)
                continue
            try:
                raw = await asyncio.to_thread(self._client.retrieve, path)
            except _RemoteError as exc:
                # Transient (locked / vanished mid-poll): leave it in place to retry next poll rather
                # than quarantine a healthy file. Logged, never silently swallowed.
                logger.warning(
                    "REMOTEFILE could not retrieve %s (will retry next poll): %s", name, exc
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
                    name,
                    (self.content_type or ContentType.HL7V2).value,
                )
                await self._move(path, self._error_dir, name)
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
                    name,
                    exc,
                )
                await self._move(path, self._error_dir, name)
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
                    name,
                    exc,
                )
                continue
            try:
                await self._handler(raw)
            except Exception as exc:
                # The handler records every message-level outcome itself and returns, so an exception
                # escaping here is an infrastructure failure (the durable store write failed). Leave the
                # file in place so the next poll retries (at-least-once) — moving it would drop a
                # received-but-unrecorded message (mirrors the File source's M-15).
                logger.warning(
                    "REMOTEFILE handler failed for %s (will retry next poll): %s", name, exc
                )
                continue
            await self._after_processing(path, name)
            if file_key is not None:
                # Record AFTER emit success (the FILE — not each split message — is the dedup unit).
                await self._leave_record(file_key)
                newly_recorded += 1
        if newly_recorded and self.processed_ledger is not None:
            await (
                self.processed_ledger.prune()
            )  # bound growth (age + count), only when something new

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

    async def _after_processing(self, path: str, name: str) -> None:
        if self._after_read == "delete":
            try:
                await asyncio.to_thread(self._client.remove, path)
            except _RemoteError as exc:
                # A processed file we can't delete will be re-read (a duplicate); surface it.
                logger.warning("REMOTEFILE could not delete processed file %s: %s", name, exc)
        elif self._after_read == "leave":
            # #142 process-in-place: never move/delete — the durable dedup ledger (recorded by
            # _poll_once AFTER this returns) is what stops it being re-ingested next poll.
            return
        else:
            await self._move(path, self._processed_dir, name)

    async def _move(self, path: str, dest_dir: str, name: str) -> None:
        dst = posixpath.join(dest_dir, name)
        try:
            await asyncio.to_thread(self._client.rename, path, dst)
        except _RemoteError as exc:
            # A stuck file (locked / dest unwritable) stays and is re-read; log it.
            logger.warning("REMOTEFILE could not move %s to %s: %s", name, dest_dir, exc)


register_destination(ConnectorType.REMOTEFILE, RemoteFileDestination)
register_source(ConnectorType.REMOTEFILE, RemoteFileSource)

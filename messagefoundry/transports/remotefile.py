"""Remote-file transport: SFTP / FTP / FTPS — directory destination + directory-polling source.

A single connector type (``REMOTEFILE``) with a ``protocol`` setting selecting the wire protocol:

- ``sftp`` — SSH file transfer (paramiko, the ``[sftp]`` extra — lazily imported, so installs that
  never use SFTP skip it). **Host-key verification is ON by default**; an unknown key is refused
  unless the explicit dev escape ``MEFOR_ALLOW_INSECURE_TLS`` is set (and logged loudly when it is),
  mirroring the SQL Server backend's weakened-TLS posture.
- ``ftp`` — plain FTP (stdlib ``ftplib``). Cleartext: credentials over plain ``ftp`` are **refused**
  unless the escape is set (use ``ftps``/``sftp``), mirroring :func:`refuse_cleartext_credentials`.
- ``ftps`` — FTP over explicit TLS (``ftplib.FTP_TLS`` + ``PROT P``), credentials encrypted.

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
import io
import logging
import posixpath
import uuid
from typing import Any, Callable, TypeVar

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import INSECURE_TLS_ESCAPE_ENV, insecure_tls_allowed
from messagefoundry.transports.base import (
    DeliveryError,
    DestinationConnector,
    InboundHandler,
    NegativeAckError,
    SourceConnector,
    register_destination,
    register_source,
)
from messagefoundry.transports.file import DEFAULT_MAX_FILE_BYTES, render_filename

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

    The connector maps a transient error to :class:`DeliveryError` (retry) and a permanent one to
    :class:`NegativeAckError` (dead-letter), so the client layer stays transport-detail-only."""

    def __init__(self, message: str, *, permanent: bool) -> None:
        super().__init__(message)
        self.permanent = permanent


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


class _FtpClient(_RemoteClient):
    """FTP / FTPS client over the stdlib ``ftplib``. ``tls`` selects ``FTP_TLS`` (explicit TLS, with
    ``PROT P`` so the data channel is encrypted too) over plain ``FTP``."""

    def __init__(self, settings: dict[str, Any], *, tls: bool) -> None:
        self._host = str(settings["host"])
        self._port = int(settings.get("port", 21))
        self._user = settings.get("username")
        self._password = settings.get("password")
        self._tls = tls
        self._timeout = float(settings.get("connect_timeout", 30.0))

    def _connect(self) -> ftplib.FTP:
        # B321: plain FTP only when explicitly selected; credentials over it are refused unless
        # MEFOR_ALLOW_INSECURE_TLS is set (see _validate_common). FTPS/SFTP are the encrypted defaults.
        if self._tls:
            ftp: ftplib.FTP = ftplib.FTP_TLS(timeout=self._timeout)
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
            try:
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
            raise _RemoteError(f"FTP login refused: {exc}", permanent=True) from exc
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
        # must never silently weaken to auto-accept. The accept-unknown policy is gated here so the
        # connector refuses to build rather than trust-on-first-use a man-in-the-middle.
        self._accept_unknown = insecure_tls_allowed()
        if self._accept_unknown:
            logger.warning(
                "REMOTEFILE sftp %s accepts UNKNOWN host keys (AutoAddPolicy) because %s is set "
                "— MITM-able; for a trusted-network dev/test bind only",
                self._host,
                INSECURE_TLS_ESCAPE_ENV,
            )

    def _connect(self) -> Any:
        paramiko = _import_paramiko()
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
                try:
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
            raise _RemoteError(f"SFTP authentication failed: {exc}", permanent=True) from exc
        except paramiko.SSHException as exc:
            # SSHException covers an unknown/rejected host key (RejectPolicy) — a security stop the
            # operator must resolve, so it's permanent, not a retry.
            raise _RemoteError(f"SFTP connection rejected: {exc}", permanent=True) from exc
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


def _make_client(settings: dict[str, Any]) -> _RemoteClient:
    """Build the protocol-appropriate client. Tests monkeypatch this (or the client classes) so no
    real server/SSH is needed; both connectors call it per operation-batch."""
    protocol = str(settings.get("protocol", "sftp")).lower()
    if protocol == "sftp":
        return _SftpClient(settings)
    if protocol == "ftp":
        return _FtpClient(settings, tls=False)
    if protocol == "ftps":
        return _FtpClient(settings, tls=True)
    raise ValueError(f"REMOTEFILE protocol must be one of {_PROTOCOLS}, got {protocol!r}")


def _validate_common(s: dict[str, Any]) -> str:
    """Shared construction-time validation: required ``host``/``remote_dir``, a known ``protocol``, and
    the cleartext-FTP credential guard. Returns the normalized protocol."""
    for req in ("host", "remote_dir"):
        if not s.get(req):
            raise ValueError(f"REMOTEFILE connector requires a {req!r} setting")
    protocol = str(s.get("protocol", "sftp")).lower()
    if protocol not in _PROTOCOLS:
        raise ValueError(f"REMOTEFILE protocol must be one of {_PROTOCOLS}, got {protocol!r}")
    if protocol == "ftp" and (s.get("username") or s.get("password")):
        # Plain FTP sends the credential in cleartext (and the body is PHI). Refuse unless the
        # explicit dev/trusted-network escape is set, mirroring refuse_cleartext_credentials.
        if not insecure_tls_allowed():
            raise ValueError(
                "REMOTEFILE plain ftp transmits credentials in CLEARTEXT; refused unless "
                f"{INSECURE_TLS_ESCAPE_ENV} is set — use ftps (tls=True) or sftp"
            )
        logger.warning(
            "REMOTEFILE %s sends credentials over CLEARTEXT ftp (no TLS)",
            _redact(str(s["host"]), str(s.get("remote_dir", ""))),
        )
    return protocol


class RemoteFileDestination(DestinationConnector):
    """Upload each payload to ``remote_dir``/``filename`` over SFTP/FTP/FTPS (temp-then-rename)."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        _validate_common(s)
        # Constructing the SFTP client validates the host-key escape posture fail-fast (build_check).
        self._client = _make_client(s)
        self._settings = s
        self._host = str(s["host"])
        self._remote_dir = str(s["remote_dir"])
        self._filename_template = str(s.get("filename", "{MSH-10}.hl7"))
        self._overwrite = bool(s.get("overwrite", False))
        self._encoding: str = s.get("encoding", "utf-8")

    async def send(self, payload: str) -> None:
        try:
            await asyncio.to_thread(self._upload, payload)
        except _RemoteError as exc:
            if exc.permanent:
                raise NegativeAckError(str(exc), code="remotefile", permanent=True) from exc
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
        self._after_read: str = s.get("after_read", "move")  # "move" | "delete"
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
            try:
                await asyncio.wait_for(self._stop.wait(), self._poll_seconds)
            except asyncio.TimeoutError:
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
        for name, size in sorted(entries):
            if self._stop.is_set():
                break  # shutting down — leave the rest for the next start (at-least-once)
            if not fnmatch.fnmatch(name, self._pattern):
                continue
            path = posixpath.join(self._remote_dir, name)
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

    async def _after_processing(self, path: str, name: str) -> None:
        if self._after_read == "delete":
            try:
                await asyncio.to_thread(self._client.remove, path)
            except _RemoteError as exc:
                # A processed file we can't delete will be re-read (a duplicate); surface it.
                logger.warning("REMOTEFILE could not delete processed file %s: %s", name, exc)
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

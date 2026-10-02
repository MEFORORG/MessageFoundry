# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An in-process SFTP share on loopback over a temporary local directory: the far side of the
engine's REMOTEFILE (``protocol = "sftp"``) inbound AND outbound.

A remote-file peer is both a driver and a sink at once. The engine's inbound POLLS this share and its
outbound WRITES to it, so one server serves two fixed directories: :data:`INBOX`, which the remotefile
driver uploads into, and :data:`OUTBOX`, which the remotefile sink watches. ``harness/config/remotefile``
names the same two paths.

It is a real SSH server (paramiko's server classes), not a stand-in for the transport: the engine dials
it, verifies its host key, authenticates and runs real SFTP requests against it. So that verification
stays ON, the share mints a throwaway ECDSA host key on every start and writes it into the
``known_hosts`` file the engine and the driver load (``harness/endpoints/remotefile.py``).

**This is the one statement of the rule for the remotefile family: never set
``MEFOR_ALLOW_INSECURE_TLS`` to make it work.** Nothing here needs it, and with it the engine would
accept any host key, so the scenarios would no longer show that verification holds. Where a pin is
refused, fix the pin (see :class:`SftpShare` for the one known cause).

The one password both ends use comes from the environment variable :data:`PASSWORD_ENV`, the same
variable the graph reads through ``env("remotefile_harness_password")``. No credential lives in source.

paramiko (the ``[sftp]`` extra) is imported lazily, so discovering the remotefile driver and sink never
fails without it. A missing extra or an unset password is a :class:`RemoteFileSetupError`, an
:class:`OSError`, which the scenario CLI reports as a SETUP error (exit 2), never as a pass.

Every path a client names is confined to the served directory: it is normalized against ``/`` first
(so ``..`` cannot climb out), and a path that resolves outside through a symlink is refused. A write
past the engine's per-message cap is refused. The server never logs what it is sent, and keeps it only
in its own temporary directory, which :meth:`SftpShare.stop` deletes.
"""

from __future__ import annotations

import contextlib
import errno
import logging
import os
import posixpath
import shutil
import socket
import stat
import tempfile
import threading
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from harness.sinks import LOOPBACK
from harness.sinks._tcp import POLL_SECONDS, LoopbackServer
from messagefoundry.parsing.peek import DEFAULT_MAX_MESSAGE_BYTES

logger = logging.getLogger(__name__)

#: The account the graph names and the share accepts. A user name is not a secret.
USERNAME = "harness"

#: The variable carrying the one password the share accepts and the graph sends. It is the engine's
#: own spelling of the environment value ``remotefile_harness_password``.
PASSWORD_ENV = "MEFOR_VALUE_REMOTEFILE_HARNESS_PASSWORD"

#: The log channel the share's server-side transports write to.
LOG_CHANNEL = "harness.sinks.sftp_share"


class _HangupFilter(logging.Filter):
    """Drops paramiko's "Socket exception" record, and nothing else. The engine opens a connection per
    operation and drops it when done, which paramiko's server side reports at ERROR once per poll.
    That is the normal life of this share, not a fault; every other record on the channel passes."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not str(record.msg).startswith("Socket exception")


logging.getLogger(LOG_CHANNEL).addFilter(_HangupFilter())

#: The directory the engine's inbound polls (the driver uploads here).
INBOX = "/inbox"
#: The directory the engine's outbound writes (the sink records what lands here).
OUTBOX = "/outbox"

#: The endpoint naming the known_hosts file a share pins its key into and the driver verifies with.
KNOWN_HOSTS_ENDPOINT = "remotefile_known_hosts"

#: How many times a known_hosts rewrite retries a replace that Windows refuses because the engine has
#: the file open for a connect, and how long it waits between tries.
_REPLACE_TRIES = 40
_REPLACE_WAIT_SECONDS = 0.05


class RemoteFileSetupError(OSError):
    """The share cannot run here: the ``[sftp]`` extra is missing or no password is set."""


def import_paramiko() -> Any:
    """paramiko, or :class:`RemoteFileSetupError` naming the extra that would provide it."""
    try:
        import paramiko
    except ImportError as exc:
        raise RemoteFileSetupError(
            "the [sftp] extra (paramiko) is not installed, so no remotefile scenario can run here; "
            "install 'messagefoundry[sftp]'"
        ) from exc
    return paramiko


def share_password(environ: Mapping[str, str] | None = None) -> str:
    """The share's password from :data:`PASSWORD_ENV`, or :class:`RemoteFileSetupError`."""
    value = (os.environ if environ is None else environ).get(PASSWORD_ENV, "")
    if not value:
        raise RemoteFileSetupError(
            f"{PASSWORD_ENV} is not set: the harness SFTP share and the engine's remotefile graph "
            "both read their one password from it"
        )
    return value


def known_hosts_name(host: str, port: int) -> str:
    """The host name a ``known_hosts`` entry carries for ``host:port``, as OpenSSH and paramiko
    spell it: bare on port 22, ``[host]:port`` anywhere else."""
    return host if port == 22 else f"[{host}]:{port}"


def _confined(root: Path, remote: str) -> str:
    """The local path for ``remote``, kept inside ``root`` (already resolved). Normalizing against
    ``/`` first collapses every ``..`` at the top, so no spelling climbs out; a symlink that resolves
    outside is refused."""
    relative = posixpath.normpath(posixpath.join("/", remote)).lstrip("/")
    local = root.joinpath(*relative.split("/")) if relative else root
    if not Path(os.path.realpath(local)).is_relative_to(root):
        raise PermissionError(errno.EACCES, "outside the served directory", remote)
    return str(local)


def _interface(paramiko: Any, root: Path) -> type:
    """An ``SFTPServerInterface`` over the local directory ``root``.

    ``RENAME`` refuses an existing target, as the SFTP version 3 draft and OpenSSH's ``link`` then
    ``unlink`` do, because the engine's outbound relies on that refusal to never replace a file
    (``RemoteFileDestination._publish_new``). ``posix-rename`` replaces, as ``rename(2)`` does."""
    server_cls: Any = paramiko.SFTPServer
    attributes: Any = paramiko.SFTPAttributes
    base: Any = paramiko.SFTPServerInterface
    handle_base: Any = paramiko.SFTPHandle

    def failure(exc: OSError) -> int:
        return int(server_cls.convert_errno(exc.errno))

    class _Handle(handle_base):  # type: ignore[misc]
        def write(self, offset: int, data: bytes) -> int:
            # Bounded like the harness's other receivers: nothing a client sends grows a file past
            # the engine's own per-message cap.
            if offset + len(data) > DEFAULT_MAX_MESSAGE_BYTES:
                return int(paramiko.SFTP_FAILURE)
            return int(super().write(offset, data))

        def stat(self) -> Any:
            try:
                return attributes.from_stat(os.fstat(self.readfile.fileno()))
            except OSError as exc:
                return failure(exc)

    class _Share(base):  # type: ignore[misc]
        def canonicalize(self, path: str) -> str:
            return posixpath.normpath(posixpath.join("/", path))

        def list_folder(self, path: str) -> Any:
            try:
                local = _confined(root, path)
                found = []
                for name in sorted(os.listdir(local)):
                    attr = attributes.from_stat(os.lstat(os.path.join(local, name)))
                    attr.filename = name
                    found.append(attr)
                return found
            except OSError as exc:
                return failure(exc)

        def stat(self, path: str) -> Any:
            try:
                return attributes.from_stat(os.stat(_confined(root, path)))
            except OSError as exc:
                return failure(exc)

        def lstat(self, path: str) -> Any:
            try:
                return attributes.from_stat(os.lstat(_confined(root, path)))
            except OSError as exc:
                return failure(exc)

        def open(self, path: str, flags: int, attr: Any) -> Any:
            try:
                fd = os.open(_confined(root, path), flags | getattr(os, "O_BINARY", 0), 0o600)
            except OSError as exc:
                return failure(exc)
            if flags & os.O_WRONLY:
                mode = "ab" if flags & os.O_APPEND else "wb"
            elif flags & os.O_RDWR:
                mode = "a+b" if flags & os.O_APPEND else "r+b"
            else:
                mode = "rb"
            try:
                fh = os.fdopen(fd, mode)
            except OSError as exc:  # a directory opened for reading, say: fdopen leaves fd open
                os.close(fd)
                return failure(exc)
            handle = _Handle(flags)
            handle.filename = path
            handle.readfile = handle.writefile = fh
            return handle

        def remove(self, path: str) -> int:
            try:
                os.remove(_confined(root, path))
            except OSError as exc:
                return failure(exc)
            return int(paramiko.SFTP_OK)

        def rename(self, oldpath: str, newpath: str) -> int:
            try:
                src, dst = _confined(root, oldpath), _confined(root, newpath)
                try:
                    os.link(src, dst)
                except FileExistsError:
                    return int(paramiko.SFTP_FAILURE)
                except OSError:
                    # No hard links here (or a directory): check, then move. Not atomic, but this
                    # share has one client per scenario.
                    if os.path.lexists(dst):
                        return int(paramiko.SFTP_FAILURE)
                    os.rename(src, dst)
                else:
                    os.unlink(src)
            except OSError as exc:
                return failure(exc)
            return int(paramiko.SFTP_OK)

        def posix_rename(self, oldpath: str, newpath: str) -> int:
            try:
                os.replace(_confined(root, oldpath), _confined(root, newpath))
            except OSError as exc:
                return failure(exc)
            return int(paramiko.SFTP_OK)

        def mkdir(self, path: str, attr: Any) -> int:
            try:
                os.mkdir(_confined(root, path), 0o700)
            except OSError as exc:
                return failure(exc)
            return int(paramiko.SFTP_OK)

        def rmdir(self, path: str) -> int:
            try:
                os.rmdir(_confined(root, path))
            except OSError as exc:
                return failure(exc)
            return int(paramiko.SFTP_OK)

        # Nothing the engine or the driver does needs these, and a symlink is how a path escapes.
        def chattr(self, path: str, attr: Any) -> int:
            return int(paramiko.SFTP_OP_UNSUPPORTED)

        def symlink(self, target_path: str, path: str) -> int:
            return int(paramiko.SFTP_OP_UNSUPPORTED)

        def readlink(self, path: str) -> Any:
            return int(paramiko.SFTP_OP_UNSUPPORTED)

    return _Share


def _authenticator(paramiko: Any, password: str) -> Any:
    base: Any = paramiko.ServerInterface

    class _Auth(base):  # type: ignore[misc]
        def get_allowed_auths(self, username: str) -> str:
            return "password"

        def check_auth_password(self, username: str, offered: str) -> int:
            # A plain comparison: a loopback test peer holding a per-run throwaway password has no
            # remote timing observer, so a constant-time compare would protect nothing here.
            if username == USERNAME and offered == password:
                return int(paramiko.AUTH_SUCCESSFUL)
            logger.warning("SFTP share refused a password login for user %r", username)
            return int(paramiko.AUTH_FAILED)

        def check_channel_request(self, kind: str, chanid: int) -> int:
            if kind == "session":
                return int(paramiko.OPEN_SUCCEEDED)
            return int(paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

    return _Auth()


class SftpShare:
    """The share: binds ``127.0.0.1:port`` (0 takes an ephemeral port) and serves a fresh temporary
    directory holding :data:`INBOX` and :data:`OUTBOX`.

    ``known_hosts`` is the file the share pins its host key into, under ``advertised_host`` (the host
    the engine and the driver dial, the ``host`` endpoint). An existing file keeps its other lines
    byte for byte, its line endings and its permission bits: only lines whose host field is exactly
    this share's ``[host]:port`` change. A symlinked path is followed, so the target gets the pin.
    paramiko cannot read ``@revoked`` or ``@cert-authority`` lines, so a file holding one fails every
    connect, the engine's included; keep such lines out of this file.

    The share does not answer a handshake until its new key is pinned, so a client connecting at
    start never meets the previous run's pin. One instance starts once.

    The engine's SFTP client also loads the account's own ``~/.ssh/known_hosts`` and consults it
    FIRST. The key is fresh on every start, so an entry there for this share's address (left by
    inspecting it with ``sftp -P``) is always stale and makes every engine connect fail as a rejected
    host key. Remove such an entry; the share cannot reach that file.

    ``password=None`` reads :data:`PASSWORD_ENV`. Constructing raises :class:`RemoteFileSetupError`
    when the extra or the password is missing."""

    def __init__(
        self,
        port: int = 0,
        *,
        known_hosts: str | Path,
        advertised_host: str = LOOPBACK,
        password: str | None = None,
    ) -> None:
        self._paramiko = import_paramiko()
        self._password = share_password() if password is None else password
        self.known_hosts = Path(known_hosts)
        self.advertised_host = advertised_host
        self._server = LoopbackServer(LOOPBACK, port, self._handle)
        self._pinned = threading.Event()
        self._lock = threading.Lock()
        self._connections = 0
        self.root: Path | None = None
        self._host_key: Any = None
        self._interface: type | None = None
        self._auth: Any = None

    @property
    def port(self) -> int:
        return self._server.port

    @property
    def host(self) -> str:
        return self._server.host

    @property
    def connections(self) -> int:
        """How many connections the share has accepted: each engine poll and delivery opens one."""
        with self._lock:
            return self._connections

    @property
    def host_key(self) -> Any:
        """This run's host key (paramiko ``PKey``), or None before :meth:`start`."""
        return self._host_key

    def local(self, remote_dir: str) -> Path:
        """Where ``remote_dir`` (``INBOX`` or ``OUTBOX``) lives on disk while the share runs."""
        if self.root is None:
            raise RuntimeError("the SFTP share is not started")
        return Path(_confined(self.root, remote_dir))

    def start(self) -> None:
        if self._server.stopping.is_set() or self.root is not None:
            raise RuntimeError("an SftpShare starts once; build a new one")
        paramiko = self._paramiko
        self.root = Path(os.path.realpath(tempfile.mkdtemp(prefix="harness-sftp-")))
        try:
            for directory in (INBOX, OUTBOX):
                self.local(directory).mkdir()
            self._host_key = paramiko.ECDSAKey.generate()
            self._interface = _interface(paramiko, self.root)
            self._auth = _authenticator(paramiko, self._password)
            self._server.start()
            self.pin_host_key()
            self._pinned.set()
        except BaseException:
            self.stop()
            raise

    def pin_host_key(self, key: Any = None) -> None:
        """Pin ``key`` (default: this share's host key) in :attr:`known_hosts` for the address the
        engine dials, replacing whatever was pinned for it."""
        key = self._host_key if key is None else key
        self._rewrite_known_hosts(f"{self._pinned_name()} {key.get_name()} {key.get_base64()}")

    def unpin_host_key(self) -> None:
        """Remove every entry for this share's address from :attr:`known_hosts`, so a verifying
        client meets it as an UNKNOWN host."""
        self._rewrite_known_hosts(None)

    def _pinned_name(self) -> str:
        return known_hosts_name(self.advertised_host, self.port)

    def _rewrite_known_hosts(self, entry: str | None) -> None:
        """Drop the lines naming exactly this share's address, append ``entry`` when given, and
        replace the file in one step, so a client connecting meanwhile reads the old file or the new.
        Bytes, not paramiko's ``HostKeys``, which would drop comments and other lines it cannot
        parse, and not text, which would also split on characters a known_hosts line never ends at."""
        target = Path(os.path.realpath(self.known_hosts))
        name = self._pinned_name().encode()
        try:
            old = target.read_bytes()
            mode: int | None = stat.S_IMODE(target.stat().st_mode)
        except FileNotFoundError:
            old, mode = b"", None
        lines = old.splitlines(keepends=True)
        if lines and not lines[-1].endswith((b"\n", b"\r")):
            lines[-1] += b"\n"
        newline = b"\r\n" if lines and lines[0].endswith(b"\r\n") else b"\n"
        kept = [line for line in lines if line.split(None, 1)[:1] != [name]]
        if entry is not None:
            kept.append(entry.encode() + newline)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".known_hosts.")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(b"".join(kept))
            if mode is not None:
                os.chmod(tmp, mode)
            for attempt in range(_REPLACE_TRIES):
                try:
                    os.replace(tmp, target)
                    break
                except PermissionError:
                    # Windows refuses to replace a file another handle holds open, and the engine
                    # opens this one on every connect. POSIX never lands here.
                    if attempt == _REPLACE_TRIES - 1:
                        raise
                    time.sleep(_REPLACE_WAIT_SECONDS)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(tmp)

    def stop(self) -> None:
        try:
            self._server.stop()
        finally:
            if self.root is not None:
                root, self.root = self.root, None
                # paramiko's SFTP threads close their file handles as their channels end, which on
                # Windows can trail the stop by a moment; a handle still open there blocks removal.
                for _ in range(_REPLACE_TRIES):
                    shutil.rmtree(root, ignore_errors=True)
                    if not root.exists():
                        break
                    time.sleep(_REPLACE_WAIT_SECONDS)
                else:
                    logger.warning("SFTP share could not remove its directory %s", root)

    def _handle(self, conn: socket.socket, peer: str) -> None:
        paramiko = self._paramiko
        with self._lock:
            self._connections += 1
        # Answer nothing until the new key is pinned (start() sets this right after binding).
        while not self._pinned.wait(POLL_SECONDS):
            if self._server.stopping.is_set():
                return
        transport = paramiko.Transport(conn)
        transport.set_log_channel(LOG_CHANNEL)
        try:
            transport.add_server_key(self._host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, self._interface)
            transport.start_server(server=self._auth)
            # The transport runs on its own thread; hold this connection's slot until the client
            # hangs up or the share stops, so stop() closes it rather than leaking it.
            while transport.is_active() and not self._server.stopping.is_set():
                transport.join(POLL_SECONDS)
        except (paramiko.SSHException, EOFError, OSError) as exc:
            # A failed handshake ends this connection only. Logged, because a client that cannot
            # negotiate is a reason a scenario sees nothing arrive.
            logger.warning("SFTP share: a handshake from %s failed: %r", peer, exc)
        finally:
            transport.close()

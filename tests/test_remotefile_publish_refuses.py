# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""With ``overwrite`` off, the remote upload's publish refuses a name taken since the listing
(BACKLOG #2553, ASVS 15.4.2).

The upload lists ``remote_dir`` to pick a free name, stores to a temp, then renames the temp onto
that name. Before #2553 the rename was SFTP ``posix_rename`` or FTP ``RNFR``/``RNTO``, and both can
replace an existing name, so a partner file written at the chosen name between the listing and the
rename was overwritten. The publish now goes through ``_RemoteClient.publish``, which refuses a
taken name, and the destination moves on to the next free name, a bounded number of times.

Three layers are tested here:

* the destination, over an in-memory client whose ``publish`` refuses a taken name;
* the real ``_SftpClient`` against a real in-process paramiko SFTP server on loopback, whose
  ``RENAME`` refuses an existing target the way OpenSSH's does. These SKIP where the ``[sftp]``
  extra is not installed; a skip claims nothing;
* the real ``_FtpClient`` over a scripted ``ftplib.FTP`` stand-in, including the residual a
  replacing FTP server leaves.

Every body is synthetic.
"""

from __future__ import annotations

import contextlib
import ftplib
import logging
import posixpath
import socket
import stat
import threading
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.wiring import Sftp
from messagefoundry.transports import build_destination, remotefile
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.remotefile import (
    PUBLISH_NAME_ATTEMPTS,
    RemoteFileDestination,
    _FtpClient,
    _RemoteClient,
    _RemoteError,
    _SftpClient,
)

_PARTNER = b"SYNTHETIC-PARTNER-FILE"


# === the destination ==========================================================


class _RacingClient(_RemoteClient):
    """In-memory client whose ``publish`` refuses a taken name, as the SFTP ``RENAME`` does.

    ``appear_after_store`` lands partner files when the store runs: after the listing, before the
    publish, which is the window #2553 is about. ``partner_takes_every_name`` lands a partner file at
    each name the publish tries, just before it tries it, which is the adversary the bound exists for.
    ``rename`` replaces, as ``posix_rename`` does."""

    def __init__(
        self,
        files: dict[str, bytes] | None = None,
        *,
        appear_after_store: dict[str, bytes] | None = None,
        partner_takes_every_name: bool = False,
    ) -> None:
        self.files: dict[str, bytes] = dict(files or {})
        self._appear_after_store = dict(appear_after_store or {})
        self._partner_takes_every_name = partner_takes_every_name
        self.ops: list[tuple[str, str]] = []

    def list_dir(self, remote_dir: str) -> list[tuple[str, int]]:
        return [
            (posixpath.basename(path), len(data))
            for path, data in self.files.items()
            if posixpath.dirname(path) == remote_dir
        ]

    def retrieve(self, path: str, *, max_bytes: int | None = None) -> bytes:
        return self.files[path]

    def store(self, path: str, data: bytes) -> None:
        self.ops.append(("store", path))
        self.files[path] = data
        self.files.update(self._appear_after_store)

    def rename(self, src: str, dst: str) -> None:
        self.ops.append(("rename", dst))
        self.files[dst] = self.files.pop(src)

    def publish(self, src: str, candidates: Sequence[str]) -> str | None:
        for dst in candidates:
            self.ops.append(("publish", dst))
            if self._partner_takes_every_name:
                self.files.setdefault(dst, _PARTNER)
            if dst not in self.files:
                self.files[dst] = self.files.pop(src)
                return dst
        return None

    def remove(self, path: str) -> None:
        self.ops.append(("remove", path))
        self.files.pop(path, None)

    def dispose_unless_changed(self, path: str, expected_size: int, dest: str | None) -> int | None:
        raise AssertionError("the destination never disposes")

    def ensure_dir(self, remote_dir: str) -> bool:
        return False


def _dest(
    monkeypatch: pytest.MonkeyPatch, client: _RemoteClient, **over: Any
) -> RemoteFileDestination:
    monkeypatch.setattr(remotefile, "_make_client", lambda settings, **_: client)
    base: dict[str, Any] = {"host": "sftp.example.com", "remote_dir": "/in"}
    base.update(over)
    dest = build_destination(
        Destination(name="OB_REMOTE", type=ConnectorType.REMOTEFILE, settings=Sftp(**base).settings)
    )
    assert isinstance(dest, RemoteFileDestination)
    return dest


async def test_a_file_written_after_the_listing_is_not_overwritten(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """THE #2553 CASE. The listing shows ``CTRL2553.hl7`` free; a partner writes it while the
    upload stores its temp. The partner file must survive, and the message lands under the next
    name. The refusal is not a fault, so the send succeeds.

    Armed: against ``origin/main`` ``c31f0c37f9`` the upload published with ``rename`` (here, a
    replace), so the partner file was overwritten and this failed."""
    client = _RacingClient(appear_after_store={"/in/CTRL2553.hl7": _PARTNER})
    dest = _dest(monkeypatch, client, filename="{MSH-10}.hl7", overwrite=False)

    with caplog.at_level(logging.DEBUG, logger="messagefoundry.transports.remotefile"):
        await dest.send("MSH|^~\\&|A|B|C|D|20261001||ADT^A01|CTRL2553|P|2.5")

    assert client.files["/in/CTRL2553.hl7"] == _PARTNER
    assert client.files["/in/CTRL2553-1.hl7"].startswith(b"MSH|")
    assert [dst for op, dst in client.ops if op == "publish"] == [
        "/in/CTRL2553.hl7",
        "/in/CTRL2553-1.hl7",
    ]
    assert not any(op == "rename" for op, _ in client.ops)  # never the replacing rename
    assert not [p for p in client.files if p.endswith(".part")]  # the temp was published
    # Logged, and only through safe_name: the rendered name carries MSH-10, an identifier.
    bumped = [r for r in caplog.records if "were taken after the listing" in r.getMessage()]
    assert len(bumped) == 1, [r.getMessage() for r in caplog.records]
    assert bumped[0].levelno == logging.WARNING
    assert "CTRL2553" not in caplog.text


async def test_the_bump_is_bounded_and_fails_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    """A partner that takes every name just before the upload tries it cannot hold the upload in a
    loop. Past ``PUBLISH_NAME_ATTEMPTS`` names the delivery fails TRANSIENT, so its retry lists
    again; nothing of the partner's is replaced, and the temp is removed.

    Armed: against ``origin/main`` the single replacing rename succeeded over the partner file, so
    no error was raised and this failed."""
    assert PUBLISH_NAME_ATTEMPTS > 1  # control: a bound of 0 or 1 would make the count vacuous
    client = _RacingClient(partner_takes_every_name=True)
    dest = _dest(monkeypatch, client, filename="msg.hl7", overwrite=False)

    with pytest.raises(DeliveryError) as caught:
        await dest.send("new")

    assert not isinstance(caught.value, NegativeAckError)  # transient: the row retries
    assert f"all {PUBLISH_NAME_ATTEMPTS} names it tried taken" in str(caught.value)
    tried = [dst for op, dst in client.ops if op == "publish"]
    assert len(tried) == PUBLISH_NAME_ATTEMPTS
    assert len(set(tried)) == PUBLISH_NAME_ATTEMPTS  # a new name each time, never the same one
    assert all(client.files[dst] == _PARTNER for dst in tried)
    assert not [p for p in client.files if p.endswith(".part")]
    assert any(op == "remove" for op, _ in client.ops)


async def test_overwrite_on_still_replaces(monkeypatch: pytest.MonkeyPatch) -> None:
    """``overwrite = true`` asks for a replace, and still gets one: a file written after the store
    is replaced through ``rename``, and ``publish`` is never asked.

    A control: this holds on ``origin/main`` too. Armed by mutation instead: routing the
    overwrite-on publish through ``publish`` turns it red."""
    client = _RacingClient(appear_after_store={"/in/msg.hl7": _PARTNER})
    dest = _dest(monkeypatch, client, filename="msg.hl7", overwrite=True)

    await dest.send("new")

    assert client.files["/in/msg.hl7"] == b"new"
    assert [op for op, _ in client.ops if op in ("rename", "publish")] == ["rename"]


# === the real SFTP client against a real paramiko SFTP server =================


@pytest.fixture(scope="module")
def host_key() -> Any:
    """One RSA host key for every server in this file; generating one is slow. Requesting it SKIPS
    the test where the ``[sftp]`` extra is not installed."""
    paramiko = pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")
    return paramiko.RSAKey.generate(2048)


class _Share:
    """The in-memory directory behind the test SFTP server, plus what it was asked to do."""

    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = dict(files)
        self.calls: list[str] = []
        #: Lands at the named path just after the first ``lstat`` of it: a partner writing there
        #: between the client's check and its rename.
        self.appear_after_lstat: dict[str, bytes] = {}
        #: When set, ``RENAME`` answers with this SFTP status and changes nothing.
        self.rename_status: int | None = None
        #: SSH connections the server accepted.
        self.connections = 0


def _sftp_interface(paramiko: Any, share: _Share) -> type:
    """An ``SFTPServerInterface`` over ``share``. ``RENAME`` refuses an existing target, as the SFTP
    version 3 draft and OpenSSH's ``link``/``unlink`` do; ``posix-rename`` replaces, as ``rename(2)``
    does."""
    base: Any = paramiko.SFTPServerInterface

    class _Interface(base):  # type: ignore[misc]
        def lstat(self, path: str) -> Any:
            share.calls.append(f"lstat {path}")
            if path not in share.files:
                if path in share.appear_after_lstat:
                    share.files[path] = share.appear_after_lstat.pop(path)
                return paramiko.SFTP_NO_SUCH_FILE
            attrs = paramiko.SFTPAttributes()
            attrs.st_size = len(share.files[path])
            attrs.st_mode = stat.S_IFREG | 0o644
            return attrs

        def rename(self, oldpath: str, newpath: str) -> int:
            share.calls.append(f"rename {newpath}")
            if share.rename_status is not None:
                return share.rename_status
            if oldpath not in share.files:
                return int(paramiko.SFTP_NO_SUCH_FILE)
            if newpath in share.files:
                return int(paramiko.SFTP_FAILURE)
            share.files[newpath] = share.files.pop(oldpath)
            return int(paramiko.SFTP_OK)

        def posix_rename(self, oldpath: str, newpath: str) -> int:
            share.calls.append(f"posix_rename {newpath}")
            share.files[newpath] = share.files.pop(oldpath)
            return int(paramiko.SFTP_OK)

    return _Interface


@contextlib.contextmanager
def _sftp_server(share: _Share, host_key: Any, tmp_path: Path) -> Iterator[dict[str, Any]]:
    """A real in-process paramiko SSH server on loopback serving ``share`` over the ``sftp``
    subsystem, for every connection the client makes. Yields ``_SftpClient`` settings for it."""
    paramiko = pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")
    interface = _sftp_interface(paramiko, share)
    server_base: Any = paramiko.ServerInterface

    class _Server(server_base):  # type: ignore[misc]
        def get_allowed_auths(self, username: str) -> str:
            return "password"

        def check_auth_password(self, username: str, password: str) -> int:
            return int(paramiko.AUTH_SUCCESSFUL)

        def check_channel_request(self, kind: str, chanid: int) -> int:
            return int(paramiko.OPEN_SUCCEEDED)

    transports: list[Any] = []
    listener = socket.create_server(("127.0.0.1", 0))

    def _serve() -> None:
        while True:
            try:
                conn, _ = listener.accept()
            except OSError:  # the listener closed: the test is over
                return
            share.connections += 1
            transport = paramiko.Transport(conn)
            transports.append(transport)
            transport.add_server_key(host_key)
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, interface)
            try:
                transport.start_server(server=_Server())
            except (paramiko.SSHException, EOFError, OSError):
                continue

    try:
        port = listener.getsockname()[1]
        known_hosts = tmp_path / "known_hosts"
        keys = paramiko.HostKeys()
        keys.add(f"[127.0.0.1]:{port}", host_key.get_name(), host_key)
        keys.save(str(known_hosts))
        threading.Thread(target=_serve, daemon=True).start()
        yield {
            "host": "127.0.0.1",
            "port": port,
            "remote_dir": "/in",
            "username": "synthetic",
            "password": "synthetic-test-password",
            "known_hosts": str(known_hosts),
        }
    finally:
        listener.close()
        for transport in transports:
            transport.close()


def test_sftp_publish_moves_the_temp_onto_a_free_name(host_key: Any, tmp_path: Path) -> None:
    share = _Share({"/in/.t.part": b"new"})
    with _sftp_server(share, host_key, tmp_path) as settings:
        assert _SftpClient(settings).publish("/in/.t.part", ["/in/msg.hl7"]) == "/in/msg.hl7"
    assert share.files == {"/in/msg.hl7": b"new"}
    assert "rename /in/msg.hl7" in share.calls
    assert not any(c.startswith("posix_rename") for c in share.calls)


def test_sftp_publish_moves_on_to_the_next_name_on_one_connection(
    host_key: Any, tmp_path: Path
) -> None:
    """The first name is taken before the check and the second right after it; the third is free.
    Every try shares one SSH connection, and nothing of the partner's is replaced."""
    share = _Share({"/in/.t.part": b"new", "/in/a.hl7": _PARTNER})
    share.appear_after_lstat["/in/b.hl7"] = _PARTNER
    with _sftp_server(share, host_key, tmp_path) as settings:
        published = _SftpClient(settings).publish(
            "/in/.t.part", ["/in/a.hl7", "/in/b.hl7", "/in/c.hl7"]
        )
    assert published == "/in/c.hl7"
    assert share.files == {"/in/a.hl7": _PARTNER, "/in/b.hl7": _PARTNER, "/in/c.hl7": b"new"}
    assert share.connections == 1


def test_sftp_publish_refuses_a_name_already_taken(host_key: Any, tmp_path: Path) -> None:
    """Taken before the publish: the ``lstat`` check refuses it, and no rename is sent."""
    share = _Share({"/in/.t.part": b"new", "/in/msg.hl7": _PARTNER})
    with _sftp_server(share, host_key, tmp_path) as settings:
        assert _SftpClient(settings).publish("/in/.t.part", ["/in/msg.hl7"]) is None
    assert share.files == {"/in/.t.part": b"new", "/in/msg.hl7": _PARTNER}
    assert not any("rename" in c for c in share.calls)


def test_sftp_publish_refuses_a_name_taken_after_its_own_check(
    host_key: Any, tmp_path: Path
) -> None:
    """The partner writes the name between the client's ``lstat`` and its rename. Only the server
    can refuse it now, and the plain ``RENAME`` does. The refusal comes back as an errno-less
    ``IOError`` and is read as a collision, because a second ``lstat`` finds the name taken.

    Armed by mutation: publishing with ``posix_rename`` replaces the partner file and returns True,
    and this goes red."""
    share = _Share({"/in/.t.part": b"new"})
    share.appear_after_lstat["/in/msg.hl7"] = _PARTNER
    with _sftp_server(share, host_key, tmp_path) as settings:
        assert _SftpClient(settings).publish("/in/.t.part", ["/in/msg.hl7"]) is None
    assert share.files == {"/in/.t.part": b"new", "/in/msg.hl7": _PARTNER}
    assert share.calls == [
        "lstat /in/msg.hl7",
        "rename /in/msg.hl7",
        "lstat /in/.t.part",  # the temp is still there, so nothing moved: a refusal
        "lstat /in/msg.hl7",  # and the name is held: a collision
    ]


def test_sftp_publish_refused_for_another_reason_is_not_a_collision(
    host_key: Any, tmp_path: Path
) -> None:
    """A ``RENAME`` failure while the name stays free is no collision: it raises, classified as any
    other SFTP failure was before #2553 (transient for a generic failure), and nothing moves."""
    paramiko = pytest.importorskip("paramiko", reason="the [sftp] extra is not installed")
    share = _Share({"/in/.t.part": b"new"})
    share.rename_status = int(paramiko.SFTP_FAILURE)
    with (
        _sftp_server(share, host_key, tmp_path) as settings,
        pytest.raises(_RemoteError) as caught,
    ):
        _SftpClient(settings).publish("/in/.t.part", ["/in/msg.hl7"])
    assert caught.value.permanent is False
    assert caught.value.connection_fault is False
    assert share.files == {"/in/.t.part": b"new"}


def test_sftp_publish_of_a_vanished_temp_stays_permanent(host_key: Any, tmp_path: Path) -> None:
    """A missing source keeps the permanent "path not found" class it had before #2553."""
    share = _Share({})
    with (
        _sftp_server(share, host_key, tmp_path) as settings,
        pytest.raises(_RemoteError) as caught,
    ):
        _SftpClient(settings).publish("/in/.t.part", ["/in/msg.hl7"])
    assert caught.value.permanent is True
    assert "not found" in str(caught.value)


# === the real FTP client over a scripted ftplib.FTP ===========================


class _ScriptedFtp:
    """An ``ftplib.FTP`` stand-in over an in-memory directory. ``MLSD`` lists it. ``RNTO`` onto an
    existing name is refused with ``550`` when ``replaces`` is False, and replaces when True: RFC 959
    leaves that to the server. ``appear_after_listing`` lands partner files after the first listing,
    which is between the client's check and its rename."""

    def __init__(self, files: dict[str, bytes], *, replaces: bool = False) -> None:
        self.files = dict(files)
        self.replaces = replaces
        self.appear_after_listing: dict[str, bytes] = {}
        self.rnto_reply: str | None = None
        #: When set, MLSD and NLST both refuse with this 5xx reply.
        self.list_reply: str | None = None
        self.calls: list[str] = []
        self.connects = 0
        self._rnfr: str | None = None

    def connected(self) -> _ScriptedFtp:
        self.connects += 1
        return self

    def mlsd(self, path: str = "", facts: Any = ()) -> Iterator[tuple[str, dict[str, str]]]:
        self.calls.append(f"MLSD {path}")
        if self.list_reply is not None:
            raise ftplib.error_perm(self.list_reply)
        listing = [
            (posixpath.basename(p), {"type": "file"})
            for p in self.files
            if posixpath.dirname(p) == path
        ]
        self.files.update(self.appear_after_listing)
        self.appear_after_listing = {}
        return iter([(".", {"type": "cdir"}), *listing])

    def nlst(self, path: str = "") -> list[str]:
        assert self.list_reply is not None, "MLSD answers unless list_reply is set"
        raise ftplib.error_perm(self.list_reply)

    def sendcmd(self, cmd: str) -> str:
        verb, _, arg = cmd.partition(" ")
        assert verb == "RNFR", cmd
        if arg not in self.files:
            raise ftplib.error_perm("550 RNFR: no such file")
        self._rnfr = arg
        return "350 Ready for RNTO"

    def voidcmd(self, cmd: str) -> str:
        verb, _, toname = cmd.partition(" ")
        assert verb == "RNTO" and self._rnfr is not None, cmd
        self.calls.append(f"RNTO {toname}")
        if self.rnto_reply is not None:
            raise ftplib.error_perm(self.rnto_reply)
        if toname in self.files and not self.replaces:
            raise ftplib.error_perm("550 Rename failed: file exists")
        self.files[toname] = self.files.pop(self._rnfr)
        return "250 Rename successful"

    def quit(self) -> str:
        return "221 Goodbye"

    def close(self) -> None:
        return None


def _ftp_client(ftp: _ScriptedFtp, monkeypatch: pytest.MonkeyPatch) -> _FtpClient:
    """A real ``_FtpClient`` whose connect hands back ``ftp``, so ``_op``'s own error mapping runs."""
    monkeypatch.setattr(_FtpClient, "_connect", lambda self: ftp.connected())
    return _FtpClient({"host": "ftp.example.com"}, tls=False)


def test_ftp_publish_moves_the_temp_onto_a_free_name(monkeypatch: pytest.MonkeyPatch) -> None:
    ftp = _ScriptedFtp({"/in/.t.part": b"new"})
    assert _ftp_client(ftp, monkeypatch).publish("/in/.t.part", ["/in/msg.hl7"]) == "/in/msg.hl7"
    assert ftp.files == {"/in/msg.hl7": b"new"}


def test_ftp_publish_moves_on_to_the_next_name_on_one_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first name is listed taken; the second is written right after the listing and the
    server refuses ``RNTO`` onto it; the third is free. One connection, and the listing is taken
    again only after the refusal."""
    ftp = _ScriptedFtp({"/in/.t.part": b"new", "/in/a.hl7": _PARTNER})
    ftp.appear_after_listing["/in/b.hl7"] = _PARTNER
    published = _ftp_client(ftp, monkeypatch).publish(
        "/in/.t.part", ["/in/a.hl7", "/in/b.hl7", "/in/c.hl7"]
    )

    assert published == "/in/c.hl7"
    assert ftp.files == {"/in/a.hl7": _PARTNER, "/in/b.hl7": _PARTNER, "/in/c.hl7": b"new"}
    assert ftp.calls == ["MLSD /in", "RNTO /in/b.hl7", "MLSD /in", "RNTO /in/c.hl7"]
    assert ftp.connects == 1


def test_ftp_publish_refuses_a_name_already_taken(monkeypatch: pytest.MonkeyPatch) -> None:
    """Taken on the publish connection's own listing: no ``RNTO`` is sent."""
    ftp = _ScriptedFtp({"/in/.t.part": b"new", "/in/msg.hl7": _PARTNER})
    assert _ftp_client(ftp, monkeypatch).publish("/in/.t.part", ["/in/msg.hl7"]) is None
    assert ftp.files["/in/msg.hl7"] == _PARTNER
    assert not any(c.startswith("RNTO") for c in ftp.calls)


def test_ftp_publish_reads_a_refused_rnto_on_a_taken_name_as_a_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The partner writes between the check and ``RNTO``, on a server that refuses ``RNTO`` onto an
    existing name. The ``550`` is a collision, confirmed by a second listing, not a fault."""
    ftp = _ScriptedFtp({"/in/.t.part": b"new"})
    ftp.appear_after_listing["/in/msg.hl7"] = _PARTNER
    assert _ftp_client(ftp, monkeypatch).publish("/in/.t.part", ["/in/msg.hl7"]) is None
    assert ftp.files == {"/in/.t.part": b"new", "/in/msg.hl7": _PARTNER}
    assert ftp.calls == ["MLSD /in", "RNTO /in/msg.hl7", "MLSD /in"]


def test_ftp_publish_on_a_replacing_server_keeps_the_documented_residual(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE RESIDUAL, PINNED SO THE DOCS CANNOT OVERCLAIM. On a server whose ``RNTO`` replaces, a
    partner file written between the check and ``RNTO`` is still replaced: FTP has no refusing
    rename to lean on. ``_FtpClient.publish`` states this residual; if this test ever goes red,
    that docstring is what to correct."""
    ftp = _ScriptedFtp({"/in/.t.part": b"new"}, replaces=True)
    ftp.appear_after_listing["/in/msg.hl7"] = _PARTNER
    assert _ftp_client(ftp, monkeypatch).publish("/in/.t.part", ["/in/msg.hl7"]) == "/in/msg.hl7"
    assert ftp.files == {"/in/msg.hl7": b"new"}


def test_ftp_publish_refused_for_another_reason_keeps_its_class(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A refused ``RNTO`` with the name still free is no collision: it raises as the permanent
    operation refusal ``_op`` made of it before #2553."""
    ftp = _ScriptedFtp({"/in/.t.part": b"new"})
    ftp.rnto_reply = "553 Requested action not taken"
    with pytest.raises(_RemoteError) as caught:
        _ftp_client(ftp, monkeypatch).publish("/in/.t.part", ["/in/msg.hl7"])
    assert caught.value.permanent is True
    assert caught.value.connection_fault is False
    assert "553" in str(caught.value)


def test_ftp_publish_skips_a_case_variant_of_a_taken_name(monkeypatch: pytest.MonkeyPatch) -> None:
    """A case-insensitive server holds ``MSG.HL7`` against ``msg.hl7`` and would refuse the
    ``RNTO``, so the check compares case-blind and moves straight on."""
    ftp = _ScriptedFtp({"/in/.t.part": b"new", "/in/MSG.HL7": _PARTNER})
    client = _ftp_client(ftp, monkeypatch)
    assert client.publish("/in/.t.part", ["/in/msg.hl7", "/in/msg-1.hl7"]) == "/in/msg-1.hl7"
    assert ftp.files == {"/in/MSG.HL7": _PARTNER, "/in/msg-1.hl7": b"new"}


def test_ftp_publish_with_the_temp_gone_is_not_a_collision(monkeypatch: pytest.MonkeyPatch) -> None:
    """``RNFR`` refused means the temp is gone. Even with a partner file now at the name, that is
    no collision: it keeps the permanent class it had, rather than trying every other name."""
    ftp = _ScriptedFtp({})
    ftp.appear_after_listing["/in/msg.hl7"] = _PARTNER
    with pytest.raises(_RemoteError) as caught:
        _ftp_client(ftp, monkeypatch).publish("/in/.t.part", ["/in/msg.hl7", "/in/msg-1.hl7"])
    assert caught.value.permanent is True
    assert "RNFR" in str(caught.value)
    assert ftp.calls == ["MLSD /in"]  # no fresh listing, no RNTO: the refusal was never weighed


def test_ftp_publish_listing_failure_is_transient(monkeypatch: pytest.MonkeyPatch) -> None:
    """A listing refused on the publish connection retries, as every send-path listing does (the
    #1936 rule), rather than dead-lettering a message whose temp is already written."""
    ftp = _ScriptedFtp({"/in/.t.part": b"new"})
    ftp.list_reply = "550 No files found"
    with pytest.raises(_RemoteError) as caught:
        _ftp_client(ftp, monkeypatch).publish("/in/.t.part", ["/in/msg.hl7"])
    assert caught.value.permanent is False
    assert caught.value.connection_fault is False
    assert ftp.files == {"/in/.t.part": b"new"}


async def test_the_listing_is_case_blind(monkeypatch: pytest.MonkeyPatch) -> None:
    """The first guess compares case-blind too: ``MSG.HL7`` listed means ``msg.hl7`` is not
    offered, so the upload lands under ``msg-1.hl7`` without a refusal."""
    client = _RacingClient({"/in/MSG.HL7": _PARTNER})
    dest = _dest(monkeypatch, client, filename="msg.hl7", overwrite=False)
    await dest.send("new")
    assert client.files["/in/MSG.HL7"] == _PARTNER
    assert client.files["/in/msg-1.hl7"] == b"new"
    assert [dst for op, dst in client.ops if op == "publish"] == ["/in/msg-1.hl7"]


# === an SFTP rename whose outcome is unknown is never a collision ==============


class _StubSftp:
    """A paramiko ``SFTPClient`` stand-in for the cases a loopback server cannot stage: ``RENAME``
    carries out the move when ``moves`` is set, then raises ``fail_with``, as a reply lost or late
    would."""

    def __init__(self, files: dict[str, bytes], fail_with: Exception, *, moves: bool) -> None:
        self.files = dict(files)
        self.calls: list[str] = []
        self._fail_with = fail_with
        self._moves = moves

    def lstat(self, path: str) -> object:
        self.calls.append(f"lstat {path}")
        if path not in self.files:
            raise FileNotFoundError(path)
        return object()

    def rename(self, oldpath: str, newpath: str) -> None:
        self.calls.append(f"rename {newpath}")
        if self._moves:
            self.files[newpath] = self.files.pop(oldpath)
        raise self._fail_with


def _stub_sftp_client(sftp: _StubSftp, monkeypatch: pytest.MonkeyPatch) -> _SftpClient:
    monkeypatch.setattr(_SftpClient, "_op", lambda self, fn, **_: fn(sftp))
    return _SftpClient({"host": "sftp.example.com"})


def test_sftp_rename_that_completed_despite_an_error_is_not_a_collision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The server moved the temp onto ``a.hl7`` but the reply came back a failure. ``a.hl7`` is
    now held, by this very message. Read as a collision, the loop would move on and fail on
    ``b.hl7`` with the temp gone. The temp's absence says nothing was refused, so it raises."""
    sftp = _StubSftp({"/in/.t.part": b"new"}, OSError("Failure"), moves=True)
    with pytest.raises(OSError, match="Failure"):
        _stub_sftp_client(sftp, monkeypatch).publish("/in/.t.part", ["/in/a.hl7", "/in/b.hl7"])
    assert sftp.files == {"/in/a.hl7": b"new"}
    assert not any("b.hl7" in c for c in sftp.calls)


def test_sftp_rename_timeout_is_not_a_collision(monkeypatch: pytest.MonkeyPatch) -> None:
    """A timed-out ``RENAME`` may still complete on the server, so it is never a refusal. It
    raises at once, with no second ``lstat`` to wait out another timeout on a stalled channel."""
    sftp = _StubSftp({"/in/.t.part": b"new"}, TimeoutError("timed out"), moves=False)
    with pytest.raises(TimeoutError):
        _stub_sftp_client(sftp, monkeypatch).publish("/in/.t.part", ["/in/a.hl7", "/in/b.hl7"])
    assert sftp.calls == ["lstat /in/a.hl7", "rename /in/a.hl7"]

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5026: a REMOTEFILE error carries a reply code, never the server's reply text.

A server's refusal can quote the path it refused, and on an upload that path ends in a name rendered
from message fields. The error text goes at least to the outbox row's ``last_error`` and to the
alert detail. Before #5026 the upload scrubbed the reply with a denylist of the rendered names
(BACKLOG #2814), so a reply that cut the name short or percent-encoded it kept the identifier. Now
the client reports an FTP reply by its code and a fixed meaning, and an SFTP failure by its type and
errno, so no form of the name can survive.

These tests run the real ``_FtpClient`` and ``_SftpClient`` error mapping, over a scripted session.
The rendered name holds a space, so percent-encoding changes it. Synthetic data only (CLAUDE.md
section 9).
"""

from __future__ import annotations

import errno
import ftplib
import posixpath
import urllib.parse
from collections.abc import Callable, Iterator
from typing import Any, BinaryIO

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Sftp
from messagefoundry.redaction import safe_exc
from messagefoundry.transports import build_destination, remotefile
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.remotefile import (
    RemoteFileDestination,
    _fault_detail,
    _FtpClient,
    _RemoteError,
)
from tests.test_file_write_error_names import MRN, TEMPLATE, _traceback
from tests.test_remotefile_sftp_bounds import (
    _FakeSftpError,
    _FakeSshException,
    _sftp_client_with,
    _StubSshClient,
)

NAME = f"{MRN}_SYN THETIC.hl7"
BODY = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    f"PID|1||{MRN}^^^H^MR||SYN THETIC^PAT\r"
)

#: The forms a server may quote a path in. Only ``exact`` was caught by the #2814 denylist.
_ECHOES: dict[str, Callable[[str], str]] = {
    "exact": lambda path: path,
    "truncated": lambda path: posixpath.join(
        posixpath.dirname(path), posixpath.basename(path)[:13]
    ),
    "percent-encoded": urllib.parse.quote,
}


class _EchoingFtp:
    """An ``ftplib.FTP`` session whose refusal at ``step`` quotes the path it refused, in ``form``.

    ``permanent`` picks a ``550`` (``error_perm``) or a ``451`` (``error_temp``). With
    ``cleanup_raises``, removing the temp raises a ``RuntimeError``, which no client maps."""

    def __init__(self, step: str, form: str, *, permanent: bool, cleanup_raises: bool = False):
        self.step = step
        self.echo = _ECHOES[form]
        self.permanent = permanent
        self.cleanup_raises = cleanup_raises
        self.replies: list[str] = []

    def _refuse(self, path: str) -> ftplib.Error:
        code, error = ("550", ftplib.error_perm) if self.permanent else ("451", ftplib.error_temp)
        self.replies.append(f"{code} {self.echo(path)}: Permission denied")
        return error(self.replies[-1])

    def mkd(self, path: str) -> str:
        raise ftplib.error_perm("550 Directory already exists")

    def mlsd(self, path: str = "", facts: Any = ()) -> Iterator[tuple[str, dict[str, str]]]:
        return iter([])

    def storbinary(self, cmd: str, fp: BinaryIO) -> str:
        if self.step == "store":
            raise self._refuse(cmd.partition(" ")[2])
        return "226 Transfer complete"

    def sendcmd(self, cmd: str) -> str:
        return "350 Ready for RNTO"  # RNFR

    def voidcmd(self, cmd: str) -> str:
        if self.step == "publish":
            raise self._refuse(cmd.partition(" ")[2])  # RNTO
        return "250 Rename successful"

    def rename(self, src: str, dst: str) -> str:
        if self.step == "rename":
            raise self._refuse(dst)
        return "250 Rename successful"

    def delete(self, path: str) -> str:
        if self.cleanup_raises:
            raise RuntimeError("synthetic cleanup fault")
        return "250 Deleted"

    def quit(self) -> str:
        return "221 Goodbye"

    def close(self) -> None:
        return None


def _dest(monkeypatch: pytest.MonkeyPatch, ftp: _EchoingFtp) -> RemoteFileDestination:
    """A destination over the real ``_FtpClient``, whose connect hands back ``ftp``."""
    client = _FtpClient({"host": "ftp.example.com"}, tls=False)
    monkeypatch.setattr(_FtpClient, "_connect", lambda self: ftp)
    monkeypatch.setattr(remotefile, "_make_client", lambda settings, **_: client)
    spec = Sftp(
        host="ftp.example.com",
        remote_dir="/in",
        filename=TEMPLATE,
        overwrite=ftp.step == "rename",
    )
    dest = build_destination(
        Destination(name="OB_REMOTE", type=ConnectorType.REMOTEFILE, settings=spec.settings),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(dest, RemoteFileDestination)
    return dest


@pytest.mark.parametrize("permanent", [True, False], ids=["550", "451"])
@pytest.mark.parametrize("form", list(_ECHOES))
@pytest.mark.parametrize("step", ["store", "publish", "rename"])
async def test_an_echoed_name_in_any_form_stays_out_of_the_error(
    monkeypatch: pytest.MonkeyPatch, step: str, form: str, permanent: bool
) -> None:
    ftp = _EchoingFtp(step, form, permanent=permanent)
    with pytest.raises(DeliveryError) as raised:
        await _dest(monkeypatch, ftp).send(BODY)
    # Positive control: the server's reply quoted the identifier, so a leak would show.
    (reply,) = ftp.replies
    assert MRN in reply
    text = str(raised.value)
    assert MRN not in text and MRN not in safe_exc(raised.value)
    assert MRN not in _traceback(raised.value)
    # The reply's code and class survive.
    if permanent:
        assert isinstance(raised.value, NegativeAckError)
        assert text == (
            "FTP rejected the operation: reply 550 (file unavailable, such as not found or no "
            "access)"
        )
    else:
        assert not isinstance(raised.value, NegativeAckError)
        assert text == "FTP operation failed: reply 451 (local error in processing)"


@pytest.mark.parametrize("step", ["store", "publish"])
async def test_a_cleanup_failure_does_not_chain_the_reply(
    monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    # Removing the temp raises something no client maps. It escapes the upload, and before #5026
    # it carried the refused operation's error, and through it the reply, on __context__.
    ftp = _EchoingFtp(step, "exact", permanent=True, cleanup_raises=True)
    with pytest.raises(RuntimeError, match="synthetic cleanup fault") as raised:
        await _dest(monkeypatch, ftp).send(BODY)
    (reply,) = ftp.replies
    assert MRN in reply  # positive control
    assert raised.value.__context__ is None and raised.value.__cause__ is None
    assert MRN not in _traceback(raised.value)


def test_a_plain_status_still_reads() -> None:
    """CONTROL: what the operator keeps is the code and a fixed meaning, not an empty text."""
    assert _fault_detail(ftplib.error_perm("550 Permission denied")) == (
        "reply 550 (file unavailable, such as not found or no access)"
    )
    assert _fault_detail(ftplib.error_temp("421-Busy\n421 Service closing")) == (
        "reply 421 (service not available)"
    )
    assert _fault_detail(ftplib.error_perm("599 Odd")) == "reply 599"
    # A digit run that is no reply code is not read as one.
    assert (
        _fault_detail(ftplib.error_proto(f"{MRN} garbled")) == "error_proto, a reply with no code"
    )
    assert _fault_detail(ftplib.error_perm("5501 x")) == "error_perm, a reply with no code"
    assert _fault_detail(ConnectionResetError(errno.ECONNRESET, "reset by peer")) == (
        f"ConnectionResetError, errno {errno.ECONNRESET} ({errno.errorcode[errno.ECONNRESET]})"
    )
    assert _fault_detail(EOFError("server text")) == "EOFError"


@pytest.mark.parametrize(
    ("raised", "says"),
    [
        (
            FileNotFoundError(errno.ENOENT, f"No such file /in/{NAME}"),
            f"SFTP path not found: FileNotFoundError, errno {errno.ENOENT} (ENOENT)",
        ),
        (
            PermissionError(errno.EACCES, f"Denied /in/{NAME[:13]}"),
            f"SFTP operation failed: PermissionError, errno {errno.EACCES} (EACCES)",
        ),
        (OSError(f"Failure: /in/{urllib.parse.quote(NAME)}"), "SFTP operation failed: OSError"),
        (EOFError(f"/in/{NAME}"), "SFTP connection closed: EOFError"),
        (_FakeSftpError(f"bad reply for /in/{NAME}"), "SFTP protocol error: _FakeSftpError"),
        (_FakeSshException(f"/in/{NAME}"), "SFTP operation failed: _FakeSshException"),
    ],
    ids=["no-such-file", "permission-denied", "other-status", "eof", "sftp-error", "ssh"],
)
def test_an_sftp_status_text_stays_out_of_the_error(
    monkeypatch: pytest.MonkeyPatch, raised: BaseException, says: str
) -> None:
    class _FailingOpenSsh(_StubSshClient):
        def open_sftp(self) -> Any:
            raise raised

    assert MRN in str(raised)  # positive control
    with pytest.raises(_RemoteError) as caught:
        _sftp_client_with(_FailingOpenSsh(None), monkeypatch).list_dir("/in")
    assert str(caught.value) == says
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert MRN not in _traceback(caught.value)

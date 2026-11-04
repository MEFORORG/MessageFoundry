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

import ast
import errno
import ftplib
import logging
import posixpath
import socket
import ssl
import urllib.parse
from collections.abc import Callable, Iterator
from pathlib import Path
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
    _ftp_size,
    _FtpClient,
    _RemoteError,
)
from tests._refusal_log_capture import record_texts
from tests.test_file_write_error_names import MRN, TEMPLATE, _traceback
from tests.test_remotefile_publish_refuses import _ftp_client, _ScriptedFtp
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


def test_a_reply_code_is_ascii_digits_only() -> None:
    # Non-ASCII decimal digits are the server's characters, not a reply code.
    assert _fault_detail(ftplib.error_perm("5٥٠ x")) == "error_perm, a reply with no code"


def test_a_tls_failure_keeps_the_tls_library_reason() -> None:
    """A TLS failure's errno is an OpenSSL code, not an errno, so it is not named as one; OpenSSL's
    own reason and verify message are this engine's wording and stay, so an expired certificate
    reads apart from a hostname mismatch."""
    exc = ssl.SSLCertVerificationError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify")
    exc.reason = "CERTIFICATE_VERIFY_FAILED"
    exc.verify_message = "certificate has expired"
    assert _fault_detail(exc) == (
        "SSLCertVerificationError, CERTIFICATE_VERIFY_FAILED, certificate has expired"
    )
    # Not EPERM, which errno 1 would read as.
    assert _fault_detail(ssl.SSLEOFError(8, "EOF occurred in violation of protocol")) == (
        "SSLEOFError"
    )


def test_a_name_lookup_failure_names_its_getaddrinfo_code() -> None:
    detail = _fault_detail(socket.gaierror(socket.EAI_NONAME, "Name or service not known"))
    assert detail.startswith(f"gaierror, errno {socket.EAI_NONAME} (EAI_")
    assert "unknown" not in detail and "Name or service" not in detail
    # An errno nothing names is shown by its number alone.
    assert _fault_detail(OSError(987654, "server text")) == "OSError, errno 987654"


def test_a_size_reply_that_is_no_number_reads_as_no_size() -> None:
    """``ftplib.FTP.size`` raises a ``ValueError`` quoting the reply when ``213`` carries no number.
    That is the server not saying, so it reads as ``None`` rather than escaping ``_op`` unmapped."""
    ftp = ftplib.FTP()  # no host: never connects
    reply = f"213 /in/{NAME}"
    ftp.sendcmd = lambda cmd: reply  # type: ignore[method-assign]
    with pytest.raises(ValueError, match=MRN):  # CONTROL: ftplib's own error quotes the reply
        ftplib.FTP.size(ftp, "/in/x")
    assert _ftp_size(ftp, "/in/x") is None


class _JunkSizeFtp:
    """An ``MLSD`` that lists a file whose ``size`` fact quotes a path, not a number."""

    def mlsd(self, path: str = "", facts: Any = ()) -> Iterator[tuple[str, dict[str, str]]]:
        return iter([("a.hl7", {"type": "file", "size": f"/in/{NAME}"})])

    def quit(self) -> str:
        return "221 Goodbye"

    def close(self) -> None:
        return None


def test_an_mlsd_size_that_is_no_number_fails_the_listing_as_fixed_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_FtpClient, "_connect", lambda self: _JunkSizeFtp())
    with pytest.raises(_RemoteError) as caught:
        _FtpClient({"host": "ftp.example.com"}, tls=False).list_entries("/in")
    assert str(caught.value) == "FTP MLSD listing gave a size that is not a number"
    assert caught.value.permanent is False
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert MRN not in _traceback(caught.value)


def test_a_failed_first_publish_listing_carries_no_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    ftp = _ScriptedFtp({"/in/.t.part": b"new"})
    ftp.list_reply = f"550 {urllib.parse.quote('/in/' + NAME)}: Permission denied"
    assert MRN in ftp.list_reply  # positive control
    with pytest.raises(_RemoteError) as caught:
        _ftp_client(ftp, monkeypatch).publish("/in/.t.part", ["/in/msg.hl7"])
    assert str(caught.value) == (
        "FTP could not list the upload directory to check a name: reply 550 (file unavailable, "
        "such as not found or no access)"
    )
    assert caught.value.permanent is False
    assert caught.value.__context__ is None and caught.value.__cause__ is None
    assert MRN not in _traceback(caught.value)


def test_a_failed_confirming_listing_logs_no_reply(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """``RNTO`` is refused, and the listing meant to confirm a collision fails with a reply quoting
    a name. The WARNING it logs, and the refusal raised after it, carry the codes alone."""
    ftp = _ScriptedFtp({"/in/.t.part": b"new"})
    ftp.rnto_reply = f"553 /in/{NAME[:13]} not allowed"
    ftp.list_reply = f"550 /in/{NAME}: Permission denied"
    ftp.listings_before_failure = 1
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.transports.remotefile"),
        pytest.raises(_RemoteError) as caught,
    ):
        _ftp_client(ftp, monkeypatch).publish("/in/.t.part", ["/in/msg.hl7"])
    assert ftp.listings == 2  # the confirming listing ran, and failed
    warned = [r for r in caplog.records if "confirm a refused RNTO" in r.getMessage()]
    assert len(warned) == 1
    assert "reply 550" in warned[0].getMessage()
    assert not [r for r in caplog.records if any(MRN in t for t in record_texts(r))]
    assert str(caught.value) == "FTP rejected the operation: reply 553 (file name not allowed)"
    assert MRN not in _traceback(caught.value)


# --- the rule, held by a scan of the module ----------------------------------

#: Exception types a handler may catch and still raise inside: the module's own, whose text the
#: rule already governs where they were built.
_OWN = frozenset({"_RemoteError", "_RemoteOversize", "_RemoteChanged"})

#: Functions allowed to raise inside a handler of another type, or to put that exception into a
#: ``_RemoteError``'s text, each with why. Exact: a site that stops needing its entry fails too.
_ALLOWED = {
    # ImportError of the optional extra; the message is fixed text.
    "_import_paramiko",
    # Thread.start's RuntimeError is this process short of a thread; no server text exists yet.
    "_start_helper",
    # The documented carve-out: an SFTP connect refusal keeps paramiko's text and chain.
    "_SftpClient._connect",
    # A configuration refusal at construction, before any connection.
    "_anon_ftp_guard",
}


def _caught(node: ast.expr | None) -> set[str]:
    if node is None:
        return {"BaseException"}
    elts = node.elts if isinstance(node, ast.Tuple) else [node]
    return {
        e.id if isinstance(e, ast.Name) else e.attr if isinstance(e, ast.Attribute) else ""
        for e in elts
    }


def _breaks(source: str) -> set[tuple[str, int, str]]:
    """Every site, as (function, line, what), that raises inside a handler of a foreign exception
    type, or interpolates that exception into a ``_RemoteError`` other than through
    ``_fault_detail``. A raise inside the handler chains the caught exception on ``__context__``,
    and the caught exception's text is the server's (BACKLOG #5026). At least one indirection is
    not seen: text read from the exception into a local first, as ``_ftp_connect_refusal`` does."""
    found: set[tuple[str, int, str]] = set()

    def visit(node: ast.AST, qual: str, bound: tuple[str, ...], inside: bool) -> None:
        for child in ast.iter_child_nodes(node):
            q, b, i = qual, bound, inside
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                q = f"{qual}.{child.name}" if qual else child.name
            if isinstance(child, ast.ExceptHandler) and not _caught(child.type) <= _OWN:
                b, i = (*bound, child.name or ""), True
            if isinstance(child, ast.Raise) and child.exc is not None and inside:
                found.add((q, child.lineno, "raise inside a handler"))
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "_RemoteError"
            ):
                for sub in ast.walk(child):
                    if not isinstance(sub, ast.FormattedValue):
                        continue
                    v = sub.value
                    if isinstance(v, ast.Call) and getattr(v.func, "id", "") == "_fault_detail":
                        continue
                    if any(isinstance(n, ast.Name) and n.id in bound for n in ast.walk(v)):
                        found.add((q, child.lineno, "interpolates the caught exception"))
            visit(child, q, b, i)

    visit(ast.parse(source), "", (), False)
    return found


def test_the_scan_sees_both_shapes() -> None:
    """CONTROL: the scan flags a raise inside a foreign handler and an interpolated reply, and
    passes the shape every client now uses."""
    source = (
        "def bad(ftp):\n"
        "    try:\n"
        "        ftp.go()\n"
        "    except ftplib.error_perm as exc:\n"
        "        raise _RemoteError(f'refused: {exc}', permanent=True) from exc\n"
        "def good(ftp):\n"
        "    try:\n"
        "        ftp.go()\n"
        "    except ftplib.error_perm as exc:\n"
        "        fault = _RemoteError(f'refused: {_fault_detail(exc)}', permanent=True)\n"
        "    raise fault\n"
    )
    assert _breaks(source) == {
        ("bad", 5, "raise inside a handler"),
        ("bad", 5, "interpolates the caught exception"),
    }


def test_no_client_raises_inside_a_handler_or_quotes_a_caught_error() -> None:
    source = Path(remotefile.__file__).read_text(encoding="utf-8")
    assert {where for where, _, _ in _breaks(source)} == _ALLOWED
